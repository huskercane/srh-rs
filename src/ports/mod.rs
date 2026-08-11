use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use bytes::Bytes;

use crate::domain::identity::{AuthError, CachedKey, Identity, IntrospectError, JwksError};
use crate::domain::resp::{AcquireError, ExecError, PoolReadiness, RespValue};

/// A raw Redis command after request argument conversion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedisCommand {
    pub name: String,
    pub args: Vec<Bytes>,
}

/// Executes Redis commands without exposing an adapter-specific value type.
#[async_trait]
pub trait CommandExecutor: Send + Sync {
    async fn execute(&self, cmd: RedisCommand) -> Result<RespValue, ExecError>;

    async fn pipeline(&self, cmds: Vec<RedisCommand>) -> Vec<Result<RespValue, ExecError>>;

    async fn transaction(
        &self,
        cmds: Vec<RedisCommand>,
    ) -> Result<Vec<Result<RespValue, ExecError>>, ExecError>;
}

/// An acquired executor whose opaque lease is released when the handle drops.
pub struct ExecutorHandle {
    executor: Arc<dyn CommandExecutor>,
    _lease: Box<dyn Send + Sync>,
}

impl ExecutorHandle {
    /// Creates a handle from an executor and its adapter-owned lease guard.
    pub fn new(executor: Arc<dyn CommandExecutor>, lease: Box<dyn Send + Sync>) -> Self {
        Self {
            executor,
            _lease: lease,
        }
    }

    /// Returns the acquired command executor.
    pub fn executor(&self) -> &Arc<dyn CommandExecutor> {
        &self.executor
    }

    /// Executes one command and releases the acquired lease before returning the result.
    pub async fn execute_and_release(self, command: RedisCommand) -> Result<RespValue, ExecError> {
        let result = self.executor.execute(command).await;
        drop(self);
        result
    }

    /// Executes a pipeline and releases the acquired lease before returning its results.
    pub async fn pipeline_and_release(
        self,
        commands: Vec<RedisCommand>,
    ) -> Vec<Result<RespValue, ExecError>> {
        let results = self.executor.pipeline(commands).await;
        drop(self);
        results
    }

    /// Executes a transaction and releases the acquired lease before returning its results.
    pub async fn transaction_and_release(
        self,
        commands: Vec<RedisCommand>,
    ) -> Result<Vec<Result<RespValue, ExecError>>, ExecError> {
        let results = self.executor.transaction(commands).await;
        drop(self);
        results
    }
}

/// Acquires bounded access to lazily built Redis executors.
#[async_trait]
pub trait ExecutorProvider: Send + Sync {
    async fn acquire(&self, pool: &str) -> Result<ExecutorHandle, AcquireError>;

    /// Checks only pools that have already been built.
    async fn readiness(&self) -> Vec<PoolReadiness>;
}

/// Authenticates a bearer credential.
#[async_trait]
pub trait Authenticator: Send + Sync {
    async fn authenticate(&self, bearer: &str) -> Result<Option<Arc<Identity>>, AuthError>;
}

/// Supplies trusted JWT verification keys.
#[async_trait]
pub trait JwksSource: Send + Sync {
    async fn key_for(&self, kid: &str) -> Result<CachedKey, JwksError>;
}

/// Checks token activity with an authorization service.
#[async_trait]
pub trait Introspector: Send + Sync {
    async fn is_active(&self, token: &str) -> Result<bool, IntrospectError>;
}

/// Supplies wall-clock and monotonic time to pure state machines.
pub trait Clock: Send + Sync {
    fn unix_secs(&self) -> u64;
    fn instant(&self) -> Instant;
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    struct NoopExecutor;

    #[async_trait]
    impl CommandExecutor for NoopExecutor {
        async fn execute(&self, _cmd: RedisCommand) -> Result<RespValue, ExecError> {
            unreachable!("executor is not invoked by this ownership test")
        }

        async fn pipeline(&self, _cmds: Vec<RedisCommand>) -> Vec<Result<RespValue, ExecError>> {
            unreachable!("executor is not invoked by this ownership test")
        }

        async fn transaction(
            &self,
            _cmds: Vec<RedisCommand>,
        ) -> Result<Vec<Result<RespValue, ExecError>>, ExecError> {
            unreachable!("executor is not invoked by this ownership test")
        }
    }

    struct Lease {
        dropped: Arc<AtomicBool>,
    }

    impl Drop for Lease {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Release);
        }
    }

    #[test]
    fn executor_handle_owns_executor_and_releases_lease_on_drop() {
        let executor: Arc<dyn CommandExecutor> = Arc::new(NoopExecutor);
        let dropped = Arc::new(AtomicBool::new(false));
        let lease = Lease {
            dropped: Arc::clone(&dropped),
        };
        let handle = ExecutorHandle::new(Arc::clone(&executor), Box::new(lease));

        assert!(Arc::ptr_eq(handle.executor(), &executor));
        assert!(!dropped.load(Ordering::Acquire));

        drop(handle);

        assert!(dropped.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn consuming_execution_releases_each_lease_before_returning() {
        struct ReplyingExecutor;

        #[async_trait]
        impl CommandExecutor for ReplyingExecutor {
            async fn execute(&self, _cmd: RedisCommand) -> Result<RespValue, ExecError> {
                Ok(RespValue::Simple("OK".to_owned()))
            }

            async fn pipeline(&self, cmds: Vec<RedisCommand>) -> Vec<Result<RespValue, ExecError>> {
                vec![Ok(RespValue::Simple("OK".to_owned())); cmds.len()]
            }

            async fn transaction(
                &self,
                cmds: Vec<RedisCommand>,
            ) -> Result<Vec<Result<RespValue, ExecError>>, ExecError> {
                Ok(vec![Ok(RespValue::Simple("OK".to_owned())); cmds.len()])
            }
        }

        fn handle(released: &Arc<AtomicBool>) -> ExecutorHandle {
            let executor: Arc<dyn CommandExecutor> = Arc::new(ReplyingExecutor);
            ExecutorHandle::new(
                executor,
                Box::new(Lease {
                    dropped: Arc::clone(released),
                }),
            )
        }

        let command = RedisCommand {
            name: "PING".to_owned(),
            args: Vec::new(),
        };
        for operation in 0..3 {
            let released = Arc::new(AtomicBool::new(false));
            match operation {
                0 => {
                    handle(&released)
                        .execute_and_release(command.clone())
                        .await
                        .unwrap();
                }
                1 => {
                    handle(&released)
                        .pipeline_and_release(vec![command.clone()])
                        .await;
                }
                _ => {
                    handle(&released)
                        .transaction_and_release(vec![command.clone()])
                        .await
                        .unwrap();
                }
            }
            assert!(released.load(Ordering::Acquire));
        }
    }

    #[test]
    fn all_ports_are_object_safe() {
        fn assert_command_executor(_: Option<&dyn CommandExecutor>) {}
        fn assert_executor_provider(_: Option<&dyn ExecutorProvider>) {}
        fn assert_authenticator(_: Option<&dyn Authenticator>) {}
        fn assert_jwks_source(_: Option<&dyn JwksSource>) {}
        fn assert_introspector(_: Option<&dyn Introspector>) {}
        fn assert_clock(_: Option<&dyn Clock>) {}

        assert_command_executor(None);
        assert_executor_provider(None);
        assert_authenticator(None);
        assert_jwks_source(None);
        assert_introspector(None);
        assert_clock(None);
    }
}
