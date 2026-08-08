use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;

use crate::domain::breaker::{Breaker, BreakerPermit, BreakerTransition};
use crate::domain::resp::{ExecError, RespValue};
use crate::ports::{CommandExecutor, RedisCommand};

/// Records Redis transport outcomes without coupling executors to acquisition.
pub struct BreakerExecutor {
    inner: Arc<dyn CommandExecutor>,
    breaker: Arc<Breaker>,
    permit: BreakerPermit,
    pool: String,
    recorded: AtomicBool,
}

impl BreakerExecutor {
    pub fn new(
        inner: Arc<dyn CommandExecutor>,
        breaker: Arc<Breaker>,
        permit: BreakerPermit,
        pool: String,
    ) -> Self {
        Self {
            inner,
            breaker,
            permit,
            pool,
            recorded: AtomicBool::new(false),
        }
    }

    fn record<'a>(&self, errors: impl IntoIterator<Item = &'a ExecError>) {
        self.recorded.store(true, Ordering::Release);
        let failed = errors.into_iter().any(counts_as_failure);
        if let Some(transition) = self.breaker.record(self.permit, failed) {
            emit_transition(&self.pool, transition);
        }
    }
}

impl Drop for BreakerExecutor {
    fn drop(&mut self) {
        if !self.recorded.load(Ordering::Acquire) {
            self.breaker.cancel(self.permit);
        }
    }
}

#[async_trait]
impl CommandExecutor for BreakerExecutor {
    async fn execute(&self, command: RedisCommand) -> Result<RespValue, ExecError> {
        let result = self.inner.execute(command).await;
        self.record(result.as_ref().err());
        result
    }

    async fn pipeline(&self, commands: Vec<RedisCommand>) -> Vec<Result<RespValue, ExecError>> {
        let results = self.inner.pipeline(commands).await;
        self.record(results.iter().filter_map(|result| result.as_ref().err()));
        results
    }

    async fn transaction(&self, commands: Vec<RedisCommand>) -> Result<Vec<RespValue>, ExecError> {
        let result = self.inner.transaction(commands).await;
        self.record(result.as_ref().err());
        result
    }
}

fn counts_as_failure(error: &ExecError) -> bool {
    matches!(error, ExecError::Transport(_) | ExecError::Timeout)
}

pub(crate) fn emit_transition(pool: &str, transition: BreakerTransition) {
    let state = match transition {
        BreakerTransition::Closed => 0.0,
        BreakerTransition::ProbeStarted => 1.0,
        BreakerTransition::Opened => 2.0,
    };
    metrics::gauge!("srh_pool_breaker_state", "pool" => pool.to_owned()).set(state);
    tracing::warn!(%pool, ?transition, "Redis circuit breaker state changed");
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use bytes::Bytes;

    use super::*;
    use crate::domain::breaker::BreakerState;
    use crate::ports::Clock;
    use crate::testsupport::FakeExecutor;

    struct FixedClock(Instant);

    impl Clock for FixedClock {
        fn unix_secs(&self) -> u64 {
            0
        }

        fn instant(&self) -> Instant {
            self.0
        }
    }

    fn command() -> RedisCommand {
        RedisCommand {
            name: "PING".to_owned(),
            args: vec![Bytes::new()],
        }
    }

    #[tokio::test]
    async fn only_transport_and_timeout_failures_open_the_breaker() {
        for error in [
            ExecError::Redis("WRONGTYPE".to_owned()),
            ExecError::ResponseTooLarge,
        ] {
            let breaker = Arc::new(Breaker::new(
                Arc::new(FixedClock(Instant::now())),
                1,
                Duration::from_secs(1),
            ));
            let executor = BreakerExecutor::new(
                Arc::new(FakeExecutor::new([Err(error)])),
                Arc::clone(&breaker),
                breaker.admit().unwrap().permit,
                "test".to_owned(),
            );
            assert!(executor.execute(command()).await.is_err());
            assert_eq!(breaker.state(), BreakerState::Closed);
        }

        let breaker = Arc::new(Breaker::new(
            Arc::new(FixedClock(Instant::now())),
            1,
            Duration::from_secs(1),
        ));
        let executor = BreakerExecutor::new(
            Arc::new(FakeExecutor::new([Err(ExecError::Timeout)])),
            Arc::clone(&breaker),
            breaker.admit().unwrap().permit,
            "test".to_owned(),
        );
        assert!(executor.execute(command()).await.is_err());
        assert_eq!(breaker.state(), BreakerState::Open);
    }

    #[tokio::test]
    async fn any_transport_failure_in_a_pipeline_counts_once() {
        let breaker = Arc::new(Breaker::new(
            Arc::new(FixedClock(Instant::now())),
            1,
            Duration::from_secs(1),
        ));
        let executor = BreakerExecutor::new(
            Arc::new(FakeExecutor::new([
                Ok(RespValue::Int(1)),
                Err(ExecError::Transport("closed".to_owned())),
            ])),
            Arc::clone(&breaker),
            breaker.admit().unwrap().permit,
            "test".to_owned(),
        );
        let _ = executor.pipeline(vec![command(), command()]).await;
        assert_eq!(breaker.state(), BreakerState::Open);
    }
}
