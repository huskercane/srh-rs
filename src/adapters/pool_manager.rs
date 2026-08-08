use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use fred::clients::Pool;
use fred::interfaces::ClientLike;
use fred::types::ConnectHandle;
use fred::types::RespVersion;
use fred::types::config::{
    Config as FredConfig, ConnectionConfig, PerformanceConfig, ReconnectPolicy,
};

use crate::adapters::breaker_executor::{BreakerExecutor, emit_transition};
use crate::adapters::fred_executor::FredExecutor;
use crate::config::{Config, PoolConfig};
use crate::domain::breaker::Breaker;
use crate::domain::resp::{AcquireError, PoolReadiness, PoolReadinessStatus, RespValue};
use crate::ports::{Clock, CommandExecutor, ExecutorHandle, ExecutorProvider, RedisCommand};

const IDLE_EVICTION_SECS: u64 = 900;

pub struct PoolManager {
    pools: DashMap<String, Arc<PoolEntry>>,
    config: Arc<Config>,
    clock: Arc<dyn Clock>,
}

struct PoolEntry {
    pool: Pool,
    connection_tasks: Mutex<Vec<ConnectHandle>>,
    last_used: AtomicU64,
    permits: Arc<tokio::sync::Semaphore>,
    permit_count: usize,
    waiters: Arc<AtomicUsize>,
    max_waiters: usize,
    acquire_timeout: Duration,
    command_timeout: Duration,
    breaker: Arc<Breaker>,
}

impl PoolManager {
    pub fn new(config: Arc<Config>, clock: Arc<dyn Clock>) -> Self {
        Self {
            pools: DashMap::new(),
            config,
            clock,
        }
    }

    fn get_or_build(&self, name: &str) -> Result<Arc<PoolEntry>, AcquireError> {
        let pool_config = self
            .config
            .pools
            .get(name)
            .ok_or_else(|| AcquireError::UnknownPool(name.to_owned()))?;
        match self.pools.entry(name.to_owned()) {
            Entry::Occupied(entry) => {
                entry.get().ensure_connection_task();
                entry
                    .get()
                    .last_used
                    .store(self.clock.unix_secs(), Ordering::Release);
                Ok(Arc::clone(entry.get()))
            }
            Entry::Vacant(entry) => {
                let built = Arc::new(self.build(name, pool_config)?);
                metrics::counter!("srh_pool_builds_total", "pool" => name.to_owned()).increment(1);
                entry.insert(Arc::clone(&built));
                Ok(built)
            }
        }
    }

    fn build(&self, name: &str, pool_config: &PoolConfig) -> Result<PoolEntry, AcquireError> {
        let mut config = FredConfig::from_url(pool_config.connection_string.expose())
            .map_err(|error| AcquireError::Internal(error.to_string()))?;
        config.version = RespVersion::RESP2;
        let command_timeout = Duration::from_millis(pool_config.command_timeout_ms);
        let connection = ConnectionConfig {
            connection_timeout: Duration::from_millis(pool_config.acquire_timeout_ms),
            internal_command_timeout: command_timeout,
            max_command_buffer_len: self.config.server.max_pipeline_commands.max(1),
            ..ConnectionConfig::default()
        };
        let performance = PerformanceConfig {
            default_command_timeout: command_timeout,
            ..PerformanceConfig::default()
        };
        let pool = Pool::new(
            config,
            Some(performance),
            Some(connection),
            Some(ReconnectPolicy::new_exponential(0, 100, 5_000, 2)),
            pool_config.max_connections,
        )
        .map_err(|error| AcquireError::Internal(error.to_string()))?;
        // `connect` starts reconnect loops but does not wait for or ping Redis.
        let connection_task = pool.connect();
        metrics::gauge!("srh_pool_breaker_state", "pool" => name.to_owned()).set(0.0);
        tracing::info!(
            pool = name,
            size = pool_config.max_connections,
            "Redis pool built"
        );
        Ok(PoolEntry {
            pool,
            connection_tasks: Mutex::new(vec![connection_task]),
            last_used: AtomicU64::new(self.clock.unix_secs()),
            permits: Arc::new(tokio::sync::Semaphore::new(pool_config.max_connections)),
            permit_count: pool_config.max_connections,
            waiters: Arc::new(AtomicUsize::new(0)),
            max_waiters: pool_config.max_waiters,
            acquire_timeout: Duration::from_millis(pool_config.acquire_timeout_ms),
            command_timeout,
            breaker: Arc::new(Breaker::new(
                Arc::clone(&self.clock),
                pool_config.breaker.failure_threshold,
                Duration::from_millis(pool_config.breaker.cooldown_ms),
            )),
        })
    }

    pub fn built_pool_count(&self) -> usize {
        self.pools.len()
    }

    async fn acquire_entry(
        &self,
        name: &str,
        entry: Arc<PoolEntry>,
    ) -> Result<ExecutorHandle, AcquireError> {
        let admission = entry
            .breaker
            .admit()
            .map_err(|retry_after_secs| AcquireError::PoolOpen { retry_after_secs })?;
        if let Some(transition) = admission.transition {
            emit_transition(name, transition);
            if transition == crate::domain::breaker::BreakerTransition::ProbeStarted {
                entry.restart_connection_task();
            }
        }
        let mut admission_guard = AdmissionGuard {
            breaker: Arc::clone(&entry.breaker),
            permit: Some(admission.permit),
        };

        entry
            .waiters
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |waiters| {
                (waiters < entry.max_waiters).then_some(waiters + 1)
            })
            .map_err(|_| AcquireError::Overloaded)?;
        let waiter = WaiterGuard(Arc::clone(&entry.waiters));
        let permit = tokio::time::timeout(
            entry.acquire_timeout,
            Arc::clone(&entry.permits).acquire_owned(),
        )
        .await
        .map_err(|_| AcquireError::Overloaded)?
        .map_err(|_| AcquireError::Internal("Redis pool semaphore closed".to_owned()))?;
        drop(waiter);

        let executor: Arc<dyn CommandExecutor> = Arc::new(FredExecutor::from_pooled_client(
            entry.pool.next_connected().clone(),
            entry.command_timeout,
        ));
        let executor: Arc<dyn CommandExecutor> = Arc::new(BreakerExecutor::new(
            executor,
            Arc::clone(&entry.breaker),
            admission.permit,
            name.to_owned(),
        ));
        admission_guard.permit = None;
        Ok(ExecutorHandle::new(executor, Box::new(permit)))
    }

    /// Evicts fully idle pools older than the Phase 4 retention window.
    pub async fn evict_idle(&self) -> usize {
        let now = self.clock.unix_secs();
        let names: Vec<String> = self.pools.iter().map(|entry| entry.key().clone()).collect();
        let mut evicted = 0;
        for name in names {
            if let Some((_, entry)) = self.pools.remove_if(&name, |_, entry| {
                now.saturating_sub(entry.last_used.load(Ordering::Acquire)) > IDLE_EVICTION_SECS
                    && entry.permits.available_permits() == entry.permit_count
                    && entry.waiters.load(Ordering::Acquire) == 0
            }) {
                entry.shutdown().await;
                evicted += 1;
                metrics::counter!("srh_pool_evictions_total", "pool" => name.clone()).increment(1);
                tracing::info!(pool = %name, "evicted idle Redis pool");
            }
        }
        evicted
    }

    /// Stops every constructed pool and waits for its connection task to finish.
    pub async fn shutdown(&self) {
        let names: Vec<String> = self.pools.iter().map(|entry| entry.key().clone()).collect();
        for name in names {
            if let Some((_, entry)) = self.pools.remove(&name) {
                entry.shutdown().await;
            }
        }
    }
}

#[async_trait]
impl ExecutorProvider for PoolManager {
    async fn acquire(&self, name: &str) -> Result<ExecutorHandle, AcquireError> {
        let entry = self.get_or_build(name)?;
        self.acquire_entry(name, entry).await
    }

    async fn readiness(&self) -> Vec<PoolReadiness> {
        let entries: Vec<(String, Arc<PoolEntry>)> = self
            .pools
            .iter()
            .map(|entry| (entry.key().clone(), Arc::clone(entry.value())))
            .collect();
        let mut readiness = Vec::with_capacity(entries.len());
        for (name, entry) in entries {
            // Readiness measures backend health, not request admission. It must
            // not compete for permits or consume a half-open traffic probe.
            let executor = FredExecutor::from_pooled_client(
                entry.pool.next_connected().clone(),
                entry.command_timeout,
            );
            let status = match executor
                .execute(RedisCommand {
                    name: "PING".to_owned(),
                    args: Vec::new(),
                })
                .await
            {
                Ok(RespValue::Simple(response)) if response == "PONG" => PoolReadinessStatus::Ready,
                Ok(response) => PoolReadinessStatus::Unavailable(format!(
                    "unexpected readiness PING response: {response:?}"
                )),
                Err(error) => PoolReadinessStatus::Unavailable(error.to_string()),
            };
            readiness.push(PoolReadiness { pool: name, status });
        }
        readiness
    }
}

struct WaiterGuard(Arc<AtomicUsize>);

impl Drop for WaiterGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

struct AdmissionGuard {
    breaker: Arc<Breaker>,
    permit: Option<crate::domain::breaker::BreakerPermit>,
}

impl Drop for AdmissionGuard {
    fn drop(&mut self) {
        if let Some(permit) = self.permit {
            self.breaker.cancel(permit);
        }
    }
}

impl PoolEntry {
    fn ensure_connection_task(&self) {
        let mut tasks = self
            .connection_tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        tasks.retain(|task| !task.is_finished());
        if tasks.is_empty() {
            tasks.push(self.pool.connect());
        }
    }

    fn restart_connection_task(&self) {
        let mut tasks = self
            .connection_tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        tasks.retain(|task| !task.is_finished());
        // Fred documents that `connect` resets prior router state. Keep the
        // prior task handle until it observes the reset and finishes.
        tasks.push(self.pool.connect());
    }

    async fn shutdown(&self) {
        if let Err(error) = self.pool.quit().await {
            tracing::warn!(%error, "failed to quit Redis pool cleanly");
        }
        let tasks = std::mem::take(
            &mut *self
                .connection_tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        for task in tasks {
            if let Err(error) = task.await {
                tracing::debug!(%error, "Redis pool connection task did not join cleanly");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU64;
    use std::time::Instant;

    use super::*;

    struct FakeClock {
        unix: AtomicU64,
        monotonic: Instant,
    }

    impl FakeClock {
        fn new() -> Self {
            Self {
                unix: AtomicU64::new(1_000),
                monotonic: Instant::now(),
            }
        }

        fn advance_secs(&self, seconds: u64) {
            self.unix.fetch_add(seconds, Ordering::AcqRel);
        }
    }

    impl Clock for FakeClock {
        fn unix_secs(&self) -> u64 {
            self.unix.load(Ordering::Acquire)
        }

        fn instant(&self) -> Instant {
            self.monotonic + Duration::from_secs(self.unix_secs())
        }
    }

    fn config(max_connections: usize, max_waiters: usize) -> Arc<Config> {
        Arc::new(
            Config::from_json(&format!(
                r#"{{
                    "auth": {{"static_tokens": {{}}}},
                    "pools": {{"test": {{
                        "connection_string": "redis://127.0.0.1:1",
                        "max_connections": {max_connections},
                        "command_timeout_ms": 20,
                        "acquire_timeout_ms": 200,
                        "max_waiters": {max_waiters},
                        "breaker": {{"failure_threshold": 2, "cooldown_ms": 20}}
                    }}}}
                }}"#
            ))
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn builds_once_lazily_and_reuses_the_pool() {
        let clock: Arc<dyn Clock> = Arc::new(FakeClock::new());
        let manager = PoolManager::new(config(1, 2), clock);
        assert_eq!(manager.built_pool_count(), 0);

        drop(manager.acquire("test").await.unwrap());
        drop(manager.acquire("test").await.unwrap());
        assert_eq!(manager.built_pool_count(), 1);

        tokio::time::timeout(Duration::from_secs(2), manager.shutdown())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn bounds_waiters_and_sheds_excess_acquisitions() {
        let clock: Arc<dyn Clock> = Arc::new(FakeClock::new());
        let manager = Arc::new(PoolManager::new(config(1, 2), clock));
        let active = manager.acquire("test").await.unwrap();

        let queued: Vec<_> = (0..2)
            .map(|_| {
                let manager = Arc::clone(&manager);
                tokio::spawn(async move {
                    let handle = manager.acquire("test").await.unwrap();
                    drop(handle);
                })
            })
            .collect();
        loop {
            let entry = manager.pools.get("test").unwrap();
            if entry.waiters.load(Ordering::Acquire) == 2 {
                break;
            }
            drop(entry);
            tokio::task::yield_now().await;
        }

        let shed_started = Instant::now();
        for _ in 0..7 {
            assert!(matches!(
                manager.acquire("test").await,
                Err(AcquireError::Overloaded)
            ));
        }
        assert!(
            shed_started.elapsed() < Duration::from_millis(50),
            "queue overflow must shed instead of waiting for acquire timeout"
        );
        drop(active);
        for task in queued {
            task.await.unwrap();
        }
        manager.shutdown().await;
    }

    #[tokio::test]
    async fn evicts_only_fully_idle_entries_after_fifteen_minutes() {
        let clock = Arc::new(FakeClock::new());
        let manager = PoolManager::new(config(1, 2), clock.clone());
        let active = manager.acquire("test").await.unwrap();
        clock.advance_secs(IDLE_EVICTION_SECS + 1);

        assert_eq!(manager.evict_idle().await, 0);
        drop(active);
        assert_eq!(manager.evict_idle().await, 1);
        assert_eq!(manager.built_pool_count(), 0);
    }

    #[tokio::test]
    async fn backend_failures_open_before_waiter_or_permit_acquisition() {
        let clock: Arc<dyn Clock> = Arc::new(FakeClock::new());
        let mut config = config(1, 2);
        Arc::get_mut(&mut config)
            .unwrap()
            .pools
            .get_mut("test")
            .unwrap()
            .breaker
            .failure_threshold = 1;
        let manager = PoolManager::new(config, clock);
        let active = manager.acquire("test").await.unwrap();
        let error = tokio::time::timeout(
            Duration::from_secs(1),
            active.executor().execute(crate::ports::RedisCommand {
                name: "PING".to_owned(),
                args: Vec::new(),
            }),
        )
        .await
        .expect("fred must bound commands while Redis is unavailable")
        .unwrap_err();
        assert!(matches!(
            error,
            crate::domain::resp::ExecError::Transport(_) | crate::domain::resp::ExecError::Timeout
        ));

        let open_started = Instant::now();
        for _ in 0..50 {
            assert!(matches!(
                manager.acquire("test").await,
                Err(AcquireError::PoolOpen { .. })
            ));
        }
        assert!(
            open_started.elapsed() < Duration::from_millis(5),
            "an open breaker must reject without entering the pool queue"
        );
        let entry = manager.pools.get("test").unwrap();
        assert_eq!(entry.waiters.load(Ordering::Acquire), 0);
        assert_eq!(entry.permits.available_permits(), 0);
        drop(entry);
        drop(active);
        manager.shutdown().await;
    }

    #[tokio::test]
    async fn half_open_probe_cancels_when_unused_and_closes_after_success() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let reservation = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let address = reservation.local_addr().unwrap();
        drop(reservation);
        let mut config = Config::from_json(&format!(
            r#"{{
                "auth": {{"static_tokens": {{}}}},
                "pools": {{"test": {{
                    "connection_string": "redis://{address}",
                    "max_connections": 1,
                    "command_timeout_ms": 20,
                    "acquire_timeout_ms": 200,
                    "max_waiters": 2,
                    "breaker": {{"failure_threshold": 1, "cooldown_ms": 20}}
                }}}}
            }}"#
        ))
        .unwrap();
        config.server.http_timeout_ms = 1_000;
        let clock = Arc::new(FakeClock::new());
        let manager = PoolManager::new(Arc::new(config), clock.clone());

        let handle = manager.acquire("test").await.unwrap();
        assert!(
            handle
                .executor()
                .execute(RedisCommand {
                    name: "PING".to_owned(),
                    args: Vec::new(),
                })
                .await
                .is_err()
        );
        drop(handle);

        let listener = tokio::net::TcpListener::bind(address).await.unwrap();
        let server = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buffer = [0_u8; 1024];
                    loop {
                        match stream.read(&mut buffer).await {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {
                                if stream.write_all(b"+PONG\r\n").await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });
        clock.advance_secs(1);

        let unused_probe = manager.acquire("test").await.unwrap();
        assert_eq!(
            manager.pools.get("test").unwrap().breaker.state(),
            crate::domain::breaker::BreakerState::HalfOpen
        );
        drop(unused_probe);
        assert_eq!(
            manager.pools.get("test").unwrap().breaker.state(),
            crate::domain::breaker::BreakerState::Open
        );

        let probe = manager.acquire("test").await.unwrap();
        assert_eq!(
            probe
                .executor()
                .execute(RedisCommand {
                    name: "PING".to_owned(),
                    args: Vec::new(),
                })
                .await,
            Ok(RespValue::Simple("PONG".to_owned()))
        );
        drop(probe);
        assert_eq!(
            manager.pools.get("test").unwrap().breaker.state(),
            crate::domain::breaker::BreakerState::Closed
        );
        drop(manager.acquire("test").await.unwrap());

        manager.shutdown().await;
        server.abort();
    }
}
