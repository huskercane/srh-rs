#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use srh_rs::adapters::auth_chain::AuthChain;
use srh_rs::adapters::pool_manager::PoolManager;
use srh_rs::adapters::static_auth::StaticAuth;
use srh_rs::adapters::system_clock::SystemClock;
use srh_rs::config::Config;
use srh_rs::domain::rate_limit::RateLimiter;
use srh_rs::ports::{Authenticator, Clock, ExecutorProvider};
use srh_rs::{AppState, http};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    initialize_tracing();
    let config = Arc::new(Config::load().context("configuration failed")?);
    if config.server.tls.is_some() {
        bail!("server.tls is configured, but direct TLS serving is not implemented yet");
    }
    warn_for_insecure_public_bind(&config.server.bind);

    let static_auth: Arc<dyn Authenticator> =
        Arc::new(StaticAuth::new(config.auth.static_tokens.clone()));
    let authenticator: Arc<dyn Authenticator> = Arc::new(AuthChain::new(vec![static_auth]));
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let rate_limiter = Arc::new(RateLimiter::new(
        config.server.rate_limit.per_token_commands_per_sec,
        Arc::clone(&clock),
    ));
    let pool_manager = Arc::new(PoolManager::new(Arc::clone(&config), Arc::clone(&clock)));
    let provider: Arc<dyn ExecutorProvider> = pool_manager.clone();
    let state = AppState {
        provider,
        authenticator,
        clock,
        rate_limiter: Arc::clone(&rate_limiter),
        cfg: Arc::clone(&config),
    };
    let address = bind_address(&config.server.bind, config.server.port);
    let listener = TcpListener::bind(&address)
        .await
        .with_context(|| format!("failed to bind {address}"))?;
    tracing::info!(%address, "SRH listening");

    let app = http::router(state);
    let graceful = GracefulShutdown::new();
    #[cfg(unix)]
    let shutdown = shutdown_signal(
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .context("failed to install SIGTERM handler")?,
    );
    #[cfg(not(unix))]
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    let (maintenance_stop, maintenance_rx) = tokio::sync::watch::channel(false);
    let maintenance = tokio::spawn(run_pool_maintenance(
        Arc::clone(&pool_manager),
        rate_limiter,
        maintenance_rx,
        Duration::from_secs(60),
    ));
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(connection) => connection,
                    Err(error) => {
                        tracing::error!(%error, "failed to accept connection");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let service = TowerToHyperService::new(app.clone());
                let watcher = graceful.watcher();
                tokio::spawn(async move {
                    let mut builder = http1::Builder::new();
                    builder
                        .timer(TokioTimer::new())
                        .header_read_timeout(Duration::from_secs(3));
                    let connection = builder.serve_connection(TokioIo::new(stream), service);
                    if let Err(error) = watcher.watch(connection).await {
                        tracing::debug!(%peer, %error, "HTTP connection closed with error");
                    }
                });
            }
            () = &mut shutdown => break,
        }
    }
    drop(listener);
    if tokio::time::timeout(Duration::from_secs(15), graceful.shutdown())
        .await
        .is_err()
    {
        tracing::error!("graceful shutdown deadline exceeded");
    }
    let _ = maintenance_stop.send(true);
    if let Err(error) = maintenance.await {
        tracing::error!(%error, "pool maintenance task failed");
    }
    pool_manager.shutdown().await;
    Ok(())
}

async fn run_pool_maintenance(
    manager: Arc<PoolManager>,
    rate_limiter: Arc<RateLimiter>,
    mut stop: tokio::sync::watch::Receiver<bool>,
    period: Duration,
) {
    let mut interval = tokio::time::interval(period);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = interval.tick() => {
                manager.evict_idle().await;
                let limiter = Arc::clone(&rate_limiter);
                match tokio::task::spawn_blocking(move || limiter.sweep_idle()).await {
                    Ok(evicted) if evicted > 0 => tracing::info!(evicted, "evicted idle rate-limit buckets"),
                    Ok(_) => {}
                    Err(error) => tracing::error!(%error, "rate-limit maintenance failed"),
                }
            }
            result = stop.changed() => {
                if result.is_err() || *stop.borrow() {
                    break;
                }
            }
        }
    }
}

fn initialize_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    if std::env::var("SRH_LOG_FORMAT").as_deref() == Ok("json") {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
}

fn warn_for_insecure_public_bind(bind: &str) {
    let loopback = bind
        .parse::<std::net::IpAddr>()
        .is_ok_and(|address| address.is_loopback());
    if !loopback {
        tracing::warn!(%bind, "binding to a non-loopback interface without TLS");
    }
}

fn bind_address(bind: &str, port: u16) -> String {
    if bind.contains(':') && !bind.starts_with('[') {
        format!("[{bind}]:{port}")
    } else {
        format!("{bind}:{port}")
    }
}

#[cfg(unix)]
async fn shutdown_signal(mut terminate: tokio::signal::unix::Signal) {
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            if let Err(error) = result {
                tracing::error!(%error, "failed to listen for SIGINT");
            }
        }
        _ = terminate.recv() => {}
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::error!(%error, "failed to listen for shutdown signal");
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    use super::{bind_address, run_pool_maintenance};
    use srh_rs::adapters::pool_manager::PoolManager;
    use srh_rs::config::Config;
    use srh_rs::domain::rate_limit::RateLimiter;
    use srh_rs::ports::Clock;

    struct ManualClock {
        base: Instant,
        seconds: AtomicU64,
    }

    impl ManualClock {
        fn advance(&self, seconds: u64) {
            self.seconds.fetch_add(seconds, Ordering::Relaxed);
        }
    }

    impl Clock for ManualClock {
        fn unix_secs(&self) -> u64 {
            0
        }

        fn instant(&self) -> Instant {
            self.base + Duration::from_secs(self.seconds.load(Ordering::Relaxed))
        }
    }

    #[test]
    fn formats_ipv4_and_ipv6_bind_addresses() {
        assert_eq!(bind_address("127.0.0.1", 80), "127.0.0.1:80");
        assert_eq!(bind_address("::1", 80), "[::1]:80");
        assert_eq!(bind_address("::", 80), "[::]:80");
    }

    #[tokio::test]
    async fn maintenance_loop_sweeps_idle_rate_limit_buckets() {
        let config = Arc::new(Config::from_json("{}").expect("empty test config should parse"));
        let clock = Arc::new(ManualClock {
            base: Instant::now(),
            seconds: AtomicU64::new(0),
        });
        let clock_port: Arc<dyn Clock> = clock.clone();
        let manager = Arc::new(PoolManager::new(config, Arc::clone(&clock_port)));
        let limiter = Arc::new(RateLimiter::new(1, clock_port));
        limiter.charge("idle", 1).unwrap();
        clock.advance(901);
        let (stop, receiver) = tokio::sync::watch::channel(false);

        let task = tokio::spawn(run_pool_maintenance(
            manager,
            Arc::clone(&limiter),
            receiver,
            Duration::from_secs(3_600),
        ));
        tokio::time::timeout(Duration::from_secs(1), async {
            while limiter.bucket_count() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the immediate maintenance tick should sweep the idle bucket");
        stop.send(true).unwrap();
        task.await.unwrap();
    }
}
