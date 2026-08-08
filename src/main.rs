#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use srh_rs::adapters::auth_chain::AuthChain;
use srh_rs::adapters::static_auth::StaticAuth;
use srh_rs::adapters::system_clock::SystemClock;
use srh_rs::config::Config;
use srh_rs::domain::resp::{AcquireError, PoolReadiness};
use srh_rs::ports::{Authenticator, ExecutorHandle, ExecutorProvider};
use srh_rs::{AppState, http};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

struct PhaseOneProvider;

#[async_trait]
impl ExecutorProvider for PhaseOneProvider {
    async fn acquire(&self, _pool: &str) -> Result<ExecutorHandle, AcquireError> {
        Err(AcquireError::Internal(
            "Redis execution is not implemented".to_owned(),
        ))
    }

    async fn readiness(&self) -> Vec<PoolReadiness> {
        Vec::new()
    }
}

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
    let state = AppState {
        provider: Arc::new(PhaseOneProvider),
        authenticator,
        clock: Arc::new(SystemClock),
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
    // TODO(phase4): quit every constructed Redis pool after requests drain.
    Ok(())
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
    use super::bind_address;

    #[test]
    fn formats_ipv4_and_ipv6_bind_addresses() {
        assert_eq!(bind_address("127.0.0.1", 80), "127.0.0.1:80");
        assert_eq!(bind_address("::1", 80), "[::1]:80");
        assert_eq!(bind_address("::", 80), "[::]:80");
    }
}
