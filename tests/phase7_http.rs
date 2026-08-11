use std::collections::HashSet;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use async_trait::async_trait;
use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::header;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use srh_rs::config::Config;
use srh_rs::domain::identity::{AuthError, Identity};
use srh_rs::domain::rate_limit::RateLimiter;
use srh_rs::domain::resp::{AcquireError, PoolReadiness, PoolReadinessStatus};
use srh_rs::ports::{Authenticator, Clock, ExecutorHandle, ExecutorProvider};
use srh_rs::{AppState, AppStateInner};
use tower::ServiceExt;

struct Provider {
    status: PoolReadinessStatus,
    calls: AtomicUsize,
}

#[async_trait]
impl ExecutorProvider for Provider {
    async fn acquire(&self, _pool: &str) -> Result<ExecutorHandle, AcquireError> {
        unreachable!("readiness tests do not acquire request executors")
    }

    async fn readiness(&self) -> Vec<PoolReadiness> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        vec![PoolReadiness {
            pool: "cache".to_owned(),
            status: self.status.clone(),
        }]
    }
}

struct Auth;

#[async_trait]
impl Authenticator for Auth {
    async fn authenticate(&self, _bearer: &str) -> Result<Option<Arc<Identity>>, AuthError> {
        Ok(Some(Arc::new(Identity {
            subject: "test".to_owned(),
            bucket_key: "test".to_owned(),
            pool: "cache".to_owned(),
            read_only: false,
            is_admin: false,
            legacy: false,
            allowed_commands: None,
            blocked_commands: HashSet::new(),
            allowed_script_sha256: HashSet::new(),
            key_prefix: None,
        })))
    }
}

struct TestClock;

impl Clock for TestClock {
    fn unix_secs(&self) -> u64 {
        0
    }

    fn instant(&self) -> Instant {
        Instant::now()
    }
}

fn app(status: PoolReadinessStatus) -> (axum::Router, Arc<Provider>) {
    let _ = test_logs();
    let config = Arc::new(Config::from_json("{}").unwrap());
    let provider = Arc::new(Provider {
        status,
        calls: AtomicUsize::new(0),
    });
    let provider_port: Arc<dyn ExecutorProvider> = provider.clone();
    let clock: Arc<dyn Clock> = Arc::new(TestClock);
    let app = srh_rs::http::router(AppState::new(AppStateInner {
        provider: provider_port,
        authenticator: Arc::new(Auth),
        clock: Arc::clone(&clock),
        rate_limiter: Arc::new(RateLimiter::new(0, clock)),
        cfg: config,
    }));
    (app, provider)
}

async fn ready(app: &axum::Router, peer: IpAddr) -> (StatusCode, Value) {
    let mut request = Request::get("/ready").body(Body::empty()).unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::new(peer, 12345)));
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

#[tokio::test]
async fn readiness_is_loopback_only_and_reports_each_built_pool() {
    let (app, provider) = app(PoolReadinessStatus::Ready);
    let (status, body) = ready(&app, IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({"status":"ready","pools":{"cache":{"status":"ready"}}})
    );
    assert_eq!(provider.calls.load(Ordering::Relaxed), 1);

    let (status, body) = ready(&app, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body, json!({"error":"Not found"}));
    assert_eq!(provider.calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn an_unavailable_built_pool_makes_readiness_503() {
    let (app, _) = app(PoolReadinessStatus::Unavailable(
        "PING timed out".to_owned(),
    ));
    let (status, body) = ready(&app, IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["status"], "not_ready");
    assert_eq!(body["pools"]["cache"]["status"], "unavailable");
    assert_eq!(body["pools"]["cache"]["error"], "PING timed out");
}

#[derive(Clone, Default)]
struct LogBuffer(Arc<Mutex<Vec<u8>>>);

impl Write for LogBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for LogBuffer {
    type Writer = Self;

    fn make_writer(&'writer self) -> Self::Writer {
        self.clone()
    }
}

fn test_logs() -> &'static LogBuffer {
    static LOGS: OnceLock<LogBuffer> = OnceLock::new();
    LOGS.get_or_init(|| {
        let output = LogBuffer::default();
        tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_writer(output.clone())
            .init();
        output
    })
}

#[test]
fn audit_line_has_required_fields_without_token_or_command_arguments() {
    let output = test_logs();
    output
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clear();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let (app, _) = app(PoolReadinessStatus::Ready);
            let response = app
                .oneshot(
                    Request::post("/")
                        .header(header::AUTHORIZATION, "Bearer secret-token")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(r#"["CONFIG","super-secret-value"]"#))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        });
    let bytes = output
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let logs = String::from_utf8(bytes).unwrap();
    for field in [
        "subject=\"test\"",
        "pool=\"cache\"",
        "command=\"CONFIG\"",
        "status=403",
        "latency_ms=",
        "pipeline_len=1",
    ] {
        assert!(logs.contains(field), "missing audit field {field}: {logs}");
    }
    assert!(!logs.contains("secret-token"));
    assert!(!logs.contains("super-secret-value"));
}
