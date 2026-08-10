use std::convert::Infallible;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use serde_json::{Value, json};
use srh_rs::AppState;
use srh_rs::adapters::auth_chain::AuthChain;
use srh_rs::adapters::static_auth::StaticAuth;
use srh_rs::config::Config;
use srh_rs::domain::rate_limit::RateLimiter;
use srh_rs::domain::resp::{AcquireError, ExecError, PoolReadiness, RespValue};
use srh_rs::ports::{
    Authenticator, Clock, CommandExecutor, ExecutorHandle, ExecutorProvider, RedisCommand,
};
use tower::ServiceExt;

#[derive(Default)]
struct RecordingExecutor {
    calls: Mutex<Vec<Vec<RedisCommand>>>,
}

impl RecordingExecutor {
    fn record(&self, commands: Vec<RedisCommand>) {
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(commands);
    }
}

#[async_trait]
impl CommandExecutor for RecordingExecutor {
    async fn execute(&self, command: RedisCommand) -> Result<RespValue, ExecError> {
        self.record(vec![command]);
        Ok(RespValue::Simple("OK".to_owned()))
    }

    async fn pipeline(&self, commands: Vec<RedisCommand>) -> Vec<Result<RespValue, ExecError>> {
        let count = commands.len();
        self.record(commands);
        vec![Ok(RespValue::Simple("OK".to_owned())); count]
    }

    async fn transaction(
        &self,
        commands: Vec<RedisCommand>,
    ) -> Result<Vec<Result<RespValue, ExecError>>, ExecError> {
        let count = commands.len();
        self.record(commands);
        Ok(vec![Ok(RespValue::Simple("OK".to_owned())); count])
    }
}

struct RecordingProvider {
    executor: Arc<RecordingExecutor>,
    acquires: AtomicUsize,
    active_leases: Arc<AtomicUsize>,
}

struct TrackedLease {
    active: Arc<AtomicUsize>,
}

impl Drop for TrackedLease {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Release);
    }
}

#[async_trait]
impl ExecutorProvider for RecordingProvider {
    async fn acquire(&self, _pool: &str) -> Result<ExecutorHandle, AcquireError> {
        self.acquires.fetch_add(1, Ordering::Relaxed);
        self.active_leases.fetch_add(1, Ordering::AcqRel);
        let executor: Arc<dyn CommandExecutor> = self.executor.clone();
        Ok(ExecutorHandle::new(
            executor,
            Box::new(TrackedLease {
                active: Arc::clone(&self.active_leases),
            }),
        ))
    }

    async fn readiness(&self) -> Vec<PoolReadiness> {
        Vec::new()
    }
}

struct ManualClock {
    base: Instant,
    millis: AtomicU64,
}

impl ManualClock {
    fn advance(&self, duration: Duration) {
        self.millis
            .fetch_add(duration.as_millis() as u64, Ordering::Relaxed);
    }
}

impl Clock for ManualClock {
    fn unix_secs(&self) -> u64 {
        0
    }

    fn instant(&self) -> Instant {
        self.base + Duration::from_millis(self.millis.load(Ordering::Relaxed))
    }
}

fn app(config: Value) -> (axum::Router, Arc<RecordingProvider>, Arc<ManualClock>) {
    let config =
        Arc::new(Config::from_json(&config.to_string()).expect("test config should parse"));
    let auth: Arc<dyn Authenticator> = Arc::new(StaticAuth::new(config.auth.static_tokens.clone()));
    let executor = Arc::new(RecordingExecutor::default());
    let provider = Arc::new(RecordingProvider {
        executor,
        acquires: AtomicUsize::new(0),
        active_leases: Arc::new(AtomicUsize::new(0)),
    });
    let clock = Arc::new(ManualClock {
        base: Instant::now(),
        millis: AtomicU64::new(0),
    });
    let clock_port: Arc<dyn Clock> = clock.clone();
    let rate_limiter = Arc::new(RateLimiter::new(
        config.server.rate_limit.per_token_commands_per_sec,
        Arc::clone(&clock_port),
    ));
    let router = srh_rs::http::router(AppState {
        provider: provider.clone(),
        authenticator: Arc::new(AuthChain::new(vec![auth])),
        clock: clock_port,
        rate_limiter,
        cfg: config,
    });
    (router, provider, clock)
}

fn current_config(tokens: Value, server: Value) -> Value {
    json!({
        "server": server,
        "auth": { "static_tokens": tokens },
        "pools": { "cache": { "connection_string": "redis://localhost:6379" } }
    })
}

fn post(path: &str, token: &str, body: impl Into<Body>) -> Request<Body> {
    Request::post(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(body.into())
        .expect("request should build")
}

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body should be readable");
    serde_json::from_slice(&bytes).expect("response should be JSON")
}

#[tokio::test]
async fn read_only_and_current_format_defaults_are_enforced_before_pool_acquisition() {
    let config = current_config(
        json!({
            "read-token": { "pool": "cache", "read_only": true },
            "write-token": { "pool": "cache" }
        }),
        json!({}),
    );
    let (app, provider, _) = app(config);

    let response = app
        .clone()
        .oneshot(post("/", "read-token", r#"["GET","key"]"#))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    for (token, body) in [
        ("read-token", r#"["SET","key","value"]"#),
        ("read-token", r#"["SCAN",0]"#),
        ("read-token", r#"["KEYS","*"]"#),
        ("write-token", r#"["FLUSHALL"]"#),
        ("write-token", r#"["INFO"]"#),
        ("write-token", r#"["KEYS","*"]"#),
        ("write-token", r#"["HELLO",2]"#),
    ] {
        let response = app.clone().oneshot(post("/", token, body)).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    let response = app
        .oneshot(post("/", "write-token", r#"["SCAN",0]"#))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(provider.acquires.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn legacy_tokens_keep_flush_and_keys_compatibility() {
    let (app, provider, _) = app(json!({
        "legacy-token": {
            "srh_id": "cache",
            "connection_string": "redis://localhost:6379"
        }
    }));
    for body in [r#"["FLUSHALL"]"#, r#"["KEYS","*"]"#] {
        let response = app
            .clone()
            .oneshot(post("/", "legacy-token", body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    assert_eq!(provider.acquires.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn pipeline_denials_are_per_slot_and_multi_exec_denial_aborts_before_redis() {
    let config = current_config(json!({ "token": { "pool": "cache" } }), json!({}));
    let (app, provider, _) = app(config);
    let body = r#"[["SET","key","value"],["KEYS","*"],["GET","key"]]"#;
    let response = app
        .clone()
        .oneshot(post("/pipeline", "token", body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        body_json(response).await,
        json!([
            { "result": "OK" },
            { "error": "NOPERM this token does not have permission to run 'KEYS'" },
            { "result": "OK" }
        ])
    );
    {
        let calls = provider
            .executor
            .calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0]
                .iter()
                .map(|command| command.name.as_str())
                .collect::<Vec<_>>(),
            ["SET", "GET"]
        );
    }

    let response = app
        .clone()
        .oneshot(post("/pipeline", "token", r#"[["KEYS","*"]]"#))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(provider.acquires.load(Ordering::Relaxed), 1);

    let response = app
        .oneshot(post("/multi-exec", "token", body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(provider.acquires.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn batch_debt_rejects_pre_parse_with_exact_retry_after_then_refills() {
    let config = current_config(
        json!({ "token": { "pool": "cache" } }),
        json!({ "rate_limit": { "per_token_commands_per_sec": 10 } }),
    );
    let (app, provider, clock) = app(config);
    let pipeline = serde_json::to_vec(&vec![vec!["PING"]; 100]).unwrap();
    let response = app
        .clone()
        .oneshot(post("/pipeline", "token", pipeline))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(provider.acquires.load(Ordering::Relaxed), 1);

    let body_polled = Arc::new(AtomicBool::new(false));
    let poll_observer = Arc::clone(&body_polled);
    let body = Body::from_stream(futures_util::stream::once(async move {
        poll_observer.store(true, Ordering::Release);
        Ok::<_, Infallible>(bytes::Bytes::from_static(b"deliberately invalid JSON"))
    }));
    let response = app.clone().oneshot(post("/", "token", body)).await.unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.headers()[header::RETRY_AFTER], "8");
    assert!(!body_polled.load(Ordering::Acquire));

    clock.advance(Duration::from_millis(8_001));
    let response = app
        .oneshot(post("/", "token", r#"["PING"]"#))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(provider.acquires.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn malformed_requests_pay_minimum_cost_on_every_command_endpoint() {
    let config = current_config(
        json!({
            "single": { "pool": "cache" },
            "pipeline": { "pool": "cache" },
            "transaction": { "pool": "cache" },
            "empty-transaction": { "pool": "cache" }
        }),
        json!({ "rate_limit": { "per_token_commands_per_sec": 1 } }),
    );
    let (app, provider, _) = app(config);
    for (path, token) in [
        ("/", "single"),
        ("/pipeline", "pipeline"),
        ("/multi-exec", "transaction"),
    ] {
        for expected in [
            StatusCode::BAD_REQUEST,
            StatusCode::BAD_REQUEST,
            StatusCode::TOO_MANY_REQUESTS,
        ] {
            let response = app
                .clone()
                .oneshot(post(path, token, "not valid JSON"))
                .await
                .unwrap();
            assert_eq!(response.status(), expected, "{path}");
        }
    }
    for expected in [
        StatusCode::BAD_REQUEST,
        StatusCode::BAD_REQUEST,
        StatusCode::TOO_MANY_REQUESTS,
    ] {
        let response = app
            .clone()
            .oneshot(post("/multi-exec", "empty-transaction", "[]"))
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
    assert_eq!(provider.acquires.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn every_handler_releases_its_real_lease_before_responding() {
    for (path, body) in [
        ("/", r#"["PING"]"#),
        ("/pipeline", r#"[["PING"]]"#),
        ("/multi-exec", r#"[["PING"]]"#),
    ] {
        let config = current_config(json!({ "token": { "pool": "cache" } }), json!({}));
        let (app, provider, _) = app(config);
        let response = app.oneshot(post(path, "token", body)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_eq!(provider.active_leases.load(Ordering::Acquire), 0, "{path}");
    }
}

#[tokio::test]
async fn single_commands_are_charged_individually() {
    let config = current_config(
        json!({ "token": { "pool": "cache" } }),
        json!({ "rate_limit": { "per_token_commands_per_sec": 10 } }),
    );
    let (app, provider, _) = app(config);
    for _ in 0..20 {
        let response = app
            .clone()
            .oneshot(post("/", "token", r#"["PING"]"#))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    let response = app
        .oneshot(post("/", "token", r#"["PING"]"#))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(provider.acquires.load(Ordering::Relaxed), 20);
}

#[tokio::test]
async fn multi_exec_charges_every_command_in_the_transaction() {
    let config = current_config(
        json!({ "token": { "pool": "cache" } }),
        json!({ "rate_limit": { "per_token_commands_per_sec": 10 } }),
    );
    let (app, provider, _) = app(config);
    let transaction = serde_json::to_vec(&vec![vec!["PING"]; 100]).unwrap();
    let response = app
        .clone()
        .oneshot(post("/multi-exec", "token", transaction))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .oneshot(post("/", "token", "not valid JSON"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.headers()[header::RETRY_AFTER], "8");
    assert_eq!(provider.acquires.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn colliding_log_subjects_still_use_isolated_full_digest_buckets() {
    const FIRST: &str = "phase5-token-45101";
    const SECOND: &str = "phase5-token-67122";
    let config = current_config(
        json!({
            (FIRST): { "pool": "cache" },
            (SECOND): { "pool": "cache" }
        }),
        json!({ "rate_limit": { "per_token_commands_per_sec": 10 } }),
    );
    let (app, provider, _) = app(config);
    let pipeline = serde_json::to_vec(&vec![vec!["PING"]; 100]).unwrap();
    assert_eq!(
        app.clone()
            .oneshot(post("/pipeline", FIRST, pipeline))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        app.oneshot(post("/", SECOND, r#"["PING"]"#))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(provider.acquires.load(Ordering::Relaxed), 2);
}

#[test]
fn collision_fixture_really_shares_only_the_short_subject() {
    use sha2::{Digest, Sha256};
    let digests: [[u8; 32]; 2] = ["phase5-token-45101", "phase5-token-67122"]
        .map(|token| Sha256::digest(token.as_bytes()).into());
    assert_eq!(&digests[0][..4], &digests[1][..4]);
    assert_ne!(digests[0], digests[1]);
}
