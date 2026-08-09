use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use async_trait::async_trait;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use serde_json::{Value, json};
use srh_rs::AppState;
use srh_rs::adapters::auth_chain::AuthChain;
use srh_rs::adapters::static_auth::StaticAuth;
use srh_rs::config::Config;
use srh_rs::domain::resp::{AcquireError, ExecError, PoolReadiness, RespValue};
use srh_rs::ports::{
    Authenticator, Clock, CommandExecutor, ExecutorHandle, ExecutorProvider, RedisCommand,
};
use tower::ServiceExt;

struct ScriptedExecutor {
    replies: Mutex<VecDeque<Result<RespValue, ExecError>>>,
    calls: Mutex<Vec<Vec<RedisCommand>>>,
}

impl ScriptedExecutor {
    fn new(replies: impl IntoIterator<Item = Result<RespValue, ExecError>>) -> Self {
        Self {
            replies: Mutex::new(replies.into_iter().collect()),
            calls: Mutex::new(Vec::new()),
        }
    }

    fn next(&self) -> Result<RespValue, ExecError> {
        self.replies
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop_front()
            .expect("test reply script should cover every command")
    }

    fn record(&self, commands: Vec<RedisCommand>) {
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(commands);
    }
}

#[async_trait]
impl CommandExecutor for ScriptedExecutor {
    async fn execute(&self, command: RedisCommand) -> Result<RespValue, ExecError> {
        self.record(vec![command]);
        self.next()
    }

    async fn pipeline(&self, commands: Vec<RedisCommand>) -> Vec<Result<RespValue, ExecError>> {
        let count = commands.len();
        self.record(commands);
        (0..count).map(|_| self.next()).collect()
    }

    async fn transaction(&self, commands: Vec<RedisCommand>) -> Result<Vec<RespValue>, ExecError> {
        let count = commands.len();
        self.record(commands);
        (0..count).map(|_| self.next()).collect()
    }
}

struct TestProvider {
    executor: Arc<dyn CommandExecutor>,
    acquires: AtomicUsize,
}

#[async_trait]
impl ExecutorProvider for TestProvider {
    async fn acquire(&self, _pool: &str) -> Result<ExecutorHandle, AcquireError> {
        self.acquires.fetch_add(1, Ordering::Relaxed);
        Ok(ExecutorHandle::new(
            Arc::clone(&self.executor),
            Box::new(()),
        ))
    }

    async fn readiness(&self) -> Vec<PoolReadiness> {
        Vec::new()
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

fn app(
    replies: impl IntoIterator<Item = Result<RespValue, ExecError>>,
    server: Value,
) -> (axum::Router, Arc<TestProvider>) {
    let config = Arc::new(
        Config::from_json(
            &json!({
                "server": server,
                "auth": { "static_tokens": { "right-token": { "pool": "cache" } } },
                "pools": { "cache": { "connection_string": "redis://localhost:6379" } }
            })
            .to_string(),
        )
        .expect("test configuration should parse"),
    );
    let static_auth: Arc<dyn Authenticator> =
        Arc::new(StaticAuth::new(config.auth.static_tokens.clone()));
    let executor: Arc<dyn CommandExecutor> = Arc::new(ScriptedExecutor::new(replies));
    let provider = Arc::new(TestProvider {
        executor,
        acquires: AtomicUsize::new(0),
    });
    let router = srh_rs::http::router(AppState {
        provider: provider.clone(),
        authenticator: Arc::new(AuthChain::new(vec![static_auth])),
        clock: Arc::new(TestClock),
        rate_limiter: Arc::new(srh_rs::domain::rate_limit::RateLimiter::new(
            config.server.rate_limit.per_token_commands_per_sec,
            Arc::new(TestClock),
        )),
        cfg: config,
    });
    (router, provider)
}

fn post(path: &str, body: impl Into<Body>) -> Request<Body> {
    Request::post(path)
        .header(header::AUTHORIZATION, "Bearer right-token")
        .header(header::CONTENT_TYPE, "application/json")
        .body(body.into())
        .expect("request should build")
}

async fn response_json(response: axum::response::Response) -> Value {
    let bytes = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("response body should be readable");
    serde_json::from_slice(&bytes).expect("response should be JSON")
}

#[tokio::test]
async fn pipeline_keeps_order_and_a_middle_redis_error_does_not_abort() {
    let raw_error = "WRONGTYPE Operation against a key holding the wrong kind of value";
    let (app, provider) = app(
        [
            Ok(RespValue::Simple("OK".to_owned())),
            Err(ExecError::Redis(raw_error.to_owned())),
            Ok(RespValue::Int(1)),
        ],
        json!({}),
    );
    let response = app
        .oneshot(post(
            "/pipeline",
            r#"[["SET","key","value"],["HGET","key","field"],["INCR","counter"]]"#,
        ))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response_json(response).await,
        json!([
            { "result": "OK" },
            { "error": raw_error },
            { "result": 1 }
        ])
    );
    assert_eq!(provider.acquires.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn empty_pipeline_is_success_without_acquiring_redis() {
    let (app, provider) = app([], json!({}));
    let response = app
        .oneshot(post("/pipeline", "[]"))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response_json(response).await, json!([]));
    assert_eq!(provider.acquires.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn oversized_pipeline_is_rejected_before_acquiring_redis() {
    let (app, provider) = app([], json!({}));
    let body = serde_json::to_vec(&vec![vec![json!("PING")]; 1001])
        .expect("pipeline body should serialize");
    let response = app
        .oneshot(post("/pipeline", body))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(response).await,
        json!({ "error": "Pipeline too large" })
    );
    assert_eq!(provider.acquires.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn multi_exec_maps_every_exec_result() {
    let (app, provider) = app(
        [
            Ok(RespValue::Simple("OK".to_owned())),
            Ok(RespValue::Bulk(bytes::Bytes::from_static(b"value"))),
        ],
        json!({}),
    );
    let response = app
        .oneshot(post(
            "/multi-exec",
            r#"[["SET","key","value"],["GET","key"]]"#,
        ))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response_json(response).await,
        json!([{ "result": "OK" }, { "result": "value" }])
    );
    assert_eq!(provider.acquires.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn invalid_or_empty_multi_exec_never_acquires_redis() {
    for body in ["[]", r#"[["SET","key","value"],[null]]"#] {
        let (app, provider) = app([], json!({}));
        let response = app
            .oneshot(post("/multi-exec", body))
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response_json(response).await,
            json!({ "error": "Invalid command" })
        );
        assert_eq!(provider.acquires.load(Ordering::Relaxed), 0);
    }
}

#[tokio::test]
async fn pipeline_budget_exhaustion_fails_the_whole_request_with_bad_gateway() {
    for path in ["/pipeline", "/multi-exec"] {
        let (app, _) = app(
            [
                Ok(RespValue::Bulk(bytes::Bytes::from_static(b"twelve bytes"))),
                Ok(RespValue::Bulk(bytes::Bytes::from_static(b"twelve bytes"))),
            ],
            json!({ "load": { "max_response_bytes": 30 } }),
        );
        let response = app
            .oneshot(post(path, r#"[["GET","one"],["GET","two"]]"#))
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            response_json(response).await,
            json!({ "error": "Response too large" })
        );
    }
}

#[tokio::test]
async fn pipeline_base64_distinguishes_bulk_ok_from_simple_ok() {
    let (app, _) = app(
        [
            Ok(RespValue::Bulk(bytes::Bytes::from_static(b"OK"))),
            Ok(RespValue::Simple("OK".to_owned())),
        ],
        json!({}),
    );
    let request = Request::post("/pipeline")
        .header(header::AUTHORIZATION, "Bearer right-token")
        .header(header::CONTENT_TYPE, "application/json")
        .header("upstash-encoding", "base64")
        .body(Body::from(r#"[["GET","key"],["SET","key","OK"]]"#))
        .expect("request should build");
    let response = app.oneshot(request).await.expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response_json(response).await,
        json!([{ "result": "T0s=" }, { "result": "OK" }])
    );
}

#[tokio::test]
async fn request_element_budget_is_enforced_before_acquiring_redis() {
    let (app, provider) = app([], json!({ "max_request_elements": 4 }));
    let response = app
        .oneshot(post("/", r#"["MGET","one","two","three","four"]"#))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(response).await,
        json!({ "error": "Request too complex" })
    );
    assert_eq!(provider.acquires.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn one_command_can_exceed_the_pipeline_command_count() {
    let mut command = vec![json!("MGET")];
    command.extend((0..5000).map(|index| json!(format!("key:{index}"))));

    let (single, provider) = app([Ok(RespValue::Nil)], json!({}));
    let response = single
        .oneshot(post(
            "/",
            serde_json::to_vec(&command).expect("command should serialize"),
        ))
        .await
        .expect("request should complete");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(provider.acquires.load(Ordering::Relaxed), 1);

    let (pipeline, provider) = app([Ok(RespValue::Nil)], json!({}));
    let response = pipeline
        .oneshot(post(
            "/pipeline",
            serde_json::to_vec(&vec![command]).expect("pipeline should serialize"),
        ))
        .await
        .expect("request should complete");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(provider.acquires.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn request_element_budget_is_shared_across_pipeline_commands() {
    let (app, provider) = app([], json!({ "max_request_elements": 5 }));
    let response = app
        .oneshot(post(
            "/pipeline",
            r#"[["SET","one","value"],["SET","two","value"]]"#,
        ))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(response).await,
        json!({ "error": "Request too complex" })
    );
    assert_eq!(provider.acquires.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn nested_argument_nodes_consume_the_budget_on_every_endpoint() {
    let command = json!(["SET", "key", vec![1; 20]]);
    for (path, body) in [
        ("/", command.clone()),
        ("/pipeline", json!([command.clone()])),
        ("/multi-exec", json!([command.clone()])),
    ] {
        let (app, provider) = app([], json!({ "max_request_elements": 10 }));
        let response = app
            .oneshot(post(
                path,
                serde_json::to_vec(&body).expect("request should serialize"),
            ))
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response_json(response).await,
            json!({ "error": "Request too complex" })
        );
        assert_eq!(provider.acquires.load(Ordering::Relaxed), 0);
    }
}
