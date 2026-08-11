use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use serde_json::{Value, json};
use srh_rs::adapters::auth_chain::AuthChain;
use srh_rs::adapters::static_auth::StaticAuth;
use srh_rs::config::Config;
use srh_rs::domain::resp::{AcquireError, ExecError, PoolReadiness, RespValue};
use srh_rs::http;
use srh_rs::ports::{
    Authenticator, Clock, CommandExecutor, ExecutorHandle, ExecutorProvider, RedisCommand,
};
use srh_rs::{AppState, AppStateInner};
use tower::ServiceExt;

struct FixedExecutor {
    result: Result<RespValue, ExecError>,
}

#[async_trait]
impl CommandExecutor for FixedExecutor {
    async fn execute(&self, _command: RedisCommand) -> Result<RespValue, ExecError> {
        self.result.clone()
    }

    async fn pipeline(&self, _commands: Vec<RedisCommand>) -> Vec<Result<RespValue, ExecError>> {
        unreachable!("pipeline remains a Phase 3 route")
    }

    async fn transaction(
        &self,
        _commands: Vec<RedisCommand>,
    ) -> Result<Vec<Result<RespValue, ExecError>>, ExecError> {
        unreachable!("transactions remain a Phase 3 route")
    }
}

struct FixedProvider {
    executor: Arc<dyn CommandExecutor>,
}

#[async_trait]
impl ExecutorProvider for FixedProvider {
    async fn acquire(&self, _pool: &str) -> Result<ExecutorHandle, AcquireError> {
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

fn app() -> axum::Router {
    let config = Arc::new(
        Config::from_json(
            r#"{"auth":{"static_tokens":{"right-token":{"pool":"cache"}}},"pools":{"cache":{"connection_string":"redis://localhost:6379"}}}"#,
        )
        .expect("test configuration should parse"),
    );
    let static_auth: Arc<dyn Authenticator> =
        Arc::new(StaticAuth::new(config.auth.static_tokens.clone()));
    app_with_auth(
        Arc::new(AuthChain::new(vec![static_auth])),
        config,
        Ok(RespValue::Simple("PONG".to_owned())),
    )
}

fn app_with_auth(
    authenticator: Arc<dyn Authenticator>,
    config: Arc<Config>,
    result: Result<RespValue, ExecError>,
) -> axum::Router {
    http::router(AppState::new(AppStateInner {
        provider: Arc::new(FixedProvider {
            executor: Arc::new(FixedExecutor { result }),
        }),
        authenticator,
        clock: Arc::new(TestClock),
        rate_limiter: Arc::new(srh_rs::domain::rate_limit::RateLimiter::new(
            0,
            Arc::new(TestClock),
        )),
        cfg: config,
    }))
}

async fn response_json(response: axum::response::Response) -> Value {
    let bytes = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("response body should be readable");
    serde_json::from_slice(&bytes).expect("response should be JSON")
}

#[tokio::test]
async fn wrong_token_returns_unauthorized_json() {
    let response = app()
        .oneshot(
            Request::post("/")
                .header(header::AUTHORIZATION, "Bearer wrong-token")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"["PING"]"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response_json(response).await,
        json!({ "error": "Unauthorized" })
    );
}

#[tokio::test]
async fn right_token_executes_command_and_tolerates_sync_header() {
    let response = app()
        .oneshot(
            Request::post("/")
                .header(header::AUTHORIZATION, "Bearer right-token")
                .header("upstash-sync-token", "whatever")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"["PING"]"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response_json(response).await, json!({ "result": "PONG" }));
}

#[tokio::test]
async fn base64_encoding_preserves_binary_bulk_values() {
    let config = Arc::new(
        Config::from_json(
            r#"{"auth":{"static_tokens":{"right-token":{"pool":"cache"}}},"pools":{"cache":{"connection_string":"redis://localhost:6379"}}}"#,
        )
        .expect("test configuration should parse"),
    );
    let static_auth: Arc<dyn Authenticator> =
        Arc::new(StaticAuth::new(config.auth.static_tokens.clone()));
    let response = app_with_auth(
        Arc::new(AuthChain::new(vec![static_auth])),
        config,
        Ok(RespValue::Bulk(bytes::Bytes::from_static(&[
            0xff, 0xfe, 0x00, 0x01,
        ]))),
    )
    .oneshot(
        Request::post("/")
            .header(header::AUTHORIZATION, "Bearer right-token")
            .header("upstash-encoding", "BASE64")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"["GET","binary"]"#))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response_json(response).await,
        json!({ "result": "//4AAQ==" })
    );
}

#[tokio::test]
async fn redis_errors_are_returned_verbatim() {
    let config = Arc::new(
        Config::from_json(
            r#"{"auth":{"static_tokens":{"right-token":{"pool":"cache"}}},"pools":{"cache":{"connection_string":"redis://localhost:6379"}}}"#,
        )
        .expect("test configuration should parse"),
    );
    let static_auth: Arc<dyn Authenticator> =
        Arc::new(StaticAuth::new(config.auth.static_tokens.clone()));
    let message = "WRONGTYPE Operation against a key holding the wrong kind of value";
    let response = app_with_auth(
        Arc::new(AuthChain::new(vec![static_auth])),
        config,
        Err(ExecError::Redis(message.to_owned())),
    )
    .oneshot(
        Request::post("/")
            .header(header::AUTHORIZATION, "Bearer right-token")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"["GET","key"]"#))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response_json(response).await, json!({ "error": message }));
}

#[tokio::test]
async fn transient_backend_failures_are_503_with_retry_after() {
    for error in [
        ExecError::Timeout,
        ExecError::Transport("connection reset".to_owned()),
    ] {
        let config = Arc::new(
            Config::from_json(
                r#"{"server":{"load":{"shed_retry_after_secs":7}},"auth":{"static_tokens":{"right-token":{"pool":"cache"}}},"pools":{"cache":{"connection_string":"redis://localhost:6379"}}}"#,
            )
            .unwrap(),
        );
        let static_auth: Arc<dyn Authenticator> =
            Arc::new(StaticAuth::new(config.auth.static_tokens.clone()));
        let response = app_with_auth(
            Arc::new(AuthChain::new(vec![static_auth])),
            config,
            Err(error),
        )
        .oneshot(
            Request::post("/")
                .header(header::AUTHORIZATION, "Bearer right-token")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"["PING"]"#))
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[header::RETRY_AFTER], "7");
        assert_eq!(
            response_json(response).await,
            json!({ "error": "Backend unavailable" })
        );
    }
}

#[tokio::test]
async fn oversized_response_fails_the_whole_request_with_bad_gateway() {
    // The commands DID execute; 502 means the reply could not be rendered
    // inside `load.max_response_bytes`. Clients must treat it as indeterminate.
    let config = Arc::new(
        Config::from_json(
            r#"{"server":{"load":{"max_response_bytes":16}},"auth":{"static_tokens":{"right-token":{"pool":"cache"}}},"pools":{"cache":{"connection_string":"redis://localhost:6379"}}}"#,
        )
        .expect("test configuration should parse"),
    );
    let static_auth: Arc<dyn Authenticator> =
        Arc::new(StaticAuth::new(config.auth.static_tokens.clone()));
    let response = app_with_auth(
        Arc::new(AuthChain::new(vec![static_auth])),
        config,
        Ok(RespValue::Bulk(bytes::Bytes::from_static(
            b"a reply far larger than the configured response budget",
        ))),
    )
    .oneshot(
        Request::post("/")
            .header(header::AUTHORIZATION, "Bearer right-token")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"["GET","key"]"#))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        response_json(response).await,
        json!({ "error": "Response too large" })
    );
}

struct UnavailableAuth;

#[async_trait]
impl Authenticator for UnavailableAuth {
    async fn authenticate(
        &self,
        _bearer: &str,
    ) -> Result<Option<Arc<srh_rs::domain::identity::Identity>>, srh_rs::domain::identity::AuthError>
    {
        Err(srh_rs::domain::identity::AuthError::ServiceUnavailable(
            "introspection endpoint unreachable".to_owned(),
        ))
    }
}

#[tokio::test]
async fn authentication_dependency_failure_returns_service_unavailable() {
    let config = Arc::new(Config::from_json("{}").expect("default config should parse"));
    let response = app_with_auth(
        Arc::new(UnavailableAuth),
        config,
        Ok(RespValue::Simple("unused".to_owned())),
    )
    .oneshot(
        Request::post("/")
            .header(header::AUTHORIZATION, "Bearer opaque-token")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"["PING"]"#))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response_json(response).await,
        json!({ "error": "Authentication service unavailable" })
    );
}

#[tokio::test]
async fn health_and_fallbacks_have_stable_json_shapes() {
    let health = app()
        .clone()
        .oneshot(Request::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::OK);
    assert_eq!(response_json(health).await, json!({ "status": "ok" }));

    let missing = app()
        .clone()
        .oneshot(Request::get("/missing").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_json(missing).await,
        json!({ "error": "Not found" })
    );

    let wrong_method = app()
        .oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(wrong_method.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        response_json(wrong_method).await,
        json!({ "error": "Method not allowed" })
    );
}
