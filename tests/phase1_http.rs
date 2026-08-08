use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use serde_json::{Value, json};
use srh_rs::AppState;
use srh_rs::adapters::auth_chain::AuthChain;
use srh_rs::adapters::static_auth::StaticAuth;
use srh_rs::config::Config;
use srh_rs::domain::resp::{AcquireError, PoolReadiness};
use srh_rs::http;
use srh_rs::ports::{Authenticator, Clock, ExecutorHandle, ExecutorProvider};
use tower::ServiceExt;

struct UnusedProvider;

#[async_trait]
impl ExecutorProvider for UnusedProvider {
    async fn acquire(&self, _pool: &str) -> Result<ExecutorHandle, AcquireError> {
        unreachable!("Phase 1 handlers do not acquire Redis pools")
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
    app_with_auth(Arc::new(AuthChain::new(vec![static_auth])), config)
}

fn app_with_auth(authenticator: Arc<dyn Authenticator>, config: Arc<Config>) -> axum::Router {
    http::router(AppState {
        provider: Arc::new(UnusedProvider),
        authenticator,
        clock: Arc::new(TestClock),
        cfg: config,
    })
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
async fn right_token_reaches_the_phase_one_stub() {
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
    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    assert_eq!(
        response_json(response).await,
        json!({ "error": "Not implemented" })
    );
}

struct UnavailableAuth;

#[async_trait]
impl Authenticator for UnavailableAuth {
    async fn authenticate(
        &self,
        _bearer: &str,
    ) -> Result<Option<srh_rs::domain::identity::Identity>, srh_rs::domain::identity::AuthError>
    {
        Err(srh_rs::domain::identity::AuthError::ServiceUnavailable(
            "introspection endpoint unreachable".to_owned(),
        ))
    }
}

#[tokio::test]
async fn authentication_dependency_failure_returns_service_unavailable() {
    let config = Arc::new(Config::from_json("{}").expect("default config should parse"));
    let response = app_with_auth(Arc::new(UnavailableAuth), config)
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
