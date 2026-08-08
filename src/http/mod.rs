use std::time::Duration;

use axum::BoxError;
use axum::Router;
use axum::error_handling::HandleErrorLayer;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use serde_json::json;
use tower::ServiceBuilder;
use tower::limit::GlobalConcurrencyLimitLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

use crate::AppState;
use crate::error::AppError;

pub mod command;
pub mod extractors;
pub mod health;

pub fn router(state: AppState) -> Router {
    let limits = &state.cfg.server;
    let api = apply_admission_controls(
        Router::new()
            .route("/", post(command::execute))
            .route("/pipeline", post(command::not_implemented))
            .route("/multi-exec", post(command::not_implemented))
            .method_not_allowed_fallback(method_not_allowed),
        limits,
    );
    let observability = Router::new()
        .route("/health", get(health::health))
        .method_not_allowed_fallback(method_not_allowed);
    api.merge(observability)
        .fallback(not_found)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

fn apply_admission_controls(
    api: Router<AppState>,
    limits: &crate::config::ServerConfig,
) -> Router<AppState> {
    let retry_after_secs = limits.load.shed_retry_after_secs;
    api.layer(
        ServiceBuilder::new()
            .layer(HandleErrorLayer::new(move |_error: BoxError| async move {
                AppError::Overloaded { retry_after_secs }
            }))
            .load_shed()
            .layer(GlobalConcurrencyLimitLayer::new(limits.load.max_in_flight))
            .timeout(Duration::from_millis(limits.http_timeout_ms))
            .layer(RequestBodyLimitLayer::new(limits.max_body_bytes)),
    )
}

async fn not_found() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        axum::Json(json!({ "error": "Not found" })),
    )
}

async fn method_not_allowed() -> impl IntoResponse {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        axum::Json(json!({ "error": "Method not allowed" })),
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    use async_trait::async_trait;
    use axum::body::Body;
    use axum::extract::Extension;
    use axum::http::{Request, StatusCode, header};
    use axum::routing::get;
    use tokio::sync::{Notify, Semaphore};
    use tower::ServiceExt;

    use super::*;
    use crate::config::Config;
    use crate::domain::identity::{AuthError, Identity};
    use crate::domain::resp::{AcquireError, PoolReadiness};
    use crate::ports::{Authenticator, Clock, ExecutorHandle, ExecutorProvider};

    struct UnusedProvider;

    #[async_trait]
    impl ExecutorProvider for UnusedProvider {
        async fn acquire(&self, _pool: &str) -> Result<ExecutorHandle, AcquireError> {
            unreachable!("concurrency test does not acquire a pool")
        }

        async fn readiness(&self) -> Vec<PoolReadiness> {
            Vec::new()
        }
    }

    struct UnusedAuthenticator;

    #[async_trait]
    impl Authenticator for UnusedAuthenticator {
        async fn authenticate(&self, _bearer: &str) -> Result<Option<Identity>, AuthError> {
            unreachable!("concurrency test routes do not authenticate")
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

    struct Probe {
        active: AtomicUsize,
        peak: AtomicUsize,
        entered: Notify,
        release: Semaphore,
    }

    async fn slow(Extension(probe): Extension<Arc<Probe>>) -> StatusCode {
        let active = probe.active.fetch_add(1, Ordering::AcqRel) + 1;
        probe.peak.fetch_max(active, Ordering::AcqRel);
        probe.entered.notify_one();
        let permit = probe
            .release
            .acquire()
            .await
            .expect("test semaphore remains open");
        permit.forget();
        probe.active.fetch_sub(1, Ordering::AcqRel);
        StatusCode::OK
    }

    fn request(path: &str) -> Request<Body> {
        Request::get(path).body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn api_routes_share_one_global_limit_while_health_remains_unlimited() {
        let config = Arc::new(
            Config::from_json(
                r#"{"server":{"load":{"max_in_flight":1,"shed_retry_after_secs":9}}}"#,
            )
            .expect("test config should parse"),
        );
        let probe = Arc::new(Probe {
            active: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            entered: Notify::new(),
            release: Semaphore::new(0),
        });
        let state = AppState {
            provider: Arc::new(UnusedProvider),
            authenticator: Arc::new(UnusedAuthenticator),
            clock: Arc::new(TestClock),
            cfg: Arc::clone(&config),
        };
        let api = Router::new()
            .route("/one", get(slow))
            .route("/two", get(slow))
            .route("/three", get(slow))
            .layer(Extension(Arc::clone(&probe)));
        let observability = Router::new().route("/health", get(health::health));
        let app = apply_admission_controls(api, &config.server)
            .merge(observability)
            .with_state(state);

        let first = tokio::spawn(app.clone().oneshot(request("/one")));
        probe.entered.notified().await;

        let health = app.clone().oneshot(request("/health")).await.unwrap();
        assert_eq!(health.status(), StatusCode::OK);

        let (second, third) = tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(
                app.clone().oneshot(request("/two")),
                app.clone().oneshot(request("/three"))
            )
        })
        .await
        .expect("excess requests must be shed immediately");
        for response in [second.unwrap(), third.unwrap()] {
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(response.headers()[header::RETRY_AFTER], "9");
        }

        probe.release.add_permits(1);
        assert_eq!(first.await.unwrap().unwrap().status(), StatusCode::OK);
        assert_eq!(probe.peak.load(Ordering::Acquire), 1);
    }
}
