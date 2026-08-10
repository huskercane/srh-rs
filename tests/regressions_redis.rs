#![cfg(feature = "testsupport")]
//! Regression locks for defects found by review that need a real Redis.
//!
//! Each test asserts the corrected behavior for a defect found by review.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use bytes::Bytes;
use serde_json::{Value, json};
use srh_rs::AppState;
use srh_rs::adapters::auth_chain::AuthChain;
use srh_rs::adapters::fred_executor::FredExecutor;
use srh_rs::adapters::pool_manager::PoolManager;
use srh_rs::adapters::static_auth::StaticAuth;
use srh_rs::config::Config;
use srh_rs::domain::rate_limit::RateLimiter;
use srh_rs::domain::resp::RespValue;
use srh_rs::ports::{Authenticator, Clock, CommandExecutor, ExecutorProvider, RedisCommand};
use testcontainers::ContainerAsync;
use testcontainers::GenericImage;
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use tower::ServiceExt;

struct FixedClock;

impl Clock for FixedClock {
    fn unix_secs(&self) -> u64 {
        0
    }

    fn instant(&self) -> Instant {
        Instant::now()
    }
}

async fn start_redis() -> (ContainerAsync<GenericImage>, u16) {
    let container = GenericImage::new("redis", "7")
        .with_exposed_port(6379.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
        .start()
        .await
        .expect("Redis 7 testcontainer should start");
    let port = container
        .get_host_port_ipv4(6379.tcp())
        .await
        .expect("Redis port should be mapped");
    (container, port)
}

/// Builds a proxy over one pool, pinned to a single connection so that any connection-state
/// leak is deterministic rather than dependent on round-robin ordering.
fn app(connection_string: String, manager: &mut Option<Arc<PoolManager>>) -> axum::Router {
    let config = Arc::new(
        Config::from_json(
            &json!({
                "auth": { "static_tokens": { "token": { "pool": "p" } } },
                "pools": {
                    "p": { "connection_string": connection_string, "max_connections": 1 }
                }
            })
            .to_string(),
        )
        .expect("single-pool config should parse"),
    );
    let static_auth: Arc<dyn Authenticator> =
        Arc::new(StaticAuth::new(config.auth.static_tokens.clone()));
    let clock: Arc<dyn Clock> = Arc::new(FixedClock);
    let pools = Arc::new(PoolManager::new(Arc::clone(&config), Arc::clone(&clock)));
    let provider: Arc<dyn ExecutorProvider> = pools.clone();
    *manager = Some(pools);
    srh_rs::http::router(AppState {
        provider,
        authenticator: Arc::new(AuthChain::new(vec![static_auth])),
        clock: Arc::clone(&clock),
        rate_limiter: Arc::new(RateLimiter::new(0, clock)),
        cfg: config,
    })
}

async fn post(app: &axum::Router, path: &str, payload: Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::post(path)
                .header(header::AUTHORIZATION, "Bearer token")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(payload.to_string()))
                .expect("request should build"),
        )
        .await
        .expect("request should complete");
    let status = response.status();
    let body: Value = serde_json::from_slice(
        &to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("response body should be readable"),
    )
    .expect("response should be JSON");
    (status, body)
}

/// `MULTI` is absent from `HARD_DENY`, so an ordinary read-write token can put a pooled
/// connection into transaction state. Every later request routed to that connection — any
/// credential on the pool, because `Pool::next_connected` round-robins independently of which
/// semaphore permit is free — receives `QUEUED` instead of its own result, and its command is
/// queued into the first caller's transaction. The first caller's `EXEC` then returns other
/// requests' results.
///
/// This is the exact class `HARD_DENY`'s own comment claims to cover: "protocol/session state
/// on pooled connections — correctness, not just security", alongside HELLO/SELECT/SWAPDB.
/// `MULTI`, `EXEC`, `DISCARD`, `WATCH` and `UNWATCH` all belong in that list.
///
/// Layer B bounds this but does not close it: a least-privilege Redis user without `+multi`
/// returns NOPERM, but the default user and any `+@all`/`+@transaction` grant do not.
#[tokio::test]
async fn multi_is_denied_and_cannot_poison_a_pooled_connection() {
    let (_container, port) = start_redis().await;
    let mut manager = None;
    let app = app(format!("redis://127.0.0.1:{port}"), &mut manager);

    let (status, _) = post(&app, "/", json!(["SET", "k", "v"])).await;
    assert_eq!(status, StatusCode::OK, "seeding the key should succeed");

    let (status, body) = post(&app, "/", json!(["MULTI"])).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "MULTI leaves session state on a pooled connection and must be denied by the proxy \
         ACL for every identity, as HELLO and SELECT already are; got {body}"
    );

    // The damage, asserted independently of how MULTI is rejected: an unrelated later request
    // must still receive its own value rather than the transaction's QUEUED acknowledgement.
    let (status, body) = post(&app, "/", json!(["GET", "k"])).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["result"].as_str(),
        Some("v"),
        "a later request on the same pooled connection received {body} instead of its own \
         value, so the connection is carrying another request's transaction state"
    );

    if let Some(manager) = manager {
        manager.shutdown().await;
    }
}

/// `/multi-exec` runs a real Redis transaction, so the documented Layer B user needs
/// `+multi`/`+exec`/`+discard` even though direct client transaction commands are denied.
#[tokio::test]
async fn the_documented_layer_b_user_authenticates_without_hello_and_serves_multi_exec() {
    let (_container, port) = start_redis().await;
    let admin = FredExecutor::connect(
        &format!("redis://127.0.0.1:{port}"),
        Duration::from_secs(5),
        Duration::from_secs(2),
        100,
    )
    .await
    .expect("admin connection should open");

    // Verbatim from the README / spec Layer B example for an auth-KV pool.
    let provisioned = admin
        .execute(RedisCommand {
            name: "ACL".to_owned(),
            args: [
                "SETUSER",
                "srh-authkv",
                "reset",
                "on",
                ">STRONG_PASSWORD",
                "~ww:auth:*",
                "+get",
                "+set",
                "+del",
                "+expireat",
                "+ttl",
                "+ping",
                "+info",
                "+command|info",
                "+multi",
                "+exec",
                "+discard",
            ]
            .into_iter()
            .map(Bytes::from)
            .collect(),
        })
        .await
        .expect("ACL user provisioning should succeed");
    assert_eq!(provisioned, RespValue::Simple("OK".to_owned()));

    let mut manager = None;
    let app = app(
        format!("redis://srh-authkv:STRONG_PASSWORD@127.0.0.1:{port}"),
        &mut manager,
    );

    let (status, body) = post(
        &app,
        "/multi-exec",
        json!([["SET", "ww:auth:t", "1"], ["GET", "ww:auth:t"]]),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the documented Layer B grant list must support the proxy's /multi-exec transaction; \
         got {body}"
    );
    assert_eq!(body[1]["result"].as_str(), Some("1"));

    if let Some(manager) = manager {
        manager.shutdown().await;
    }
}
