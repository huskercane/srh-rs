#![cfg(feature = "testsupport")]

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use bytes::Bytes;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use srh_rs::AppState;
use srh_rs::adapters::auth_chain::AuthChain;
use srh_rs::adapters::fred_executor::FredExecutor;
use srh_rs::adapters::pool_manager::PoolManager;
use srh_rs::adapters::static_auth::StaticAuth;
use srh_rs::config::Config;
use srh_rs::domain::rate_limit::RateLimiter;
use srh_rs::domain::resp::RespValue;
use srh_rs::ports::{Authenticator, Clock, CommandExecutor, ExecutorProvider, RedisCommand};
use testcontainers::GenericImage;
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use tower::ServiceExt;

struct TestClock;

impl Clock for TestClock {
    fn unix_secs(&self) -> u64 {
        0
    }

    fn instant(&self) -> Instant {
        Instant::now()
    }
}

#[tokio::test]
async fn an_allowlisted_eval_is_still_confined_by_the_redis_acl_user() {
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
    let admin = FredExecutor::connect(
        &format!("redis://127.0.0.1:{port}"),
        Duration::from_secs(5),
        Duration::from_secs(2),
        100,
    )
    .await
    .expect("admin connection should open");
    let result = admin
        .execute(RedisCommand {
            name: "ACL".to_owned(),
            args: [
                "SETUSER",
                "srh-phase5",
                "reset",
                "on",
                ">phase5-password",
                "~phase5:*",
                "+get",
                "+set",
                "+ping",
            ]
            .into_iter()
            .map(Bytes::from)
            .collect(),
        })
        .await
        .expect("ACL user provisioning should succeed");
    assert_eq!(result, RespValue::Simple("OK".to_owned()));

    let script = "return redis.call('SET', KEYS[1], ARGV[1])";
    let script_sha256 = Sha256::digest(script.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let config = Arc::new(
        Config::from_json(
            &json!({
                "auth": {
                    "static_tokens": {
                        "token": {
                            "pool": "restricted",
                            "allowed_commands": ["EVAL"],
                            "allowed_script_sha256": [script_sha256]
                        }
                    }
                },
                "pools": {
                    "restricted": {
                        "connection_string": format!(
                            "redis://srh-phase5:phase5-password@127.0.0.1:{port}"
                        )
                    }
                }
            })
            .to_string(),
        )
        .expect("restricted-pool config should parse"),
    );
    let static_auth: Arc<dyn Authenticator> =
        Arc::new(StaticAuth::new(config.auth.static_tokens.clone()));
    let clock: Arc<dyn Clock> = Arc::new(TestClock);
    let manager = Arc::new(PoolManager::new(Arc::clone(&config), Arc::clone(&clock)));
    let provider: Arc<dyn ExecutorProvider> = manager.clone();
    let app = srh_rs::http::router(AppState {
        provider,
        authenticator: Arc::new(AuthChain::new(vec![static_auth])),
        clock: Arc::clone(&clock),
        rate_limiter: Arc::new(RateLimiter::new(0, clock)),
        cfg: config,
    });
    let response = app
        .oneshot(
            Request::post("/")
                .header(header::AUTHORIZATION, "Bearer token")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!(["EVAL", script, 1, "phase5:key", "value"]).to_string(),
                ))
                .expect("request should build"),
        )
        .await
        .expect("request should complete");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(
        &to_bytes(response.into_body(), 16 * 1024)
            .await
            .expect("response body should be readable"),
    )
    .expect("response should be JSON");
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|message| message.starts_with("NOPERM"))
    );
    manager.shutdown().await;
}
