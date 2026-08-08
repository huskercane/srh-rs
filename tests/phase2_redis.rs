#![cfg(feature = "testsupport")]

use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use async_trait::async_trait;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use bytes::Bytes;
use serde_json::Value;
use srh_rs::AppState;
use srh_rs::adapters::auth_chain::AuthChain;
use srh_rs::adapters::fred_executor::FredExecutor;
use srh_rs::adapters::static_auth::StaticAuth;
use srh_rs::config::Config;
use srh_rs::domain::resp::{AcquireError, PoolReadiness, RespValue};
use srh_rs::ports::{
    Authenticator, Clock, CommandExecutor, ExecutorHandle, ExecutorProvider, RedisCommand,
};
use srh_rs::testsupport::executor_contract;
use testcontainers::GenericImage;
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use tower::ServiceExt;

struct TestProvider {
    executor: Arc<dyn CommandExecutor>,
}

#[async_trait]
impl ExecutorProvider for TestProvider {
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

#[tokio::test]
async fn fred_executor_satisfies_contract_and_preserves_binary_values() {
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
    let executor: Arc<dyn CommandExecutor> = Arc::new(
        FredExecutor::connect(
            &format!("redis://127.0.0.1:{port}"),
            Duration::from_secs(5),
            Duration::from_secs(2),
            100,
        )
        .await
        .expect("Fred should connect to Redis"),
    );

    executor_contract(Arc::clone(&executor)).await;

    let binary = Bytes::from_static(&[0xff, 0xfe, 0x00, 0x01]);
    assert_eq!(
        executor
            .execute(RedisCommand {
                name: "SET".to_owned(),
                args: vec![Bytes::from_static(b"srh:binary"), binary.clone()],
            })
            .await,
        Ok(RespValue::Simple("OK".to_owned()))
    );
    let config = Arc::new(
        Config::from_json(&format!(
            r#"{{"auth":{{"static_tokens":{{"right-token":{{"pool":"cache"}}}}}},"pools":{{"cache":{{"connection_string":"redis://127.0.0.1:{port}"}}}}}}"#
        ))
        .expect("HTTP test configuration should parse"),
    );
    let static_auth: Arc<dyn Authenticator> =
        Arc::new(StaticAuth::new(config.auth.static_tokens.clone()));
    let app = srh_rs::http::router(AppState {
        provider: Arc::new(TestProvider {
            executor: Arc::clone(&executor),
        }),
        authenticator: Arc::new(AuthChain::new(vec![static_auth])),
        clock: Arc::new(TestClock),
        cfg: config,
    });
    let response = app
        .oneshot(
            Request::post("/")
                .header(header::AUTHORIZATION, "Bearer right-token")
                .header("upstash-encoding", "base64")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"["GET","srh:binary"]"#))
                .expect("request should build"),
        )
        .await
        .expect("request should complete");
    assert_eq!(response.status(), StatusCode::OK);
    let response: Value = serde_json::from_slice(
        &to_bytes(response.into_body(), 1024)
            .await
            .expect("response body should be readable"),
    )
    .expect("response should be JSON");
    let encoded = response["result"]
        .as_str()
        .expect("result should be a base64 string");
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .expect("result should decode"),
        binary
    );

    assert_eq!(
        executor.execute(command("INCR", &["srh:integer"])).await,
        Ok(RespValue::Int(1))
    );
    assert_eq!(
        executor
            .execute(command("LPUSH", &["srh:list", "first", "second"]))
            .await,
        Ok(RespValue::Int(2))
    );
    assert_eq!(
        executor
            .execute(command("LRANGE", &["srh:list", "0", "-1"]))
            .await,
        Ok(RespValue::Array(vec![
            RespValue::Bulk(Bytes::from_static(b"second")),
            RespValue::Bulk(Bytes::from_static(b"first")),
        ]))
    );
}

/// Phase 3 acceptance, red today. `FredExecutor`'s pipeline path converts
/// through fred's `Value`, which classifies lowercase Redis errors as transport
/// failures and collapses a bulk `OK` into a simple string. Remove `ignore`
/// when Phase 3 replaces that path; the assertions then belong in
/// `executor_contract` alongside the rest.
#[tokio::test]
#[ignore = "Phase 3: pipeline must preserve raw frames (lowercase errors, bulk OK)"]
async fn fred_executor_meets_phase3_framing_and_error_contract() {
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
    let executor: Arc<dyn CommandExecutor> = Arc::new(
        FredExecutor::connect(
            &format!("redis://127.0.0.1:{port}"),
            Duration::from_secs(5),
            Duration::from_secs(2),
            100,
        )
        .await
        .expect("Fred should connect to Redis"),
    );
    srh_rs::testsupport::executor_contract_phase3(executor).await;
}

fn command(name: &str, args: &[&str]) -> RedisCommand {
    RedisCommand {
        name: name.to_owned(),
        args: args
            .iter()
            .map(|argument| Bytes::copy_from_slice(argument.as_bytes()))
            .collect(),
    }
}
