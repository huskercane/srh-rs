#![cfg(feature = "testsupport")]

use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use bytes::Bytes;
use futures_util::future::join_all;
use serde_json::Value;
use srh_rs::AppState;
use srh_rs::adapters::auth_chain::AuthChain;
use srh_rs::adapters::fred_executor::FredExecutor;
use srh_rs::adapters::pool_manager::PoolManager;
use srh_rs::adapters::static_auth::StaticAuth;
use srh_rs::config::Config;
use srh_rs::domain::resp::{PoolReadiness, PoolReadinessStatus, RespValue};
use srh_rs::ports::{Authenticator, Clock, CommandExecutor, ExecutorProvider, RedisCommand};
use srh_rs::testsupport::executor_contract;
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};
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

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn fred_executor_satisfies_contract_and_preserves_binary_values() {
    let reservation = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("a host port should be reservable");
    let fixed_host_port = reservation.local_addr().unwrap().port();
    drop(reservation);
    let container = GenericImage::new("redis", "7")
        .with_exposed_port(6379.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
        .with_mapped_port(fixed_host_port, 6379.tcp())
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
            1000,
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
            r#"{{"auth":{{"static_tokens":{{"right-token":{{"pool":"cache"}}}}}},"pools":{{"cache":{{"connection_string":"redis://127.0.0.1:{port}","max_connections":1}}}}}}"#
        ))
        .expect("HTTP test configuration should parse"),
    );
    let static_auth: Arc<dyn Authenticator> =
        Arc::new(StaticAuth::new(config.auth.static_tokens.clone()));
    let manager = Arc::new(PoolManager::new(Arc::clone(&config), Arc::new(TestClock)));
    let provider: Arc<dyn ExecutorProvider> = manager.clone();
    let app = srh_rs::http::router(AppState {
        provider,
        authenticator: Arc::new(AuthChain::new(vec![static_auth])),
        clock: Arc::new(TestClock),
        rate_limiter: Arc::new(srh_rs::domain::rate_limit::RateLimiter::new(
            0,
            Arc::new(TestClock),
        )),
        cfg: config,
    });
    let response = app
        .clone()
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

    let response = app
        .clone()
        .oneshot(
            Request::post("/pipeline")
                .header(header::AUTHORIZATION, "Bearer right-token")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"[["SET","srh:http:pipeline","value"],["HGET","srh:http:pipeline","field"],["INCR","srh:http:counter"]]"#,
                ))
                .expect("request should build"),
        )
        .await
        .expect("pipeline request should complete");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response_json(response).await,
        serde_json::json!([
            { "result": "OK" },
            { "error": "WRONGTYPE Operation against a key holding the wrong kind of value" },
            { "result": 1 }
        ])
    );

    executor
        .execute(command("SET", &["srh:http:multi:bulk-ok", "OK"]))
        .await
        .expect("fixture SET should succeed");
    let response = app
        .clone()
        .oneshot(
            Request::post("/multi-exec")
                .header(header::AUTHORIZATION, "Bearer right-token")
                .header(header::CONTENT_TYPE, "application/json")
                .header("upstash-encoding", "base64")
                .body(Body::from(r#"[["GET","srh:http:multi:bulk-ok"]]"#))
                .expect("request should build"),
        )
        .await
        .expect("multi-exec base64 request should complete");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response_json(response).await,
        serde_json::json!([{ "result": "T0s=" }]),
        "raw EXEC frames must preserve bulk framing in base64 mode"
    );

    executor
        .execute(command("SET", &["srh:http:multi:bad-int", "not-an-int"]))
        .await
        .expect("fixture SET should succeed");
    let response = app
        .clone()
        .oneshot(
            Request::post("/multi-exec")
                .header(header::AUTHORIZATION, "Bearer right-token")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"[["SET","srh:http:multi:committed-a","1"],["INCR","srh:http:multi:bad-int"],["SET","srh:http:multi:committed-b","1"]]"#,
                ))
                .expect("request should build"),
        )
        .await
        .expect("multi-exec runtime-error request should complete");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response_json(response).await,
        serde_json::json!([
            { "result": "OK" },
            { "error": "ERR value is not an integer or out of range" },
            { "result": "OK" }
        ])
    );
    assert_eq!(
        executor
            .execute(command(
                "MGET",
                &["srh:http:multi:committed-a", "srh:http:multi:committed-b"],
            ))
            .await,
        Ok(RespValue::Array(vec![
            RespValue::Bulk(Bytes::from_static(b"1")),
            RespValue::Bulk(Bytes::from_static(b"1")),
        ])),
        "Redis does not roll back successful commands after an EXEC-time error"
    );

    let response = app
        .clone()
        .oneshot(
            Request::post("/multi-exec")
                .header(header::AUTHORIZATION, "Bearer right-token")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"[["SET","srh:http:multi","0"],["INCR","srh:http:multi"],["GET","srh:http:multi"]]"#,
                ))
                .expect("request should build"),
        )
        .await
        .expect("multi-exec request should complete");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response_json(response).await,
        serde_json::json!([
            { "result": "OK" },
            { "result": 1 },
            { "result": "1" }
        ])
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

    pipeline_submission_order_survives_concurrent_load(Arc::clone(&executor)).await;
    transactions_remain_isolated_from_concurrent_commands(Arc::clone(&executor)).await;

    assert_eq!(
        manager.built_pool_count(),
        1,
        "HTTP requests reuse one lazy pool"
    );
    let saturated = manager.acquire("cache").await.unwrap();
    assert_eq!(
        manager.readiness().await,
        vec![PoolReadiness {
            pool: "cache".to_owned(),
            status: PoolReadinessStatus::Ready,
        }],
        "a saturated healthy pool remains ready"
    );
    drop(saturated);
    manager.shutdown().await;
    fred_timeout_does_not_desynchronize_pooled_connection(port).await;

    container.stop().await.expect("Redis container should stop");
    let recovery_config = Arc::new(
        Config::from_json(&format!(
            r#"{{
                "auth": {{"static_tokens": {{}}}},
                "pools": {{"recovery": {{
                    "connection_string": "redis://127.0.0.1:{port}",
                    "max_connections": 1,
                    "command_timeout_ms": 200,
                    "acquire_timeout_ms": 500,
                    "breaker": {{"failure_threshold": 100, "cooldown_ms": 100}}
                }}}}
            }}"#
        ))
        .expect("recovery test configuration should parse"),
    );
    let recovery = PoolManager::new(recovery_config, Arc::new(TestClock));
    assert_eq!(recovery.built_pool_count(), 0);
    assert!(recovery.readiness().await.is_empty());
    let handle = recovery.acquire("recovery").await.unwrap();
    assert!(
        handle
            .executor()
            .execute(command("PING", &[]))
            .await
            .is_err(),
        "a request while Redis is stopped must fail cleanly"
    );
    drop(handle);

    container
        .start()
        .await
        .expect("Redis container should restart");
    let restarted_port = container
        .get_host_port_ipv4(6379.tcp())
        .await
        .expect("restarted Redis port should be mapped");
    assert_eq!(restarted_port, port);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_ok()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("restarted Redis TCP listener should become reachable");
    // The locked reconnect policy caps at five seconds; depending on where the
    // container restart lands in the backoff sequence, the next attempt can be
    // just past six seconds.
    tokio::time::timeout(Duration::from_secs(12), async {
        loop {
            let handle = recovery.acquire("recovery").await.unwrap();
            let result = handle.executor().execute(command("PING", &[])).await;
            drop(handle);
            if result == Ok(RespValue::Simple("PONG".to_owned())) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("lazy pool should recover after Redis starts without a process restart");
    recovery.shutdown().await;
}

async fn fred_timeout_does_not_desynchronize_pooled_connection(port: u16) {
    let config = Arc::new(
        Config::from_json(&format!(
            r#"{{
                "auth": {{"static_tokens": {{}}}},
                "pools": {{"slow": {{
                    "connection_string": "redis://127.0.0.1:{port}",
                    "max_connections": 1,
                    "command_timeout_ms": 100,
                    "acquire_timeout_ms": 500
                }}}}
            }}"#
        ))
        .expect("timeout test configuration should parse"),
    );
    let manager = PoolManager::new(config, Arc::new(TestClock));
    let handle = manager.acquire("slow").await.unwrap();
    let results = handle
        .executor()
        .pipeline(
            (0..8)
                .map(|index| command("BLPOP", &[&format!("srh:timeout:missing:{index}"), "1"]))
                .collect(),
        )
        .await;
    assert!(
        results
            .iter()
            .all(|result| *result == Err(srh_rs::domain::resp::ExecError::Timeout)),
        "every blocking pipeline slot should time out"
    );
    drop(handle);

    let recovery_started = Instant::now();
    let handle = manager.acquire("slow").await.unwrap();
    assert_eq!(
        handle.executor().execute(command("PING", &[])).await,
        Ok(RespValue::Simple("PONG".to_owned())),
        "the request after a Fred-level timeout must receive its own reply"
    );
    assert!(
        recovery_started.elapsed() < Duration::from_millis(200),
        "one reset must recover an all-timeout pipeline before another command timeout"
    );
    drop(handle);
    manager.shutdown().await;
}

async fn pipeline_submission_order_survives_concurrent_load(executor: Arc<dyn CommandExecutor>) {
    for size in [25_usize, 40, 200] {
        for round in 0..3 {
            let key = format!("srh:order:{size}:{round}");
            let commands = (0..size)
                .map(|index| RedisCommand {
                    name: "RPUSH".to_owned(),
                    args: vec![
                        Bytes::copy_from_slice(key.as_bytes()),
                        Bytes::from(index.to_string()),
                    ],
                })
                .collect();
            let background = (0..50).map(|index| {
                let executor = Arc::clone(&executor);
                tokio::spawn(async move {
                    executor
                        .execute(RedisCommand {
                            name: "INCR".to_owned(),
                            args: vec![Bytes::from(format!(
                                "srh:order:background:{size}:{round}:{index}"
                            ))],
                        })
                        .await
                })
            });
            let (pipeline, background) =
                tokio::join!(executor.pipeline(commands), join_all(background));

            assert_eq!(
                pipeline,
                (1..=size)
                    .map(|index| Ok(RespValue::Int(index as i64)))
                    .collect::<Vec<_>>(),
                "pipeline replies must preserve request order at size {size}, round {round}"
            );
            assert!(background.into_iter().all(|result| {
                result.expect("background command task should complete") == Ok(RespValue::Int(1))
            }));
            assert_eq!(
                executor
                    .execute(RedisCommand {
                        name: "LRANGE".to_owned(),
                        args: vec![
                            Bytes::copy_from_slice(key.as_bytes()),
                            Bytes::from_static(b"0"),
                            Bytes::from_static(b"-1"),
                        ],
                    })
                    .await,
                Ok(RespValue::Array(
                    (0..size)
                        .map(|index| RespValue::Bulk(Bytes::from(index.to_string())))
                        .collect()
                )),
                "pipeline commands must execute in request order at size {size}, round {round}"
            );
        }
    }
}

async fn transactions_remain_isolated_from_concurrent_commands(executor: Arc<dyn CommandExecutor>) {
    let transactions = (0..40).map(|index| {
        let executor = Arc::clone(&executor);
        tokio::spawn(async move {
            let key = format!("srh:isolation:transaction:{index}");
            let initial = index.to_string();
            let expected = (index + 1).to_string();
            let result = executor
                .transaction(vec![
                    RedisCommand {
                        name: "SET".to_owned(),
                        args: vec![Bytes::copy_from_slice(key.as_bytes()), Bytes::from(initial)],
                    },
                    RedisCommand {
                        name: "INCR".to_owned(),
                        args: vec![Bytes::copy_from_slice(key.as_bytes())],
                    },
                    RedisCommand {
                        name: "GET".to_owned(),
                        args: vec![Bytes::copy_from_slice(key.as_bytes())],
                    },
                ])
                .await;
            (
                index,
                result,
                vec![
                    RespValue::Simple("OK".to_owned()),
                    RespValue::Int((index + 1) as i64),
                    RespValue::Bulk(Bytes::from(expected)),
                ],
            )
        })
    });
    let singles = (0..100).map(|index| {
        let executor = Arc::clone(&executor);
        tokio::spawn(async move {
            executor
                .execute(RedisCommand {
                    name: "INCR".to_owned(),
                    args: vec![Bytes::from(format!("srh:isolation:single:{index}"))],
                })
                .await
        })
    });
    let (transactions, singles) = tokio::join!(join_all(transactions), join_all(singles));

    for transaction in transactions {
        let (index, result, expected) = transaction.expect("transaction task should complete");
        assert_eq!(
            result,
            Ok(expected.into_iter().map(Ok).collect()),
            "transaction {index} received another command's reply"
        );
    }
    assert!(
        singles.into_iter().all(|result| {
            result.expect("single command task should complete") == Ok(RespValue::Int(1))
        }),
        "every concurrent single command must receive its own reply"
    );
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

async fn response_json(response: axum::response::Response) -> Value {
    let bytes = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("response body should be readable");
    serde_json::from_slice(&bytes).expect("response should be JSON")
}
