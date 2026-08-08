use std::sync::Arc;

use bytes::Bytes;

use crate::domain::resp::{ExecError, RespValue};
use crate::ports::{CommandExecutor, RedisCommand};

pub async fn executor_contract(executor: Arc<dyn CommandExecutor>) {
    let raw_error = "WRONGTYPE Operation against a key holding the wrong kind of value";
    assert_eq!(
        executor
            .execute(command("SET", &["srh:contract:wrongtype", "value"]))
            .await,
        Ok(RespValue::Simple("OK".to_owned()))
    );
    assert_eq!(
        executor
            .execute(command("HGET", &["srh:contract:wrongtype", "field"]))
            .await,
        Err(ExecError::Redis(raw_error.to_owned())),
        "Redis error text must pass through verbatim"
    );

    assert_eq!(
        executor
            .pipeline(vec![
                command("SET", &["srh:contract:pipeline", "value"]),
                command("HGET", &["srh:contract:pipeline", "field"]),
                command("INCR", &["srh:contract:counter"]),
            ])
            .await,
        vec![
            Ok(RespValue::Simple("OK".to_owned())),
            Err(ExecError::Redis(raw_error.to_owned())),
            Ok(RespValue::Int(1)),
        ],
        "a per-command error must not abort the pipeline"
    );

    assert_eq!(
        executor
            .execute(command("GET", &["srh:contract:missing"]))
            .await,
        Ok(RespValue::Nil),
        "nil must remain a successful value"
    );

    assert_eq!(
        executor
            .transaction(vec![
                command("INCR", &["srh:contract:first"]),
                command("INCR", &["srh:contract:second"]),
            ])
            .await,
        Ok(vec![RespValue::Int(1), RespValue::Int(1)]),
        "transaction results must remain ordered and all-or-error"
    );

    let transaction_error = executor
        .transaction(vec![
            command("SET", &["srh:contract:atomic:first", "written"]),
            command("SRH_UNKNOWN_COMMAND", &[]),
            command("SET", &["srh:contract:atomic:second", "written"]),
        ])
        .await;
    assert!(
        matches!(transaction_error, Err(ExecError::Redis(message)) if message.starts_with("ERR unknown command")),
        "a queue error must fail the whole transaction with the raw Redis error"
    );
    for key in ["srh:contract:atomic:first", "srh:contract:atomic:second"] {
        assert_eq!(
            executor.execute(command("GET", &[key])).await,
            Ok(RespValue::Nil),
            "a failed transaction must not execute any queued command"
        );
    }
}

/// Semantics every `CommandExecutor` must share, which no implementation
/// satisfies yet. These are the Phase 3 acceptance requirements; when the
/// pipeline path stops converting through fred's lossy `Value`, fold this into
/// [`executor_contract`] and delete it.
///
/// Both currently fail for `FredExecutor`:
/// - a lowercase Redis error is classified `Transport`, which Phase 4's breaker
///   would count as backend failure on a healthy server;
/// - a bulk reply whose bytes are `OK` collapses to `Simple`, which §1.6 exempts
///   from base64, so the value does not round-trip.
pub async fn executor_contract_phase3(executor: Arc<dyn CommandExecutor>) {
    let lowercase = "boom lowercase failure";
    assert_eq!(
        executor
            .pipeline(vec![command(
                "EVAL",
                &[&format!("return redis.error_reply('{lowercase}')"), "0"],
            )])
            .await,
        vec![Err(ExecError::Redis(lowercase.to_owned()))],
        "a lowercase Redis error must stay a per-slot raw Redis error, not a transport failure"
    );

    assert_eq!(
        executor
            .execute(command("SET", &["srh:contract:okvalue", "OK"]))
            .await,
        Ok(RespValue::Simple("OK".to_owned()))
    );
    assert_eq!(
        executor
            .pipeline(vec![command("GET", &["srh:contract:okvalue"])])
            .await,
        vec![Ok(RespValue::Bulk(Bytes::from_static(b"OK")))],
        "a bulk value of `OK` must stay Bulk; only a RESP simple-string OK is base64-exempt"
    );
}

fn command(name: &str, args: &[&str]) -> RedisCommand {
    RedisCommand {
        name: name.to_owned(),
        args: args
            .iter()
            .map(|arg| Bytes::copy_from_slice(arg.as_bytes()))
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testsupport::FakeExecutor;

    #[tokio::test]
    async fn fake_executor_satisfies_contract() {
        let replies = vec![
            Ok(RespValue::Simple("OK".to_owned())),
            Err(ExecError::Redis(
                "WRONGTYPE Operation against a key holding the wrong kind of value".to_owned(),
            )),
            Ok(RespValue::Simple("OK".to_owned())),
            Err(ExecError::Redis(
                "WRONGTYPE Operation against a key holding the wrong kind of value".to_owned(),
            )),
            Ok(RespValue::Int(1)),
            Ok(RespValue::Nil),
            Ok(RespValue::Int(1)),
            Ok(RespValue::Int(1)),
            Err(ExecError::Redis(
                "ERR unknown command 'SRH_UNKNOWN_COMMAND'".to_owned(),
            )),
            Ok(RespValue::Nil),
            Ok(RespValue::Nil),
        ];
        executor_contract(Arc::new(FakeExecutor::new(replies))).await;
    }
}
