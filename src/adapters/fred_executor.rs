use std::time::Duration;

use async_trait::async_trait;
use fred::clients::Client;
use fred::error::{Error, ErrorKind};
use fred::interfaces::{ClientLike, TransactionInterface};
use fred::types::config::{Config, ConnectionConfig, PerformanceConfig, ReconnectPolicy};
use fred::types::{ClusterHash, ConnectHandle, CustomCommand, Resp3Frame, RespVersion, Value};
use futures_util::future::join_all;

use crate::domain::convert::MAX_DEPTH;
use crate::domain::resp::{ExecError, RespValue};
use crate::ports::{CommandExecutor, RedisCommand};

pub struct FredExecutor {
    client: Client,
    connection_task: ConnectHandle,
}

impl FredExecutor {
    /// Connect a temporary RESP2 executor used until Phase 4 introduces pools.
    pub async fn connect(
        connection_string: &str,
        connection_timeout: Duration,
        command_timeout: Duration,
        max_command_buffer_len: usize,
    ) -> Result<Self, ExecError> {
        let mut config = Config::from_url(connection_string).map_err(map_fred_error)?;
        config.version = RespVersion::RESP2;

        let connection = ConnectionConfig {
            connection_timeout,
            internal_command_timeout: command_timeout,
            max_command_buffer_len: max_command_buffer_len.max(1),
            ..ConnectionConfig::default()
        };
        let performance = PerformanceConfig {
            default_command_timeout: command_timeout,
            ..PerformanceConfig::default()
        };
        let client = Client::new(
            config,
            Some(performance),
            Some(connection),
            Some(ReconnectPolicy::new_constant(1, 100)),
        );
        let connection_task = client.init().await.map_err(map_fred_error)?;
        Ok(Self {
            client,
            connection_task,
        })
    }

    fn command(command: RedisCommand) -> (CustomCommand, Vec<bytes::Bytes>) {
        (
            CustomCommand::new(command.name, ClusterHash::FirstKey, false),
            command.args,
        )
    }
}

impl Drop for FredExecutor {
    fn drop(&mut self) {
        // Phases 2–3 create one client per request. Aborting prevents detached
        // reconnect tasks; Phase 4 replaces this with long-lived pools + quit().
        self.connection_task.abort();
    }
}

#[async_trait]
impl CommandExecutor for FredExecutor {
    async fn execute(&self, command: RedisCommand) -> Result<RespValue, ExecError> {
        let (command, args) = Self::command(command);
        let frame = self
            .client
            .custom_raw(command, args)
            .await
            .map_err(map_fred_error)?;
        fred_frame_to_resp(frame)
    }

    async fn pipeline(&self, commands: Vec<RedisCommand>) -> Vec<Result<RespValue, ExecError>> {
        // Poll in request order on one task. Fred enqueues each command on its
        // first poll; spawning per command can reorder dependent commands.
        join_all(commands.into_iter().map(|command| self.execute(command))).await
    }

    async fn transaction(&self, commands: Vec<RedisCommand>) -> Result<Vec<RespValue>, ExecError> {
        if commands.is_empty() {
            return Ok(Vec::new());
        }
        let transaction = self.client.multi();
        for command in commands {
            let (command, args) = Self::command(command);
            transaction
                .custom::<Value, _>(command, args)
                .await
                .map_err(map_fred_error)?;
        }
        let value: Value = transaction
            .exec(true)
            .await
            .map_err(map_fred_response_error)?;
        match fred_value_to_resp(value)? {
            RespValue::Array(values) => Ok(values),
            RespValue::Nil => Err(ExecError::Redis(
                "EXECABORT Transaction discarded because of previous errors.".to_owned(),
            )),
            _ => Err(protocol_violation("EXEC returned a non-array response")),
        }
    }
}

fn fred_value_to_resp(value: Value) -> Result<RespValue, ExecError> {
    value_within_depth(value, MAX_DEPTH)
}

fn value_within_depth(value: Value, depth_remaining: usize) -> Result<RespValue, ExecError> {
    let depth_remaining = depth_remaining
        .checked_sub(1)
        .ok_or(ExecError::ResponseTooLarge)?;
    match value {
        // Fred's public transaction API collapses simple and valid UTF-8 bulk
        // strings into Value::String before returning. See the documented
        // multi-exec/base64 `OK` divergence in §1.7.
        Value::String(value) if value.as_bytes() == b"OK" => {
            Ok(RespValue::Simple(value.to_string()))
        }
        Value::String(value) => Ok(RespValue::Bulk(bytes::Bytes::copy_from_slice(
            value.as_bytes(),
        ))),
        Value::Bytes(value) => Ok(RespValue::Bulk(value)),
        Value::Integer(value) => Ok(RespValue::Int(value)),
        Value::Null => Ok(RespValue::Nil),
        Value::Array(values) => values
            .into_iter()
            .map(|value| value_within_depth(value, depth_remaining))
            .collect::<Result<Vec<_>, _>>()
            .map(RespValue::Array),
        Value::Boolean(_) => Err(protocol_violation("unexpected RESP3 boolean")),
        Value::Double(_) => Err(protocol_violation("unexpected RESP3 double")),
        Value::Map(_) => Err(protocol_violation("unexpected RESP3 map")),
        Value::Queued => Err(protocol_violation("unexpected queued response")),
    }
}

fn fred_frame_to_resp(frame: Resp3Frame) -> Result<RespValue, ExecError> {
    frame_within_depth(frame, MAX_DEPTH)
}

fn frame_within_depth(frame: Resp3Frame, depth_remaining: usize) -> Result<RespValue, ExecError> {
    // `ResponseTooLarge`, not `Transport`: a deeply nested reply comes from a
    // healthy backend, so Phase 4's breaker must not count it as a failure.
    let depth_remaining = depth_remaining
        .checked_sub(1)
        .ok_or(ExecError::ResponseTooLarge)?;
    match frame {
        Resp3Frame::SimpleString { data, .. } => String::from_utf8(data.to_vec())
            .map(RespValue::Simple)
            .map_err(|_| protocol_violation("non-UTF-8 RESP2 simple string")),
        Resp3Frame::BlobString { data, .. } => Ok(RespValue::Bulk(data)),
        Resp3Frame::Number { data, .. } => Ok(RespValue::Int(data)),
        Resp3Frame::Null => Ok(RespValue::Nil),
        Resp3Frame::Array { data, .. } => data
            .into_iter()
            .map(|frame| frame_within_depth(frame, depth_remaining))
            .collect::<Result<Vec<_>, _>>()
            .map(RespValue::Array),
        Resp3Frame::SimpleError { data, .. } => Err(ExecError::Redis(data.to_string())),
        Resp3Frame::BlobError { data, .. } => Err(ExecError::Redis(
            String::from_utf8_lossy(&data).into_owned(),
        )),
        Resp3Frame::Boolean { .. } => Err(protocol_violation("unexpected RESP3 boolean")),
        Resp3Frame::Double { .. } => Err(protocol_violation("unexpected RESP3 double")),
        Resp3Frame::BigNumber { .. } => Err(protocol_violation("unexpected RESP3 big number")),
        Resp3Frame::VerbatimString { .. } => {
            Err(protocol_violation("unexpected RESP3 verbatim string"))
        }
        Resp3Frame::Map { .. } => Err(protocol_violation("unexpected RESP3 map")),
        Resp3Frame::Set { .. } => Err(protocol_violation("unexpected RESP3 set")),
        Resp3Frame::Push { .. } => Err(protocol_violation("unexpected RESP3 push")),
        Resp3Frame::Hello { .. } => Err(protocol_violation("unexpected RESP3 hello")),
        Resp3Frame::ChunkedString(_) => Err(protocol_violation("unexpected RESP3 chunked string")),
    }
}

fn map_fred_error(error: Error) -> ExecError {
    if is_redis_error(error.details()) {
        ExecError::Redis(error.details().to_owned())
    } else if error.kind() == &ErrorKind::Timeout {
        ExecError::Timeout
    } else {
        ExecError::Transport(error.to_string())
    }
}

fn map_fred_response_error(error: Error) -> ExecError {
    if error.kind() == &ErrorKind::Unknown {
        ExecError::Redis(error.details().to_owned())
    } else {
        map_fred_error(error)
    }
}

fn is_redis_error(details: &str) -> bool {
    details.split_whitespace().next().is_some_and(|prefix| {
        !prefix.is_empty()
            && prefix
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    })
}

fn protocol_violation(message: &str) -> ExecError {
    ExecError::Transport(format!("Redis protocol violation: {message}"))
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;

    #[test]
    fn maps_all_resp2_fred_values() {
        assert_eq!(
            fred_value_to_resp(Value::String("OK".into())),
            Ok(RespValue::Simple("OK".to_owned()))
        );
        assert_eq!(
            fred_value_to_resp(Value::Bytes(Bytes::from_static(b"raw"))),
            Ok(RespValue::Bulk(Bytes::from_static(b"raw")))
        );
        assert_eq!(fred_value_to_resp(Value::Integer(2)), Ok(RespValue::Int(2)));
        assert_eq!(fred_value_to_resp(Value::Null), Ok(RespValue::Nil));
        assert_eq!(
            fred_value_to_resp(Value::Array(vec![Value::Integer(1), Value::Null])),
            Ok(RespValue::Array(vec![RespValue::Int(1), RespValue::Nil]))
        );
    }

    #[test]
    fn raw_frames_preserve_simple_and_bulk_string_kinds() {
        assert_eq!(
            fred_frame_to_resp(Resp3Frame::SimpleString {
                data: Bytes::from_static(b"OK"),
                attributes: None,
            }),
            Ok(RespValue::Simple("OK".to_owned()))
        );
        assert_eq!(
            fred_frame_to_resp(Resp3Frame::BlobString {
                data: Bytes::from_static(b"OK"),
                attributes: None,
            }),
            Ok(RespValue::Bulk(Bytes::from_static(b"OK")))
        );
    }

    #[test]
    fn rejects_resp3_only_fred_values() {
        for value in [Value::Boolean(true), Value::Double(1.5), Value::Queued] {
            assert!(matches!(
                fred_value_to_resp(value),
                Err(ExecError::Transport(message)) if message.contains("protocol violation")
            ));
        }
    }

    #[test]
    fn preserves_raw_redis_errors_and_classifies_client_errors() {
        let redis = Error::new(
            ErrorKind::InvalidArgument,
            "WRONGTYPE Operation against a key",
        );
        assert_eq!(
            map_fred_error(redis),
            ExecError::Redis("WRONGTYPE Operation against a key".to_owned())
        );
        assert_eq!(
            map_fred_error(Error::new(ErrorKind::Timeout, "command timed out")),
            ExecError::Timeout
        );
        assert!(matches!(
            map_fred_error(Error::new(ErrorKind::IO, "connection reset")),
            ExecError::Transport(_)
        ));
        assert_eq!(
            map_fred_response_error(Error::new(ErrorKind::Unknown, "boom lowercase failure")),
            ExecError::Redis("boom lowercase failure".to_owned())
        );
        assert!(matches!(
            map_fred_response_error(Error::new(ErrorKind::IO, "connection reset")),
            ExecError::Transport(_)
        ));
    }
}
