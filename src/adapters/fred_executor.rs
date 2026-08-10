use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use fred::clients::Client;
use fred::error::{Error, ErrorKind};
use fred::interfaces::ClientLike;
use fred::types::config::{Config, ConnectionConfig, PerformanceConfig, ReconnectPolicy};
use fred::types::{ClusterHash, ConnectHandle, CustomCommand, Resp3Frame, RespVersion};
use futures_util::future::join_all;

use crate::domain::convert::MAX_DEPTH;
use crate::domain::resp::{ExecError, RespValue};
use crate::ports::{CommandExecutor, RedisCommand};

pub struct FredExecutor {
    client: Client,
    connection_task: Option<ConnectHandle>,
    reset_timeout: Duration,
    reset_started: AtomicBool,
    operation_lock: std::sync::Arc<tokio::sync::Mutex<()>>,
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
            connection_task: Some(connection_task),
            reset_timeout: command_timeout,
            reset_started: AtomicBool::new(false),
            operation_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    /// Wraps a client whose connection task is owned by a long-lived pool.
    pub fn from_pooled_client(
        client: Client,
        reset_timeout: Duration,
        operation_lock: std::sync::Arc<tokio::sync::Mutex<()>>,
    ) -> Self {
        Self {
            client,
            connection_task: None,
            reset_timeout,
            reset_started: AtomicBool::new(false),
            operation_lock,
        }
    }

    fn command(command: RedisCommand) -> (CustomCommand, Vec<bytes::Bytes>) {
        (
            CustomCommand::new(command.name, ClusterHash::FirstKey, false),
            command.args,
        )
    }

    async fn map_error(&self, error: Error) -> ExecError {
        let mapped = map_fred_error(error);
        // A timeout on a connected client can leave an unread response. A
        // disconnected client is already in Fred's reconnect loop; sending a
        // second reconnect command there can delay recovery.
        if mapped == ExecError::Timeout
            && self.client.is_connected()
            && !self.reset_started.swap(true, Ordering::AcqRel)
        {
            match tokio::time::timeout(self.reset_timeout, self.client.force_reconnection()).await {
                Ok(Ok(())) => {}
                Ok(Err(reconnect_error)) => {
                    tracing::warn!(%reconnect_error, "failed to reset Redis connection after timeout");
                }
                Err(_) => {
                    tracing::warn!("timed out resetting Redis connection after command timeout");
                }
            }
        }
        mapped
    }

    async fn raw(
        &self,
        command: CustomCommand,
        args: Vec<bytes::Bytes>,
    ) -> Result<Resp3Frame, ExecError> {
        match self.client.custom_raw(command, args).await {
            Ok(frame) => Ok(frame),
            Err(error) => Err(self.map_error(error).await),
        }
    }

    async fn execute_unlocked(&self, command: RedisCommand) -> Result<RespValue, ExecError> {
        let (command, args) = Self::command(command);
        fred_frame_to_resp(self.raw(command, args).await?)
    }
}

impl Drop for FredExecutor {
    fn drop(&mut self) {
        if let Some(connection_task) = &self.connection_task {
            connection_task.abort();
        }
    }
}

#[async_trait]
impl CommandExecutor for FredExecutor {
    async fn execute(&self, command: RedisCommand) -> Result<RespValue, ExecError> {
        let _guard = self.operation_lock.lock().await;
        self.execute_unlocked(command).await
    }

    async fn pipeline(&self, commands: Vec<RedisCommand>) -> Vec<Result<RespValue, ExecError>> {
        let _guard = self.operation_lock.lock().await;
        // Poll in request order on one task. Fred enqueues each command on its
        // first poll; spawning per command can reorder dependent commands.
        join_all(
            commands
                .into_iter()
                .map(|command| self.execute_unlocked(command)),
        )
        .await
    }

    async fn transaction(
        &self,
        commands: Vec<RedisCommand>,
    ) -> Result<Vec<Result<RespValue, ExecError>>, ExecError> {
        if commands.is_empty() {
            return Ok(Vec::new());
        }
        let _guard = self.operation_lock.lock().await;
        let slot = commands
            .iter()
            .find_map(|command| command.args.first())
            .map(|key| fred::util::redis_keyslot(key));
        let hash = slot.map_or(ClusterHash::FirstKey, ClusterHash::Custom);
        let control = |name| CustomCommand::new(name, hash.clone(), false);

        match fred_frame_to_resp(self.raw(control("MULTI"), Vec::new()).await?)? {
            RespValue::Simple(response) if response == "OK" => {}
            response => return Err(protocol_violation(&format!("MULTI returned {response:?}"))),
        }
        for command in commands {
            let command_name = command.name;
            let args = command.args;
            let command = CustomCommand::new(command_name, hash.clone(), false);
            match self.raw(command, args).await.and_then(fred_frame_to_resp) {
                Ok(RespValue::Simple(response)) if response == "QUEUED" => {}
                Ok(response) => {
                    let _ = self.raw(control("DISCARD"), Vec::new()).await;
                    return Err(protocol_violation(&format!(
                        "transaction command returned {response:?} instead of QUEUED"
                    )));
                }
                Err(error) => {
                    let _ = self.raw(control("DISCARD"), Vec::new()).await;
                    return Err(error);
                }
            }
        }
        match self.raw(control("EXEC"), Vec::new()).await? {
            Resp3Frame::Array { data, .. } => Ok(data
                .into_iter()
                .map(|frame| frame_within_depth(frame, MAX_DEPTH))
                .collect()),
            Resp3Frame::Null => Err(ExecError::Redis(
                "EXECABORT Transaction discarded because of previous errors.".to_owned(),
            )),
            frame => match fred_frame_to_resp(frame) {
                Err(error) => Err(error),
                Ok(_) => Err(protocol_violation("EXEC returned a non-array response")),
            },
        }
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
    }
}
