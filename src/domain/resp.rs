use std::error::Error;
use std::fmt::{self, Display, Formatter};

use bytes::Bytes;

/// A transport-independent RESP2 value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RespValue {
    Simple(String),
    Bulk(Bytes),
    Int(i64),
    Nil,
    Array(Vec<Self>),
}

/// A command execution failure independent of the Redis client adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecError {
    Transport(String),
    Timeout,
    Redis(String),
    ResponseTooLarge,
}

impl Display for ExecError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(message) | Self::Redis(message) => formatter.write_str(message),
            Self::Timeout => formatter.write_str("Redis command timed out"),
            Self::ResponseTooLarge => formatter.write_str("Redis response is too large"),
        }
    }
}

impl Error for ExecError {}

/// A bounded pool-acquisition failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AcquireError {
    UnknownPool(String),
    Overloaded,
    PoolOpen { retry_after_secs: u64 },
    Internal(String),
}

impl Display for AcquireError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownPool(pool) => write!(formatter, "unknown Redis pool '{pool}'"),
            Self::Overloaded => formatter.write_str("Redis pool is overloaded"),
            Self::PoolOpen { .. } => formatter.write_str("Redis backend is unavailable"),
            Self::Internal(message) => formatter.write_str(message),
        }
    }
}

impl Error for AcquireError {}

/// Readiness of an already-built Redis pool.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoolReadiness {
    pub pool: String,
    pub status: PoolReadinessStatus,
}

/// Result of a readiness PING for a built pool.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PoolReadinessStatus {
    Ready,
    Unavailable(String),
}
