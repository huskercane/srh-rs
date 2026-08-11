use std::time::Duration;

use axum::Json;
use axum::body::to_bytes;
use axum::extract::{Extension, Request, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};

use crate::AppState;
use crate::domain::convert::{Encoding, ResponseJson, charge_response_budget};
use crate::domain::resp::{AcquireError, ExecError};
use crate::error::AppError;
use crate::http::extractors::AuthedIdentity;

pub async fn execute(
    identity: AuthedIdentity,
    Extension(audit): Extension<crate::http::observability::AuditContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request,
) -> Result<Response, AppError> {
    audit.identity(&identity.0);
    let body = read_body(&state, request).await?;
    let command = match super::parse::command(&body, state.cfg.server.max_request_elements) {
        Ok(command) => command,
        Err(error) => {
            // An invalid request still consumed a bounded parse. Charging the minimum cost makes
            // repeated garbage reach the pre-parse shed instead of buying unlimited parsing.
            charge_rate_limit(&state, &identity.0.bucket_key, 1)?;
            return Err(match error {
                super::parse::ParseError::RequestTooComplex => {
                    AppError::BadRequest("Request too complex".to_owned())
                }
                super::parse::ParseError::Invalid | super::parse::ParseError::PipelineTooLarge => {
                    AppError::BadRequest("Invalid command".to_owned())
                }
            });
        }
    };
    audit.command(Some(command.name.as_str()), 1);
    charge_rate_limit(&state, &identity.0.bucket_key, 1)?;
    crate::domain::acl::check(&identity.0, &command)?;
    let command = crate::domain::compat::normalize(command);
    let handle = state
        .provider
        .acquire(&identity.0.pool)
        .await
        .map_err(|error| map_acquire_error(error, &state))?;
    let value = handle
        .execute_and_release(command)
        .await
        .map_err(|error| map_exec_error(error, &state))?;
    let mut budget = state.cfg.server.load.max_response_bytes;
    let encoding = response_encoding(&headers);
    // The budget is charged in full before anything is written, so an oversized reply
    // fails the request rather than truncating a response already committed to.
    charge_response_budget(&value, encoding, &mut budget)?;
    Ok(Json(Envelope {
        result: ResponseJson::new(&value, encoding),
    })
    .into_response())
}

/// The `{"result": ...}` wrapper for a single command.
#[derive(serde::Serialize)]
struct Envelope<T> {
    result: T,
}

/// One `{"result": ...}` or `{"error": ...}` entry of a pipeline or transaction response.
///
/// Holding the RESP value and rendering it at serialization time is what keeps the
/// response off the `serde_json::Value` path; the slot is built only once the value has
/// been charged against the shared response budget.
pub(super) enum Slot {
    Result {
        value: crate::domain::resp::RespValue,
        encoding: Encoding,
    },
    Error(String),
}

impl serde::Serialize for Slot {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        let mut entry = serializer.serialize_map(Some(1))?;
        match self {
            Self::Result { value, encoding } => {
                entry.serialize_entry("result", &ResponseJson::new(value, *encoding))?;
            }
            Self::Error(message) => entry.serialize_entry("error", message)?,
        }
        entry.end()
    }
}

pub(super) fn charge_rate_limit(
    state: &AppState,
    bucket_key: &str,
    command_count: usize,
) -> Result<(), AppError> {
    let result = state
        .rate_limiter
        .charge(bucket_key, command_count)
        .map_err(|error| {
            metrics::counter!("srh_rate_limit_rejections_total").increment(1);
            AppError::RateLimited {
                retry_after_secs: error.retry_after_secs,
            }
        });
    record_debt_forgiveness(state);
    result
}

pub(super) fn record_debt_forgiveness(state: &AppState) {
    let count = state.rate_limiter.take_debt_forgiven_evictions();
    if count > 0 {
        metrics::counter!("srh_shed_total", "cause" => "debt_forgiven_by_eviction")
            .increment(count);
    }
}

pub(super) async fn read_body(
    state: &AppState,
    request: Request,
) -> Result<bytes::Bytes, AppError> {
    tokio::time::timeout(
        Duration::from_millis(state.cfg.server.load.body_read_timeout_ms),
        to_bytes(request.into_body(), state.cfg.server.max_body_bytes),
    )
    .await
    .map_err(|_| AppError::RequestBodyTimeout)?
    .map_err(|_| AppError::BadRequest("Invalid command".to_owned()))
}

pub(super) fn response_encoding(headers: &HeaderMap) -> Encoding {
    headers
        .get("upstash-encoding")
        .and_then(|value| value.to_str().ok())
        .filter(|value| value.eq_ignore_ascii_case("base64"))
        .map_or(Encoding::None, |_| Encoding::Base64)
}

pub(super) fn map_exec_error(error: ExecError, state: &AppState) -> AppError {
    match error {
        ExecError::Redis(message) => AppError::RedisError(message),
        ExecError::ResponseTooLarge => AppError::ResponseTooLarge,
        ExecError::Timeout => AppError::PoolOpen {
            retry_after_secs: state.cfg.server.load.shed_retry_after_secs,
            reason: "Redis command timed out".to_owned(),
        },
        ExecError::Transport(reason) => AppError::PoolOpen {
            retry_after_secs: state.cfg.server.load.shed_retry_after_secs,
            reason,
        },
    }
}

pub(super) fn map_acquire_error(error: AcquireError, state: &AppState) -> AppError {
    match error {
        AcquireError::UnknownPool(pool) => {
            AppError::Internal(format!("identity referenced unknown Redis pool '{pool}'"))
        }
        AcquireError::Overloaded => AppError::Overloaded {
            retry_after_secs: state.cfg.server.load.shed_retry_after_secs,
        },
        AcquireError::PoolOpen { retry_after_secs } => AppError::PoolOpen {
            retry_after_secs,
            reason: "circuit breaker cooldown active".to_owned(),
        },
        AcquireError::Internal(message) => AppError::Internal(message),
    }
}
