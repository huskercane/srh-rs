use std::time::Duration;

use axum::Json;
use axum::body::to_bytes;
use axum::extract::{Extension, Request, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::AppState;
use crate::domain::convert::{Encoding, json_args_to_redis, redis_value_to_json};
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
    let values = match super::parse::command(&body, state.cfg.server.max_request_elements) {
        Ok(values) => values,
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
    audit.command(values.first().and_then(serde_json::Value::as_str), 1);
    charge_rate_limit(&state, &identity.0.bucket_key, 1)?;
    crate::domain::acl::check(&identity.0, &values)?;
    let command = crate::domain::compat::normalize(json_args_to_redis(&values)?);
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
    let value = redis_value_to_json(value, response_encoding(&headers), &mut budget)?;
    Ok(Json(json!({ "result": value })).into_response())
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
