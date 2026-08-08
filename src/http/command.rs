use std::time::Duration;

use axum::Json;
use axum::body::to_bytes;
use axum::extract::{Request, State};
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
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request,
) -> Result<Response, AppError> {
    let body = read_body(&state, request).await?;
    let values: Vec<serde_json::Value> = serde_json::from_slice(&body)
        .map_err(|_| AppError::BadRequest("Invalid command".to_owned()))?;
    let command = json_args_to_redis(&values)?;

    // TODO(phase5): apply command ACLs before acquiring a pool.
    let handle = state
        .provider
        .acquire(&identity.0.pool)
        .await
        .map_err(|error| map_acquire_error(error, &state))?;
    let value = handle
        .executor()
        .execute(command)
        .await
        .map_err(map_exec_error)?;
    let mut budget = state.cfg.server.load.max_response_bytes;
    let value = redis_value_to_json(value, response_encoding(&headers), &mut budget)?;
    Ok(Json(json!({ "result": value })).into_response())
}

pub async fn not_implemented(
    identity: AuthedIdentity,
    State(state): State<AppState>,
    request: Request,
) -> Result<Response, AppError> {
    // TODO(phase3): replace this authenticated stub with pipeline/transaction execution.
    let _identity = identity.0;
    read_body(&state, request).await?;
    Ok((
        axum::http::StatusCode::NOT_IMPLEMENTED,
        Json(json!({ "error": "Not implemented" })),
    )
        .into_response())
}

async fn read_body(state: &AppState, request: Request) -> Result<bytes::Bytes, AppError> {
    tokio::time::timeout(
        Duration::from_millis(state.cfg.server.load.body_read_timeout_ms),
        to_bytes(request.into_body(), state.cfg.server.max_body_bytes),
    )
    .await
    .map_err(|_| AppError::RequestBodyTimeout)?
    .map_err(|_| AppError::BadRequest("Invalid command".to_owned()))
}

fn response_encoding(headers: &HeaderMap) -> Encoding {
    headers
        .get("upstash-encoding")
        .and_then(|value| value.to_str().ok())
        .filter(|value| value.eq_ignore_ascii_case("base64"))
        .map_or(Encoding::None, |_| Encoding::Base64)
}

fn map_exec_error(error: ExecError) -> AppError {
    match error {
        ExecError::Redis(message) => AppError::RedisError(message),
        ExecError::ResponseTooLarge => AppError::ResponseTooLarge,
        ExecError::Timeout => AppError::Internal("Redis command timed out".to_owned()),
        ExecError::Transport(message) => AppError::Internal(message),
    }
}

fn map_acquire_error(error: AcquireError, state: &AppState) -> AppError {
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
