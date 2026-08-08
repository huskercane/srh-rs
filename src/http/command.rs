use std::time::Duration;

use axum::Json;
use axum::body::to_bytes;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::AppState;
use crate::error::AppError;
use crate::http::extractors::AuthedIdentity;

pub async fn not_implemented(
    identity: AuthedIdentity,
    State(state): State<AppState>,
    request: Request,
) -> Result<Response, AppError> {
    // TODO(phase2): replace this authenticated stub with command parsing and execution.
    // TODO(phase4): acquire the pool only after the complete body has been parsed.
    // TODO(phase5): apply command ACLs before acquiring a pool.
    let _identity = identity.0;
    let body = tokio::time::timeout(
        Duration::from_millis(state.cfg.server.load.body_read_timeout_ms),
        to_bytes(request.into_body(), state.cfg.server.max_body_bytes),
    )
    .await
    .map_err(|_| AppError::RequestBodyTimeout)?
    .map_err(|error| AppError::BadRequest(error.to_string()))?;
    serde_json::from_slice::<serde_json::Value>(&body)
        .map_err(|_| AppError::BadRequest("Invalid command".to_owned()))?;
    Ok((
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({ "error": "Not implemented" })),
    )
        .into_response())
}
