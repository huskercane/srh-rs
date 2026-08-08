use axum::Json;
use axum::extract::{Request, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::AppState;
use crate::domain::convert::{json_args_to_redis, redis_value_to_json};
use crate::error::AppError;
use crate::http::command::{map_acquire_error, map_exec_error, response_encoding};
use crate::http::extractors::AuthedIdentity;

pub async fn execute(
    identity: AuthedIdentity,
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request,
) -> Result<Response, AppError> {
    let body = super::command::read_body(&state, request).await?;
    let values = super::parse::pipeline(
        &body,
        state.cfg.server.max_pipeline_commands,
        state.cfg.server.max_request_elements,
    )
    .map_err(|error| match error {
        super::parse::ParseError::Invalid => AppError::BadRequest("Invalid command".to_owned()),
        super::parse::ParseError::PipelineTooLarge => {
            AppError::BadRequest("Pipeline too large".to_owned())
        }
        super::parse::ParseError::RequestTooComplex => {
            AppError::BadRequest("Request too complex".to_owned())
        }
    })?;
    if values.is_empty() {
        return Err(AppError::BadRequest("Invalid command".to_owned()));
    }
    let commands = values
        .iter()
        .map(|values| json_args_to_redis(values))
        .collect::<Result<Vec<_>, _>>()?;

    // TODO(phase5): validate every command's ACL before acquiring a pool.
    let handle = state
        .provider
        .acquire(&identity.0.pool)
        .await
        .map_err(|error| map_acquire_error(error, &state))?;
    let results = handle
        .executor()
        .transaction(commands)
        .await
        .map_err(map_exec_error)?;
    // Redis work is complete; do not hold a scarce pool permit through
    // potentially large response conversion.
    drop(handle);
    let mut budget = state.cfg.server.load.max_response_bytes;
    let encoding = response_encoding(&headers);
    let response = results
        .into_iter()
        .map(|value| {
            redis_value_to_json(value, encoding, &mut budget)
                .map(|value| json!({ "result": value }))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(response).into_response())
}
