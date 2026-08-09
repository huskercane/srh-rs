use axum::Json;
use axum::extract::{Request, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use crate::AppState;
use crate::domain::convert::{json_args_to_redis, redis_value_to_json};
use crate::domain::resp::ExecError;
use crate::error::AppError;
use crate::http::command::{charge_rate_limit, map_acquire_error, response_encoding};
use crate::http::extractors::AuthedIdentity;

pub async fn execute(
    identity: AuthedIdentity,
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request,
) -> Result<Response, AppError> {
    let body = super::command::read_body(&state, request).await?;
    let values = match super::parse::pipeline(
        &body,
        state.cfg.server.max_pipeline_commands,
        state.cfg.server.max_request_elements,
    ) {
        Ok(values) => values,
        Err(error) => {
            charge_rate_limit(&state, &identity.0.bucket_key, 1)?;
            return Err(match error {
                super::parse::ParseError::Invalid => {
                    AppError::BadRequest("Invalid command".to_owned())
                }
                super::parse::ParseError::PipelineTooLarge => {
                    AppError::BadRequest("Pipeline too large".to_owned())
                }
                super::parse::ParseError::RequestTooComplex => {
                    AppError::BadRequest("Request too complex".to_owned())
                }
            });
        }
    };
    charge_rate_limit(&state, &identity.0.bucket_key, values.len())?;
    let mut allowed_commands = Vec::new();
    let mut slots = Vec::with_capacity(values.len());
    for command in &values {
        match crate::domain::acl::check(&identity.0, command) {
            Ok(()) => {
                allowed_commands.push(json_args_to_redis(command)?);
                slots.push(None);
            }
            Err(crate::domain::acl::AclError::Forbidden(message)) => {
                slots.push(Some(json!({ "error": message })));
            }
            Err(error) => return Err(error.into()),
        }
    }
    if values.is_empty() {
        return Ok(Json(Vec::<Value>::new()).into_response());
    }
    let results = if allowed_commands.is_empty() {
        Vec::new()
    } else {
        let handle = state
            .provider
            .acquire(&identity.0.pool)
            .await
            .map_err(|error| map_acquire_error(error, &state))?;
        handle.pipeline_and_release(allowed_commands).await
    };
    let mut budget = state.cfg.server.load.max_response_bytes;
    let encoding = response_encoding(&headers);
    let mut results = results.into_iter();
    let mut response = Vec::with_capacity(slots.len());
    for denied in slots {
        if let Some(denied) = denied {
            response.push(denied);
            continue;
        }
        let result = results.next().ok_or_else(|| {
            AppError::Internal("pipeline executor returned too few results".to_owned())
        })?;
        let slot = match result {
            Ok(value) => {
                let value = redis_value_to_json(value, encoding, &mut budget)?;
                json!({ "result": value })
            }
            Err(ExecError::Redis(message)) => json!({ "error": message }),
            Err(ExecError::ResponseTooLarge) => return Err(AppError::ResponseTooLarge),
            Err(ExecError::Timeout) => json!({ "error": "Redis command timed out" }),
            Err(ExecError::Transport(message)) => {
                tracing::error!(error = %message, "pipeline command transport failure");
                json!({ "error": "Internal server error" })
            }
        };
        response.push(slot);
    }
    if results.next().is_some() {
        return Err(AppError::Internal(
            "pipeline executor returned too many results".to_owned(),
        ));
    }
    Ok(Json(response).into_response())
}
