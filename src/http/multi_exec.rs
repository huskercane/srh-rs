use axum::Json;
use axum::extract::{Extension, Request, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::AppState;
use crate::domain::convert::{json_args_to_redis, redis_value_to_json};
use crate::domain::resp::ExecError;
use crate::error::AppError;
use crate::http::command::{
    charge_rate_limit, map_acquire_error, map_exec_error, response_encoding,
};
use crate::http::extractors::AuthedIdentity;

pub async fn execute(
    identity: AuthedIdentity,
    Extension(audit): Extension<crate::http::observability::AuditContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request,
) -> Result<Response, AppError> {
    audit.identity(&identity.0);
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
    audit.command(Some("MULTI-EXEC"), values.len());
    if values.is_empty() {
        charge_rate_limit(&state, &identity.0.bucket_key, 1)?;
        return Err(AppError::BadRequest("Invalid command".to_owned()));
    }
    charge_rate_limit(&state, &identity.0.bucket_key, values.len())?;
    for command in &values {
        crate::domain::acl::check(&identity.0, command)?;
    }
    let commands = values
        .iter()
        .map(|values| json_args_to_redis(values).map(crate::domain::compat::normalize))
        .collect::<Result<Vec<_>, _>>()?;
    let handle = state
        .provider
        .acquire(&identity.0.pool)
        .await
        .map_err(|error| map_acquire_error(error, &state))?;
    let results = handle
        .transaction_and_release(commands)
        .await
        .map_err(|error| map_exec_error(error, &state))?;
    let mut budget = state.cfg.server.load.max_response_bytes;
    let encoding = response_encoding(&headers);
    let response = results
        .into_iter()
        .map(|result| match result {
            Ok(value) => redis_value_to_json(value, encoding, &mut budget)
                .map(|value| json!({ "result": value }))
                .map_err(AppError::from),
            Err(ExecError::Redis(message)) => Ok(json!({ "error": message })),
            Err(ExecError::ResponseTooLarge) => Err(AppError::ResponseTooLarge),
            Err(ExecError::Timeout) => Ok(json!({ "error": "Redis command timed out" })),
            Err(ExecError::Transport(message)) => {
                tracing::error!(error = %message, "transaction command transport failure");
                Ok(json!({ "error": "Internal server error" }))
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(response).into_response())
}
