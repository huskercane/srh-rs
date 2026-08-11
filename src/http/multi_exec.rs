use axum::Json;
use axum::extract::{Extension, Request, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};

use crate::AppState;
use crate::domain::convert::charge_response_budget;
use crate::domain::resp::ExecError;
use crate::error::AppError;
use crate::http::command::{
    Slot, charge_rate_limit, map_acquire_error, map_exec_error, response_encoding,
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
    let commands = match super::parse::pipeline(
        &body,
        state.cfg.server.max_pipeline_commands,
        state.cfg.server.max_request_elements,
    ) {
        Ok(commands) => commands,
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
    audit.command(Some("MULTI-EXEC"), commands.len());
    if commands.is_empty() {
        charge_rate_limit(&state, &identity.0.bucket_key, 1)?;
        return Err(AppError::BadRequest("Invalid command".to_owned()));
    }
    charge_rate_limit(&state, &identity.0.bucket_key, commands.len())?;
    for command in &commands {
        crate::domain::acl::check(&identity.0, command)?;
    }
    let commands = commands
        .into_iter()
        .map(crate::domain::compat::normalize)
        .collect::<Vec<_>>();
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
            Ok(value) => {
                // Charged before the slot is built so the shared budget still fails the
                // whole request, as it did when each value was converted eagerly.
                charge_response_budget(&value, encoding, &mut budget)?;
                Ok(Slot::Result { value, encoding })
            }
            Err(ExecError::Redis(message)) => Ok(Slot::Error(message)),
            Err(ExecError::ResponseTooLarge) => Err(AppError::ResponseTooLarge),
            Err(ExecError::Timeout) => Ok(Slot::Error("Redis command timed out".to_owned())),
            Err(ExecError::Transport(message)) => {
                tracing::error!(error = %message, "transaction command transport failure");
                Ok(Slot::Error("Internal server error".to_owned()))
            }
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    Ok(Json(response).into_response())
}
