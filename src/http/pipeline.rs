use axum::Json;
use axum::extract::{Extension, Request, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};

use crate::AppState;
use crate::domain::convert::charge_response_budget;
use crate::domain::resp::ExecError;
use crate::error::AppError;
use crate::http::command::{Slot, charge_rate_limit, map_acquire_error, response_encoding};
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
    let command_count = commands.len();
    audit.command(Some("PIPELINE"), command_count);
    charge_rate_limit(&state, &identity.0.bucket_key, command_count)?;
    let mut allowed_commands = Vec::new();
    let mut slots = Vec::with_capacity(command_count);
    for command in commands {
        match crate::domain::acl::check(&identity.0, &command) {
            Ok(()) => {
                allowed_commands.push(crate::domain::compat::normalize(command));
                slots.push(None);
            }
            Err(crate::domain::acl::AclError::Forbidden(message)) => {
                slots.push(Some(Slot::Error(message)));
            }
            Err(error) => return Err(error.into()),
        }
    }
    if command_count == 0 {
        return Ok(Json(Vec::<Slot>::new()).into_response());
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
                // Charged before the slot is built so the shared budget still fails the
                // whole request, as it did when each value was converted eagerly.
                charge_response_budget(&value, encoding, &mut budget)?;
                Slot::Result { value, encoding }
            }
            Err(ExecError::Redis(message)) => Slot::Error(message),
            Err(ExecError::ResponseTooLarge) => return Err(AppError::ResponseTooLarge),
            Err(ExecError::Timeout) => Slot::Error("Redis command timed out".to_owned()),
            Err(ExecError::Transport(message)) => {
                tracing::error!(error = %message, "pipeline command transport failure");
                Slot::Error("Internal server error".to_owned())
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
