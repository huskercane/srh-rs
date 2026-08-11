use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::{header, request::Parts};

use crate::AppState;
use crate::domain::identity::{AuthError, Identity};
use crate::error::AppError;

pub struct AuthedIdentity(pub Arc<Identity>);

impl FromRequestParts<AppState> for AuthedIdentity {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let authorization = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| unauthorized("missing_or_malformed"))?;
        let (scheme, bearer) = authorization
            .split_once(' ')
            .ok_or_else(|| unauthorized("missing_or_malformed"))?;
        if !scheme.eq_ignore_ascii_case("Bearer") || bearer.is_empty() {
            return Err(unauthorized("missing_or_malformed"));
        }
        let identity = state
            .authenticator
            .authenticate(bearer)
            .await
            .map_err(|error| match error {
                AuthError::Rejected => {
                    metrics::counter!("srh_auth_failures_total", "kind" => "rejected").increment(1);
                    AppError::Unauthorized
                }
                AuthError::Forbidden(reason) => {
                    metrics::counter!("srh_auth_failures_total", "kind" => "forbidden")
                        .increment(1);
                    AppError::Forbidden(reason)
                }
                AuthError::ServiceUnavailable(reason) => {
                    metrics::counter!("srh_auth_failures_total", "kind" => "unavailable")
                        .increment(1);
                    tracing::error!(%reason, "authentication service unavailable");
                    AppError::AuthServiceUnavailable
                }
            })?
            .ok_or_else(|| unauthorized("rejected"))?;
        let probe = state
            .rate_limiter
            .probe(&identity.bucket_key)
            .map_err(|error| {
                metrics::counter!("srh_rate_limit_rejections_total").increment(1);
                AppError::RateLimited {
                    retry_after_secs: error.retry_after_secs,
                }
            });
        super::command::record_debt_forgiveness(state);
        probe?;
        Ok(Self(identity))
    }
}

fn unauthorized(kind: &'static str) -> AppError {
    metrics::counter!("srh_auth_failures_total", "kind" => kind).increment(1);
    AppError::Unauthorized
}
