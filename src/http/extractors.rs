use axum::extract::FromRequestParts;
use axum::http::{header, request::Parts};

use crate::AppState;
use crate::domain::identity::{AuthError, Identity};
use crate::error::AppError;

pub struct AuthedIdentity(pub Identity);

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
            .ok_or(AppError::Unauthorized)?;
        let (scheme, bearer) = authorization
            .split_once(' ')
            .ok_or(AppError::Unauthorized)?;
        if !scheme.eq_ignore_ascii_case("Bearer") || bearer.is_empty() {
            return Err(AppError::Unauthorized);
        }
        let identity = state
            .authenticator
            .authenticate(bearer)
            .await
            .map_err(|error| match error {
                AuthError::Rejected => AppError::Unauthorized,
                AuthError::ServiceUnavailable(reason) => {
                    tracing::error!(%reason, "authentication service unavailable");
                    AppError::AuthServiceUnavailable
                }
            })?
            .ok_or(AppError::Unauthorized)?;
        Ok(Self(identity))
    }
}
