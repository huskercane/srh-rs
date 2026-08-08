use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::domain::convert::ConversionError;

#[derive(Debug)]
pub enum AppError {
    Unauthorized,
    Forbidden(String),
    BadRequest(String),
    RedisError(String),
    RateLimited {
        retry_after_secs: u64,
    },
    AuthServiceUnavailable,
    Overloaded {
        retry_after_secs: u64,
    },
    PoolOpen {
        retry_after_secs: u64,
        reason: String,
    },
    ResponseTooLarge,
    RequestBodyTimeout,
    Internal(String),
}

impl From<ConversionError> for AppError {
    fn from(error: ConversionError) -> Self {
        match error {
            ConversionError::InvalidCommand => Self::BadRequest("Invalid command".to_owned()),
            ConversionError::ResponseTooLarge => Self::ResponseTooLarge,
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message, retry_after) = match self {
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized".to_owned(), None),
            Self::Forbidden(message) => (StatusCode::FORBIDDEN, message, None),
            Self::BadRequest(message) | Self::RedisError(message) => {
                (StatusCode::BAD_REQUEST, message, None)
            }
            Self::RateLimited { retry_after_secs } => (
                StatusCode::TOO_MANY_REQUESTS,
                "Rate limit exceeded".to_owned(),
                Some(retry_after_secs),
            ),
            Self::AuthServiceUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "Authentication service unavailable".to_owned(),
                None,
            ),
            Self::Overloaded { retry_after_secs } => (
                StatusCode::SERVICE_UNAVAILABLE,
                "Server overloaded".to_owned(),
                Some(retry_after_secs),
            ),
            Self::PoolOpen {
                retry_after_secs,
                reason,
            } => {
                tracing::warn!(%reason, retry_after_secs, "Redis circuit breaker is open");
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Backend unavailable".to_owned(),
                    Some(retry_after_secs),
                )
            }
            Self::ResponseTooLarge => (
                StatusCode::BAD_GATEWAY,
                "Response too large".to_owned(),
                None,
            ),
            Self::RequestBodyTimeout => (
                StatusCode::REQUEST_TIMEOUT,
                "Request body timeout".to_owned(),
                None,
            ),
            Self::Internal(error) => {
                tracing::error!(error = %error, "internal request failure");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_owned(),
                    None,
                )
            }
        };
        let mut response = (status, Json(json!({ "error": message }))).into_response();
        if let Some(seconds) = retry_after
            && let Ok(value) = HeaderValue::from_str(&seconds.to_string())
        {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limit_response_has_retry_after() {
        let response = AppError::RateLimited {
            retry_after_secs: 17,
        }
        .into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[header::RETRY_AFTER], "17");
    }

    #[test]
    fn overload_response_uses_its_configured_retry_delay() {
        let response = AppError::Overloaded {
            retry_after_secs: 23,
        }
        .into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[header::RETRY_AFTER], "23");
    }

    #[test]
    fn open_pool_response_uses_the_breaker_retry_delay() {
        let response = AppError::PoolOpen {
            retry_after_secs: 7,
            reason: "cooldown active".to_owned(),
        }
        .into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[header::RETRY_AFTER], "7");
    }
}
