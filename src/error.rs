//! Application errors and their HTTP representation.
//!
//! [`AppError`] is the error type for the machine-to-machine endpoints
//! (`/oauth/token`, `/oauth/revoke`). Its variants map directly onto the
//! error codes defined in [RFC 6749 section 5.2], and [`IntoResponse`]
//! renders them as the JSON body that OAuth client libraries expect:
//!
//! ```json
//! { "error": "invalid_grant", "error_description": "authorization code has expired" }
//! ```
//!
//! Two rules are enforced by the types here:
//!
//! 1. **Descriptions are `&'static str`.** They can never contain user input,
//!    token values or database details, because those are not `'static`.
//! 2. **Infrastructure errors are opaque.** `Database` and `Internal` are
//!    logged server-side and returned to the client only as `server_error`.
//!
//! Browser-facing endpoints (sign-in pages, `/oauth/authorize`) have their own
//! error handling in [`crate::http`] because they render HTML or redirect.
//!
//! [RFC 6749 section 5.2]: https://www.rfc-editor.org/rfc/rfc6749#section-5.2

use axum::{
    Json,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    /// The request is missing a parameter, repeats one, or is malformed.
    #[error("invalid_request: {0}")]
    InvalidRequest(&'static str),

    /// Client authentication failed: unknown client, wrong secret, or no
    /// authentication where it is required.
    #[error("invalid_client")]
    InvalidClient,

    /// The authorization code or refresh token is invalid, expired, revoked,
    /// already used, or was issued to another client.
    #[error("invalid_grant: {0}")]
    InvalidGrant(&'static str),

    /// The client is authenticated but not allowed to do this.
    #[error("unauthorized_client: {0}")]
    UnauthorizedClient(&'static str),

    /// `grant_type` is not one we support.
    #[error("unsupported_grant_type")]
    UnsupportedGrantType,

    /// The requested scope is unknown or exceeds what was granted.
    #[error("invalid_scope: {0}")]
    InvalidScope(&'static str),

    #[error("database error: {0}")]
    Database(#[from] sea_orm::DbErr),

    #[error("internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

impl AppError {
    /// The RFC 6749 `error` code for this variant.
    pub fn code(&self) -> &'static str {
        match self {
            AppError::InvalidRequest(_) => "invalid_request",
            AppError::InvalidClient => "invalid_client",
            AppError::InvalidGrant(_) => "invalid_grant",
            AppError::UnauthorizedClient(_) => "unauthorized_client",
            AppError::UnsupportedGrantType => "unsupported_grant_type",
            AppError::InvalidScope(_) => "invalid_scope",
            AppError::Database(_) | AppError::Internal(_) => "server_error",
        }
    }

    fn description(&self) -> Option<&'static str> {
        match self {
            AppError::InvalidRequest(d)
            | AppError::InvalidGrant(d)
            | AppError::UnauthorizedClient(d)
            | AppError::InvalidScope(d) => Some(d),
            AppError::InvalidClient => Some("client authentication failed"),
            AppError::UnsupportedGrantType => {
                Some("supported grant types are authorization_code and refresh_token")
            }
            AppError::Database(_) | AppError::Internal(_) => None,
        }
    }
}

#[derive(Serialize)]
struct OAuthErrorBody {
    error: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_description: Option<&'static str>,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match &self {
            AppError::InvalidClient => StatusCode::UNAUTHORIZED,
            AppError::Database(_) | AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::BAD_REQUEST,
        };

        if status.is_server_error() {
            // Full detail goes to the server log only.
            tracing::error!(error = %self, "request failed with an internal error");
        }

        let body = OAuthErrorBody {
            error: self.code(),
            error_description: self.description(),
        };
        let mut response = (status, Json(body)).into_response();

        if matches!(self, AppError::InvalidClient) {
            // RFC 6749 section 5.2: a 401 must tell the client which
            // authentication scheme to use.
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Basic realm=\"sharp-oauth\""),
            );
        }
        response
    }
}
