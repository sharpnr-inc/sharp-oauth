//! `/.well-known/` endpoints: the discovery document and the JWKS.

use axum::{
    Json,
    extract::State,
    http::{HeaderValue, header},
    response::{IntoResponse, Response},
};

use crate::{AppState, oidc::services::discovery};

/// `GET /.well-known/openid-configuration`
pub async fn discovery(State(state): State<AppState>) -> Response {
    match discovery::document(&state).await {
        Ok(document) => cacheable(Json(document).into_response(), "public, max-age=3600"),
        Err(err) => err.into_response(),
    }
}

/// `GET /.well-known/jwks.json`
///
/// Cached briefly: verifiers should not fetch it for every token, but must
/// see a newly added key soon after rotation.
pub async fn jwks(State(state): State<AppState>) -> Response {
    cacheable(
        Json(state.signing_keys.jwks()).into_response(),
        "public, max-age=300",
    )
}

fn cacheable(mut response: Response, cache_control: &'static str) -> Response {
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(cache_control),
    );
    response
}
