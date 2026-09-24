//! `/oauth/userinfo`

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};

use crate::{
    AppState,
    oauth::services::client::has_scheme,
    oidc::services::userinfo::{self, UserInfoError},
};

/// `GET|POST /oauth/userinfo` with `Authorization: Bearer <access token>`.
pub async fn userinfo(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .filter(|value| has_scheme(value, "Bearer"))
        .and_then(|value| value.split_once(' '))
        .map(|(_, token)| token.trim());

    // RFC 6750 §3.1: with no credentials at all, answer 401 without an
    // error code. Otherwise say what was wrong.
    let Some(token) = token else {
        return bearer_error(StatusCode::UNAUTHORIZED, "Bearer realm=\"sharp-oauth\"");
    };

    match userinfo::userinfo(&state, token).await {
        Ok(claims) => Json(claims).into_response(),
        Err(UserInfoError::InvalidToken) => bearer_error(
            StatusCode::UNAUTHORIZED,
            "Bearer realm=\"sharp-oauth\", error=\"invalid_token\"",
        ),
        Err(UserInfoError::InsufficientScope) => bearer_error(
            StatusCode::FORBIDDEN,
            "Bearer realm=\"sharp-oauth\", error=\"insufficient_scope\", scope=\"openid\"",
        ),
        Err(UserInfoError::Internal(err)) => err.into_response(),
    }
}

fn bearer_error(status: StatusCode, challenge: &'static str) -> Response {
    (
        status,
        [(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static(challenge),
        )],
    )
        .into_response()
}
