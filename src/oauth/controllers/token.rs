//! Endpoints called by client applications: `/oauth/token` and `/oauth/revoke`.

use axum::{
    Form, Json,
    extract::{State, rejection::FormRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};

use crate::{
    AppState,
    oauth::services::{revocation, token},
    shared::error::AppError,
};

type Pairs = Vec<(String, String)>;

/// `POST /oauth/token`
pub async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    form: Result<Form<Pairs>, FormRejection>,
) -> Response {
    let mut response = match form {
        Ok(Form(pairs)) => match token::handle(&state, authorization_header(&headers), pairs).await
        {
            Ok(tokens) => Json(tokens).into_response(),
            Err(err) => err.into_response(),
        },
        Err(_) => AppError::InvalidRequest("the body must be application/x-www-form-urlencoded")
            .into_response(),
    };
    // `Cache-Control: no-store` comes from the middleware; `Pragma` is for
    // old HTTP/1.0 caches (RFC 6749 §5.1).
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

/// `POST /oauth/revoke`
pub async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    form: Result<Form<Pairs>, FormRejection>,
) -> Response {
    let Ok(Form(pairs)) = form else {
        return AppError::InvalidRequest("the body must be application/x-www-form-urlencoded")
            .into_response();
    };
    match revocation::handle(&state, authorization_header(&headers), pairs).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(err) => err.into_response(),
    }
}

fn authorization_header(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
}
