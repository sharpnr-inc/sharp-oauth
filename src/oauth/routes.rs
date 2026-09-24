//! Routes for the OAuth feature.
//!
//! | Method   | Path               | Who calls it | Handler                      |
//! |----------|--------------------|--------------|------------------------------|
//! | GET/POST | `/oauth/authorize` | browser      | [`authorize::authorize_get`] |
//! | POST     | `/oauth/consent`   | browser      | [`authorize::consent`]       |
//! | POST     | `/oauth/token`     | client app   | [`token::token`]             |
//! | POST     | `/oauth/revoke`    | client app   | [`token::revoke`]            |

use axum::{
    Router,
    routing::{get, post},
};

use crate::{
    AppState,
    oauth::controllers::{authorize, token},
};

/// Endpoints a browser reaches by navigation or form submit.
pub fn web_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/oauth/authorize",
            get(authorize::authorize_get).post(authorize::authorize_post),
        )
        .route("/oauth/consent", post(authorize::consent))
}

/// Endpoints called by client applications (CORS is added by the router).
pub fn api_routes() -> Router<AppState> {
    Router::new()
        .route("/oauth/token", post(token::token))
        .route("/oauth/revoke", post(token::revoke))
}
