//! The URL map: mounts every feature's routes and applies middleware.
//!
//! Each feature declares its own routes in its `routes.rs`:
//!
//! * [`crate::authentication::routes`]: `/`, `/signin`, `/signup`, `/logout`
//! * [`crate::oauth::routes`]: `/oauth/authorize`, `/oauth/consent`,
//!   `/oauth/token`, `/oauth/revoke`
//! * [`crate::oidc::routes`]: `/oauth/userinfo`, `/.well-known/*`
//!
//! Routes come in two groups. **Web** routes are pages a person uses in a
//! browser on Sharpnr's own origin. **API** routes are called by client
//! applications and get CORS.

use std::time::Duration;

use axum::{
    Router,
    http::{Method, header},
    middleware::from_fn,
    routing::get,
};
use tower_http::cors::{Any, CorsLayer};

use crate::{
    AppState,
    api::{favicon, health, stylesheets},
    authentication,
    middlewares::security_headers,
    oauth, oidc,
};

pub fn router(state: AppState) -> Router {
    let web = Router::new()
        .route("/health", get(health::health))
        .route("/favicon.svg", get(favicon::favicon))
        .route("/css/{file}", get(stylesheets::stylesheet))
        .merge(authentication::routes::web_routes())
        .merge(oauth::routes::web_routes());

    // Browser-based apps (SPAs) call the API routes with `fetch` from their
    // own origin, so they need CORS. Allowing any origin is safe here
    // because none of these endpoints use cookies: they authenticate with
    // client credentials or bearer tokens.
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
        .max_age(Duration::from_secs(3600));

    let api = Router::new()
        .merge(oauth::routes::api_routes())
        .merge(oidc::routes::api_routes())
        .layer(cors);

    web.merge(api)
        .layer(from_fn(security_headers::security_headers))
        .layer(from_fn(security_headers::log_requests))
        .with_state(state)
}
