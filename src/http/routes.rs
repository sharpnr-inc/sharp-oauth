//! The URL map.
//!
//! | Method   | Path                                  | Who calls it     | Handler                  |
//! |----------|---------------------------------------|------------------|--------------------------|
//! | GET      | `/health`                             | monitoring       | [`pages::health`]        |
//! | GET      | `/`                                   | browser          | [`pages::home`]          |
//! | GET/POST | `/signin`                             | browser          | [`pages::sign_in`]       |
//! | GET/POST | `/signup`                             | browser          | [`pages::sign_up`]       |
//! | POST     | `/logout`                             | browser          | [`pages::logout`]        |
//! | GET/POST | `/oauth/authorize`                    | browser          | [`oauth::authorize_get`] |
//! | POST     | `/oauth/consent`                      | browser          | [`oauth::consent`]       |
//! | POST     | `/oauth/token`                        | client app       | [`oauth::token`]         |
//! | POST     | `/oauth/revoke`                       | client app       | [`oauth::revoke`]        |
//! | GET/POST | `/oauth/userinfo`                     | client app       | [`oidc::userinfo`]       |
//! | GET      | `/.well-known/openid-configuration`   | client library   | [`oidc::discovery`]      |
//! | GET      | `/.well-known/jwks.json`              | token verifiers  | [`oidc::jwks`]           |

use std::time::Duration;

use axum::{
    Router,
    http::{Method, header},
    middleware::from_fn,
    routing::{get, post},
};
use tower_http::cors::{Any, CorsLayer};

use crate::{
    AppState,
    http::{middleware, oauth, oidc, pages},
};

pub fn router(state: AppState) -> Router {
    // Pages used by a person in a browser, on Sharpnr's own origin.
    let browser = Router::new()
        .route("/health", get(pages::health))
        .route("/", get(pages::home))
        .route("/signin", get(pages::sign_in_page).post(pages::sign_in))
        .route("/signup", get(pages::sign_up_page).post(pages::sign_up))
        .route("/logout", post(pages::logout))
        .route(
            "/oauth/authorize",
            get(oauth::authorize_get).post(oauth::authorize_post),
        )
        .route("/oauth/consent", post(oauth::consent));

    // Endpoints called by client applications. Browser-based apps (SPAs)
    // call these with `fetch` from their own origin, so they need CORS.
    // Allowing any origin is safe here because none of these endpoints use
    // cookies: they authenticate with client credentials or bearer tokens.
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
        .max_age(Duration::from_secs(3600));

    let api = Router::new()
        .route("/oauth/token", post(oauth::token))
        .route("/oauth/revoke", post(oauth::revoke))
        .route("/oauth/userinfo", get(oidc::userinfo).post(oidc::userinfo))
        .route("/.well-known/openid-configuration", get(oidc::discovery))
        .route("/.well-known/jwks.json", get(oidc::jwks))
        .layer(cors);

    browser
        .merge(api)
        .layer(from_fn(middleware::security_headers))
        .layer(from_fn(middleware::log_requests))
        .with_state(state)
}
