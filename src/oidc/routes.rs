//! Routes for the OpenID Connect feature.
//!
//! | Method   | Path                                | Who calls it    | Handler                    |
//! |----------|-------------------------------------|-----------------|----------------------------|
//! | GET/POST | `/oauth/userinfo`                   | client app      | [`userinfo::userinfo`]     |
//! | GET      | `/.well-known/openid-configuration` | client library  | [`well_known::discovery`]  |
//! | GET      | `/.well-known/jwks.json`            | token verifiers | [`well_known::jwks`]       |

use axum::{Router, routing::get};

use crate::{
    AppState,
    oidc::controllers::{userinfo, well_known},
};

/// Endpoints called by client applications (CORS is added by the router).
pub fn api_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/oauth/userinfo",
            get(userinfo::userinfo).post(userinfo::userinfo),
        )
        .route(
            "/.well-known/openid-configuration",
            get(well_known::discovery),
        )
        .route("/.well-known/jwks.json", get(well_known::jwks))
}
