//! # Sharp-OAuth
//!
//! An OAuth 2.0 Authorization Server and OpenID Connect Provider: the engine
//! behind "Sign in with Sharpnr".
//!
//! This file is the crate root. It declares the modules and defines
//! [`AppState`], the bundle of shared resources every request handler needs.
//! `main.rs` is a thin binary on top of this library; the split exists so the
//! integration tests in `tests/` can build the exact same application.
//!
//! ## Where things live
//!
//! The layout is feature-first: each feature folder owns its routes,
//! controllers (HTTP handlers), services (business rules), repo (queries) and
//! models (SeaORM entities). Cross-cutting code sits at the top level.
//!
//! | Module             | Responsibility                                               |
//! |--------------------|--------------------------------------------------------------|
//! | [`config`]         | Reading settings from environment variables                  |
//! | [`api`]            | The router: mounts every feature's routes and middleware     |
//! | [`middlewares`]    | Security headers, request logging, CSRF, current session     |
//! | [`shared`]         | Errors, secrets, database connection, HTML views, responses  |
//! | [`pkg`]            | Standalone helpers: cookies, JWT signing keys                |
//! | [`authentication`] | Sharpnr users, passwords, sessions; sign-in/sign-up pages    |
//! | [`oauth`]          | OAuth 2.0: clients, scopes, PKCE, authorize, consent, token  |
//! | [`token`]          | Access tokens (JWT) and refresh tokens                       |
//! | [`oidc`]           | OpenID Connect: ID tokens, UserInfo, discovery, JWKS         |
//!
//! Inside a feature, dependencies point one way:
//! `routes` → `controllers` → `services` → `repo` → `models`. Controllers stay
//! thin; protocol rules live in services, where they can be unit tested
//! without HTTP.

use std::sync::Arc;

use sea_orm::DatabaseConnection;

pub mod api;
pub mod authentication;
pub mod config;
pub mod middlewares;
pub mod oauth;
pub mod oidc;
pub mod pkg;
pub mod shared;
pub mod token;

use config::Config;
use pkg::jwt_manager::SigningKeys;

/// Shared, cheaply clonable application context.
///
/// Axum clones this for every request, so expensive members sit behind an
/// [`Arc`] (`PgPool` is already an `Arc` internally).
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    /// SeaORM handle. Cloning it shares the underlying connection pool.
    pub db: DatabaseConnection,
    pub signing_keys: Arc<SigningKeys>,
}

impl AppState {
    pub fn new(config: Config, db: DatabaseConnection, signing_keys: SigningKeys) -> Self {
        Self {
            config: Arc::new(config),
            db,
            signing_keys: Arc::new(signing_keys),
        }
    }
}

/// Builds the complete Axum application (routes + middleware).
pub fn app(state: AppState) -> axum::Router {
    api::router::router(state)
}
