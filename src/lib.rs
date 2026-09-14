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
//! | Module       | Responsibility                                                  |
//! |--------------|-----------------------------------------------------------------|
//! | [`config`]   | Reading settings from environment variables                     |
//! | [`error`]    | [`error::AppError`] and its mapping to OAuth error responses    |
//! | [`secret`]   | Random secrets, hashing them, constant-time comparison          |
//! | [`db`]       | Connection pool, migrations and all SQL queries                 |
//! | [`identity`] | Sharpnr users, passwords and browser sessions                   |
//! | [`oauth`]    | OAuth 2.0: clients, scopes, PKCE, authorize, consent, token     |
//! | [`token`]    | Access tokens (JWT), refresh tokens, signing keys               |
//! | [`oidc`]     | OpenID Connect: ID tokens, UserInfo, discovery                  |
//! | [`http`]     | Axum routes, handlers, cookies, CSRF and HTML pages             |
//!
//! The dependency direction is always `http` → services (`identity`, `oauth`,
//! `token`, `oidc`) → `db`. Handlers stay thin; protocol rules live in the
//! service modules where they can be unit tested without HTTP.

use std::sync::Arc;

use sqlx::PgPool;

pub mod config;
pub mod db;
pub mod error;
pub mod http;
pub mod identity;
pub mod oauth;
pub mod oidc;
pub mod secret;
pub mod token;

use config::Config;
use token::signing::SigningKeys;

/// Shared, cheaply clonable application context.
///
/// Axum clones this for every request, so expensive members sit behind an
/// [`Arc`] (`PgPool` is already an `Arc` internally).
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: PgPool,
    pub signing_keys: Arc<SigningKeys>,
}

impl AppState {
    pub fn new(config: Config, db: PgPool, signing_keys: SigningKeys) -> Self {
        Self {
            config: Arc::new(config),
            db,
            signing_keys: Arc::new(signing_keys),
        }
    }
}

/// Builds the complete Axum application (routes + middleware).
pub fn app(state: AppState) -> axum::Router {
    http::routes::router(state)
}
