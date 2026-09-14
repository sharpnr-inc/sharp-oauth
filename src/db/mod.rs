//! Database access.
//!
//! Every SQL statement in the application lives in a submodule here, one per
//! table. Service modules (`identity`, `oauth`, `token`) call these functions
//! and never write SQL themselves, and HTTP handlers never touch the database
//! directly.
//!
//! ## Query style
//!
//! Queries use `sqlx::query_as::<_, T>(...)` with `#[derive(sqlx::FromRow)]`
//! structs. These are checked at *runtime*, not compile time, so
//! `cargo build` works without a running database. The integration tests in
//! `tests/` run every query against a real PostgreSQL instance, which is what
//! keeps them honest.
//!
//! ## Executors and transactions
//!
//! Functions that may run inside a transaction take `impl PgExecutor<'_>`.
//! That accepts both `&PgPool` (auto-commit) and `&mut *transaction`, so the
//! caller decides the transactional boundary.

use anyhow::{Context, Result};
use sqlx::{PgPool, postgres::PgPoolOptions};

pub mod authorization_codes;
pub mod clients;
pub mod consents;
pub mod refresh_tokens;
pub mod scopes;
pub mod sessions;
pub mod users;

/// Opens a connection pool.
pub async fn connect(database_url: &str) -> Result<PgPool> {
    PgPoolOptions::new()
        .max_connections(10)
        .connect(database_url)
        .await
        .context("failed to connect to PostgreSQL (check DATABASE_URL)")
}

/// Applies any pending migrations from `migrations/`.
///
/// Migrations are embedded into the binary at compile time, so a deployed
/// binary always carries the schema it expects.
pub async fn migrate(pool: &PgPool) -> Result<()> {
    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .context("failed to run database migrations")
}
