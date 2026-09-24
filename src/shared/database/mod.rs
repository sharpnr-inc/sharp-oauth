//! Database connection, migrations and conventions shared by every feature.
//!
//! Queries do not live here. Each feature has a `repo/` folder with one
//! module per table (for example [`crate::authentication::repo::users`]), and
//! a `models/` folder with the SeaORM entity for that table. Services call
//! repo functions and never build queries themselves, and controllers never
//! touch the database directly.
//!
//! ## SeaORM
//!
//! Queries are written with [SeaORM](https://www.sea-ql.org/SeaORM/) against
//! the entities in each feature's `models/` folder:
//!
//! ```ignore
//! Users::find()
//!     .filter(users::Column::Email.eq(email))
//!     .one(db)
//!     .await
//! ```
//!
//! Columns are checked by the compiler, so a renamed column is a build error
//! rather than a runtime surprise, and a `Model` describes each table once
//! for the whole application.
//!
//! Where a query encodes a security rule the plain SQL is quoted in the
//! comment above it, because the exact statement is the thing being reviewed
//! (see [`crate::oauth::repo::authorization_codes::claim`] and
//! [`crate::token::repo::refresh_tokens::find_by_hash_for_update`]).
//!
//! ## Connections and transactions
//!
//! Functions take `&impl ConnectionTrait`, which accepts both a
//! `DatabaseConnection` (auto-commit) and a `DatabaseTransaction`, so the
//! caller decides the transactional boundary:
//!
//! ```ignore
//! let tx = state.db.begin().await?;
//! authorization_codes::claim(&tx, &code_hash, now).await?;
//! tx.commit().await?;
//! ```
//!
//! ## Models
//!
//! Each `models/` module describes a table once, and the SeaORM macros
//! generate everything else from it:
//!
//! * `Model`: one row, used directly as the domain struct. `User`,
//!   `OAuthClient`, `Session`, `AuthorizationCode` and `RefreshToken` are all
//!   aliases of a `Model`, so a column exists in exactly one place.
//! * `ActiveModel`: a row being written, where each field is `Set` or
//!   `NotSet`.
//! * `Column`: the type-safe column names used to build queries
//!   (`Column::Email.eq(email)`), which is what replaces hand-written SQL.
//!
//! The behaviour that belongs to a row lives in the feature's services, not
//! in the model: `OAuthClient::has_redirect_uri` is in
//! [`crate::oauth::services::client`] and `RefreshToken::check_usable` in
//! [`crate::token::services::refresh`]. Rust allows that because it is all
//! one crate.
//!
//! ### Secrets in models
//!
//! Some tables store the SHA-256 hash of a secret (`password_hash`,
//! `session_token_hash`, `code_hash`, `token_hash`, `client_secret_hash`).
//! A `Model` has a field for every column, and SeaORM requires models to
//! implement `Debug`, so those columns use the [`SecretHash`] newtype, which
//! prints `<redacted>`. That keeps a stray `{:?}` from putting a credential
//! hash in the logs.
//!
//! ## Migrations
//!
//! The schema is owned by the plain SQL files in `migrations/`, run by SQLx
//! (SeaORM borrows the same connection pool). Forward-only: to change a
//! table, add a migration and update its entity to match.

use anyhow::{Context, Result};
use sea_orm::{DatabaseConnection, SqlxPostgresConnector};
use sqlx::postgres::PgPoolOptions;

mod secret_hash;

pub use secret_hash::SecretHash;

/// Opens a connection pool and wraps it for SeaORM.
pub async fn connect(database_url: &str) -> Result<DatabaseConnection> {
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(database_url)
        .await
        .context("failed to connect to PostgreSQL (check DATABASE_URL)")?;

    Ok(SqlxPostgresConnector::from_sqlx_postgres_pool(pool))
}

/// Applies any pending migrations from `migrations/`.
///
/// Migrations are embedded into the binary at compile time, so a deployed
/// binary always carries the schema it expects.
pub async fn migrate(db: &DatabaseConnection) -> Result<()> {
    sqlx::migrate!("./migrations")
        .run(db.get_postgres_connection_pool())
        .await
        .context("failed to run database migrations")
}
