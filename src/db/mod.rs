//! Database access.
//!
//! Every query in the application lives in a submodule here, one per table.
//! Service modules (`identity`, `oauth`, `token`) call these functions and
//! never build queries themselves, and HTTP handlers never touch the
//! database directly.
//!
//! ## SeaORM
//!
//! Queries are written with [SeaORM](https://www.sea-ql.org/SeaORM/) against
//! the entities in [`entities`]:
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
//! (see [`authorization_codes::claim`] and
//! [`refresh_tokens::find_by_hash_for_update`]).
//!
//! ## Connections and transactions
//!
//! Functions take `&impl ConnectionTrait`, which accepts both a
//! `DatabaseConnection` (auto-commit) and a `DatabaseTransaction`, so the
//! caller decides the transactional boundary:
//!
//! ```ignore
//! let tx = state.db.begin().await?;
//! db::authorization_codes::claim(&tx, &code_hash, now).await?;
//! tx.commit().await?;
//! ```
//!
//! ## Migrations
//!
//! The schema is owned by the plain SQL files in `migrations/`, run by SQLx
//! (SeaORM borrows the same connection pool). Forward-only: to change a
//! table, add a migration and update its entity to match.

use anyhow::{Context, Result};
use sea_orm::{DatabaseConnection, SqlxPostgresConnector};
use sqlx::postgres::PgPoolOptions;

pub mod authorization_codes;
pub mod clients;
pub mod consents;
pub mod entities;
pub mod refresh_tokens;
pub mod scopes;
pub mod sessions;
pub mod users;

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
