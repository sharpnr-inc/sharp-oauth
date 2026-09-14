//! Queries for the `user_sessions` table.
//!
//! Sessions are always looked up by `session_token_hash`; the raw token never
//! reaches the database.

use chrono::{DateTime, Utc};
use sqlx::PgExecutor;

use crate::identity::session::Session;

pub async fn insert(
    db: impl PgExecutor<'_>,
    session: &Session,
    session_token_hash: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO user_sessions (id, user_id, session_token_hash, expires_at, created_at)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(session.id)
    .bind(session.user_id)
    .bind(session_token_hash)
    .bind(session.expires_at)
    .bind(session.created_at)
    .execute(db)
    .await?;
    Ok(())
}

/// Finds a session that is neither revoked nor expired.
pub async fn find_active_by_hash(
    db: impl PgExecutor<'_>,
    session_token_hash: &str,
    now: DateTime<Utc>,
) -> Result<Option<Session>, sqlx::Error> {
    sqlx::query_as::<_, Session>(
        "SELECT id, user_id, expires_at, created_at
         FROM user_sessions
         WHERE session_token_hash = $1
           AND revoked_at IS NULL
           AND expires_at > $2",
    )
    .bind(session_token_hash)
    .bind(now)
    .fetch_optional(db)
    .await
}

pub async fn revoke_by_hash(
    db: impl PgExecutor<'_>,
    session_token_hash: &str,
    now: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE user_sessions SET revoked_at = $2
         WHERE session_token_hash = $1 AND revoked_at IS NULL",
    )
    .bind(session_token_hash)
    .bind(now)
    .execute(db)
    .await?;
    Ok(())
}
