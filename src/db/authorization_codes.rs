//! Queries for the `oauth_authorization_codes` table.

use chrono::{DateTime, Utc};
use sqlx::PgExecutor;

use crate::oauth::authorization::AuthorizationCode;

pub async fn insert(
    db: impl PgExecutor<'_>,
    code: &AuthorizationCode,
    code_hash: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO oauth_authorization_codes
            (id, code_hash, client_id, user_id, redirect_uri, scope, code_challenge,
             code_challenge_method, nonce, auth_time, expires_at, created_at, used_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
    )
    .bind(code.id)
    .bind(code_hash)
    .bind(code.client_id)
    .bind(code.user_id)
    .bind(&code.redirect_uri)
    .bind(&code.scope)
    .bind(&code.code_challenge)
    .bind(&code.code_challenge_method)
    .bind(&code.nonce)
    .bind(code.auth_time)
    .bind(code.expires_at)
    .bind(code.created_at)
    .bind(code.used_at)
    .execute(db)
    .await?;
    Ok(())
}

/// Atomically marks an unused code as used and returns it.
///
/// This single `UPDATE ... WHERE used_at IS NULL` is what makes codes
/// one-time: if two requests race with the same code, PostgreSQL's row lock
/// guarantees only one of them gets a row back. Returns `None` if the code
/// does not exist *or* was already used.
///
/// Note that expiry is deliberately *not* checked here: an expired code is
/// still consumed so it can never be tried again.
pub async fn claim(
    db: impl PgExecutor<'_>,
    code_hash: &str,
    now: DateTime<Utc>,
) -> Result<Option<AuthorizationCode>, sqlx::Error> {
    // The struct has no `code_hash` field, so that column is never read back.
    sqlx::query_as::<_, AuthorizationCode>(
        "UPDATE oauth_authorization_codes SET used_at = $2
         WHERE code_hash = $1 AND used_at IS NULL
         RETURNING *",
    )
    .bind(code_hash)
    .bind(now)
    .fetch_optional(db)
    .await
}

pub async fn find_by_hash(
    db: impl PgExecutor<'_>,
    code_hash: &str,
) -> Result<Option<AuthorizationCode>, sqlx::Error> {
    sqlx::query_as::<_, AuthorizationCode>(
        "SELECT * FROM oauth_authorization_codes WHERE code_hash = $1",
    )
    .bind(code_hash)
    .fetch_optional(db)
    .await
}
