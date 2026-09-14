//! Queries for the `oauth_refresh_tokens` table.

use chrono::{DateTime, Utc};
use sqlx::PgExecutor;
use uuid::Uuid;

use crate::token::refresh::RefreshToken;

pub async fn insert(
    db: impl PgExecutor<'_>,
    token: &RefreshToken,
    token_hash: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO oauth_refresh_tokens
            (id, token_hash, family_id, authorization_code_id, client_id, user_id, scope,
             auth_time, expires_at, created_at, revoked_at, rotated_to_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
    )
    .bind(token.id)
    .bind(token_hash)
    .bind(token.family_id)
    .bind(token.authorization_code_id)
    .bind(token.client_id)
    .bind(token.user_id)
    .bind(&token.scope)
    .bind(token.auth_time)
    .bind(token.expires_at)
    .bind(token.created_at)
    .bind(token.revoked_at)
    .bind(token.rotated_to_id)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn find_by_hash(
    db: impl PgExecutor<'_>,
    token_hash: &str,
) -> Result<Option<RefreshToken>, sqlx::Error> {
    sqlx::query_as::<_, RefreshToken>("SELECT * FROM oauth_refresh_tokens WHERE token_hash = $1")
        .bind(token_hash)
        .fetch_optional(db)
        .await
}

/// Like [`find_by_hash`] but locks the row until the transaction ends.
///
/// Two concurrent refreshes with the same token are serialised: the second
/// waits, then sees `rotated_to_id` set by the first and is treated as a
/// replay instead of both succeeding.
pub async fn find_by_hash_for_update(
    db: impl PgExecutor<'_>,
    token_hash: &str,
) -> Result<Option<RefreshToken>, sqlx::Error> {
    sqlx::query_as::<_, RefreshToken>(
        "SELECT * FROM oauth_refresh_tokens WHERE token_hash = $1 FOR UPDATE",
    )
    .bind(token_hash)
    .fetch_optional(db)
    .await
}

pub async fn mark_rotated(
    db: impl PgExecutor<'_>,
    id: Uuid,
    rotated_to_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE oauth_refresh_tokens SET rotated_to_id = $2 WHERE id = $1")
        .bind(id)
        .bind(rotated_to_id)
        .execute(db)
        .await?;
    Ok(())
}

/// Revokes every token in a family. Returns how many were newly revoked.
pub async fn revoke_family(
    db: impl PgExecutor<'_>,
    family_id: Uuid,
    now: DateTime<Utc>,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE oauth_refresh_tokens SET revoked_at = $2
         WHERE family_id = $1 AND revoked_at IS NULL",
    )
    .bind(family_id)
    .bind(now)
    .execute(db)
    .await?;
    Ok(result.rows_affected())
}

/// Revokes every token that descends from an authorization code.
pub async fn revoke_by_authorization_code(
    db: impl PgExecutor<'_>,
    authorization_code_id: Uuid,
    now: DateTime<Utc>,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE oauth_refresh_tokens SET revoked_at = $2
         WHERE family_id IN (
             SELECT family_id FROM oauth_refresh_tokens WHERE authorization_code_id = $1
         )
         AND revoked_at IS NULL",
    )
    .bind(authorization_code_id)
    .bind(now)
    .execute(db)
    .await?;
    Ok(result.rows_affected())
}
