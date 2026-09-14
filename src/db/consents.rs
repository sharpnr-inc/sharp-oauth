//! Queries for the `oauth_consents` table.

use chrono::{DateTime, Utc};
use sqlx::PgExecutor;
use uuid::Uuid;

/// Returns the approved scope names, ignoring revoked consents.
pub async fn find_active(
    db: impl PgExecutor<'_>,
    user_id: Uuid,
    client_id: Uuid,
) -> Result<Option<Vec<String>>, sqlx::Error> {
    sqlx::query_scalar::<_, Vec<String>>(
        "SELECT scopes FROM oauth_consents
         WHERE user_id = $1 AND client_id = $2 AND revoked_at IS NULL",
    )
    .bind(user_id)
    .bind(client_id)
    .fetch_optional(db)
    .await
}

/// Inserts or replaces the consent for a (user, client) pair.
///
/// Re-approving after a revocation clears `revoked_at`.
pub async fn upsert(
    db: impl PgExecutor<'_>,
    user_id: Uuid,
    client_id: Uuid,
    scopes: &[String],
    now: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO oauth_consents (id, user_id, client_id, scopes, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $5)
         ON CONFLICT (user_id, client_id) DO UPDATE
         SET scopes = EXCLUDED.scopes, updated_at = EXCLUDED.updated_at, revoked_at = NULL",
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(client_id)
    .bind(scopes)
    .bind(now)
    .execute(db)
    .await?;
    Ok(())
}
