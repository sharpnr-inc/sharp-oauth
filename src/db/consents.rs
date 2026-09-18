//! Queries for the `oauth_consents` table.

use chrono::{DateTime, Utc};
use sea_orm::{
    ActiveValue::Set,
    ColumnTrait, ConnectionTrait, DbErr, EntityTrait, Insert, QueryFilter,
    prelude::DateTimeUtc,
    sea_query::{Expr, OnConflict},
};
use uuid::Uuid;

use crate::db::entities::oauth_consents::{ActiveModel, Column, Entity as Consents};

/// Returns the approved scope names, ignoring revoked consents.
pub async fn find_active(
    db: &impl ConnectionTrait,
    user_id: Uuid,
    client_id: Uuid,
) -> Result<Option<Vec<String>>, DbErr> {
    let consent = Consents::find()
        .filter(Column::UserId.eq(user_id))
        .filter(Column::ClientId.eq(client_id))
        .filter(Column::RevokedAt.is_null())
        .one(db)
        .await?;

    Ok(consent.map(|consent| consent.scopes))
}

/// Inserts or replaces the consent for a (user, client) pair.
///
/// ```sql
/// INSERT INTO oauth_consents (...) VALUES (...)
/// ON CONFLICT (user_id, client_id) DO UPDATE
/// SET scopes = EXCLUDED.scopes, updated_at = EXCLUDED.updated_at, revoked_at = NULL
/// ```
///
/// Re-approving after a revocation clears `revoked_at`.
fn upsert_statement(
    user_id: Uuid,
    client_id: Uuid,
    scopes: &[String],
    now: DateTime<Utc>,
) -> Insert<ActiveModel> {
    let consent = ActiveModel {
        id: Set(Uuid::now_v7()),
        user_id: Set(user_id),
        client_id: Set(client_id),
        scopes: Set(scopes.to_vec()),
        created_at: Set(now),
        updated_at: Set(now),
        revoked_at: Set(None),
    };

    Consents::insert(consent).on_conflict(
        OnConflict::columns([Column::UserId, Column::ClientId])
            .update_columns([Column::Scopes, Column::UpdatedAt])
            // Re-approving after a revocation must clear `revoked_at`;
            // `update_columns` alone would leave the old value in place.
            .value(Column::RevokedAt, Expr::value(None::<DateTimeUtc>))
            .to_owned(),
    )
}

/// Inserts or replaces the consent for a (user, client) pair.
pub async fn upsert(
    db: &impl ConnectionTrait,
    user_id: Uuid,
    client_id: Uuid,
    scopes: &[String],
    now: DateTime<Utc>,
) -> Result<(), DbErr> {
    upsert_statement(user_id, client_id, scopes, now)
        .exec(db)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use sea_orm::{DbBackend, QueryTrait};

    use super::*;

    #[test]
    fn reapproving_replaces_scopes_and_clears_revocation() {
        let sql = upsert_statement(Uuid::nil(), Uuid::nil(), &["openid".to_owned()], Utc::now())
            .build(DbBackend::Postgres)
            .to_string();

        assert!(
            sql.contains(r#"ON CONFLICT ("user_id", "client_id") DO UPDATE"#),
            "{sql}"
        );
        assert!(sql.contains(r#""scopes" = "excluded"."scopes""#), "{sql}");
        assert!(
            sql.contains(r#""revoked_at" = NULL"#),
            "a re-approved consent must stop being revoked: {sql}"
        );
    }
}
