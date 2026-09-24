//! Queries for the `oauth_refresh_tokens` table.

use chrono::{DateTime, Utc};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DbErr, EntityTrait, IntoActiveModel, QueryFilter, QuerySelect,
    Select, UpdateMany,
    sea_query::{Expr, Query},
};
use uuid::Uuid;

use crate::token::{
    models::oauth_refresh_tokens::{Column, Entity as RefreshTokens},
    services::refresh::RefreshToken,
};

pub async fn insert(db: &impl ConnectionTrait, token: &RefreshToken) -> Result<(), DbErr> {
    RefreshTokens::insert(token.clone().into_active_model())
        .exec(db)
        .await?;
    Ok(())
}

pub async fn find_by_hash(
    db: &impl ConnectionTrait,
    token_hash: &str,
) -> Result<Option<RefreshToken>, DbErr> {
    RefreshTokens::find()
        .filter(Column::TokenHash.eq(token_hash))
        .one(db)
        .await
}

/// `SELECT … WHERE token_hash = $1 FOR UPDATE`
///
/// The row lock is what serialises two concurrent refreshes with the same
/// token: the second waits, then sees `rotated_to_id` set by the first and is
/// treated as a replay instead of both succeeding.
fn find_for_update_statement(token_hash: &str) -> Select<RefreshTokens> {
    RefreshTokens::find()
        .filter(Column::TokenHash.eq(token_hash))
        .lock_exclusive()
}

/// Like [`find_by_hash`] but locks the row until the transaction ends.
pub async fn find_by_hash_for_update(
    db: &impl ConnectionTrait,
    token_hash: &str,
) -> Result<Option<RefreshToken>, DbErr> {
    find_for_update_statement(token_hash).one(db).await
}

pub async fn mark_rotated(
    db: &impl ConnectionTrait,
    id: Uuid,
    rotated_to_id: Uuid,
) -> Result<(), DbErr> {
    RefreshTokens::update_many()
        .col_expr(Column::RotatedToId, Expr::value(rotated_to_id))
        .filter(Column::Id.eq(id))
        .exec(db)
        .await?;
    Ok(())
}

/// Revokes every token in a family. Returns how many were newly revoked.
pub async fn revoke_family(
    db: &impl ConnectionTrait,
    family_id: Uuid,
    now: DateTime<Utc>,
) -> Result<u64, DbErr> {
    let result = RefreshTokens::update_many()
        .col_expr(Column::RevokedAt, Expr::value(now))
        .filter(Column::FamilyId.eq(family_id))
        .filter(Column::RevokedAt.is_null())
        .exec(db)
        .await?;

    Ok(result.rows_affected)
}

/// ```sql
/// UPDATE oauth_refresh_tokens SET revoked_at = $2
/// WHERE family_id IN (
///     SELECT family_id FROM oauth_refresh_tokens WHERE authorization_code_id = $1
/// )
/// AND revoked_at IS NULL
/// ```
fn revoke_by_code_statement(
    authorization_code_id: Uuid,
    now: DateTime<Utc>,
) -> UpdateMany<RefreshTokens> {
    let families = Query::select()
        .column(Column::FamilyId)
        .from(RefreshTokens)
        .and_where(Column::AuthorizationCodeId.eq(authorization_code_id))
        .to_owned();

    RefreshTokens::update_many()
        .col_expr(Column::RevokedAt, Expr::value(now))
        .filter(Column::FamilyId.in_subquery(families))
        .filter(Column::RevokedAt.is_null())
}

/// Revokes every token that descends from an authorization code, used when a
/// code is replayed (RFC 6749 §4.1.2).
pub async fn revoke_by_authorization_code(
    db: &impl ConnectionTrait,
    authorization_code_id: Uuid,
    now: DateTime<Utc>,
) -> Result<u64, DbErr> {
    let result = revoke_by_code_statement(authorization_code_id, now)
        .exec(db)
        .await?;
    Ok(result.rows_affected)
}

#[cfg(test)]
mod tests {
    use sea_orm::{DbBackend, QueryTrait};

    use super::*;

    #[test]
    fn lookup_for_rotation_locks_the_row() {
        let sql = find_for_update_statement("the-hash")
            .build(DbBackend::Postgres)
            .to_string();

        assert!(sql.contains(r#""token_hash" = 'the-hash'"#), "{sql}");
        assert!(
            sql.ends_with("FOR UPDATE"),
            "replay detection depends on the row lock: {sql}"
        );
    }

    #[test]
    fn code_replay_revokes_whole_families_not_single_tokens() {
        let sql = revoke_by_code_statement(Uuid::nil(), Utc::now())
            .build(DbBackend::Postgres)
            .to_string();

        assert!(
            sql.contains(r#""family_id" IN (SELECT "family_id""#),
            "{sql}"
        );
        assert!(sql.contains(r#""authorization_code_id" ="#), "{sql}");
        assert!(sql.contains(r#""revoked_at" IS NULL"#), "{sql}");
    }
}
