//! Queries for the `user_sessions` table.
//!
//! Sessions are always looked up by `session_token_hash`; the raw token never
//! reaches the database.

use chrono::{DateTime, Utc};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DbErr, EntityTrait, IntoActiveModel, QueryFilter, sea_query::Expr,
};

use crate::{
    db::entities::user_sessions::{Column, Entity as Sessions},
    identity::session::Session,
};

pub async fn insert(db: &impl ConnectionTrait, session: &Session) -> Result<(), DbErr> {
    Sessions::insert(session.clone().into_active_model())
        .exec(db)
        .await?;
    Ok(())
}

/// Finds a session that is neither revoked nor expired.
pub async fn find_active_by_hash(
    db: &impl ConnectionTrait,
    session_token_hash: &str,
    now: DateTime<Utc>,
) -> Result<Option<Session>, DbErr> {
    Sessions::find()
        .filter(Column::SessionTokenHash.eq(session_token_hash))
        .filter(Column::RevokedAt.is_null())
        .filter(Column::ExpiresAt.gt(now))
        .one(db)
        .await
}

pub async fn revoke_by_hash(
    db: &impl ConnectionTrait,
    session_token_hash: &str,
    now: DateTime<Utc>,
) -> Result<(), DbErr> {
    Sessions::update_many()
        .col_expr(Column::RevokedAt, Expr::value(now))
        .filter(Column::SessionTokenHash.eq(session_token_hash))
        .filter(Column::RevokedAt.is_null())
        .exec(db)
        .await?;
    Ok(())
}
