//! The `user_sessions` table. Aliased as [`crate::authentication::services::session::Session`].

use sea_orm::entity::prelude::*;

use crate::shared::database::SecretHash;

/// A browser session on the Sharpnr sign-in site.
///
/// `session_token_hash` is a [`SecretHash`], so `{:?}` prints `<redacted>`.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "user_sessions")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub user_id: Uuid,
    /// `SHA-256(session token)`. The raw token lives only in the cookie.
    #[sea_orm(unique, column_type = "Text")]
    pub session_token_hash: SecretHash,
    #[sea_orm(column_type = "TimestampWithTimeZone")]
    pub expires_at: DateTimeUtc,
    /// The moment the user authenticated; reported as OIDC `auth_time`.
    #[sea_orm(column_type = "TimestampWithTimeZone")]
    pub created_at: DateTimeUtc,
    #[sea_orm(column_type = "TimestampWithTimeZone", nullable)]
    pub revoked_at: Option<DateTimeUtc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
