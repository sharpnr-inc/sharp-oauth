//! The `oauth_refresh_tokens` table.
//! Aliased as [`crate::token::refresh::RefreshToken`].

use sea_orm::entity::prelude::*;

use super::SecretHash;

/// One refresh token. Tokens rotated from the same sign-in share a
/// `family_id`; see [`crate::token::refresh`].
///
/// `token_hash` is a [`SecretHash`], so `{:?}` prints `<redacted>`.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "oauth_refresh_tokens")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// `SHA-256(refresh token)`.
    #[sea_orm(unique, column_type = "Text")]
    pub token_hash: SecretHash,
    pub family_id: Uuid,
    /// The authorization code this family was born from.
    #[sea_orm(nullable)]
    pub authorization_code_id: Option<Uuid>,
    pub client_id: Uuid,
    pub user_id: Uuid,
    pub scope: String,
    #[sea_orm(column_type = "TimestampWithTimeZone")]
    pub auth_time: DateTimeUtc,
    #[sea_orm(column_type = "TimestampWithTimeZone")]
    pub expires_at: DateTimeUtc,
    #[sea_orm(column_type = "TimestampWithTimeZone")]
    pub created_at: DateTimeUtc,
    #[sea_orm(column_type = "TimestampWithTimeZone", nullable)]
    pub revoked_at: Option<DateTimeUtc>,
    /// Set when this token was exchanged for a successor.
    #[sea_orm(nullable)]
    pub rotated_to_id: Option<Uuid>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
