//! The `users` table. Aliased as [`crate::identity::user::User`].

use sea_orm::entity::prelude::*;

use super::SecretHash;

/// A Sharpnr account.
///
/// `password_hash` is a [`SecretHash`], so `{:?}` prints `<redacted>`.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "users")]
pub struct Model {
    /// Stable identifier. Exposed to clients as the OIDC `sub` claim.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Lower-cased email address.
    #[sea_orm(unique)]
    pub email: String,
    /// Argon2id PHC string. Never sent anywhere.
    #[sea_orm(column_type = "Text")]
    pub password_hash: SecretHash,
    pub display_name: Option<String>,
    /// Sharp-OAuth has no email verification flow yet, so this is always
    /// `false`, and that is what we truthfully report to clients.
    pub email_verified: bool,
    #[sea_orm(column_type = "TimestampWithTimeZone")]
    pub created_at: DateTimeUtc,
    #[sea_orm(column_type = "TimestampWithTimeZone")]
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
