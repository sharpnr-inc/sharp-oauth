//! The `oauth_authorization_codes` table.
//! Aliased as [`crate::oauth::authorization::AuthorizationCode`].

use sea_orm::entity::prelude::*;

use super::SecretHash;

/// A short-lived, one-time authorization code.
///
/// Every column after `code_hash` is a *binding*: the token endpoint checks
/// that the redeeming request matches what was approved.
///
/// `code_hash` is a [`SecretHash`], so `{:?}` prints `<redacted>`.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "oauth_authorization_codes")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// `SHA-256(code)`. The raw code exists only in the redirect to the client.
    #[sea_orm(unique, column_type = "Text")]
    pub code_hash: SecretHash,
    /// UUID of the client (not the public `client_id` string).
    pub client_id: Uuid,
    pub user_id: Uuid,
    pub redirect_uri: String,
    /// Space-delimited granted scopes, e.g. `"openid profile"`.
    pub scope: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    /// OIDC: echoed into the ID token so the client can detect replay.
    #[sea_orm(nullable)]
    pub nonce: Option<String>,
    /// OIDC: when the user authenticated.
    #[sea_orm(column_type = "TimestampWithTimeZone")]
    pub auth_time: DateTimeUtc,
    #[sea_orm(column_type = "TimestampWithTimeZone")]
    pub expires_at: DateTimeUtc,
    #[sea_orm(column_type = "TimestampWithTimeZone")]
    pub created_at: DateTimeUtc,
    /// Set on first redemption. A second redemption is an attack signal.
    #[sea_orm(column_type = "TimestampWithTimeZone", nullable)]
    pub used_at: Option<DateTimeUtc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
