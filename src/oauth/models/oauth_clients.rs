//! The `oauth_clients` table. Aliased as [`crate::oauth::services::client::OAuthClient`].

use sea_orm::entity::prelude::*;

use crate::shared::database::SecretHash;

/// A registered third-party application.
///
/// `client_secret_hash` is a [`SecretHash`], so `{:?}` prints `<redacted>`.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "oauth_clients")]
pub struct Model {
    /// Internal primary key, used by foreign keys.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// The public identifier clients send, e.g. `sharp_client_…`.
    #[sea_orm(unique)]
    pub client_id: String,
    /// `SHA-256(client_secret)`, or `None` for public clients.
    #[sea_orm(nullable, column_type = "Text")]
    pub client_secret_hash: Option<SecretHash>,
    pub name: String,
    /// Exact redirect URIs (PostgreSQL `TEXT[]`).
    pub redirect_uris: Vec<String>,
    /// Scopes this client may request.
    pub allowed_scopes: Vec<String>,
    #[sea_orm(column_type = "TimestampWithTimeZone")]
    pub created_at: DateTimeUtc,
    #[sea_orm(column_type = "TimestampWithTimeZone")]
    pub updated_at: DateTimeUtc,
    #[sea_orm(column_type = "TimestampWithTimeZone", nullable)]
    pub disabled_at: Option<DateTimeUtc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
