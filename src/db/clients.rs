//! Queries for the `oauth_clients` table.

use sea_orm::{ColumnTrait, ConnectionTrait, DbErr, EntityTrait, IntoActiveModel, QueryFilter};

use crate::{
    db::entities::oauth_clients::{Column, Entity as Clients},
    oauth::client::OAuthClient,
};

pub async fn insert(db: &impl ConnectionTrait, client: &OAuthClient) -> Result<(), DbErr> {
    Clients::insert(client.clone().into_active_model())
        .exec(db)
        .await?;
    Ok(())
}

/// Looks a client up by its public `client_id` (not the UUID primary key).
pub async fn find_by_client_id(
    db: &impl ConnectionTrait,
    client_id: &str,
) -> Result<Option<OAuthClient>, DbErr> {
    Clients::find()
        .filter(Column::ClientId.eq(client_id))
        .one(db)
        .await
}
