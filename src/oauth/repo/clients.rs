//! Queries for the `oauth_clients` table.

use chrono::{DateTime, Utc};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DbErr, EntityTrait, IntoActiveModel, PaginatorTrait, QueryFilter,
    QueryOrder, sea_query::Expr,
};
use uuid::Uuid;

use crate::{
    oauth::{
        models::oauth_clients::{Column, Entity as Clients},
        services::client::OAuthClient,
    },
    shared::database::SecretHash,
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

/// The clients a developer-portal user registered, newest first.
pub async fn list_by_owner(
    db: &impl ConnectionTrait,
    owner_user_id: Uuid,
) -> Result<Vec<OAuthClient>, DbErr> {
    Clients::find()
        .filter(Column::OwnerUserId.eq(owner_user_id))
        .order_by_desc(Column::CreatedAt)
        .all(db)
        .await
}

pub async fn count_by_owner(db: &impl ConnectionTrait, owner_user_id: Uuid) -> Result<u64, DbErr> {
    Clients::find()
        .filter(Column::OwnerUserId.eq(owner_user_id))
        .count(db)
        .await
}

/// Looks a client up by `client_id`, but only if `owner_user_id` owns it.
///
/// The ownership check is part of the query, so a client that belongs to
/// someone else is indistinguishable from one that does not exist.
pub async fn find_owned(
    db: &impl ConnectionTrait,
    owner_user_id: Uuid,
    client_id: &str,
) -> Result<Option<OAuthClient>, DbErr> {
    Clients::find()
        .filter(Column::ClientId.eq(client_id))
        .filter(Column::OwnerUserId.eq(owner_user_id))
        .one(db)
        .await
}

pub async fn update_details(
    db: &impl ConnectionTrait,
    id: Uuid,
    name: &str,
    redirect_uris: &[String],
    allowed_scopes: &[String],
    now: DateTime<Utc>,
) -> Result<(), DbErr> {
    Clients::update_many()
        .col_expr(Column::Name, Expr::value(name))
        .col_expr(Column::RedirectUris, Expr::value(redirect_uris.to_vec()))
        .col_expr(Column::AllowedScopes, Expr::value(allowed_scopes.to_vec()))
        .col_expr(Column::UpdatedAt, Expr::value(now))
        .filter(Column::Id.eq(id))
        .exec(db)
        .await?;
    Ok(())
}

pub async fn update_secret_hash(
    db: &impl ConnectionTrait,
    id: Uuid,
    secret_hash: SecretHash,
    now: DateTime<Utc>,
) -> Result<(), DbErr> {
    Clients::update_many()
        .col_expr(Column::ClientSecretHash, Expr::value(secret_hash))
        .col_expr(Column::UpdatedAt, Expr::value(now))
        .filter(Column::Id.eq(id))
        .exec(db)
        .await?;
    Ok(())
}

pub async fn delete(db: &impl ConnectionTrait, id: Uuid) -> Result<(), DbErr> {
    Clients::delete_by_id(id).exec(db).await?;
    Ok(())
}
