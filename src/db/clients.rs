//! Queries for the `oauth_clients` table.

use sqlx::PgExecutor;

use crate::oauth::client::OAuthClient;

pub async fn insert(db: impl PgExecutor<'_>, client: &OAuthClient) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO oauth_clients
            (id, client_id, client_secret_hash, name, redirect_uris, allowed_scopes, created_at, updated_at, disabled_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(client.id)
    .bind(&client.client_id)
    .bind(&client.client_secret_hash)
    .bind(&client.name)
    .bind(&client.redirect_uris)
    .bind(&client.allowed_scopes)
    .bind(client.created_at)
    .bind(client.updated_at)
    .bind(client.disabled_at)
    .execute(db)
    .await?;
    Ok(())
}

/// Looks a client up by its public `client_id` (not the UUID primary key).
pub async fn find_by_client_id(
    db: impl PgExecutor<'_>,
    client_id: &str,
) -> Result<Option<OAuthClient>, sqlx::Error> {
    sqlx::query_as::<_, OAuthClient>("SELECT * FROM oauth_clients WHERE client_id = $1")
        .bind(client_id)
        .fetch_optional(db)
        .await
}
