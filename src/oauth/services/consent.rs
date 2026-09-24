//! User consent.
//!
//! Before a client receives any access, the user must approve the scopes it
//! asked for. We remember the approval in `oauth_consents` so the user is only
//! asked again when a client requests *more* than it already has.

use chrono::Utc;
use sea_orm::DatabaseConnection;
use uuid::Uuid;

use crate::{
    oauth::{repo::consents, services::scope::ScopeSet},
    shared::error::AppError,
};

/// The scopes `user_id` has approved for `client_id` (UUID), if any.
pub async fn granted_scopes(
    db: &DatabaseConnection,
    user_id: Uuid,
    client_id: Uuid,
) -> Result<Option<ScopeSet>, AppError> {
    let scopes = consents::find_active(db, user_id, client_id).await?;
    Ok(scopes.map(|scopes| scopes.into_iter().collect()))
}

/// Records approval of `scopes`, adding to anything approved earlier.
pub async fn grant(
    db: &DatabaseConnection,
    user_id: Uuid,
    client_id: Uuid,
    scopes: &ScopeSet,
) -> Result<(), AppError> {
    let all = match granted_scopes(db, user_id, client_id).await? {
        Some(existing) => existing.union(scopes),
        None => scopes.clone(),
    };
    consents::upsert(db, user_id, client_id, &all.to_vec(), Utc::now()).await?;

    tracing::info!(
        target: "audit",
        event = "consent_granted",
        %user_id,
        client = %client_id,
        scopes = %all
    );
    Ok(())
}
