//! Queries for the `oauth_scopes` registry.

use sqlx::PgExecutor;

/// A scope and the sentence shown for it on the consent screen.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ScopeDescription {
    pub name: String,
    pub description: String,
}

pub async fn list_all(db: impl PgExecutor<'_>) -> Result<Vec<ScopeDescription>, sqlx::Error> {
    sqlx::query_as::<_, ScopeDescription>(
        "SELECT name, description FROM oauth_scopes ORDER BY name",
    )
    .fetch_all(db)
    .await
}

/// Returns the registry entries for the given names. Unknown names are
/// simply absent from the result.
pub async fn find_by_names(
    db: impl PgExecutor<'_>,
    names: &[String],
) -> Result<Vec<ScopeDescription>, sqlx::Error> {
    sqlx::query_as::<_, ScopeDescription>(
        "SELECT name, description FROM oauth_scopes WHERE name = ANY($1) ORDER BY name",
    )
    .bind(names)
    .fetch_all(db)
    .await
}
