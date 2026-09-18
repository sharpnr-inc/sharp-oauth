//! Queries for the `oauth_scopes` registry.

use sea_orm::{ColumnTrait, ConnectionTrait, DbErr, EntityTrait, QueryFilter, QueryOrder};

use crate::db::entities::oauth_scopes::{Column, Entity as Scopes};

/// A scope and the sentence shown for it on the consent screen.
pub use crate::db::entities::oauth_scopes::Model as ScopeDescription;

pub async fn list_all(db: &impl ConnectionTrait) -> Result<Vec<ScopeDescription>, DbErr> {
    Scopes::find().order_by_asc(Column::Name).all(db).await
}

/// Returns the registry entries for the given names. Unknown names are
/// simply absent from the result.
pub async fn find_by_names(
    db: &impl ConnectionTrait,
    names: &[String],
) -> Result<Vec<ScopeDescription>, DbErr> {
    Scopes::find()
        .filter(Column::Name.is_in(names.iter().map(String::as_str)))
        .order_by_asc(Column::Name)
        .all(db)
        .await
}
