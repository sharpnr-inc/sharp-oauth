//! The `oauth_scopes` registry. Aliased as [`crate::oauth::repo::scopes::ScopeDescription`].

use sea_orm::entity::prelude::*;

/// A scope and the sentence shown for it on the consent screen.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "oauth_scopes")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub name: String,
    pub description: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
