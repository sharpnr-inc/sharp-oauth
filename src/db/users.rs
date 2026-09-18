//! Queries for the `users` table.

use sea_orm::{ColumnTrait, ConnectionTrait, DbErr, EntityTrait, IntoActiveModel, QueryFilter};
use uuid::Uuid;

use crate::{
    db::entities::users::{Column, Entity as Users},
    identity::user::User,
};

/// Fails with a unique-violation error if the email is already taken; see
/// [`crate::identity::user::sign_up`], which relies on that.
pub async fn insert(db: &impl ConnectionTrait, user: &User) -> Result<(), DbErr> {
    Users::insert(user.clone().into_active_model())
        .exec(db)
        .await?;
    Ok(())
}

/// `email` must already be normalised (see [`crate::identity::user::normalize_email`]).
pub async fn find_by_email(db: &impl ConnectionTrait, email: &str) -> Result<Option<User>, DbErr> {
    Users::find().filter(Column::Email.eq(email)).one(db).await
}

pub async fn find_by_id(db: &impl ConnectionTrait, id: Uuid) -> Result<Option<User>, DbErr> {
    Users::find_by_id(id).one(db).await
}
