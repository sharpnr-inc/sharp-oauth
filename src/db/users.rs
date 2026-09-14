//! Queries for the `users` table.

use sqlx::PgExecutor;
use uuid::Uuid;

use crate::identity::user::User;

pub async fn insert(db: impl PgExecutor<'_>, user: &User) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, display_name, email_verified, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(user.id)
    .bind(&user.email)
    .bind(&user.password_hash)
    .bind(&user.display_name)
    .bind(user.email_verified)
    .bind(user.created_at)
    .bind(user.updated_at)
    .execute(db)
    .await?;
    Ok(())
}

/// `email` must already be normalised (see [`crate::identity::user::normalize_email`]).
pub async fn find_by_email(
    db: impl PgExecutor<'_>,
    email: &str,
) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = $1")
        .bind(email)
        .fetch_optional(db)
        .await
}

pub async fn find_by_id(db: impl PgExecutor<'_>, id: Uuid) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(id)
        .fetch_optional(db)
        .await
}
