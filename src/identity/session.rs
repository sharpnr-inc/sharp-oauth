//! Browser sessions for the Sharpnr sign-in site.
//!
//! When a user signs in we generate a random session token, put it in an
//! `HttpOnly` cookie and store `SHA-256(token)` in `user_sessions`. On every
//! request the cookie is hashed and looked up again.
//!
//! These sessions belong to *Sharp-OAuth itself*. Third-party applications
//! never see this cookie; they get OAuth tokens instead.

use chrono::{Duration, Utc};
use sea_orm::DatabaseConnection;
use uuid::Uuid;

use crate::{
    db::{self, entities::SecretHash},
    error::AppError,
    identity::user::User,
    secret::{generate_token, hash_token},
};

/// Name of the cookie holding the raw session token.
pub const SESSION_COOKIE: &str = "sharp_session";

/// How long a sign-in lasts before the user must enter their password again.
pub const SESSION_TTL: Duration = Duration::days(7);

/// A browser session.
///
/// The SeaORM model for `user_sessions`
/// ([`crate::db::entities::user_sessions`]). `session_token_hash` is a
/// [`SecretHash`], so `{:?}` prints `<redacted>`.
pub use crate::db::entities::user_sessions::Model as Session;

/// Starts a session for `user`. Returns the raw token for the cookie.
///
/// The raw token is returned exactly once and is not stored anywhere.
pub async fn create(db: &DatabaseConnection, user: &User) -> Result<(String, Session), AppError> {
    let token = generate_token();
    let now = Utc::now();
    let session = Session {
        id: Uuid::now_v7(),
        user_id: user.id,
        session_token_hash: SecretHash::from(hash_token(&token)),
        expires_at: now + SESSION_TTL,
        created_at: now,
        revoked_at: None,
    };

    db::sessions::insert(db, &session).await?;
    Ok((token, session))
}

/// Resolves a raw cookie value to its active session and user.
pub async fn find_active(
    db: &DatabaseConnection,
    token: &str,
) -> Result<Option<(Session, User)>, AppError> {
    let Some(session) =
        db::sessions::find_active_by_hash(db, &hash_token(token), Utc::now()).await?
    else {
        return Ok(None);
    };
    let Some(user) = db::users::find_by_id(db, session.user_id).await? else {
        return Ok(None);
    };
    Ok(Some((session, user)))
}

/// Ends a session. Revoking an unknown or already revoked token is a no-op.
pub async fn revoke(db: &DatabaseConnection, token: &str) -> Result<(), AppError> {
    db::sessions::revoke_by_hash(db, &hash_token(token), Utc::now()).await?;
    Ok(())
}
