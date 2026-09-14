//! Refresh tokens with rotation and replay detection.
//!
//! A refresh token lets a client get new access tokens without sending the
//! user through the browser again. It is long-lived, which makes it valuable
//! to steal, so it gets the strongest protections:
//!
//! * **Opaque and hashed.** A random string; only `SHA-256(token)` is stored.
//! * **Bound to one client.** Another client cannot redeem it.
//! * **Rotated.** Every use returns a *new* refresh token and retires the
//!   old one (`rotated_to_id` points at its successor).
//! * **Replay detection.** Tokens from one sign-in form a *family*. If a
//!   retired token is presented again, two parties hold copies: the real
//!   client and an attacker. We cannot tell which is which, so the whole
//!   family is revoked and the user must sign in again (RFC 9700 §4.14.2).
//!
//! ```text
//!  sign-in ──▶ RT1 ──use──▶ RT2 ──use──▶ RT3        (family F)
//!                │
//!                └── RT1 used again?  ⇒ revoke RT1, RT2, RT3
//! ```
//!
//! Refresh tokens are only issued when the `offline_access` scope was granted.

use chrono::{DateTime, Duration, Utc};
use sqlx::PgExecutor;
use uuid::Uuid;

use crate::{
    db,
    secret::{generate_token, hash_token},
};

/// A refresh token expires 30 days after it was issued. Because every use
/// issues a new token, an app used at least monthly stays signed in.
pub const REFRESH_TOKEN_TTL: Duration = Duration::days(30);

/// A row of `oauth_refresh_tokens` (without the hash).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RefreshToken {
    pub id: Uuid,
    pub family_id: Uuid,
    pub authorization_code_id: Option<Uuid>,
    /// UUID of the client.
    pub client_id: Uuid,
    pub user_id: Uuid,
    pub scope: String,
    pub auth_time: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub rotated_to_id: Option<Uuid>,
}

/// Why a stored refresh token cannot be used.
#[derive(Debug, PartialEq, Eq)]
pub enum Unusable {
    WrongClient,
    Revoked,
    /// Already exchanged once. This is the replay signal.
    AlreadyRotated,
    Expired,
}

impl RefreshToken {
    /// Checks whether `client` may use this token right now.
    ///
    /// The order is deliberate: a token belonging to another client is
    /// rejected before anything else, so one client can never trigger
    /// revocation of another client's tokens.
    pub fn check_usable(&self, client_id: Uuid, now: DateTime<Utc>) -> Result<(), Unusable> {
        if self.client_id != client_id {
            Err(Unusable::WrongClient)
        } else if self.revoked_at.is_some() {
            Err(Unusable::Revoked)
        } else if self.rotated_to_id.is_some() {
            Err(Unusable::AlreadyRotated)
        } else if self.expires_at <= now {
            Err(Unusable::Expired)
        } else {
            Ok(())
        }
    }
}

/// Everything needed to create a refresh token.
pub struct NewRefreshToken {
    pub family_id: Uuid,
    pub authorization_code_id: Option<Uuid>,
    pub client_id: Uuid,
    pub user_id: Uuid,
    pub scope: String,
    pub auth_time: DateTime<Utc>,
}

/// Stores a new refresh token and returns `(raw_token, record)`.
pub async fn issue(
    db: impl PgExecutor<'_>,
    new: NewRefreshToken,
    now: DateTime<Utc>,
) -> Result<(String, RefreshToken), sqlx::Error> {
    let raw = generate_token();
    let record = RefreshToken {
        id: Uuid::now_v7(),
        family_id: new.family_id,
        authorization_code_id: new.authorization_code_id,
        client_id: new.client_id,
        user_id: new.user_id,
        scope: new.scope,
        auth_time: new.auth_time,
        expires_at: now + REFRESH_TOKEN_TTL,
        created_at: now,
        revoked_at: None,
        rotated_to_id: None,
    };
    db::refresh_tokens::insert(db, &record, &hash_token(&raw)).await?;
    Ok((raw, record))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(now: DateTime<Utc>, client_id: Uuid) -> RefreshToken {
        RefreshToken {
            id: Uuid::now_v7(),
            family_id: Uuid::now_v7(),
            authorization_code_id: None,
            client_id,
            user_id: Uuid::now_v7(),
            scope: "openid offline_access".into(),
            auth_time: now,
            expires_at: now + REFRESH_TOKEN_TTL,
            created_at: now,
            revoked_at: None,
            rotated_to_id: None,
        }
    }

    #[test]
    fn fresh_token_is_usable_by_its_client_only() {
        let now = Utc::now();
        let client = Uuid::now_v7();
        let t = token(now, client);
        assert_eq!(t.check_usable(client, now), Ok(()));
        assert_eq!(
            t.check_usable(Uuid::now_v7(), now),
            Err(Unusable::WrongClient)
        );
    }

    #[test]
    fn expired_revoked_and_rotated_tokens_are_unusable() {
        let now = Utc::now();
        let client = Uuid::now_v7();

        let mut expired = token(now, client);
        expired.expires_at = now;
        assert_eq!(expired.check_usable(client, now), Err(Unusable::Expired));

        let mut revoked = token(now, client);
        revoked.revoked_at = Some(now);
        assert_eq!(revoked.check_usable(client, now), Err(Unusable::Revoked));

        let mut rotated = token(now, client);
        rotated.rotated_to_id = Some(Uuid::now_v7());
        assert_eq!(
            rotated.check_usable(client, now),
            Err(Unusable::AlreadyRotated)
        );
    }
}
