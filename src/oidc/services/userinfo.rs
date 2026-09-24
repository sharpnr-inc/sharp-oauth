//! The UserInfo endpoint (OpenID Connect Core §5.3).
//!
//! A client calls `GET /oauth/userinfo` with `Authorization: Bearer <access
//! token>` and receives the user's claims, filtered by the scopes that token
//! carries:
//!
//! ```json
//! { "sub": "0199a3c4-…", "name": "Kashif", "email": "kashif@sharpnr.com", "email_verified": false }
//! ```

use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::{
    AppState,
    authentication::{repo::users, services::user::User},
    oauth::services::scope::{self, ScopeSet},
    shared::error::AppError,
    token::services::access,
};

/// Errors in RFC 6750 (Bearer Token Usage) terms.
#[derive(Debug, thiserror::Error)]
pub enum UserInfoError {
    /// Missing, malformed, expired or forged token, or the user is gone.
    #[error("invalid_token")]
    InvalidToken,
    /// A valid access token that was not issued with the `openid` scope.
    #[error("insufficient_scope")]
    InsufficientScope,
    #[error(transparent)]
    Internal(#[from] AppError),
}

/// Returns the claims for the user behind `access_token`.
pub async fn userinfo(
    state: &AppState,
    access_token: &str,
) -> Result<Map<String, Value>, UserInfoError> {
    let claims =
        access::verify(&state.signing_keys, &state.config.issuer, access_token).map_err(|err| {
            tracing::debug!(error = %err, "userinfo rejected access token");
            UserInfoError::InvalidToken
        })?;

    let scopes = claims.scopes();
    if !scopes.contains(scope::OPENID) {
        return Err(UserInfoError::InsufficientScope);
    }

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| UserInfoError::InvalidToken)?;
    let user = users::find_by_id(&state.db, user_id)
        .await
        .map_err(AppError::from)?
        .ok_or(UserInfoError::InvalidToken)?;

    Ok(claims_for(&user, &scopes))
}

/// Builds the claim set a user shares for a set of scopes.
///
/// Only claims we actually hold are included: `name` is omitted when the
/// user has no display name rather than sent as `null`.
pub fn claims_for(user: &User, scopes: &ScopeSet) -> Map<String, Value> {
    let mut claims = Map::new();
    claims.insert("sub".into(), json!(user.id.to_string()));

    if scopes.contains(scope::PROFILE) {
        if let Some(name) = &user.display_name {
            claims.insert("name".into(), json!(name));
        }
        claims.insert("updated_at".into(), json!(user.updated_at.timestamp()));
    }
    if scopes.contains(scope::EMAIL) {
        claims.insert("email".into(), json!(user.email));
        claims.insert("email_verified".into(), json!(user.email_verified));
    }
    claims
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;

    fn user() -> User {
        User {
            id: Uuid::now_v7(),
            email: "kashif@sharpnr.com".into(),
            password_hash: "$argon2id$...".into(),
            display_name: Some("Kashif".into()),
            email_verified: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn openid_alone_returns_only_sub() {
        let claims = claims_for(&user(), &ScopeSet::parse("openid").unwrap());
        assert_eq!(claims.keys().collect::<Vec<_>>(), vec!["sub"]);
    }

    #[test]
    fn profile_and_email_add_their_claims() {
        let claims = claims_for(&user(), &ScopeSet::parse("openid profile email").unwrap());
        assert_eq!(claims["name"], "Kashif");
        assert_eq!(claims["email"], "kashif@sharpnr.com");
        assert_eq!(claims["email_verified"], false);
    }

    #[test]
    fn password_hash_is_never_a_claim() {
        let claims = claims_for(
            &user(),
            &ScopeSet::parse("openid profile email offline_access").unwrap(),
        );
        let json = serde_json::to_string(&claims).unwrap();
        assert!(!json.contains("argon2"));
    }
}
