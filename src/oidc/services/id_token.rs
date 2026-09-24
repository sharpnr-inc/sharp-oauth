//! ID tokens (OpenID Connect Core §2).
//!
//! An ID token is a JWT the client must validate before trusting it:
//!
//! | Claim       | Meaning                                         | Client checks                     |
//! |-------------|-------------------------------------------------|-----------------------------------|
//! | `iss`       | Who issued it                                   | equals the expected issuer        |
//! | `sub`       | Stable user ID (never the email)                | used as the user's key            |
//! | `aud`       | The client it was issued to (`client_id`)       | equals its own client_id          |
//! | `exp`/`iat` | Validity window                                 | not expired                       |
//! | `auth_time` | When the user entered their password            | if it sent `max_age`              |
//! | `nonce`     | Echo of the request's nonce                     | equals the nonce it generated     |
//!
//! Profile data (name, email) is deliberately *not* in the ID token. The
//! client gets it from the UserInfo endpoint using the access token, which
//! keeps the token small and avoids copying personal data into every JWT.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::pkg::jwt_manager::SigningKeys;

pub const ID_TOKEN_TTL: Duration = Duration::minutes(15);

/// JWT `typ` header for ID tokens.
pub const JWT_TYPE: &str = "JWT";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub auth_time: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

impl IdTokenClaims {
    /// `nonce` must be the value from the original authorization request, or
    /// `None` when there was none (and always `None` on refresh, per
    /// OIDC Core §12.2).
    pub fn new(
        issuer: &str,
        user_id: Uuid,
        client_id: &str,
        auth_time: DateTime<Utc>,
        nonce: Option<String>,
        now: DateTime<Utc>,
    ) -> Self {
        Self {
            iss: issuer.to_owned(),
            sub: user_id.to_string(),
            aud: client_id.to_owned(),
            exp: (now + ID_TOKEN_TTL).timestamp(),
            iat: now.timestamp(),
            auth_time: auth_time.timestamp(),
            nonce,
        }
    }
}

pub fn issue(keys: &SigningKeys, claims: &IdTokenClaims) -> anyhow::Result<String> {
    keys.sign(JWT_TYPE, claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claims_are_bound_to_client_user_and_nonce() {
        let now = DateTime::from_timestamp(1_780_000_000, 0).unwrap();
        let auth_time = now - Duration::minutes(5);
        let user_id = Uuid::now_v7();

        let claims = IdTokenClaims::new(
            "https://auth.sharpnr.com",
            user_id,
            "sharp_client_abc",
            auth_time,
            Some("n-0S6_WzA2Mj".into()),
            now,
        );

        assert_eq!(claims.iss, "https://auth.sharpnr.com");
        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.aud, "sharp_client_abc");
        assert_eq!(claims.iat, 1_780_000_000);
        assert_eq!(claims.exp, 1_780_000_900);
        assert_eq!(claims.auth_time, 1_779_999_700);
        assert_eq!(claims.nonce.as_deref(), Some("n-0S6_WzA2Mj"));
    }

    #[test]
    fn nonce_is_omitted_when_absent() {
        let now = Utc::now();
        let claims = IdTokenClaims::new("https://i", Uuid::now_v7(), "c", now, None, now);
        let json = serde_json::to_value(claims).unwrap();
        assert!(json.get("nonce").is_none());
    }
}
