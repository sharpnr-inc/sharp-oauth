//! JWT access tokens ([RFC 9068]).
//!
//! An access token looks like this once decoded:
//!
//! ```json
//! // header
//! { "alg": "RS256", "typ": "at+jwt", "kid": "20260914T120000-d4e5f6" }
//! // payload
//! {
//!   "iss": "https://auth.sharpnr.com",
//!   "sub": "0199a3c4-…",          // the user
//!   "aud": "https://auth.sharpnr.com",
//!   "client_id": "sharp_client_…", // the app acting for the user
//!   "scope": "email openid",
//!   "iat": 1780000000, "exp": 1780000900, "auth_time": 1779999000,
//!   "jti": "0199a3c5-…"
//! }
//! ```
//!
//! The payload is only base64, not encrypted, so it contains identifiers
//! and nothing sensitive (no email, no name).
//!
//! **Audience:** all Sharpnr resource servers, including our own UserInfo
//! endpoint, currently share one audience equal to the issuer URL. Resource
//! servers must check `iss`, `aud`, `exp`, the signature and `typ`.
//! Per-API audiences (RFC 8707 resource indicators) can be added later.
//!
//! [RFC 9068]: https://www.rfc-editor.org/rfc/rfc9068

use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::Validation;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    oauth::scope::ScopeSet,
    token::signing::{ALGORITHM, SigningKeys, VerifyError},
};

/// Short on purpose: a JWT cannot be revoked, so its lifetime is the window
/// in which a leaked token remains usable.
pub const ACCESS_TOKEN_TTL: Duration = Duration::minutes(15);

/// JWT `typ` header for access tokens (RFC 9068 §2.1).
pub const JWT_TYPE: &str = "at+jwt";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub iss: String,
    /// User ID.
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    /// Unique token ID, useful in audit logs.
    pub jti: String,
    pub client_id: String,
    pub scope: String,
    pub auth_time: i64,
}

impl AccessTokenClaims {
    pub fn new(
        issuer: &str,
        user_id: Uuid,
        client_id: &str,
        scope: &ScopeSet,
        auth_time: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Self {
        Self {
            iss: issuer.to_owned(),
            sub: user_id.to_string(),
            aud: issuer.to_owned(),
            exp: (now + ACCESS_TOKEN_TTL).timestamp(),
            iat: now.timestamp(),
            jti: Uuid::now_v7().to_string(),
            client_id: client_id.to_owned(),
            scope: scope.to_string(),
            auth_time: auth_time.timestamp(),
        }
    }

    pub fn scopes(&self) -> ScopeSet {
        ScopeSet::parse(&self.scope).unwrap_or_default()
    }
}

pub fn issue(keys: &SigningKeys, claims: &AccessTokenClaims) -> anyhow::Result<String> {
    keys.sign(JWT_TYPE, claims)
}

/// Verifies an access token issued by this server.
pub fn verify(
    keys: &SigningKeys,
    issuer: &str,
    token: &str,
) -> Result<AccessTokenClaims, VerifyError> {
    let mut validation = Validation::new(ALGORITHM);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[issuer]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    // We issued the token with this same clock, so no skew allowance needed.
    validation.leeway = 0;
    keys.verify(token, JWT_TYPE, validation)
}
