//! OpenID Provider metadata ([OpenID Connect Discovery 1.0] / [RFC 8414]).
//!
//! Served at `/.well-known/openid-configuration`. Client libraries fetch it
//! to find our endpoints and learn what we support.
//!
//! **Every value here is a promise.** Only list what is actually implemented;
//! a client that believes an advertised feature exists will use it.
//!
//! [OpenID Connect Discovery 1.0]: https://openid.net/specs/openid-connect-discovery-1_0.html
//! [RFC 8414]: https://www.rfc-editor.org/rfc/rfc8414

use serde_json::{Value, json};

use crate::{AppState, db, error::AppError, token::signing::ALGORITHM_NAME};

pub async fn document(state: &AppState) -> Result<Value, AppError> {
    let config = &state.config;
    let scopes: Vec<String> = db::scopes::list_all(&state.db)
        .await?
        .into_iter()
        .map(|scope| scope.name)
        .collect();

    Ok(json!({
        "issuer": config.issuer,
        "authorization_endpoint": config.url("/oauth/authorize"),
        "token_endpoint": config.url("/oauth/token"),
        "userinfo_endpoint": config.url("/oauth/userinfo"),
        "revocation_endpoint": config.url("/oauth/revoke"),
        "jwks_uri": config.url("/.well-known/jwks.json"),

        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": scopes,

        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": [ALGORITHM_NAME],
        "claims_supported": [
            "iss", "sub", "aud", "exp", "iat", "auth_time", "nonce",
            "name", "updated_at", "email", "email_verified"
        ],
        "prompt_values_supported": ["none", "login", "consent", "select_account"],

        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "revocation_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],

        // RFC 9207: authorization responses carry `iss`.
        "authorization_response_iss_parameter_supported": true,

        // Explicitly "no". `request_uri_parameter_supported` defaults to
        // true in the spec, so omitting it would advertise a feature we lack.
        "request_parameter_supported": false,
        "request_uri_parameter_supported": false,
        "claims_parameter_supported": false
    }))
}
