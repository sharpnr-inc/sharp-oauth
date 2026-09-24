//! The token endpoint: `POST /oauth/token`.
//!
//! Clients call this server-to-server (or from an app's own code, never via
//! browser redirects) to exchange a *grant* for tokens. Two grant types:
//!
//! ## `grant_type=authorization_code`
//!
//! ```text
//! POST /oauth/token
//! Authorization: Basic base64(client_id:client_secret)   ← omitted by public clients
//! Content-Type: application/x-www-form-urlencoded
//!
//! grant_type=authorization_code&code=…&redirect_uri=…&code_verifier=…
//! ```
//!
//! Checks, in order: client authentication → code exists and is unused →
//! code belongs to this client → not expired → same redirect_uri → PKCE.
//!
//! ## `grant_type=refresh_token`
//!
//! ```text
//! grant_type=refresh_token&refresh_token=…[&scope=narrower scopes]
//! ```
//!
//! Checks: client authentication → token belongs to client → not revoked →
//! not already used (else revoke family) → not expired. Returns a *new*
//! refresh token; the old one is dead.
//!
//! ## Response
//!
//! ```json
//! {
//!   "access_token": "eyJ…", "token_type": "Bearer", "expires_in": 900,
//!   "scope": "email offline_access openid",
//!   "refresh_token": "…",   // only with offline_access
//!   "id_token": "eyJ…"      // only with openid
//! }
//! ```

use chrono::{DateTime, Utc};
use sea_orm::TransactionTrait;
use serde::Serialize;
use uuid::Uuid;

use crate::{
    AppState,
    oauth::{
        repo::authorization_codes,
        services::{
            authorization::AuthorizationCode,
            client::{self, OAuthClient},
            params::Params,
            pkce,
            scope::{self, ScopeSet},
        },
    },
    oidc::services::id_token::{self, IdTokenClaims},
    shared::{error::AppError, secret::hash_token},
    token::{
        repo::refresh_tokens,
        services::{
            access::{self, ACCESS_TOKEN_TTL, AccessTokenClaims},
            refresh::{self, NewRefreshToken, Unusable},
        },
    },
};

/// The grant types this server supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantType {
    AuthorizationCode,
    RefreshToken,
}

impl GrantType {
    pub fn parse(raw: Option<&str>) -> Result<Self, AppError> {
        match raw {
            Some("authorization_code") => Ok(GrantType::AuthorizationCode),
            Some("refresh_token") => Ok(GrantType::RefreshToken),
            Some(_) => Err(AppError::UnsupportedGrantType),
            None => Err(AppError::InvalidRequest("grant_type is required")),
        }
    }
}

/// A successful token response (RFC 6749 §5.1).
///
/// No `Debug`: every field is a credential.
#[derive(Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
}

/// Handles a token request.
///
/// `authorization_header` is the raw `Authorization` header, if any, and
/// `pairs` the decoded form body.
pub async fn handle(
    state: &AppState,
    authorization_header: Option<&str>,
    pairs: Vec<(String, String)>,
) -> Result<TokenResponse, AppError> {
    let params = Params::from_pairs(pairs)
        .map_err(|_| AppError::InvalidRequest("parameters must not be repeated"))?;
    let grant_type = GrantType::parse(params.get("grant_type"))?;

    let credentials = client::extract_credentials(authorization_header, &params)?;
    let client = client::authenticate(&state.db, &credentials).await?;

    match grant_type {
        GrantType::AuthorizationCode => exchange_authorization_code(state, &client, &params).await,
        GrantType::RefreshToken => exchange_refresh_token(state, &client, &params).await,
    }
}

// ---------------------------------------------------------------------------
// authorization_code
// ---------------------------------------------------------------------------

async fn exchange_authorization_code(
    state: &AppState,
    client: &OAuthClient,
    params: &Params,
) -> Result<TokenResponse, AppError> {
    let code = params
        .get("code")
        .ok_or(AppError::InvalidRequest("code is required"))?;
    let redirect_uri = params
        .get("redirect_uri")
        .ok_or(AppError::InvalidRequest("redirect_uri is required"))?;
    let code_verifier = params
        .get("code_verifier")
        .ok_or(AppError::InvalidRequest("code_verifier is required (PKCE)"))?;

    let code_hash = hash_token(code);
    let now = Utc::now();
    let tx = state.db.begin().await?;

    // Step 1: consume the code. From this point it can never be used again,
    // whether or not the rest of the checks pass.
    let Some(record) = authorization_codes::claim(&tx, &code_hash, now).await? else {
        // Unknown, or already used. A second use of a real code means it
        // leaked: RFC 6749 §4.1.2 says to revoke what the first use produced.
        if let Some(used) = authorization_codes::find_by_hash(&tx, &code_hash).await? {
            let revoked = refresh_tokens::revoke_by_authorization_code(&tx, used.id, now).await?;
            tx.commit().await?;
            tracing::warn!(
                target: "audit",
                event = "authorization_code_replayed",
                client_id = %client.client_id,
                user_id = %used.user_id,
                revoked_refresh_tokens = revoked
            );
            return Err(AppError::InvalidGrant(
                "authorization code has already been used",
            ));
        }
        return Err(AppError::InvalidGrant("authorization code is invalid"));
    };

    // Step 2: check the bindings. On failure we still commit, so the code
    // stays consumed and an attacker gets exactly one guess.
    if let Err(err) = check_code_bindings(&record, client, redirect_uri, code_verifier, now) {
        tx.commit().await?;
        tracing::warn!(
            target: "audit",
            event = "authorization_code_rejected",
            client_id = %client.client_id,
            reason = %err
        );
        return Err(err);
    }

    // Step 3: issue tokens. JWTs are signed before commit so a signing
    // failure rolls back the refresh token instead of orphaning it.
    let scope = stored_scope(&record.scope)?;
    let mut response = signed_tokens(
        state,
        client,
        record.user_id,
        &scope,
        record.auth_time,
        record.nonce.clone(),
        now,
    )?;

    if scope.contains(scope::OFFLINE_ACCESS) {
        let (raw, _) = refresh::issue(
            &tx,
            NewRefreshToken {
                family_id: Uuid::now_v7(),
                authorization_code_id: Some(record.id),
                client_id: client.id,
                user_id: record.user_id,
                scope: record.scope.clone(),
                auth_time: record.auth_time,
            },
            now,
        )
        .await?;
        response.refresh_token = Some(raw);
    }
    tx.commit().await?;

    tracing::info!(
        target: "audit",
        event = "tokens_issued",
        grant_type = "authorization_code",
        client_id = %client.client_id,
        user_id = %record.user_id,
        scope = %scope
    );
    Ok(response)
}

/// Verifies that the token request matches what the code was issued for.
fn check_code_bindings(
    record: &AuthorizationCode,
    client: &OAuthClient,
    redirect_uri: &str,
    code_verifier: &str,
    now: DateTime<Utc>,
) -> Result<(), AppError> {
    if record.client_id != client.id {
        return Err(AppError::InvalidGrant(
            "authorization code was issued to another client",
        ));
    }
    if record.expires_at <= now {
        return Err(AppError::InvalidGrant("authorization code has expired"));
    }
    // RFC 6749 §4.1.3: must be identical to the value in the authorization request.
    if record.redirect_uri != redirect_uri {
        return Err(AppError::InvalidGrant(
            "redirect_uri does not match the authorization request",
        ));
    }
    if record.code_challenge_method != pkce::S256
        || !pkce::verify_s256(code_verifier, &record.code_challenge)
    {
        return Err(AppError::InvalidGrant(
            "code_verifier does not match code_challenge",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// refresh_token
// ---------------------------------------------------------------------------

async fn exchange_refresh_token(
    state: &AppState,
    client: &OAuthClient,
    params: &Params,
) -> Result<TokenResponse, AppError> {
    let raw = params
        .get("refresh_token")
        .ok_or(AppError::InvalidRequest("refresh_token is required"))?;
    let requested_scope = params
        .get("scope")
        .map(ScopeSet::parse)
        .transpose()
        .map_err(|_| AppError::InvalidScope("scope is malformed"))?;

    let now = Utc::now();
    let tx = state.db.begin().await?;

    let record = refresh_tokens::find_by_hash_for_update(&tx, &hash_token(raw))
        .await?
        .ok_or(AppError::InvalidGrant("refresh token is invalid"))?;

    match record.check_usable(client.id, now) {
        Ok(()) => {}
        Err(Unusable::AlreadyRotated) => {
            let revoked = refresh_tokens::revoke_family(&tx, record.family_id, now).await?;
            tx.commit().await?;
            tracing::warn!(
                target: "audit",
                event = "refresh_token_replayed",
                client_id = %client.client_id,
                user_id = %record.user_id,
                family_id = %record.family_id,
                revoked_refresh_tokens = revoked
            );
            return Err(AppError::InvalidGrant(
                "refresh token has already been used",
            ));
        }
        // Don't reveal that the token exists for another client.
        Err(Unusable::WrongClient) => {
            return Err(AppError::InvalidGrant("refresh token is invalid"));
        }
        Err(Unusable::Revoked) => {
            return Err(AppError::InvalidGrant("refresh token has been revoked"));
        }
        Err(Unusable::Expired) => return Err(AppError::InvalidGrant("refresh token has expired")),
    }

    // RFC 6749 §6: a client may ask for fewer scopes, never more.
    let granted = stored_scope(&record.scope)?;
    let scope = match requested_scope {
        Some(requested) if !requested.is_subset_of(&granted) => {
            return Err(AppError::InvalidScope(
                "requested scope exceeds the original grant",
            ));
        }
        Some(requested) => requested,
        None => granted,
    };

    // ID tokens issued on refresh carry no nonce (OIDC Core §12.2).
    let mut response = signed_tokens(
        state,
        client,
        record.user_id,
        &scope,
        record.auth_time,
        None,
        now,
    )?;

    // Rotate. The new token keeps the *original* scope (RFC 6749 §6) so a
    // narrowed request does not permanently shrink the grant.
    let (new_raw, new_record) = refresh::issue(
        &tx,
        NewRefreshToken {
            family_id: record.family_id,
            authorization_code_id: record.authorization_code_id,
            client_id: client.id,
            user_id: record.user_id,
            scope: record.scope.clone(),
            auth_time: record.auth_time,
        },
        now,
    )
    .await?;
    refresh_tokens::mark_rotated(&tx, record.id, new_record.id).await?;
    tx.commit().await?;

    response.refresh_token = Some(new_raw);

    tracing::info!(
        target: "audit",
        event = "tokens_issued",
        grant_type = "refresh_token",
        client_id = %client.client_id,
        user_id = %record.user_id,
        family_id = %record.family_id,
        scope = %scope
    );
    Ok(response)
}

// ---------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------

/// Signs the access token and, for `openid` requests, the ID token.
fn signed_tokens(
    state: &AppState,
    client: &OAuthClient,
    user_id: Uuid,
    scope: &ScopeSet,
    auth_time: DateTime<Utc>,
    nonce: Option<String>,
    now: DateTime<Utc>,
) -> Result<TokenResponse, AppError> {
    let issuer = &state.config.issuer;

    let access_claims =
        AccessTokenClaims::new(issuer, user_id, &client.client_id, scope, auth_time, now);
    let access_token = access::issue(&state.signing_keys, &access_claims)?;

    let id_token = if scope.contains(scope::OPENID) {
        let claims = IdTokenClaims::new(issuer, user_id, &client.client_id, auth_time, nonce, now);
        Some(id_token::issue(&state.signing_keys, &claims)?)
    } else {
        None
    };

    Ok(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: ACCESS_TOKEN_TTL.num_seconds(),
        scope: scope.to_string(),
        refresh_token: None,
        id_token,
    })
}

fn stored_scope(raw: &str) -> Result<ScopeSet, AppError> {
    ScopeSet::parse(raw)
        .map_err(|_| AppError::Internal(anyhow::anyhow!("stored scope is malformed")))
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;

    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    fn client(now: DateTime<Utc>) -> OAuthClient {
        OAuthClient {
            id: Uuid::now_v7(),
            client_id: "sharp_client_test".into(),
            client_secret_hash: None,
            name: "Test".into(),
            redirect_uris: vec!["https://app.example.com/cb".into()],
            allowed_scopes: vec!["openid".into()],
            created_at: now,
            updated_at: now,
            disabled_at: None,
        }
    }

    fn code_for(client: &OAuthClient, now: DateTime<Utc>) -> AuthorizationCode {
        AuthorizationCode {
            id: Uuid::now_v7(),
            code_hash: crate::shared::database::SecretHash::from("hash".to_owned()),
            client_id: client.id,
            user_id: Uuid::now_v7(),
            redirect_uri: "https://app.example.com/cb".into(),
            scope: "openid".into(),
            code_challenge: CHALLENGE.into(),
            code_challenge_method: "S256".into(),
            nonce: None,
            auth_time: now,
            expires_at: now + Duration::seconds(60),
            created_at: now,
            used_at: Some(now),
        }
    }

    fn grant_error(result: Result<(), AppError>) -> &'static str {
        match result {
            Err(AppError::InvalidGrant(description)) => description,
            other => panic!("expected invalid_grant, got {other:?}"),
        }
    }

    #[test]
    fn matching_request_passes() {
        let now = Utc::now();
        let client = client(now);
        let code = code_for(&client, now);
        assert!(
            check_code_bindings(&code, &client, "https://app.example.com/cb", VERIFIER, now)
                .is_ok()
        );
    }

    #[test]
    fn code_from_another_client_is_rejected() {
        let now = Utc::now();
        let code = code_for(&client(now), now);
        let other = client(now);
        let err = grant_error(check_code_bindings(
            &code,
            &other,
            "https://app.example.com/cb",
            VERIFIER,
            now,
        ));
        assert!(err.contains("another client"));
    }

    #[test]
    fn expired_code_is_rejected() {
        let now = Utc::now();
        let client = client(now);
        let code = code_for(&client, now);
        let later = now + Duration::seconds(61);
        let err = grant_error(check_code_bindings(
            &code,
            &client,
            "https://app.example.com/cb",
            VERIFIER,
            later,
        ));
        assert!(err.contains("expired"));
    }

    #[test]
    fn different_redirect_uri_is_rejected() {
        let now = Utc::now();
        let client = client(now);
        let code = code_for(&client, now);
        let err = grant_error(check_code_bindings(
            &code,
            &client,
            "https://app.example.com/cb2",
            VERIFIER,
            now,
        ));
        assert!(err.contains("redirect_uri"));
    }

    #[test]
    fn wrong_pkce_verifier_is_rejected() {
        let now = Utc::now();
        let client = client(now);
        let code = code_for(&client, now);
        let wrong = "x".repeat(43);
        let err = grant_error(check_code_bindings(
            &code,
            &client,
            "https://app.example.com/cb",
            &wrong,
            now,
        ));
        assert!(err.contains("code_verifier"));
    }

    #[test]
    fn grant_type_parsing() {
        assert_eq!(
            GrantType::parse(Some("authorization_code")).unwrap(),
            GrantType::AuthorizationCode
        );
        assert_eq!(
            GrantType::parse(Some("refresh_token")).unwrap(),
            GrantType::RefreshToken
        );
        assert!(matches!(
            GrantType::parse(Some("password")),
            Err(AppError::UnsupportedGrantType)
        ));
        assert!(matches!(
            GrantType::parse(None),
            Err(AppError::InvalidRequest(_))
        ));
    }
}
