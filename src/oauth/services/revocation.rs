//! Token revocation: `POST /oauth/revoke` ([RFC 7009]).
//!
//! A client calls this when the user signs out of the client app, so the
//! refresh token stops working immediately:
//!
//! ```text
//! POST /oauth/revoke
//! Authorization: Basic …
//! token=<refresh token>
//! ```
//!
//! Revoking a refresh token revokes its whole family (every token rotated
//! from the same sign-in).
//!
//! **Access tokens** are self-contained JWTs and cannot be revoked; they
//! simply expire within 15 minutes. As RFC 7009 §2.2 requires, presenting
//! one (or any unknown string) still returns `200 OK`, because a client
//! cannot do anything useful with an error here.
//!
//! [RFC 7009]: https://www.rfc-editor.org/rfc/rfc7009

use chrono::Utc;

use crate::{
    AppState,
    oauth::services::{client, params::Params},
    shared::{error::AppError, secret::hash_token},
    token::repo::refresh_tokens,
};

pub async fn handle(
    state: &AppState,
    authorization_header: Option<&str>,
    pairs: Vec<(String, String)>,
) -> Result<(), AppError> {
    let params = Params::from_pairs(pairs)
        .map_err(|_| AppError::InvalidRequest("parameters must not be repeated"))?;

    let credentials = client::extract_credentials(authorization_header, &params)?;
    let client = client::authenticate(&state.db, &credentials).await?;

    let token = params
        .get("token")
        .ok_or(AppError::InvalidRequest("token is required"))?;
    // `token_type_hint` is optional and only an optimisation; we have a
    // single revocable token type, so it is ignored.

    let Some(record) = refresh_tokens::find_by_hash(&state.db, &hash_token(token)).await? else {
        return Ok(());
    };

    // RFC 7009 §2.1: a client may only revoke its own tokens.
    if record.client_id != client.id {
        tracing::warn!(
            target: "audit",
            event = "revocation_rejected_wrong_client",
            client_id = %client.client_id
        );
        return Err(AppError::UnauthorizedClient(
            "the token was not issued to this client",
        ));
    }

    let revoked = refresh_tokens::revoke_family(&state.db, record.family_id, Utc::now()).await?;
    tracing::info!(
        target: "audit",
        event = "refresh_token_revoked",
        client_id = %client.client_id,
        user_id = %record.user_id,
        family_id = %record.family_id,
        revoked_refresh_tokens = revoked
    );
    Ok(())
}
