//! Who is signed in: the [`CurrentSession`] extractor.
//!
//! This plays the role of an auth middleware. Axum extractors run before the
//! handler, so listing `CurrentSession` in a handler's arguments is enough to
//! resolve the session cookie.

use axum::{extract::FromRequestParts, http::request::Parts, response::Response};

use crate::{
    AppState,
    authentication::services::{
        session::{self, SESSION_COOKIE, Session},
        user::User,
    },
    pkg::cookie_manager,
    shared::response::internal_error,
};

/// The signed-in Sharpnr user for this request, if any.
///
/// Add `CurrentSession(session): CurrentSession` to a handler's arguments
/// and Axum resolves the session cookie before the handler runs.
pub struct CurrentSession(pub Option<(Session, User)>);

impl FromRequestParts<AppState> for CurrentSession {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let Some(token) = cookie_manager::get(&parts.headers, SESSION_COOKIE) else {
            return Ok(CurrentSession(None));
        };
        session::find_active(&state.db, &token)
            .await
            .map(CurrentSession)
            .map_err(internal_error)
    }
}
