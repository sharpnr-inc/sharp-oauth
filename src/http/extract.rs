//! Custom Axum extractors.

use axum::{extract::FromRequestParts, http::request::Parts, response::Response};

use crate::{
    AppState,
    http::{cookies, internal_error},
    identity::{
        session::{self, SESSION_COOKIE, Session},
        user::User,
    },
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
        let Some(token) = cookies::get(&parts.headers, SESSION_COOKIE) else {
            return Ok(CurrentSession(None));
        };
        session::find_active(&state.db, &token)
            .await
            .map(CurrentSession)
            .map_err(internal_error)
    }
}
