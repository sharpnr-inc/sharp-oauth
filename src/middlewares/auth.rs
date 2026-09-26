//! Who is signed in: the [`CurrentSession`] and [`SignedInUser`] extractors.
//!
//! This plays the role of an auth middleware. Axum extractors run before the
//! handler, so listing `CurrentSession` in a handler's arguments is enough to
//! resolve the session cookie.

use axum::{
    extract::FromRequestParts,
    http::{Method, request::Parts},
    response::Response,
};

use crate::{
    AppState,
    authentication::services::{
        session::{self, SESSION_COOKIE, Session},
        user::User,
    },
    pkg::cookie_manager,
    shared::response::{internal_error, redirect},
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

/// The signed-in user, for pages that require one.
///
/// Like `RequireAuth` middleware in Gin: if nobody is signed in, the handler
/// never runs and the browser is sent to `/signin`. For a GET the sign-in
/// page returns to the same URL afterwards. A form submission has no page to
/// return to (replaying it as a GET would fail), so it returns to `/`.
pub struct SignedInUser(pub User);

impl FromRequestParts<AppState> for SignedInUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let CurrentSession(session) = CurrentSession::from_request_parts(parts, state).await?;
        if let Some((_, user)) = session {
            return Ok(SignedInUser(user));
        }

        let return_to = match (&parts.method, parts.uri.path_and_query()) {
            (&Method::GET, Some(path)) => path.as_str(),
            _ => "/",
        };
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("return_to", return_to)
            .finish();
        Err(redirect(&format!("/signin?{query}")))
    }
}
