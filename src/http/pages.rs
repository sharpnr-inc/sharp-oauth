//! Browser pages for Sharpnr accounts: home, sign-in, sign-up, logout.

use axum::{
    Form,
    extract::{Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;

use crate::{
    AppState,
    http::{
        cookies,
        csrf::{self, CsrfToken},
        extract::CurrentSession,
        html, internal_error, redirect,
    },
    identity::{
        session::{self, SESSION_COOKIE, SESSION_TTL},
        user::{self, NewAccount, SignUpError},
    },
};

#[derive(Deserialize)]
pub struct ReturnToQuery {
    return_to: Option<String>,
}

/// Sign-in form body. No `Debug` derive: it contains a password.
#[derive(Deserialize)]
pub struct SignInForm {
    #[serde(default)]
    email: String,
    #[serde(default)]
    password: String,
    return_to: Option<String>,
    csrf_token: Option<String>,
}

/// Sign-up form body. No `Debug` derive: it contains a password.
#[derive(Deserialize)]
pub struct SignUpForm {
    #[serde(default)]
    email: String,
    #[serde(default)]
    password: String,
    display_name: Option<String>,
    return_to: Option<String>,
    csrf_token: Option<String>,
}

#[derive(Deserialize)]
pub struct CsrfForm {
    csrf_token: Option<String>,
}

pub async fn health() -> &'static str {
    "sharp-oauth is alive"
}

/// `GET /`
pub async fn home(
    State(state): State<AppState>,
    headers: HeaderMap,
    CurrentSession(session): CurrentSession,
) -> Response {
    let csrf = csrf::issue(&headers, state.config.secure_cookies());
    let user = session.as_ref().map(|(_, user)| user);
    with_csrf_cookie(html::home_page(user, &csrf.value).into_response(), csrf)
}

/// `GET /signin?return_to=/oauth/authorize?...`
///
/// Always shows the form, even to a signed-in user: the authorization
/// endpoint sends users here precisely when it needs a *fresh* sign-in
/// (`prompt=login`, `max_age`).
pub async fn sign_in_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ReturnToQuery>,
) -> Response {
    let csrf = csrf::issue(&headers, state.config.secure_cookies());
    let return_to = query.return_to.as_deref().map(safe_return_to);
    let page = html::sign_in_page(&csrf.value, return_to, "", None);
    with_csrf_cookie(page.into_response(), csrf)
}

/// `POST /signin`
pub async fn sign_in(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<SignInForm>,
) -> Response {
    if !csrf::verify(&headers, form.csrf_token.as_deref()) {
        return csrf_failure();
    }
    let return_to = safe_return_to(form.return_to.as_deref().unwrap_or("/"));

    let user = match user::authenticate(&state.db, &form.email, form.password).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            let csrf = csrf::issue(&headers, state.config.secure_cookies());
            // Same message for "no such account" and "wrong password".
            let page = html::sign_in_page(
                &csrf.value,
                Some(return_to),
                &form.email,
                Some("Invalid email or password."),
            );
            return with_csrf_cookie((StatusCode::UNAUTHORIZED, page).into_response(), csrf);
        }
        Err(err) => return internal_error(err),
    };

    start_session(&state, &headers, &user, return_to).await
}

/// `GET /signup`
pub async fn sign_up_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ReturnToQuery>,
) -> Response {
    let csrf = csrf::issue(&headers, state.config.secure_cookies());
    let return_to = query.return_to.as_deref().map(safe_return_to);
    let page = html::sign_up_page(&csrf.value, return_to, "", "", None);
    with_csrf_cookie(page.into_response(), csrf)
}

/// `POST /signup`
pub async fn sign_up(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<SignUpForm>,
) -> Response {
    if !csrf::verify(&headers, form.csrf_token.as_deref()) {
        return csrf_failure();
    }
    let return_to = safe_return_to(form.return_to.as_deref().unwrap_or("/"));
    let display_name = form.display_name.clone().unwrap_or_default();

    let account = NewAccount {
        email: form.email.clone(),
        password: form.password,
        display_name: form.display_name,
    };
    let user = match user::sign_up(&state.db, account).await {
        Ok(user) => user,
        Err(SignUpError::Internal(err)) => return internal_error(err),
        Err(err) => {
            let csrf = csrf::issue(&headers, state.config.secure_cookies());
            let message = err.to_string();
            let page = html::sign_up_page(
                &csrf.value,
                Some(return_to),
                &form.email,
                &display_name,
                Some(&message),
            );
            return with_csrf_cookie(
                (StatusCode::UNPROCESSABLE_ENTITY, page).into_response(),
                csrf,
            );
        }
    };

    start_session(&state, &headers, &user, return_to).await
}

/// `POST /logout`
pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    if !csrf::verify(&headers, form.csrf_token.as_deref()) {
        return csrf_failure();
    }
    if let Some(token) = cookies::get(&headers, SESSION_COOKIE)
        && let Err(err) = session::revoke(&state.db, &token).await
    {
        return internal_error(err);
    }

    let mut response = redirect("/");
    response.headers_mut().append(
        header::SET_COOKIE,
        cookies::clear(SESSION_COOKIE, state.config.secure_cookies()),
    );
    response
}

/// Creates a session cookie for `user` and redirects to `return_to`.
async fn start_session(
    state: &AppState,
    headers: &HeaderMap,
    user: &crate::identity::user::User,
    return_to: &str,
) -> Response {
    // Retire any previous session in this browser, so an old (possibly
    // attacker-planted) session token does not outlive a fresh sign-in.
    if let Some(old) = cookies::get(headers, SESSION_COOKIE)
        && let Err(err) = session::revoke(&state.db, &old).await
    {
        return internal_error(err);
    }

    let token = match session::create(&state.db, user).await {
        Ok((token, _session)) => token,
        Err(err) => return internal_error(err),
    };

    let mut response = redirect(return_to);
    response.headers_mut().append(
        header::SET_COOKIE,
        cookies::set(
            SESSION_COOKIE,
            &token,
            Some(SESSION_TTL),
            state.config.secure_cookies(),
        ),
    );
    response
}

/// Only allow redirects to paths on this server.
///
/// `return_to` arrives in a URL anyone can craft. Without this check,
/// `/signin?return_to=https://evil.example` would turn our sign-in page into
/// an open redirector that lends Sharpnr's credibility to phishing links.
/// `//evil.example` and `/\evil.example` are rejected too: browsers treat both
/// as links to another host.
pub fn safe_return_to(candidate: &str) -> &str {
    let is_local_path = candidate.starts_with('/')
        && !candidate.starts_with("//")
        && !candidate.contains('\\')
        && !candidate.chars().any(char::is_control);
    if is_local_path { candidate } else { "/" }
}

/// Attaches the CSRF cookie if a new one was generated.
pub fn with_csrf_cookie(mut response: Response, csrf: CsrfToken) -> Response {
    if let Some(cookie) = csrf.set_cookie {
        response.headers_mut().append(header::SET_COOKIE, cookie);
    }
    response
}

pub fn csrf_failure() -> Response {
    html::error_page(
        StatusCode::FORBIDDEN,
        "Please try again",
        "This form expired or was submitted from another site. Go back, reload the page and try again.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn return_to_accepts_local_paths_only() {
        assert_eq!(
            safe_return_to("/oauth/authorize?client_id=x"),
            "/oauth/authorize?client_id=x"
        );
        assert_eq!(safe_return_to("/"), "/");

        for bad in [
            "https://evil.example",
            "//evil.example",
            "/\\evil.example",
            "evil",
            "",
            "/a\nb",
        ] {
            assert_eq!(safe_return_to(bad), "/", "{bad:?} must be rejected");
        }
    }
}
