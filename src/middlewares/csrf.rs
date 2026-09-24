//! CSRF protection for our HTML forms (double-submit cookie pattern).
//!
//! **The attack:** a malicious site auto-submits a hidden form to
//! `POST /oauth/consent` with `decision=approve`. The victim's browser
//! attaches their Sharpnr cookie, and the attacker's app is approved without
//! the user ever seeing a consent screen. The same trick against `/signin`
//! can sign the victim into the *attacker's* account ("login CSRF").
//!
//! **The defence:** when we render a form we also set a random `sharp_csrf`
//! cookie and put the same value in a hidden `csrf_token` field. On submit
//! both must match. An attacker's page can make the browser *send* our
//! cookie, but cannot *read* it, so it cannot put the right value in the form.
//!
//! `SameSite=Lax` on the session cookie already blocks most of these; this
//! is a second, independent layer.

use axum::{
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::Response,
};

use crate::{
    pkg::cookie_manager,
    shared::{
        secret::{constant_time_eq, generate_token},
        views,
    },
};

pub const CSRF_COOKIE: &str = "sharp_csrf";
pub const CSRF_FIELD: &str = "csrf_token";

/// A token to embed in a form, plus the cookie to set if it is new.
pub struct CsrfToken {
    pub value: String,
    pub set_cookie: Option<HeaderValue>,
}

/// Reuses the browser's existing CSRF cookie or creates a new one.
///
/// Reusing it means several open tabs keep working instead of each new page
/// invalidating the forms in the others.
pub fn issue(headers: &HeaderMap, secure: bool) -> CsrfToken {
    match cookie_manager::get(headers, CSRF_COOKIE).filter(|value| value.len() == 43) {
        Some(value) => CsrfToken {
            value,
            set_cookie: None,
        },
        None => {
            let value = generate_token();
            let set_cookie = Some(cookie_manager::set(CSRF_COOKIE, &value, None, secure));
            CsrfToken { value, set_cookie }
        }
    }
}

/// True if the submitted form token matches the cookie.
pub fn verify(headers: &HeaderMap, submitted: Option<&str>) -> bool {
    match (cookie_manager::get(headers, CSRF_COOKIE), submitted) {
        (Some(cookie), Some(submitted)) => {
            constant_time_eq(cookie.as_bytes(), submitted.as_bytes())
        }
        _ => false,
    }
}

/// Attaches the CSRF cookie if a new one was generated.
pub fn with_csrf_cookie(mut response: Response, csrf: CsrfToken) -> Response {
    if let Some(cookie) = csrf.set_cookie {
        response.headers_mut().append(header::SET_COOKIE, cookie);
    }
    response
}

/// The page shown when a form's CSRF token is missing or wrong.
pub fn csrf_failure() -> Response {
    views::error_page(
        StatusCode::FORBIDDEN,
        "Please try again",
        "This form expired or was submitted from another site. Go back, reload the page and try again.",
    )
}

#[cfg(test)]
mod tests {
    use axum::http::header;

    use super::*;

    fn headers_with_cookie(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("{CSRF_COOKIE}={value}")).unwrap(),
        );
        headers
    }

    #[test]
    fn matching_token_verifies() {
        let token = generate_token();
        assert!(verify(&headers_with_cookie(&token), Some(&token)));
    }

    #[test]
    fn missing_or_different_token_fails() {
        let token = generate_token();
        assert!(!verify(&headers_with_cookie(&token), None));
        assert!(!verify(
            &headers_with_cookie(&token),
            Some(&generate_token())
        ));
        assert!(!verify(&HeaderMap::new(), Some(&token)));
    }

    #[test]
    fn existing_cookie_is_reused() {
        let token = generate_token();
        let issued = issue(&headers_with_cookie(&token), false);
        assert_eq!(issued.value, token);
        assert!(issued.set_cookie.is_none());

        let fresh = issue(&HeaderMap::new(), false);
        assert!(fresh.set_cookie.is_some());
    }
}
