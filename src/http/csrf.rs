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

use axum::http::{HeaderMap, HeaderValue};

use crate::{
    http::cookies,
    secret::{constant_time_eq, generate_token},
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
    match cookies::get(headers, CSRF_COOKIE).filter(|value| value.len() == 43) {
        Some(value) => CsrfToken {
            value,
            set_cookie: None,
        },
        None => {
            let value = generate_token();
            let set_cookie = Some(cookies::set(CSRF_COOKIE, &value, None, secure));
            CsrfToken { value, set_cookie }
        }
    }
}

/// True if the submitted form token matches the cookie.
pub fn verify(headers: &HeaderMap, submitted: Option<&str>) -> bool {
    match (cookies::get(headers, CSRF_COOKIE), submitted) {
        (Some(cookie), Some(submitted)) => {
            constant_time_eq(cookie.as_bytes(), submitted.as_bytes())
        }
        _ => false,
    }
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
