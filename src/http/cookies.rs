//! Minimal cookie reading and writing.
//!
//! Every cookie we set uses the same hardened attributes:
//!
//! * `HttpOnly`: JavaScript cannot read it, so an XSS bug cannot steal it.
//! * `SameSite=Lax`: not sent on cross-site POSTs or sub-requests (a strong
//!   CSRF defence), but *is* sent when another site links the user to us
//!   with a top-level GET. That is exactly how `/oauth/authorize` is
//!   reached, so `Strict` would make every user look signed out there.
//! * `Secure` whenever the issuer is HTTPS (see `Config::secure_cookies`).
//! * `Path=/`.

use axum::http::{HeaderMap, HeaderValue, header};
use chrono::Duration;

/// Reads a cookie value from the request headers.
pub fn get(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.to_owned())
        .filter(|value| !value.is_empty())
}

/// A `Set-Cookie` header value. `max_age: None` makes a browser-session cookie.
///
/// `name` and `value` must be cookie-safe; we only ever pass constants and
/// base64url tokens.
pub fn set(name: &str, value: &str, max_age: Option<Duration>, secure: bool) -> HeaderValue {
    let mut cookie = format!("{name}={value}; Path=/; HttpOnly; SameSite=Lax");
    if let Some(max_age) = max_age {
        cookie.push_str(&format!("; Max-Age={}", max_age.num_seconds()));
    }
    if secure {
        cookie.push_str("; Secure");
    }
    HeaderValue::from_str(&cookie).expect("cookie names and values are header-safe")
}

/// A `Set-Cookie` header value that deletes the cookie.
pub fn clear(name: &str, secure: bool) -> HeaderValue {
    set(name, "", Some(Duration::zero()), secure)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_cookie_among_several() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("a=1; sharp_session=abc; b=2"),
        );
        assert_eq!(get(&headers, "sharp_session").as_deref(), Some("abc"));
        assert_eq!(get(&headers, "missing"), None);
    }

    #[test]
    fn cookie_name_must_match_exactly() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("xsharp_session=evil"),
        );
        assert_eq!(get(&headers, "sharp_session"), None);
    }

    #[test]
    fn set_cookie_has_security_attributes() {
        let value = set("sharp_session", "tok", Some(Duration::days(7)), true);
        let value = value.to_str().unwrap();
        assert!(value.contains("HttpOnly"));
        assert!(value.contains("SameSite=Lax"));
        assert!(value.contains("Secure"));
        assert!(value.contains("Max-Age=604800"));
    }
}
