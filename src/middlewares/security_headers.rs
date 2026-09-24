//! Middleware applied to every response.

use std::time::Instant;

use axum::{
    extract::Request,
    http::{HeaderValue, header},
    middleware::Next,
    response::Response,
};

/// Adds defensive HTTP headers.
///
/// | Header                     | Why                                                          |
/// |----------------------------|--------------------------------------------------------------|
/// | `X-Frame-Options: DENY` and CSP `frame-ancestors 'none'` | Clickjacking: a hostile site must not be able to show our consent page in an invisible iframe and trick the user into clicking "Allow". |
/// | CSP `default-src 'none'`   | Our pages load no scripts, images or external resources.     |
/// | `X-Content-Type-Options`   | Stops browsers guessing a different content type.            |
/// | `Referrer-Policy: no-referrer` | URLs may contain `state`/`code` values; never leak them via `Referer`. |
/// | `Cache-Control: no-store`  | Tokens and personal pages must not be cached (RFC 6749 §5.1). Handlers that serve public, cacheable data (JWKS, discovery) set their own value. |
///
/// CSP deliberately has no `form-action`: browsers apply it to the redirect
/// *after* a form submit, which would block the final redirect to the
/// client's callback URL.
pub async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    if !headers.contains_key(header::CACHE_CONTROL) {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    response
}

/// Logs one line per request.
///
/// Only the *path* is logged, never the query string: query strings on
/// `/oauth/authorize` and `/signin` carry request details we do not want in
/// logs. Headers and bodies (passwords, secrets, tokens) are never logged.
pub async fn log_requests(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let started = Instant::now();

    let response = next.run(request).await;

    tracing::info!(
        %method,
        %path,
        status = response.status().as_u16(),
        elapsed_ms = started.elapsed().as_millis() as u64,
        "request"
    );
    response
}
