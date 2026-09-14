//! The HTTP layer: everything that knows about Axum, headers and HTML.
//!
//! Handlers here are intentionally thin. A typical handler:
//!
//! 1. extracts raw input (query, form, headers, cookies),
//! 2. calls one service function (`oauth::token::handle`, …),
//! 3. turns the result into a response (JSON, redirect or HTML page).
//!
//! Protocol decisions (is this redirect URI allowed? is this code expired?)
//! never happen here.
//!
//! * [`routes`]: the URL map
//! * [`middleware`]: security headers and request logging
//! * [`pages`]: home, sign-in, sign-up and logout pages
//! * [`oauth`]: `/oauth/authorize`, `/oauth/consent`, `/oauth/token`, `/oauth/revoke`
//! * [`oidc`]: discovery, JWKS and UserInfo
//! * [`extract`]: the current-session extractor
//! * [`cookies`], [`csrf`], [`html`]: small helpers used by the pages

pub mod cookies;
pub mod csrf;
pub mod extract;
pub mod html;
pub mod middleware;
pub mod oauth;
pub mod oidc;
pub mod pages;
pub mod routes;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};

/// A `303 See Other` redirect.
///
/// 303 always turns into a GET. We never use 307/308 for OAuth redirects:
/// those replay a POST body, which after a sign-in form would forward the
/// user's password to the client's redirect URI (RFC 9700 §4.12).
pub fn redirect(location: &str) -> Response {
    Redirect::to(location).into_response()
}

/// Logs an internal error and renders a generic error page.
pub fn internal_error(err: impl std::fmt::Display) -> Response {
    tracing::error!(error = %err, "internal error while rendering a page");
    html::error_page(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Something went wrong",
        "Please try again in a moment.",
    )
}
