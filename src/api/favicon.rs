//! `GET /favicon.svg`: the Sharp-OAuth mark for browser tabs.
//!
//! Compiled into the binary, so the server needs no static-file directory.
//! The SVG switches its ink shards to light grey in dark mode.

use axum::{
    http::{HeaderValue, header},
    response::{IntoResponse, Response},
};

const FAVICON_SVG: &str = include_str!("../../assets/web/favicon.svg");

pub async fn favicon() -> Response {
    (
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("image/svg+xml"),
            ),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=86400"),
            ),
        ],
        FAVICON_SVG,
    )
        .into_response()
}
