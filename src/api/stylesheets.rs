//! `GET /css/{file}`: the stylesheets for our HTML pages.
//!
//! The CSS sits next to the templates in `templates/*.css` and is compiled
//! into the binary, like the favicon, so the server needs no static-file
//! directory. Serving it from our own origin (instead of inline `<style>`)
//! lets the CSP be `style-src 'self'` with no `'unsafe-inline'`.
//!
//! Only the files listed in [`STYLESHEETS`] exist; any other name is a 404,
//! so the path can never reach the filesystem.

use axum::{
    extract::Path,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};

const STYLESHEETS: &[(&str, &str)] = &[
    ("layout.css", include_str!("../../templates/layout.css")),
    ("signin.css", include_str!("../../templates/signin.css")),
    ("signup.css", include_str!("../../templates/signup.css")),
    ("consent.css", include_str!("../../templates/consent.css")),
    ("home.css", include_str!("../../templates/home.css")),
    ("error.css", include_str!("../../templates/error.css")),
];

pub async fn stylesheet(Path(file): Path<String>) -> Response {
    let Some((_, css)) = STYLESHEETS.iter().find(|(name, _)| *name == file) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    (
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/css; charset=utf-8"),
            ),
            // Short enough that a deploy's new styles show up within the
            // hour, since the URLs carry no version.
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=3600"),
            ),
        ],
        *css,
    )
        .into_response()
}
