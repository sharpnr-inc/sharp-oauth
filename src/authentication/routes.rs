//! Routes for the authentication feature.
//!
//! | Method   | Path       | Handler                     |
//! |----------|------------|-----------------------------|
//! | GET      | `/`        | [`pages::home`]             |
//! | GET/POST | `/signin`  | [`pages::sign_in_page`] / [`pages::sign_in`] |
//! | GET/POST | `/signup`  | [`pages::sign_up_page`] / [`pages::sign_up`] |
//! | POST     | `/logout`  | [`pages::logout`]           |

use axum::{
    Router,
    routing::{get, post},
};

use crate::{AppState, authentication::controllers::pages};

/// Pages used by a person in a browser, on Sharpnr's own origin.
pub fn web_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(pages::home))
        .route("/signin", get(pages::sign_in_page).post(pages::sign_in))
        .route("/signup", get(pages::sign_up_page).post(pages::sign_up))
        .route("/logout", post(pages::logout))
}
