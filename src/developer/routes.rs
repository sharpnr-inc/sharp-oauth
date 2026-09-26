//! Routes for the developer portal. Every page requires a signed-in user.
//!
//! | Method | Path                                    | Handler                  |
//! |--------|-----------------------------------------|--------------------------|
//! | GET    | `/developer/apps`                       | [`apps::list`]           |
//! | GET    | `/developer/apps/new`                   | [`apps::new_page`]       |
//! | POST   | `/developer/apps`                       | [`apps::create`]         |
//! | GET    | `/developer/apps/{client_id}`           | [`apps::show`]           |
//! | POST   | `/developer/apps/{client_id}`           | [`apps::update`]         |
//! | POST   | `/developer/apps/{client_id}/secret`    | [`apps::rotate_secret`]  |
//! | POST   | `/developer/apps/{client_id}/delete`    | [`apps::delete`]         |

use axum::{
    Router,
    routing::{get, post},
};

use crate::{AppState, developer::controllers::apps};

/// Pages used by a developer in a browser, on Sharpnr's own origin.
pub fn web_routes() -> Router<AppState> {
    Router::new()
        .route("/developer/apps", get(apps::list).post(apps::create))
        .route("/developer/apps/new", get(apps::new_page))
        .route(
            "/developer/apps/{client_id}",
            get(apps::show).post(apps::update),
        )
        .route(
            "/developer/apps/{client_id}/secret",
            post(apps::rotate_secret),
        )
        .route("/developer/apps/{client_id}/delete", post(apps::delete))
}
