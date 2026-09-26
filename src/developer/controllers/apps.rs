//! Developer portal pages: a signed-in user's applications.
//!
//! Every handler takes [`SignedInUser`], so without a session the browser is
//! sent to `/signin` before the handler runs. For a single application, not
//! the owner → 404. Every POST also checks the CSRF token, like the account
//! pages do.

use axum::{
    Form,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};

use crate::{
    AppState,
    authentication::services::user::User,
    developer::{
        dtos::{AppForm, NoticeQuery},
        services::apps::{self, AppFormError},
    },
    middlewares::{
        auth::SignedInUser,
        csrf::{self, csrf_failure, with_csrf_cookie},
    },
    oauth::{repo::scopes, services::client::OAuthClient},
    shared::{
        response::{internal_error, redirect},
        views::{self, DeveloperAppMessages},
    },
};

/// `GET /developer/apps`
pub async fn list(
    State(state): State<AppState>,
    SignedInUser(user): SignedInUser,
    Query(query): Query<NoticeQuery>,
) -> Response {
    let apps = match apps::list(&state.db, &user).await {
        Ok(apps) => apps,
        Err(err) => return internal_error(err),
    };
    // Only known values produce a message, so a crafted URL cannot put
    // arbitrary text on the page.
    let notice = match query.notice.as_deref() {
        Some("deleted") => Some("Application deleted. Its tokens no longer work."),
        _ => None,
    };
    views::developer_apps_page(&apps, notice)
}

/// `GET /developer/apps/new`
pub async fn new_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    _user: SignedInUser,
) -> Response {
    let form = AppForm {
        scopes: vec!["openid".into()],
        client_type: "confidential".into(),
        ..AppForm::default()
    };
    new_app_form(&state, &headers, StatusCode::OK, &form, None).await
}

/// `POST /developer/apps`
pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    SignedInUser(user): SignedInUser,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    let form = AppForm::from_pairs(pairs);
    if !csrf::verify(&headers, form.csrf_token.as_deref()) {
        return csrf_failure();
    }

    match apps::create(&state.db, &user, &form).await {
        // The secret is rendered straight into this response instead of
        // redirecting: a redirect would need to carry it in the URL or store
        // it somewhere, and it must exist in plaintext nowhere but here.
        Ok(registered) => {
            let form = AppForm::from_client(&registered.client);
            let notice = if registered.client_secret.is_some() {
                "Application created. Copy the client secret now: it will not be shown again."
            } else {
                "Application created."
            };
            app_page(
                &state,
                &headers,
                StatusCode::CREATED,
                &registered.client,
                &form,
                DeveloperAppMessages {
                    new_secret: registered.client_secret.as_deref(),
                    notice: Some(notice),
                    error: None,
                },
            )
            .await
        }
        Err(AppFormError::Database(err)) => internal_error(err),
        Err(err) => {
            let message = err.to_string();
            new_app_form(
                &state,
                &headers,
                StatusCode::UNPROCESSABLE_ENTITY,
                &form,
                Some(&message),
            )
            .await
        }
    }
}

/// `GET /developer/apps/{client_id}`
pub async fn show(
    State(state): State<AppState>,
    headers: HeaderMap,
    SignedInUser(user): SignedInUser,
    Path(client_id): Path<String>,
    Query(query): Query<NoticeQuery>,
) -> Response {
    let app = match owned_app(&state, &user, &client_id).await {
        Ok(app) => app,
        Err(response) => return response,
    };
    let notice = match query.notice.as_deref() {
        Some("saved") => Some("Changes saved."),
        _ => None,
    };
    let form = AppForm::from_client(&app);
    let messages = DeveloperAppMessages {
        notice,
        ..DeveloperAppMessages::default()
    };
    app_page(&state, &headers, StatusCode::OK, &app, &form, messages).await
}

/// `POST /developer/apps/{client_id}`: save name, redirect URLs and scopes.
pub async fn update(
    State(state): State<AppState>,
    headers: HeaderMap,
    SignedInUser(user): SignedInUser,
    Path(client_id): Path<String>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    let app = match owned_app(&state, &user, &client_id).await {
        Ok(app) => app,
        Err(response) => return response,
    };
    let form = AppForm::from_pairs(pairs);
    if !csrf::verify(&headers, form.csrf_token.as_deref()) {
        return csrf_failure();
    }

    match apps::update(&state.db, &app, &form).await {
        Ok(()) => redirect(&format!("/developer/apps/{}?notice=saved", app.client_id)),
        Err(AppFormError::Database(err)) => internal_error(err),
        Err(err) => {
            let message = err.to_string();
            let messages = DeveloperAppMessages {
                error: Some(&message),
                ..DeveloperAppMessages::default()
            };
            app_page(
                &state,
                &headers,
                StatusCode::UNPROCESSABLE_ENTITY,
                &app,
                &form,
                messages,
            )
            .await
        }
    }
}

/// `POST /developer/apps/{client_id}/secret`
pub async fn rotate_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    SignedInUser(user): SignedInUser,
    Path(client_id): Path<String>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    let app = match owned_app(&state, &user, &client_id).await {
        Ok(app) => app,
        Err(response) => return response,
    };
    let form = AppForm::from_pairs(pairs);
    if !csrf::verify(&headers, form.csrf_token.as_deref()) {
        return csrf_failure();
    }

    match apps::rotate_secret(&state.db, &app).await {
        Ok(Some(secret)) => {
            let messages = DeveloperAppMessages {
                new_secret: Some(&secret),
                notice: Some("New client secret created. The old secret has stopped working."),
                error: None,
            };
            let form = AppForm::from_client(&app);
            app_page(&state, &headers, StatusCode::OK, &app, &form, messages).await
        }
        // A public app has no secret; nothing to do.
        Ok(None) => redirect(&format!("/developer/apps/{}", app.client_id)),
        Err(err) => internal_error(err),
    }
}

/// `POST /developer/apps/{client_id}/delete`
pub async fn delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    SignedInUser(user): SignedInUser,
    Path(client_id): Path<String>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    let app = match owned_app(&state, &user, &client_id).await {
        Ok(app) => app,
        Err(response) => return response,
    };
    let form = AppForm::from_pairs(pairs);
    if !csrf::verify(&headers, form.csrf_token.as_deref()) {
        return csrf_failure();
    }

    // The checkbox is `required`, so a browser will not submit without it;
    // this catches anything that bypasses the browser.
    if !form.confirm {
        let messages = DeveloperAppMessages {
            error: Some("Tick the confirmation box to delete this application."),
            ..DeveloperAppMessages::default()
        };
        let form = AppForm::from_client(&app);
        return app_page(
            &state,
            &headers,
            StatusCode::UNPROCESSABLE_ENTITY,
            &app,
            &form,
            messages,
        )
        .await;
    }

    match apps::delete(&state.db, &app).await {
        Ok(()) => redirect("/developer/apps?notice=deleted"),
        Err(err) => internal_error(err),
    }
}

/// The application `client_id`, if `user` owns it; otherwise a 404 page.
async fn owned_app(
    state: &AppState,
    user: &User,
    client_id: &str,
) -> Result<OAuthClient, Response> {
    match apps::find(&state.db, user, client_id).await {
        Ok(Some(app)) => Ok(app),
        Ok(None) => Err(views::error_page(
            StatusCode::NOT_FOUND,
            "Application not found",
            "It may have been deleted, or it belongs to a different Sharpnr account.",
        )),
        Err(err) => Err(internal_error(err)),
    }
}

async fn new_app_form(
    state: &AppState,
    headers: &HeaderMap,
    status: StatusCode,
    form: &AppForm,
    error: Option<&str>,
) -> Response {
    let scopes = match scopes::list_all(&state.db).await {
        Ok(scopes) => scopes,
        Err(err) => return internal_error(err),
    };
    let csrf = csrf::issue(headers, state.config.secure_cookies());
    let page = views::developer_new_app_page(status, &csrf.value, &scopes, form, error);
    with_csrf_cookie(page, csrf)
}

async fn app_page(
    state: &AppState,
    headers: &HeaderMap,
    status: StatusCode,
    app: &OAuthClient,
    form: &AppForm,
    messages: DeveloperAppMessages<'_>,
) -> Response {
    let scopes = match scopes::list_all(&state.db).await {
        Ok(scopes) => scopes,
        Err(err) => return internal_error(err),
    };
    let csrf = csrf::issue(headers, state.config.secure_cookies());
    let page = views::developer_app_page(
        status,
        &csrf.value,
        &state.config.issuer,
        app,
        &scopes,
        form,
        messages,
    );
    with_csrf_cookie(page, csrf)
}
