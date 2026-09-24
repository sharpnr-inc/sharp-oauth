//! Browser-facing OAuth endpoints: `/oauth/authorize` and `/oauth/consent`.

use axum::{
    Form,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};

use crate::{
    AppState,
    authentication::services::{session::Session, user::User},
    middlewares::{
        auth::CurrentSession,
        csrf::{self, CSRF_FIELD, csrf_failure, with_csrf_cookie},
    },
    oauth::services::{
        authorization::{self, AuthorizationError, AuthorizationRequest, NextStep},
        params::Params,
    },
    shared::{
        response::{internal_error, redirect},
        views,
    },
};

type Pairs = Vec<(String, String)>;

/// `GET /oauth/authorize?response_type=code&client_id=…`
pub async fn authorize_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    CurrentSession(session): CurrentSession,
    Query(pairs): Query<Pairs>,
) -> Response {
    authorize(&state, &headers, session, pairs).await
}

/// `POST /oauth/authorize` with a form body. OIDC Core §3.1.2.1 requires
/// providers to accept both GET and POST.
pub async fn authorize_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    CurrentSession(session): CurrentSession,
    Form(pairs): Form<Pairs>,
) -> Response {
    authorize(&state, &headers, session, pairs).await
}

async fn authorize(
    state: &AppState,
    headers: &HeaderMap,
    session: Option<(Session, User)>,
    pairs: Pairs,
) -> Response {
    let Ok(params) = Params::from_pairs(pairs) else {
        return repeated_parameter_page();
    };
    let request = AuthorizationRequest::from_params(&params);

    match authorization::decide(state, &request, session).await {
        Ok(NextStep::SignIn { return_to }) => {
            let query = url::form_urlencoded::Serializer::new(String::new())
                .append_pair("return_to", &return_to)
                .finish();
            redirect(&format!("/signin?{query}"))
        }
        Ok(NextStep::AskConsent {
            request: validated,
            user,
            scopes,
        }) => {
            let csrf = csrf::issue(headers, state.config.secure_cookies());
            let page = views::consent_page(
                &csrf.value,
                &validated.client.name,
                &user,
                &scopes,
                &request.to_pairs(),
            );
            with_csrf_cookie(page, csrf)
        }
        Ok(NextStep::RedirectToClient(url)) => redirect(&url),
        Err(err) => authorization_error(state, err),
    }
}

/// `POST /oauth/consent`: the Allow / Deny buttons.
pub async fn consent(
    State(state): State<AppState>,
    headers: HeaderMap,
    CurrentSession(session): CurrentSession,
    Form(pairs): Form<Pairs>,
) -> Response {
    let Ok(params) = Params::from_pairs(pairs) else {
        return repeated_parameter_page();
    };
    if !csrf::verify(&headers, params.get(CSRF_FIELD)) {
        return csrf_failure();
    }
    let request = AuthorizationRequest::from_params(&params);

    // The session may have expired while the consent page was open.
    let Some((session, user)) = session else {
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("return_to", &request.to_path())
            .finish();
        return redirect(&format!("/signin?{query}"));
    };

    let approved = params.get("decision") == Some("approve");
    match authorization::complete_consent(&state, &request, approved, &session, &user).await {
        Ok(url) => redirect(&url),
        Err(err) => authorization_error(&state, err),
    }
}

fn authorization_error(state: &AppState, err: AuthorizationError) -> Response {
    match err {
        AuthorizationError::Unsafe(message) => views::error_page(
            StatusCode::BAD_REQUEST,
            "This sign-in link is not valid",
            message,
        ),
        AuthorizationError::Redirect(error) => match error.to_url(&state.config.issuer) {
            Ok(url) => redirect(&url),
            Err(err) => internal_error(err),
        },
        AuthorizationError::Internal(err) => internal_error(err),
    }
}

fn repeated_parameter_page() -> Response {
    views::error_page(
        StatusCode::BAD_REQUEST,
        "This sign-in link is not valid",
        "A request parameter was included more than once.",
    )
}
