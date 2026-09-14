//! HTTP handlers for the OAuth endpoints.

use axum::{
    Form, Json,
    extract::{Query, State, rejection::FormRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};

use crate::{
    AppState,
    error::AppError,
    http::{
        csrf::{self, CSRF_FIELD},
        extract::CurrentSession,
        html, internal_error,
        pages::{csrf_failure, with_csrf_cookie},
        redirect,
    },
    identity::{session::Session, user::User},
    oauth::{
        authorization::{self, AuthorizationError, AuthorizationRequest, NextStep},
        params::Params,
        revocation, token,
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
            let page = html::consent_page(
                &csrf.value,
                &validated.client.name,
                &user,
                &scopes,
                &request.to_pairs(),
            );
            with_csrf_cookie(page.into_response(), csrf)
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

/// `POST /oauth/token`
pub async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    form: Result<Form<Pairs>, FormRejection>,
) -> Response {
    let mut response = match form {
        Ok(Form(pairs)) => match token::handle(&state, authorization_header(&headers), pairs).await
        {
            Ok(tokens) => Json(tokens).into_response(),
            Err(err) => err.into_response(),
        },
        Err(_) => AppError::InvalidRequest("the body must be application/x-www-form-urlencoded")
            .into_response(),
    };
    // `Cache-Control: no-store` comes from the middleware; `Pragma` is for
    // old HTTP/1.0 caches (RFC 6749 §5.1).
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

/// `POST /oauth/revoke`
pub async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    form: Result<Form<Pairs>, FormRejection>,
) -> Response {
    let Ok(Form(pairs)) = form else {
        return AppError::InvalidRequest("the body must be application/x-www-form-urlencoded")
            .into_response();
    };
    match revocation::handle(&state, authorization_header(&headers), pairs).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(err) => err.into_response(),
    }
}

fn authorization_header(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
}

fn authorization_error(state: &AppState, err: AuthorizationError) -> Response {
    match err {
        AuthorizationError::Unsafe(message) => html::error_page(
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
    html::error_page(
        StatusCode::BAD_REQUEST,
        "This sign-in link is not valid",
        "A request parameter was included more than once.",
    )
}
