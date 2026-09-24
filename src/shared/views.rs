//! Server-rendered HTML pages.
//!
//! The markup lives in `templates/` as ordinary `.html` files, rendered with
//! [Askama](https://crates.io/crates/askama). Each struct below is the data
//! one template may use; Askama compiles the templates during `cargo build`,
//! so a typo in a field name is a build error rather than a broken page.
//!
//! **Escaping is automatic.** `{{ value }}` in an `.html` template is
//! HTML-escaped, so a client name like `<script>…` can never become markup on
//! our sign-in pages. Nothing here needs a manual escape call, and nobody can
//! forget one.
//!
//! These pages are deliberately plain: no JavaScript and no external
//! resources, which is what lets the Content-Security-Policy stay at
//! `default-src 'none'` (see [`crate::middlewares::security_headers`]).
//! They are the most security-sensitive screens in the product, so the less that runs on them,
//! the better.

use askama::Template;
use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};

use crate::{authentication::services::user::User, oauth::repo::scopes::ScopeDescription};

#[derive(Template)]
#[template(path = "home.html")]
struct HomeTemplate<'a> {
    user: Option<&'a User>,
    csrf: &'a str,
}

#[derive(Template)]
#[template(path = "signin.html")]
struct SignInTemplate<'a> {
    csrf: &'a str,
    return_to: Option<&'a str>,
    /// `?return_to=…`, already percent-encoded, for the link to `/signup`.
    return_to_query: String,
    email: &'a str,
    error: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "signup.html")]
struct SignUpTemplate<'a> {
    csrf: &'a str,
    return_to: Option<&'a str>,
    return_to_query: String,
    email: &'a str,
    display_name: &'a str,
    error: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "consent.html")]
struct ConsentTemplate<'a> {
    csrf: &'a str,
    client_name: &'a str,
    user: &'a User,
    scopes: &'a [ScopeDescription],
    request_fields: &'a [(&'a str, &'a str)],
}

#[derive(Template)]
#[template(path = "error.html")]
struct ErrorTemplate<'a> {
    title: &'a str,
    message: &'a str,
}

pub fn home_page(user: Option<&User>, csrf: &str) -> Response {
    render(StatusCode::OK, HomeTemplate { user, csrf })
}

pub fn sign_in_page(
    status: StatusCode,
    csrf: &str,
    return_to: Option<&str>,
    email: &str,
    error: Option<&str>,
) -> Response {
    render(
        status,
        SignInTemplate {
            csrf,
            return_to,
            return_to_query: return_to_query(return_to),
            email,
            error,
        },
    )
}

pub fn sign_up_page(
    status: StatusCode,
    csrf: &str,
    return_to: Option<&str>,
    email: &str,
    display_name: &str,
    error: Option<&str>,
) -> Response {
    render(
        status,
        SignUpTemplate {
            csrf,
            return_to,
            return_to_query: return_to_query(return_to),
            email,
            display_name,
            error,
        },
    )
}

/// The consent screen.
///
/// `request_fields` are the original authorization parameters, re-submitted
/// as hidden fields so the consent POST can validate the request again.
pub fn consent_page(
    csrf: &str,
    client_name: &str,
    user: &User,
    scopes: &[ScopeDescription],
    request_fields: &[(&str, &str)],
) -> Response {
    render(
        StatusCode::OK,
        ConsentTemplate {
            csrf,
            client_name,
            user,
            scopes,
            request_fields,
        },
    )
}

pub fn error_page(status: StatusCode, title: &str, message: &str) -> Response {
    render(status, ErrorTemplate { title, message })
}

/// Renders a template, falling back to a fixed page if rendering fails.
///
/// Templates are checked at compile time, so a failure here means something
/// like an allocation error rather than a broken template. We still never
/// panic in a request handler.
fn render(status: StatusCode, template: impl Template) -> Response {
    match template.render() {
        Ok(body) => (status, Html(body)).into_response(),
        Err(err) => {
            tracing::error!(error = %err, "failed to render a template");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html("<h1>Something went wrong</h1><p>Please try again in a moment.</p>"),
            )
                .into_response()
        }
    }
}

fn return_to_query(return_to: Option<&str>) -> String {
    return_to
        .map(|path| {
            format!(
                "?{}",
                url::form_urlencoded::Serializer::new(String::new())
                    .append_pair("return_to", path)
                    .finish()
            )
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use uuid::Uuid;

    use super::*;

    fn user() -> User {
        User {
            id: Uuid::now_v7(),
            email: "kashif@sharpnr.com".into(),
            password_hash: "$argon2id$secret".into(),
            display_name: None,
            email_verified: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn body_of(template: impl Template) -> String {
        template.render().unwrap()
    }

    #[test]
    fn hostile_client_name_cannot_inject_markup() {
        // A client name is chosen by whoever registered the application.
        let body = body_of(ConsentTemplate {
            csrf: "token",
            client_name: r#"<script>alert("xss")</script>"#,
            user: &user(),
            scopes: &[],
            request_fields: &[],
        });

        assert!(!body.contains("<script>"), "{body}");
        // Askama writes numeric character references (`&#60;`); named
        // entities (`&lt;`) are equally valid, so accept either.
        assert!(
            body.contains("&#60;script&#62;") || body.contains("&lt;script&gt;"),
            "{body}"
        );
    }

    #[test]
    fn hidden_field_values_cannot_break_out_of_the_attribute() {
        // `state` is copied straight from the client's request.
        let body = body_of(ConsentTemplate {
            csrf: "token",
            client_name: "App",
            user: &user(),
            scopes: &[],
            request_fields: &[("state", "\"><script>")],
        });

        assert!(!body.contains(r#"value=""><script>"#), "{body}");
        assert!(!body.contains("<script>"), "{body}");
        assert!(
            body.contains(r#"value="&#34;&#62;&#60;script&#62;""#)
                || body.contains(r#"value="&quot;&gt;&lt;script&gt;""#),
            "{body}"
        );
    }

    #[test]
    fn sign_in_page_carries_csrf_token_and_return_path() {
        let body = body_of(SignInTemplate {
            csrf: "csrf-value",
            return_to: Some("/oauth/authorize?client_id=abc"),
            return_to_query: return_to_query(Some("/oauth/authorize?client_id=abc")),
            email: "",
            error: Some("Invalid email or password."),
        });

        assert!(
            body.contains(r#"<input type="hidden" name="csrf_token" value="csrf-value">"#),
            "{body}"
        );
        assert!(
            body.contains(r#"name="return_to" value="/oauth/authorize?client_id=abc"#),
            "{body}"
        );
        assert!(body.contains("Invalid email or password."), "{body}");
        assert!(
            body.contains("/signup?return_to=%2Foauth%2Fauthorize"),
            "{body}"
        );
    }
}
