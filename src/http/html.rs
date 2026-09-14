//! Server-rendered HTML pages.
//!
//! Deliberately plain: `format!` strings, no template engine, no JavaScript.
//! Visual polish comes after the protocol is correct.
//!
//! **Every dynamic value goes through [`escape`].** Values like the client
//! name, email or `state` come from users or third parties; unescaped they
//! would let someone inject HTML (and script) into our sign-in pages.

use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};

use crate::{db::scopes::ScopeDescription, http::csrf::CSRF_FIELD, identity::user::User};

/// Escapes text for use in HTML content and double-quoted attributes.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

const STYLE: &str = "
  body { font-family: system-ui, sans-serif; background: #f4f5f7; color: #1d2433; margin: 0; }
  main { max-width: 420px; margin: 8vh auto; background: #fff; padding: 2rem; border-radius: 12px;
         box-shadow: 0 2px 12px rgba(0,0,0,.08); }
  h1 { font-size: 1.4rem; margin-top: 0; }
  label { display: block; margin: 1rem 0 .3rem; font-weight: 600; }
  input[type=email], input[type=password], input[type=text] {
         width: 100%; box-sizing: border-box; padding: .6rem; border: 1px solid #c8ccd4; border-radius: 6px; }
  button { margin-top: 1.2rem; padding: .6rem 1.2rem; border: 0; border-radius: 6px; font-size: 1rem;
           background: #2456d3; color: #fff; cursor: pointer; }
  button.secondary { background: #e4e7ec; color: #1d2433; }
  .error { background: #fde8e8; color: #9b1c1c; padding: .6rem; border-radius: 6px; }
  .muted { color: #5b6475; font-size: .9rem; }
  ul.scopes { padding-left: 1.2rem; }
";

fn layout(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{title} · Sharpnr</title><style>{STYLE}</style></head>\
         <body><main>{body}</main></body></html>",
        title = escape(title),
    )
}

fn hidden(name: &str, value: &str) -> String {
    format!(
        "<input type=\"hidden\" name=\"{}\" value=\"{}\">",
        escape(name),
        escape(value)
    )
}

fn error_banner(error: Option<&str>) -> String {
    error
        .map(|message| format!("<p class=\"error\">{}</p>", escape(message)))
        .unwrap_or_default()
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

pub fn home_page(user: Option<&User>, csrf: &str) -> Html<String> {
    let body = match user {
        Some(user) => format!(
            "<h1>Sharpnr account</h1>\
             <p>You are signed in as <strong>{email}</strong>.</p>\
             <form method=\"post\" action=\"/logout\">{csrf}<button class=\"secondary\">Sign out</button></form>",
            email = escape(&user.email),
            csrf = hidden(CSRF_FIELD, csrf),
        ),
        None => "<h1>Sharpnr account</h1>\
                 <p>You are not signed in.</p>\
                 <p><a href=\"/signin\">Sign in</a> or <a href=\"/signup\">create an account</a>.</p>"
            .to_owned(),
    };
    Html(layout("Account", &body))
}

pub fn sign_in_page(
    csrf: &str,
    return_to: Option<&str>,
    email: &str,
    error: Option<&str>,
) -> Html<String> {
    let body = format!(
        "<h1>Sign in to Sharpnr</h1>{error}\
         <form method=\"post\" action=\"/signin\">\
           {csrf}{return_to}\
           <label for=\"email\">Email</label>\
           <input id=\"email\" type=\"email\" name=\"email\" value=\"{email}\" autocomplete=\"username\" required>\
           <label for=\"password\">Password</label>\
           <input id=\"password\" type=\"password\" name=\"password\" autocomplete=\"current-password\" required>\
           <button>Sign in</button>\
         </form>\
         <p class=\"muted\">No account? <a href=\"/signup{query}\">Create one</a>.</p>",
        error = error_banner(error),
        csrf = hidden(CSRF_FIELD, csrf),
        return_to = return_to
            .map(|r| hidden("return_to", r))
            .unwrap_or_default(),
        email = escape(email),
        query = escape(&return_to_query(return_to)),
    );
    Html(layout("Sign in", &body))
}

pub fn sign_up_page(
    csrf: &str,
    return_to: Option<&str>,
    email: &str,
    display_name: &str,
    error: Option<&str>,
) -> Html<String> {
    let body = format!(
        "<h1>Create your Sharpnr account</h1>{error}\
         <form method=\"post\" action=\"/signup\">\
           {csrf}{return_to}\
           <label for=\"email\">Email</label>\
           <input id=\"email\" type=\"email\" name=\"email\" value=\"{email}\" autocomplete=\"username\" required>\
           <label for=\"display_name\">Display name (optional)</label>\
           <input id=\"display_name\" type=\"text\" name=\"display_name\" value=\"{display_name}\" autocomplete=\"name\">\
           <label for=\"password\">Password</label>\
           <input id=\"password\" type=\"password\" name=\"password\" autocomplete=\"new-password\" minlength=\"8\" required>\
           <button>Create account</button>\
         </form>\
         <p class=\"muted\">Already have an account? <a href=\"/signin{query}\">Sign in</a>.</p>",
        error = error_banner(error),
        csrf = hidden(CSRF_FIELD, csrf),
        return_to = return_to
            .map(|r| hidden("return_to", r))
            .unwrap_or_default(),
        email = escape(email),
        display_name = escape(display_name),
        query = escape(&return_to_query(return_to)),
    );
    Html(layout("Create account", &body))
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
) -> Html<String> {
    let scope_items: String = scopes
        .iter()
        .map(|scope| format!("<li>{}</li>", escape(&scope.description)))
        .collect();
    let fields: String = request_fields
        .iter()
        .map(|(name, value)| hidden(name, value))
        .collect();

    let body = format!(
        "<h1>{client} wants to access your Sharpnr account</h1>\
         <p class=\"muted\">Signed in as {email}</p>\
         <p>This will allow <strong>{client}</strong> to:</p>\
         <ul class=\"scopes\">{scope_items}</ul>\
         <form method=\"post\" action=\"/oauth/consent\">\
           {csrf}{fields}\
           <button name=\"decision\" value=\"approve\">Allow</button> \
           <button name=\"decision\" value=\"deny\" class=\"secondary\">Deny</button>\
         </form>\
         <p class=\"muted\">You will be sent back to {client}. Only continue if you trust this application.</p>",
        client = escape(client_name),
        email = escape(&user.email),
        csrf = hidden(CSRF_FIELD, csrf),
    );
    Html(layout("Authorize application", &body))
}

pub fn error_page(status: StatusCode, title: &str, message: &str) -> Response {
    let body = format!("<h1>{}</h1><p>{}</p>", escape(title), escape(message));
    (status, Html(layout(title, &body))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_html_special_characters() {
        assert_eq!(
            escape(r#"<script>alert("x")</script> & 'y'"#),
            "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt; &amp; &#39;y&#39;"
        );
    }

    #[test]
    fn hidden_field_values_cannot_break_out_of_the_attribute() {
        let field = hidden("state", "\"><script>");
        assert!(!field.contains("<script>"));
    }
}
