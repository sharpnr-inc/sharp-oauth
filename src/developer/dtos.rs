//! The application form submitted by the developer portal pages.

use serde::Deserialize;

use crate::oauth::services::{client::OAuthClient, scope::ScopeSet};

/// `?notice=…`, set when a form redirects back to a page.
#[derive(Deserialize)]
pub struct NoticeQuery {
    pub notice: Option<String>,
}

/// The create/edit application form, as submitted.
///
/// It is also what the page shows again after a validation error, so the
/// developer does not lose what they typed.
///
/// The form has one checkbox per scope, all named `scope`, so the body can
/// repeat a key (`scope=openid&scope=email`). Axum's `Form` cannot collect
/// repeated keys into a struct field, so handlers take the raw pairs and
/// build this with [`AppForm::from_pairs`].
#[derive(Default)]
pub struct AppForm {
    pub csrf_token: Option<String>,
    pub name: String,
    /// The textarea's raw text: one redirect URL per line.
    pub redirect_uris: String,
    pub scopes: Vec<String>,
    /// `"public"` or `"confidential"`. Only used when creating an app.
    pub client_type: String,
    /// The "I understand" checkbox on the delete form.
    pub confirm: bool,
}

impl AppForm {
    pub fn from_pairs(pairs: Vec<(String, String)>) -> Self {
        let mut form = AppForm::default();
        for (name, value) in pairs {
            match name.as_str() {
                // A page with several forms repeats the token; they are equal.
                "csrf_token" if form.csrf_token.is_none() => form.csrf_token = Some(value),
                "name" => form.name = value,
                "redirect_uris" => form.redirect_uris = value,
                "scope" if !form.scopes.contains(&value) => form.scopes.push(value),
                "client_type" => form.client_type = value,
                "confirm" => form.confirm = value == "yes",
                _ => {}
            }
        }
        form
    }

    /// The form's current values for an existing application.
    pub fn from_client(client: &OAuthClient) -> Self {
        AppForm {
            name: client.name.clone(),
            redirect_uris: client.redirect_uris.join("\n"),
            scopes: client.allowed_scopes.clone(),
            client_type: if client.is_confidential() {
                "confidential"
            } else {
                "public"
            }
            .into(),
            ..AppForm::default()
        }
    }

    /// Anything other than an explicit `public` gets a secret: the safer
    /// default if the field is missing.
    pub fn is_public(&self) -> bool {
        self.client_type == "public"
    }

    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }

    /// Non-empty lines of the textarea, trimmed.
    pub fn redirect_uri_list(&self) -> Vec<String> {
        self.redirect_uris
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect()
    }

    pub fn scope_set(&self) -> ScopeSet {
        self.scopes.iter().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(items: &[(&str, &str)]) -> Vec<(String, String)> {
        items
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn collects_repeated_scopes_and_splits_redirect_lines() {
        let form = AppForm::from_pairs(pairs(&[
            ("csrf_token", "first"),
            ("csrf_token", "second"),
            ("name", "My App"),
            (
                "redirect_uris",
                "https://a.example/cb\r\n\n  https://b.example/cb  \n",
            ),
            ("scope", "openid"),
            ("scope", "email"),
            ("scope", "openid"),
            ("client_type", "public"),
        ]));

        assert_eq!(form.csrf_token.as_deref(), Some("first"));
        assert_eq!(form.scopes, ["openid", "email"]);
        assert_eq!(
            form.redirect_uri_list(),
            ["https://a.example/cb", "https://b.example/cb"]
        );
        assert!(form.is_public());
        assert!(!form.confirm);
    }

    #[test]
    fn missing_client_type_means_confidential() {
        assert!(!AppForm::from_pairs(vec![]).is_public());
    }
}
