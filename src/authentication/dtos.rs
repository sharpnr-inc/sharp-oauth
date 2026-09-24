//! Form and query bodies submitted to the authentication pages.

use serde::Deserialize;

#[derive(Deserialize)]
pub struct ReturnToQuery {
    pub return_to: Option<String>,
}

/// Sign-in form body. No `Debug` derive: it contains a password.
#[derive(Deserialize)]
pub struct SignInForm {
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub password: String,
    pub return_to: Option<String>,
    pub csrf_token: Option<String>,
}

/// Sign-up form body. No `Debug` derive: it contains a password.
#[derive(Deserialize)]
pub struct SignUpForm {
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub password: String,
    pub display_name: Option<String>,
    pub return_to: Option<String>,
    pub csrf_token: Option<String>,
}

#[derive(Deserialize)]
pub struct CsrfForm {
    pub csrf_token: Option<String>,
}
