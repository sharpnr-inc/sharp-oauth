//! Middleware and request guards shared by every feature.
//!
//! * [`security_headers`]: defensive headers and request logging on every response
//! * [`csrf`]: double-submit CSRF tokens for HTML forms
//! * [`auth`]: the [`auth::CurrentSession`] extractor (who is signed in?)

pub mod auth;
pub mod csrf;
pub mod security_headers;
