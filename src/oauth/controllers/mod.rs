//! HTTP handlers for the OAuth endpoints.
//!
//! * [`authorize`]: `/oauth/authorize` and `/oauth/consent` (browser)
//! * [`token`]: `/oauth/token` and `/oauth/revoke` (client apps)

pub mod authorize;
pub mod token;
