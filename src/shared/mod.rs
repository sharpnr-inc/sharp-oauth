//! Code used by every feature.
//!
//! * [`error`]: [`error::AppError`] and its mapping to OAuth error responses
//! * [`secret`]: random secrets, hashing them, constant-time comparison
//! * [`database`]: connection pool, migrations and the [`database::SecretHash`] column type
//! * [`views`]: Askama templates for the HTML pages
//! * [`response`]: redirect and internal-error responses for HTML handlers

pub mod database;
pub mod error;
pub mod response;
pub mod secret;
pub mod views;
