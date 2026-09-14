//! Sharpnr identities: who the user is and whether they are signed in.
//!
//! This module knows nothing about OAuth. It answers two questions that the
//! OAuth layer asks:
//!
//! * "Is this email/password correct?" → [`user::authenticate`]
//! * "Which user owns this browser?" → [`session::find_active`]

pub mod password;
pub mod session;
pub mod user;
