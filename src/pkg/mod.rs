//! Self-contained helpers with no knowledge of features or the database.
//!
//! * [`cookie_manager`]: reading and writing hardened cookies
//! * [`jwt_manager`]: RSA signing keys, JWT signing/verification and JWKS

pub mod cookie_manager;
pub mod jwt_manager;
