//! Tokens issued by the token endpoint, and the keys that sign them.
//!
//! ## Access token strategy
//!
//! Access tokens are **self-contained JWTs** ([RFC 9068]) signed with RS256:
//!
//! * A resource server (e.g. a Sharpnr API) verifies them locally with our
//!   public keys from `/.well-known/jwks.json`. No database call per request.
//! * The cost is that a JWT cannot be revoked before it expires. We keep them
//!   short-lived ([`services::access::ACCESS_TOKEN_TTL`], 15 minutes) to bound that.
//! * There is no access-token table.
//!
//! ## Refresh tokens
//!
//! Refresh tokens are the opposite: opaque random strings, stored hashed,
//! long-lived, revocable, and rotated on every use. See [`services::refresh`].
//!
//! [RFC 9068]: https://www.rfc-editor.org/rfc/rfc9068

//!
//! ## Signing keys
//!
//! The RSA keys that sign both access tokens and ID tokens live in
//! [`crate::pkg::jwt_manager`].
//!
//! This feature has no routes of its own: the token endpoint is in
//! [`crate::oauth`], which calls these services.

pub mod models;
pub mod repo;
pub mod services;
