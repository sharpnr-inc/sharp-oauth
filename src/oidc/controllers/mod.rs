//! HTTP handlers for the OpenID Connect endpoints.
//!
//! * [`well_known`]: discovery document and JWKS
//! * [`userinfo`]: the `/oauth/userinfo` endpoint

pub mod userinfo;
pub mod well_known;
