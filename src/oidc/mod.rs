//! OpenID Connect: the identity layer on top of OAuth 2.0.
//!
//! OAuth answers "may this app access these resources?". OpenID Connect adds
//! "and who is the user?". A request becomes an OIDC request when its scope
//! contains `openid`. The token response then includes an **ID token**, a
//! signed statement addressed to the client saying which user signed in.
//!
//! * [`id_token`]: building ID token claims
//! * [`userinfo`]: `/oauth/userinfo`, returning profile claims for an access token
//! * [`discovery`]: `/.well-known/openid-configuration`, the machine-readable
//!   description that lets OIDC libraries configure themselves from the
//!   issuer URL alone

pub mod discovery;
pub mod id_token;
pub mod userinfo;
