//! OAuth 2.0 protocol logic.
//!
//! The Authorization Code flow with PKCE, step by step, and where each step
//! is implemented:
//!
//! ```text
//!  Client app                    Sharp-OAuth                         User
//!  ──────────                    ───────────                         ────
//!  1. redirect browser ────────▶ GET /oauth/authorize
//!                                  authorization::validate
//!                                  (client, redirect_uri, scope, PKCE)
//!                                  no session? ─────────────────────▶ /signin
//!                                  consent::covers? no ─────────────▶ consent page
//!                                                                     approves
//!                                  authorization::approve
//!                                  (store consent, issue one-time code)
//!  2. callback ◀──────────────── 303 redirect_uri?code=…&state=…&iss=…
//!  3. POST /oauth/token ───────▶ token::handle
//!     code + code_verifier         (client auth, redeem code, verify PKCE)
//!  4. ◀─────────────────────────  access_token (+ id_token, refresh_token)
//! ```
//!
//! * [`client`]: registered applications and client authentication
//! * [`scope`]: parsing and comparing space-delimited scope strings
//! * [`pkce`]: Proof Key for Code Exchange (RFC 7636)
//! * [`authorization`]: the `/oauth/authorize` decision logic
//! * [`consent`]: remembering what a user approved
//! * [`token`]: the `/oauth/token` endpoint (both grant types)
//! * [`revocation`]: the `/oauth/revoke` endpoint (RFC 7009)
//! * [`params`]: shared parsing of form/query parameters

pub mod authorization;
pub mod client;
pub mod consent;
pub mod params;
pub mod pkce;
pub mod revocation;
pub mod scope;
pub mod token;
