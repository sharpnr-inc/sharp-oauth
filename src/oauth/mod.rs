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
//! Services, in [`services`]:
//!
//! * [`services::client`]: registered applications and client authentication
//! * [`services::scope`]: parsing and comparing space-delimited scope strings
//! * [`services::pkce`]: Proof Key for Code Exchange (RFC 7636)
//! * [`services::authorization`]: the `/oauth/authorize` decision logic
//! * [`services::consent`]: remembering what a user approved
//! * [`services::token`]: the `/oauth/token` endpoint (both grant types)
//! * [`services::revocation`]: the `/oauth/revoke` endpoint (RFC 7009)
//! * [`services::params`]: shared parsing of form/query parameters
//!
//! The rest of the feature: [`routes`], [`controllers`] (HTTP handlers),
//! [`repo`] (queries) and [`models`] (SeaORM entities).

pub mod controllers;
pub mod models;
pub mod repo;
pub mod routes;
pub mod services;
