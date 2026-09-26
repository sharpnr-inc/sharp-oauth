//! The developer portal: where Sharpnr users register their own applications.
//!
//! This is the self-service version of the `create-client` CLI. A signed-in
//! user can create an application, choose its redirect URLs and scopes, get a
//! `client_id` (and, for confidential apps, a `client_secret` shown once),
//! and later edit, rotate the secret of, or delete it.
//!
//! Ownership is the one rule this feature adds on top of
//! [`crate::oauth::services::client`]: every query filters by the signed-in
//! user, so someone else's application looks exactly like one that does not
//! exist (404).
//!
//! * [`routes`]: URL → handler table for this feature
//! * [`controllers`]: HTTP handlers for the portal pages
//! * [`dtos`]: the application form
//! * [`services`]: ownership, limits and user-facing error messages
//!
//! It has no tables of its own: applications are rows in `oauth_clients`,
//! linked to their owner by `owner_user_id`.

pub mod controllers;
pub mod dtos;
pub mod routes;
pub mod services;
