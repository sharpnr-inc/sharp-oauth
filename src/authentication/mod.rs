//! Sharpnr identities: who the user is and whether they are signed in.
//!
//! This module knows nothing about OAuth. It answers two questions that the
//! OAuth layer asks:
//!
//! * "Is this email/password correct?" → [`services::user::authenticate`]
//! * "Which user owns this browser?" → [`services::session::find_active`]
//!
//! It also serves the browser pages for Sharpnr accounts: home, sign-in,
//! sign-up and logout.
//!
//! * [`routes`]: URL → handler table for this feature
//! * [`controllers`]: HTTP handlers for the pages
//! * [`dtos`]: form bodies the pages submit
//! * [`services`]: users, password hashing, sessions
//! * [`repo`]: queries for `users` and `user_sessions`
//! * [`models`]: SeaORM entities for those tables

pub mod controllers;
pub mod dtos;
pub mod models;
pub mod repo;
pub mod routes;
pub mod services;
