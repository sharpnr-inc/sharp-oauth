//! The HTTP entry point: builds the router from every feature's routes.
//!
//! * [`router`]: mounts the feature routes and applies middleware
//! * [`health`]: `GET /health` for monitoring and container health checks
//! * [`favicon`]: `GET /favicon.svg`, the brand mark for browser tabs
//! * [`stylesheets`]: `GET /css/{file}`, the CSS for our HTML pages

pub mod favicon;
pub mod health;
pub mod router;
pub mod stylesheets;
