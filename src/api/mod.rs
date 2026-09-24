//! The HTTP entry point: builds the router from every feature's routes.
//!
//! * [`router`]: mounts the feature routes and applies middleware
//! * [`health`]: `GET /health` for monitoring and container health checks
//! * [`favicon`]: `GET /favicon.svg`, the brand mark for browser tabs

pub mod favicon;
pub mod health;
pub mod router;
