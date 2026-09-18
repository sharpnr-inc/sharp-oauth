//! SeaORM entities: one module per table.
//!
//! Each module describes a table once, and the macros generate everything
//! else from it:
//!
//! * `Model` — one row, used directly as the domain struct. `User`,
//!   `OAuthClient`, `Session`, `AuthorizationCode` and `RefreshToken` are all
//!   aliases of a `Model`, so a column exists in exactly one place.
//! * `ActiveModel` — a row being written, where each field is `Set` or
//!   `NotSet`.
//! * `Column` — the type-safe column names used to build queries
//!   (`Column::Email.eq(email)`), which is what replaces hand-written SQL.
//!
//! The behaviour that belongs to a row lives with its domain module, not
//! here: `OAuthClient::has_redirect_uri` is in [`crate::oauth::client`] and
//! `RefreshToken::check_usable` in [`crate::token::refresh`]. Rust allows
//! that because it is all one crate, and it keeps protocol rules next to the
//! protocol code rather than in the table definitions.
//!
//! ## Secrets in models
//!
//! Some tables store the SHA-256 hash of a secret (`password_hash`,
//! `session_token_hash`, `code_hash`, `token_hash`, `client_secret_hash`).
//! A `Model` has a field for every column, and SeaORM requires models to
//! implement `Debug`, so those columns use the [`SecretHash`] newtype, which
//! prints `<redacted>`. That keeps a stray `{:?}` from putting a credential
//! hash in the logs.
//!
//! The schema itself is owned by the SQL files in `migrations/`, not by these
//! structs. When a migration changes a table, update its entity to match.

mod secret_hash;

pub use secret_hash::SecretHash;

pub mod oauth_authorization_codes;
pub mod oauth_clients;
pub mod oauth_consents;
pub mod oauth_refresh_tokens;
pub mod oauth_scopes;
pub mod user_sessions;
pub mod users;
