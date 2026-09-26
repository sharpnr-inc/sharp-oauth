# Architecture

This document explains how the code is organised and why. For the protocol
itself see [oauth-flow.md](oauth-flow.md); for security reasoning see
[security.md](security.md).

## One package, organised by feature

Sharp-OAuth is a single Cargo package. It has a library (`src/lib.rs`) and a
thin binary (`src/main.rs`). The library/binary split exists only so the
integration tests in `tests/` can build the exact same application.

The code is organised **by feature**, the same way as `sharpnr-engine`
(Go/Gin): each feature folder owns its routes, controllers, services, repo
and models, and cross-cutting code sits at the top level.

Inside a feature, every request flows through the same layers, and
dependencies only point downwards:

```text
┌──────────────────────────────────────────────────────────────────────┐
│ routes.rs       URL → handler table for the feature                  │
├──────────────────────────────────────────────────────────────────────┤
│ controllers/    Axum handlers: parse input, call a service, respond  │
│                  "What did the browser/client send? What do we reply?"│
└───────────────┬──────────────────────────────────────────────────────┘
                │ calls one service function
┌───────────────▼──────────────────────────────────────────────────────┐
│ services/       protocol and domain logic                            │
│                  "Is this allowed? What should happen?"               │
└───────────────┬──────────────────────────────────────────────────────┘
                │ calls repo functions
┌───────────────▼──────────────────────────────────────────────────────┐
│ repo/           one query module per table (SeaORM)                  │
│ models/         SeaORM entities: one Model per table                 │
└──────────────────────────────────────────────────────────────────────┘
```

A controller never contains protocol rules, and a service never builds an
HTTP response. For example, the token endpoint handler is ~10 lines
([src/oauth/controllers/token.rs](../src/oauth/controllers/token.rs)). It
hands the form body to `oauth::services::token::handle`, which does all the
checking.

Features may use each other's services and repos (the OAuth feature needs to
know who is signed in, so it calls `authentication::services::session`).

## Module map

```text
src/
├── main.rs                  CLI: serve | generate-signing-key | create-client
├── lib.rs                   module list, AppState, app()
│
├── config/                  environment variables → Config
├── api/
│   ├── router.rs            mounts every feature's routes, CORS, middleware
│   └── health.rs            GET /health
├── middlewares/
│   ├── security_headers.rs  security headers, request logging
│   ├── csrf.rs              double-submit CSRF tokens for forms
│   └── auth.rs              CurrentSession extractor (who is signed in?)
├── shared/
│   ├── error.rs             AppError → OAuth JSON error responses
│   ├── secret.rs            random tokens, SHA-256, constant-time compare
│   ├── response.rs          redirect, internal_error for HTML handlers
│   ├── views.rs             the data each Askama template needs
│   └── database/            connect, migrate, SecretHash column type
├── pkg/
│   ├── cookie_manager.rs    hardened cookie read/write
│   └── jwt_manager.rs       RSA keys from disk, sign/verify JWTs, JWKS, rotation
│
├── authentication/          Sharpnr accounts (knows nothing about OAuth)
│   ├── routes.rs            /, /signin, /signup, /logout
│   ├── controllers/pages.rs home, sign-in, sign-up, logout handlers
│   ├── dtos.rs              form bodies
│   ├── services/
│   │   ├── user.rs          User, sign_up, authenticate
│   │   ├── password.rs      Argon2id hashing on the blocking thread pool
│   │   └── session.rs       browser sessions (cookie token ↔ hashed row)
│   ├── repo/                users.rs  sessions.rs
│   └── models/              users.rs  user_sessions.rs
│
├── oauth/                   OAuth 2.0
│   ├── routes.rs            web: /oauth/authorize, /oauth/consent
│   │                        api: /oauth/token, /oauth/revoke
│   ├── controllers/
│   │   ├── authorize.rs     authorize and consent handlers (browser)
│   │   └── token.rs         token and revoke handlers (client apps)
│   ├── services/
│   │   ├── params.rs        query/form pairs with duplicate detection
│   │   ├── scope.rs         ScopeSet: parse, subset, union
│   │   ├── pkce.rs          S256 challenge verification
│   │   ├── client.rs        OAuthClient, registration, client authentication
│   │   ├── consent.rs       remembering approved scopes
│   │   ├── authorization.rs /oauth/authorize: validate → sign in? → consent? → code
│   │   ├── token.rs         /oauth/token: authorization_code and refresh_token grants
│   │   └── revocation.rs    /oauth/revoke
│   ├── repo/                clients.rs  scopes.rs  consents.rs  authorization_codes.rs
│   └── models/              oauth_clients.rs  oauth_scopes.rs  oauth_consents.rs
│                            oauth_authorization_codes.rs
│
├── token/                   what the token endpoint hands out (no routes)
│   ├── services/
│   │   ├── access.rs        JWT access tokens (RFC 9068)
│   │   └── refresh.rs       opaque refresh tokens, rotation rules
│   ├── repo/                refresh_tokens.rs
│   └── models/              oauth_refresh_tokens.rs
│
└── oidc/                    OpenID Connect on top of OAuth
    ├── routes.rs            /oauth/userinfo, /.well-known/*
    ├── controllers/
    │   ├── userinfo.rs      userinfo handler
    │   └── well_known.rs    discovery and JWKS handlers
    └── services/
        ├── id_token.rs      ID token claims
        ├── userinfo.rs      /oauth/userinfo claims per scope
        └── discovery.rs     /.well-known/openid-configuration

templates/                   HTML, rendered with Askama; each .css sits next to its page
├── layouts/
│   └── base.html  base.css  shared shell: <head>, page frame
├── partials/
│   ├── header.html          Sharpnr mark and wordmark
│   └── footer.html
└── pages/
    ├── home.html  signin.html  signup.html
    ├── consent.html         the "App wants access" screen
    └── error.html
```

### Where domain types live

Each table is described once, as a SeaORM `Model` in its feature's
`models/`, and the service that owns it re-exports it under a domain name:

```rust
// src/authentication/services/user.rs
pub use crate::authentication::models::users::Model as User;
```

So `User`, `OAuthClient`, `Session`, `AuthorizationCode` and `RefreshToken`
are entity models, and there is no separate row struct to keep in sync and no
mapping layer. The *behaviour* still lives in services: `impl OAuthClient`
(with `has_redirect_uri`) is in `oauth/services/client.rs`, and
`RefreshToken::check_usable` in `token/services/refresh.rs`. Rust allows that
because it is all one crate.

Columns holding a secret's hash use the `SecretHash` newtype
(`shared/database/secret_hash.rs`), which prints `<redacted>`: SeaORM
requires models to implement `Debug`, and a model has a field for every
column.

### Rust modules for Go developers

A folder is not a module until it is declared. Each folder has a `mod.rs`
listing its files (`pub mod users;`), much like a Go package's file set, and
`lib.rs` lists the top-level folders. When you add a file, add a
`pub mod <name>;` line to the `mod.rs` next to it.

Imports use paths from the crate root, for example
`use crate::authentication::repo::users;`, and calls then read like Go
package calls: `users::find_by_id(db, id)`.

## Shared state

```rust
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: DatabaseConnection,         // SeaORM handle over a shared pool
    pub signing_keys: Arc<SigningKeys>,
}
```

Axum clones `AppState` for every request, which is cheap because every member
is reference-counted (cloning a `DatabaseConnection` shares its pool). Service
functions take `&AppState` when they need more than the database, or
`&DatabaseConnection` when they do not.

## Data model

```text
users ─────────────┬──────────────────┬──────────────────────┬──────────────────┐
  id (= OIDC sub)  │                  │                      │                  │
                   ▼                  ▼                      ▼                  ▼
            user_sessions      oauth_consents     oauth_authorization_codes   oauth_refresh_tokens
            token_hash         (user, client)     code_hash                   token_hash
            expires_at         scopes[]           redirect_uri, scope         family_id
            revoked_at                            code_challenge (PKCE)       rotated_to_id ─┐
                                   ▲              nonce, auth_time            revoked_at     │
                                   │              expires_at, used_at         authorization_code_id
oauth_clients ─────────────────────┴──────────────────────┘                     ▲    └──────┘
  client_id, client_secret_hash                                                  │
  redirect_uris[], allowed_scopes[]  ────────────────────────────────────────────┘

oauth_scopes: name, description (registry; seeded by migration)
```

Things worth noticing:

* **No secret is stored in plaintext.** Session tokens, codes, refresh tokens
  and client secrets are stored as `SHA-256`; passwords as Argon2id.
* **No access-token table.** Access tokens are self-contained JWTs.
* **Refresh token families.** `family_id` groups all tokens rotated from one
  sign-in, so a replay can revoke the whole chain in one `UPDATE`.
* **Two IDs for clients.** `oauth_clients.id` (UUID) is the internal key used
  by foreign keys; `client_id` (`sharp_client_…`) is the public identifier.
* **UUID v7** for every primary key (`Uuid::now_v7()`), which sorts by
  creation time. UUIDs are identifiers, never secrets.

Migrations are in `migrations/` (forward-only, one file per table). They are
compiled into the binary with `sqlx::migrate!` and applied at startup and by
`create-client`. SQLx still owns the connection pool and the migration runner;
SeaORM borrows that same pool, so there is one driver and one pool.

## Queries

Each feature's `repo/` uses [SeaORM](https://www.sea-ql.org/SeaORM/). Queries are built from
type-safe columns, so a renamed column is a compile error:

```rust
Users::find().filter(users::Column::Email.eq(email)).one(db).await
```

Four queries carry a security rule rather than just fetching rows: the
one-time code claim, the `FOR UPDATE` lookup used for refresh rotation, the
consent upsert and the family revocation on code replay. Each is built by its
own small function whose generated SQL is asserted in a unit test, for
example:

```rust
assert!(sql.contains(r#""used_at" IS NULL"#), "one-time use depends on this");
```

That keeps the SQL contract visible and reviewable even though no SQL string
is hand-written. The integration tests then exercise every query against real
PostgreSQL.

Functions that may run inside a transaction accept `&impl ConnectionTrait`,
so the caller can pass either the `DatabaseConnection` or a
`DatabaseTransaction`. The token endpoint uses transactions so that "consume
code + create refresh token" and "rotate refresh token" are atomic.

## HTML rendering

Pages are server-rendered with [Askama](https://crates.io/crates/askama):
markup lives in `templates/*.html`, and each struct in
[src/shared/views.rs](../src/shared/views.rs) declares the data one template may
use. Templates are compiled during `cargo build`, so a field that does not
exist is a build error, and `{{ value }}` is HTML-escaped automatically — an
injection cannot come from a forgotten escape call.

The auth pages stay server-rendered on purpose. They load **no JavaScript**,
which is what lets the Content-Security-Policy remain `default-src 'none'` on
the screens where an XSS bug would mean account takeover. A future developer
portal is a different case: it is dashboard-shaped and not part of the
credential flow, so it can be a separate frontend over a JSON API.

Because Askama compiles templates into the binary, `templates/` is copied
into the Docker build context (see the `Dockerfile`).

## Error handling

There are four kinds of error response, because OAuth has four different
audiences:

| Where                          | Type                               | Response                                   |
|--------------------------------|------------------------------------|--------------------------------------------|
| `/oauth/token`, `/oauth/revoke` | `shared::error::AppError`          | JSON `{"error","error_description"}` (RFC 6749 §5.2) |
| `/oauth/authorize`             | `authorization::AuthorizationError` | `Unsafe` → HTML error page; `Redirect` → `redirect_uri?error=…` |
| `/oauth/userinfo`              | `userinfo::UserInfoError`          | 401/403 with `WWW-Authenticate: Bearer error=…` (RFC 6750) |
| HTML pages                     | `shared::response::internal_error` | Generic error page                          |

Two rules hold everywhere:

1. Error descriptions are `&'static str`, so they cannot contain user input,
   token values or database messages.
2. Database and internal errors are logged in full on the server but reach
   the client only as `server_error` / a generic page.

## Configuration and keys

`Config::from_env` reads environment variables once at startup (see the
README). Signing keys are loaded from `SIGNING_KEYS_DIR` by
`SigningKeys::load_from_dir`; the server refuses to start without one.

## Logging

* `middlewares::security_headers::log_requests` logs method, **path without query
  string**, status and latency.
* Security-relevant events are logged with `target: "audit"`, for example
  `user_signed_in`, `authorization_code_issued`, `refresh_token_replayed`.
  They include IDs (user, client, token family), never secret values. An
  `audit_events` table can later be fed from the same call sites.

## Testing strategy

| Level        | Location              | Needs DB | Examples                                                      |
|--------------|-----------------------|----------|---------------------------------------------------------------|
| Unit         | `#[cfg(test)]` in `src/` | no    | PKCE vector, exact redirect matching, scope parsing, JWT tamper/rotation, claims, CSRF |
| Integration  | `tests/*.rs`          | yes      | full flow through the router, every negative case in the plan |

`tests/common/mod.rs` provides `TestApp` (router + state on a fresh database)
and a tiny `Browser` that keeps cookies and submits forms with their hidden
fields. That lets tests go through sign-in and consent exactly as a user
would, CSRF tokens included.

`scripts/demo-flow.sh` is the manual verification path against a running
server.

## Adding things later

* **A new scope**: add a migration inserting into `oauth_scopes`. If it
  should expose claims, extend `oidc::services::userinfo::claims_for`.
* **A new endpoint**: service function in the feature's `services/` →
  thin handler in its `controllers/` → route in its `routes.rs` →
  integration test. If clients should discover it, add it to
  `oidc/services/discovery.rs`, and only once it works.
* **A new table**: new migration file, an entity in the owning feature's
  `models/`, a query module in its `repo/`, and the domain alias in the
  service that uses it.
* **A new feature**: a folder with `routes.rs`, `controllers/`, `services/`,
  `repo/` and `models/` (each with a `mod.rs`), a `pub mod` line in
  `lib.rs`, and its routes merged in `api/router.rs`.
