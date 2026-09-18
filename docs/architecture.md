# Architecture

This document explains how the code is organised and why. For the protocol
itself see [oauth-flow.md](oauth-flow.md); for security reasoning see
[security.md](security.md).

## One package, three layers

Sharp-OAuth is a single Cargo package. It has a library (`src/lib.rs`) and a
thin binary (`src/main.rs`). The library/binary split exists only so the
integration tests in `tests/` can build the exact same application.

Every request flows through three layers, and dependencies only point downwards:

```text
┌──────────────────────────────────────────────────────────────────────┐
│ http/            Axum handlers, cookies, CSRF, HTML, middleware       │
│                  "What did the browser/client send? What do we reply?"│
└───────────────┬──────────────────────────────────────────────────────┘
                │ calls one service function
┌───────────────▼──────────────────────────────────────────────────────┐
│ identity/  oauth/  token/  oidc/      protocol and domain logic       │
│                  "Is this allowed? What should happen?"               │
└───────────────┬──────────────────────────────────────────────────────┘
                │ calls repository functions
┌───────────────▼──────────────────────────────────────────────────────┐
│ db/              entities + one query module per table (SeaORM)       │
└──────────────────────────────────────────────────────────────────────┘
```

A handler never contains protocol rules, and a service never builds an HTTP
response. For example, the token endpoint handler is ~10 lines
([src/http/oauth.rs](../src/http/oauth.rs)). It hands the form body to
`oauth::token::handle`, which does all the checking.

## Module map

```text
src/
├── main.rs                  CLI: serve | generate-signing-key | create-client
├── lib.rs                   module list, AppState, app()
├── config.rs                environment variables → Config
├── error.rs                 AppError → OAuth JSON error responses
├── secret.rs                random tokens, SHA-256, constant-time compare
│
├── identity/                Sharpnr accounts (knows nothing about OAuth)
│   ├── user.rs              User, sign_up, authenticate
│   ├── password.rs          Argon2id hashing on the blocking thread pool
│   └── session.rs           browser sessions (cookie token ↔ hashed row)
│
├── oauth/                   OAuth 2.0
│   ├── params.rs            query/form pairs with duplicate detection
│   ├── scope.rs             ScopeSet: parse, subset, union
│   ├── pkce.rs              S256 challenge verification
│   ├── client.rs            OAuthClient, registration, client authentication
│   ├── consent.rs           remembering approved scopes
│   ├── authorization.rs     /oauth/authorize: validate → sign in? → consent? → code
│   ├── token.rs             /oauth/token: authorization_code and refresh_token grants
│   └── revocation.rs        /oauth/revoke
│
├── token/                   what the token endpoint hands out
│   ├── signing.rs           RSA keys from disk, sign/verify JWTs, JWKS, rotation
│   ├── access.rs            JWT access tokens (RFC 9068)
│   └── refresh.rs           opaque refresh tokens, rotation rules
│
├── oidc/                    OpenID Connect on top of OAuth
│   ├── id_token.rs          ID token claims
│   ├── userinfo.rs          /oauth/userinfo claims per scope
│   └── discovery.rs         /.well-known/openid-configuration
│
├── db/                      queries, one module per table
│   ├── entities/            SeaORM entities: one Model per table
│   ├── users.rs  sessions.rs  clients.rs  scopes.rs
│   └── authorization_codes.rs  consents.rs  refresh_tokens.rs
│
└── http/
    ├── routes.rs            URL → handler table
    ├── middleware.rs        security headers, request logging
    ├── extract.rs           CurrentSession extractor
    ├── pages.rs             home, sign-in, sign-up, logout
    ├── oauth.rs             authorize, consent, token, revoke handlers
    ├── oidc.rs              discovery, jwks, userinfo handlers
    ├── cookies.rs  csrf.rs  html.rs
```

### Where domain types live

Each table is described once, as a SeaORM `Model` in `db/entities/`, and the
domain modules re-export the one they own:

```rust
// src/identity/user.rs
pub use crate::db::entities::users::Model as User;
```

So `User`, `OAuthClient`, `Session`, `AuthorizationCode` and `RefreshToken`
are entity models, and there is no separate row struct to keep in sync and no
mapping layer. The *behaviour* still lives with the domain: `impl OAuthClient`
(with `has_redirect_uri`) is in `oauth/client.rs`, and
`RefreshToken::check_usable` in `token/refresh.rs`. Rust allows that because
it is all one crate.

Columns holding a secret's hash use the `SecretHash` newtype
(`db/entities/secret_hash.rs`), which prints `<redacted>`: SeaORM requires
models to implement `Debug`, and a model has a field for every column.

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

`db/` uses [SeaORM](https://www.sea-ql.org/SeaORM/). Queries are built from
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

## Error handling

There are four kinds of error response, because OAuth has four different
audiences:

| Where                          | Type                               | Response                                   |
|--------------------------------|------------------------------------|--------------------------------------------|
| `/oauth/token`, `/oauth/revoke` | `error::AppError`                 | JSON `{"error","error_description"}` (RFC 6749 §5.2) |
| `/oauth/authorize`             | `authorization::AuthorizationError` | `Unsafe` → HTML error page; `Redirect` → `redirect_uri?error=…` |
| `/oauth/userinfo`              | `userinfo::UserInfoError`          | 401/403 with `WWW-Authenticate: Bearer error=…` (RFC 6750) |
| HTML pages                     | `http::internal_error`             | Generic error page                          |

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

* `http::middleware::log_requests` logs method, **path without query
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
  should expose claims, extend `oidc::userinfo::claims_for`.
* **A new endpoint**: service function in the right domain module →
  thin handler in `http/` → route in `http/routes.rs` → integration test.
  If clients should discover it, add it to `oidc/discovery.rs`, and only
  once it works.
* **A new table**: new migration file, a `db/<table>.rs` module, and the
  domain struct next to the logic that uses it.
