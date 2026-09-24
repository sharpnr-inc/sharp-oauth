<p align="center">
  <img src="assets/brand/png/gh-readme.png" alt="Sharp-OAuth: OAuth engine, OIDC provider, open source" width="100%">
</p>

**Sharp-OAuth** is an open-source **OAuth 2.0 Authorization Server** and
**OpenID Connect Provider** written in Rust. It is the engine behind
**"Sign in with Sharpnr"**.

A third-party app sends its user here, the user signs in with their Sharpnr
account and approves access, and the app receives tokens. It never sees the
user's password.

```text
Third-party app ──▶ /oauth/authorize ──▶ sign in ──▶ consent ──▶ code ──▶ app callback
                                                                          │
      app backend ◀── access_token + id_token + refresh_token ◀── /oauth/token
```

## Documentation

| Read this                                        | To learn                                                    |
|--------------------------------------------------|-------------------------------------------------------------|
| [docs/oauth-flow.md](docs/oauth-flow.md)         | The protocol step by step, with the code that handles each step |
| [docs/architecture.md](docs/architecture.md)     | How the code is organised, the data model, errors, testing  |
| [docs/security.md](docs/security.md)             | Every security decision, the attack it stops, and where it lives |
| [docs/deployment.md](docs/deployment.md)         | Docker image, Docker Compose, and production checklist      |
| [SHARP_OAUTH_PLAN.md](SHARP_OAUTH_PLAN.md)       | The original project plan                                   |
| `cargo doc --open --document-private-items`      | API docs. Every module starts with an explanation of its job |

The code is organised by feature (`authentication/`, `oauth/`, `token/`,
`oidc/`), each with `routes.rs`, `controllers/`, `services/`, `repo/` and
`models/`; see [docs/architecture.md](docs/architecture.md). Suggested
reading order: `src/lib.rs` → `src/api/router.rs` → `src/oauth/mod.rs` →
`src/oauth/services/authorization.rs` → `src/oauth/services/token.rs` →
`src/token/services/` → `src/oidc/`.

## Quick start with Docker

Requirements: Docker with Compose. No Rust or PostgreSQL install needed.

```bash
docker compose up --build -d
curl http://localhost:3000/health          # → sharp-oauth is alive

docker compose run --rm sharp-oauth create-client \
    --name "Demo App" \
    --redirect-uri http://localhost:4000/callback \
    --scopes "openid profile email offline_access"
```

This starts PostgreSQL, creates a signing key on first run, and serves on
`http://localhost:3000`. See [docs/deployment.md](docs/deployment.md).

## Quick start without Docker

Requirements: Rust (edition 2024), PostgreSQL, and for the demo script `curl`,
`jq` and `openssl`.

```bash
# 1. Configure
cp .env.example .env              # edit DATABASE_URL if needed
createdb sharp_oauth              # or: psql -c 'create database sharp_oauth'

# 2. Create a signing key (written to keys/, which is git-ignored)
cargo run -- generate-signing-key

# 3. Register a client application
cargo run -- create-client \
    --name "Demo App" \
    --redirect-uri http://localhost:4000/callback \
    --scopes "openid profile email offline_access"
#   → prints client_id and client_secret (the secret is shown only once)

# 4. Run the server (migrations are applied automatically)
cargo run
curl http://localhost:3000/health          # → sharp-oauth is alive

# 5. Walk through the whole flow with curl
CLIENT_ID=sharp_client_... CLIENT_SECRET=sharp_secret_... scripts/demo-flow.sh
```

You can also do the browser part by hand: open
`http://localhost:3000/signup`, create an account, then visit an authorize URL
(see [docs/oauth-flow.md](docs/oauth-flow.md#1-the-client-sends-the-user-to-oauthauthorize)).

## Commands

| Command                                     | What it does                                        |
|---------------------------------------------|-----------------------------------------------------|
| `cargo run` / `cargo run -- serve`          | Start the server                                    |
| `cargo run -- generate-signing-key`         | Create a new RSA key in `SIGNING_KEYS_DIR` (mode 0600) |
| `cargo run -- create-client --name N --redirect-uri U [--redirect-uri U2] --scopes "S1 S2" [--public]` | Register a client. `--public` = no secret (SPA/mobile) |
| `cargo run -- generate-signing-key --if-missing` | Create a key only if none exists (used by Compose) |
| `cargo run -- healthcheck`                  | Exit 0 if the local server answers `/health` (container health check) |
| `docker compose up --build -d`              | Run the whole stack in containers                   |
| `cargo test`                                | Unit + integration tests (needs PostgreSQL, see below) |
| `cargo fmt && cargo clippy --all-targets`   | Format and lint                                     |

## Configuration

Environment variables (loaded from `.env` in development):

| Variable             | Default     | Description                                               |
|----------------------|-------------|-----------------------------------------------------------|
| `DATABASE_URL`       | required    | PostgreSQL connection string                              |
| `ISSUER_URL`         | required    | Public base URL, e.g. `https://auth.sharpnr.com`. Becomes the `iss` claim. `http` is only accepted for localhost |
| `HOST` / `PORT`      | `127.0.0.1` / `3000` | Listen address                                   |
| `SIGNING_KEYS_DIR`   | `keys`      | Directory of RSA private keys (`<kid>.pem`)               |
| `SIGNING_ACTIVE_KID` | newest file | Which key signs new tokens (for key rotation)             |
| `RUST_LOG`           | `info`      | Log filter, e.g. `debug,sqlx=warn`                        |

## Endpoints

| Endpoint                                   | Purpose                                    | Spec            |
|--------------------------------------------|--------------------------------------------|-----------------|
| `GET /health`                              | Liveness                                   |                 |
| `GET,POST /signin`, `/signup`, `POST /logout` | Sharpnr account pages                   |                 |
| `GET,POST /oauth/authorize`                | Start of the flow (browser)                | RFC 6749 §4.1, OIDC Core §3.1 |
| `POST /oauth/consent`                      | Consent screen submit (browser)            |                 |
| `POST /oauth/token`                        | Code → tokens, refresh → tokens            | RFC 6749 §4.1.3, §6 |
| `POST /oauth/revoke`                       | Revoke a refresh token                     | RFC 7009        |
| `GET,POST /oauth/userinfo`                 | User claims for an access token            | OIDC Core §5.3  |
| `GET /.well-known/openid-configuration`    | Discovery document                         | OIDC Discovery, RFC 8414 |
| `GET /.well-known/jwks.json`               | Public signing keys                        | RFC 7517        |

## Tests

```bash
cargo test
```

* **Unit tests** (in `src/`) cover pure logic: PKCE (with the RFC 7636 test
  vector), scope parsing, exact redirect URI matching, JWT signing/rotation,
  claim building, CSRF, cookie and HTML escaping helpers. They also assert the
  SQL generated for the four security-critical queries (one-time code claim,
  `FOR UPDATE` rotation lookup, consent upsert, family revocation).
* **Integration tests** (in `tests/`) run the real router against PostgreSQL.
  `#[sqlx::test]` creates a throw-away database per test from `DATABASE_URL`,
  so that user needs permission to create databases. They cover the complete
  flow plus the negative cases from the plan: unknown client, wrong redirect
  URI, missing/`plain` PKCE, wrong verifier, reused/expired code, invalid
  scope, missing state, CSRF, wrong client secret, refresh replay, expiry and
  revocation.

## Status against the plan

| Phase | Scope                                   | Status |
|-------|-----------------------------------------|--------|
| 0     | Axum, config, errors, tracing, `/health`| ✅ |
| 1     | PostgreSQL, migrations, repositories    | ✅ |
| 2     | Sign-up, Argon2, sign-in, sessions, logout | ✅ |
| 3     | Client registry, redirect URI validation | ✅ via `create-client` CLI |
| 4     | Authorization endpoint, PKCE, consent   | ✅ |
| 5     | Token endpoint, code exchange           | ✅ |
| 6     | Refresh tokens: rotation, replay detection, revocation | ✅ |
| 7     | JWT signing, `kid`, JWKS, key rotation  | ✅ file-based keys |
| 8     | OIDC: ID token, nonce, UserInfo, discovery | ✅ |
| 9     | Developer portal                        | ⏳ not started (CLI only) |
| 10    | Hardening                               | 🟡 partial: CSRF, secure cookies, security headers, audit log lines. Missing: rate limiting, login throttling, `audit_events` table |

Known gaps, deliberately left for later: email verification (so
`email_verified` is always `false`), account/session management pages,
consent revocation UI, token introspection, per-API access-token audiences
(RFC 8707), and a grace period for concurrent refresh requests.

## Brand

The logo, icons and social images are in [assets/brand/](assets/brand/),
with usage rules in [assets/brand/README.md](assets/brand/README.md).

| Name   | Hex       | Use                                      |
|--------|-----------|------------------------------------------|
| Ink    | `#201e1d` | Text, primary buttons, the two dark shards |
| Red    | `#ec3013` | The third shard and accents only          |
| Ground | `#f3f2f2` | Backgrounds                               |

The wordmark is set in Archivo ExtraBold (800). Keep clear space of at least
one blade width around the mark, and never recolor the red blade except to
ink on red backgrounds.

The sign-in pages use the mark inline and serve `assets/web/favicon.svg`,
which adapts to dark mode. To set the GitHub link preview, upload
`assets/brand/png/gh-social.png` under the repository's
**Settings → Social preview**.
