# Security design

Every protection in Sharp-OAuth exists to stop a specific attack. This page
lists them as **threat → defence → where in the code → which test proves it**.

If you change one of these, change the test too, and never weaken a check to
make a test pass.

## Secrets at rest

| Secret           | Stored as               | Code                                  |
|------------------|-------------------------|---------------------------------------|
| Password         | Argon2id PHC string     | `authentication/services/password.rs`                |
| Session token    | SHA-256                 | `authentication/services/session.rs`                 |
| Authorization code | SHA-256               | `oauth/authorization.rs::issue_code`  |
| Refresh token    | SHA-256                 | `token/refresh.rs::issue`             |
| Client secret    | SHA-256                 | `oauth/client.rs::register`           |
| Signing key      | PEM file, mode 0600, outside Git | `main.rs::generate_signing_key` |

**Threat:** database leak or backup theft.
**Defence:** a hash cannot be used as the token. Random tokens are 256 bits
(`secret::generate_token`), so SHA-256 is enough; passwords are low-entropy,
so they get slow, salted Argon2id.
**Tests:** `sign_up_creates_account_and_session` (hash format),
`sign_in_logout_and_session_invalidation` (raw session token not in DB),
`complete_flow…` (raw code not in DB).

UUIDs identify rows; they are never used as secrets (UUID v7 is mostly a timestamp).

## Passwords and sign-in

| Threat | Defence | Code |
|---|---|---|
| Account enumeration by message | Same "Invalid email or password." for both cases | `authentication/controllers/pages.rs::sign_in` |
| Account enumeration by timing | Argon2 runs against a dummy hash for unknown emails | `authentication/services/password.rs::DUMMY_PASSWORD_HASH` |
| DoS with huge passwords | 1024-byte limit | `authentication/services/user.rs::MAX_PASSWORD_BYTES` |
| Argon2 blocking the async runtime | `spawn_blocking` | `authentication/services/password.rs` |
| Duplicate accounts via races | DB `UNIQUE(email)` + lower-casing | `migrations/0001`, `normalize_email` |

Tests: `wrong_password_and_unknown_email_look_identical`, `duplicate_email_is_rejected`.

**Not yet done:** rate limiting and lockout (plan phase 10).

## Browser sessions and forms

| Threat | Defence | Code |
|---|---|---|
| Session theft via XSS | Cookie is `HttpOnly` | `pkg/cookie_manager.rs` |
| Session sent over plain HTTP | `Secure` when issuer is https | `Config::secure_cookies` |
| Cross-site requests riding the session | `SameSite=Lax` | `pkg/cookie_manager.rs` |
| Forced consent approval (CSRF) | Double-submit CSRF token on every POST form | `middlewares/csrf.rs` |
| Login CSRF (victim signed into attacker's account) | Same CSRF token on `/signin` and `/signup` | `authentication/controllers/pages.rs` |
| Session fixation / stale sessions | Old session revoked on sign-in; logout revokes server-side | `pages.rs::start_session`, `logout` |
| Open redirect via `return_to` | Local paths only; rejects `//host` and `/\host` | `pages.rs::safe_return_to` |
| Clickjacking the consent button | `X-Frame-Options: DENY`, CSP `frame-ancestors 'none'` | `middlewares/security_headers.rs` |
| HTML/script injection via client name, email, `state` | Askama escapes every `{{ value }}`; no manual escaping to forget | `templates/`, `shared/views.rs` |
| Script execution on the consent screen | Pages ship no JavaScript, so CSP stays `default-src 'none'` | `middlewares/security_headers.rs` |
| Tokens cached by proxies/browsers | `Cache-Control: no-store` default | `middlewares/security_headers.rs` |
| Codes leaking via `Referer` | `Referrer-Policy: no-referrer` | `middlewares/security_headers.rs` |

`SameSite=Lax` (not `Strict`) is deliberate: a third-party site links users
to `/oauth/authorize` with a top-level GET, and the session cookie must be
sent then.

Tests: `hostile_client_name_cannot_inject_markup`,
`hidden_field_values_cannot_break_out_of_the_attribute`,
`sign_in_without_csrf_token_is_rejected`,
`consent_without_csrf_token_is_rejected`, `sign_in_does_not_redirect_off_site`,
`security_headers_are_present`, `sign_in_logout_and_session_invalidation`.

## Authorization endpoint

| Threat | Defence | Code |
|---|---|---|
| Code delivered to attacker's URL | Exact string match against registered redirect URIs. No `starts_with`/`contains` | `OAuthClient::has_redirect_uri` |
| Using the error redirect as an open redirector | Unknown client / unregistered URI → error page, never a redirect | `authorization::validate` phase 1 |
| Parameter pollution (`redirect_uri` twice) | Duplicate parameters rejected | `oauth/params.rs` |
| Stolen code redeemed by someone else | PKCE `S256` required for **all** clients | `authorization::validate`, `oauth/pkce.rs` |
| PKCE downgrade | `plain` and missing method rejected | `authorization::validate` |
| CSRF on the client's callback | `state` required and returned | `authorization::validate` |
| ID token replay | `nonce` bound into the code and the ID token | `issue_code`, `oidc/id_token.rs` |
| Mix-up attacks between providers | `iss` in authorization responses (RFC 9207) | `issue_code`, `ErrorRedirect::to_url` |
| Security parameters silently ignored | `request` / `request_uri` explicitly rejected | `authorization::validate` |
| Scope escalation | Requested ⊆ client's allowed scopes; scopes must exist in registry | `validate`, `client::register` |
| Trusting echoed hidden fields | Consent POST re-validates the full request | `complete_consent` |
| Password forwarded to client by redirect | Always `303 See Other`, never 307/308 | `shared::response::redirect` |

Registration rules for redirect URIs (`validate_redirect_uri_for_registration`):
absolute, `https` (or `http` on localhost/loopback only), no fragment, no
embedded credentials.

Tests (`tests/oauth_flow.rs`): `unknown_client_shows_error_page_instead_of_redirecting`,
`unregistered_redirect_uri_shows_error_page`, `repeated_parameters_are_rejected`,
`missing_pkce_is_rejected`, `plain_pkce_method_is_rejected`,
`scope_not_allowed_for_client_is_rejected`, `missing_state_is_rejected`,
`request_objects_are_rejected_not_ignored`; unit test
`redirect_uri_matching_is_exact`.

## Token endpoint

| Threat | Defence | Code |
|---|---|---|
| Code reuse | Atomic `UPDATE … WHERE used_at IS NULL` (SQL asserted in `claim_statement`'s test); replay revokes refresh tokens from that code | `oauth/repo/authorization_codes.rs::claim`, `exchange_authorization_code` |
| Brute-forcing the verifier | A failed attempt still consumes the code | `exchange_authorization_code` |
| Code used by another client | Code bound to client UUID | `check_code_bindings` |
| Redirect URI substitution | `redirect_uri` must equal the authorize request | `check_code_bindings` |
| Slow code theft | 60-second code lifetime | `AUTHORIZATION_CODE_TTL` |
| Confidential client skipping auth | Secret required when the client has one; public clients may not send one | `client::authenticate` |
| Secret guessing via timing | Constant-time hash comparison | `secret::constant_time_eq` |
| Client enumeration | Every client-auth failure is identical `invalid_client` | `client::authenticate` |
| Mixed auth methods | Basic header + body secret together rejected | `client::extract_credentials` |

Tests: `reused_code_is_rejected_and_revokes_issued_refresh_tokens`,
`wrong_pkce_verifier_is_rejected_and_burns_the_code`, `expired_code_is_rejected`,
`code_cannot_be_redeemed_by_another_client`, `redirect_uri_must_match_at_token_endpoint`,
`wrong_client_secret_is_invalid_client`, `confidential_client_must_authenticate`,
`missing_code_verifier_is_rejected`.

## Refresh tokens

| Threat | Defence | Code |
|---|---|---|
| Stolen refresh token used silently | Rotation on every use; reuse of a rotated token revokes the whole family | `exchange_refresh_token`, `token::repo::refresh_tokens::revoke_family` |
| Race: two parallel refreshes both succeed | `SELECT … FOR UPDATE` (SQL asserted in `find_for_update_statement`'s test) | `find_by_hash_for_update` |
| Token used by another client | Bound to client; another client's attempt does not revoke it | `RefreshToken::check_usable` |
| Scope widening on refresh | Requested scope must be ⊆ original grant | `exchange_refresh_token` |
| Endless validity | 30-day expiry per token; revocation endpoint | `REFRESH_TOKEN_TTL`, `oauth/revocation.rs` |
| Unnecessary long-lived credentials | Only issued with `offline_access` | `exchange_authorization_code` |

Tests: `refresh_token_rotation_and_replay_detection`, `refresh_token_is_bound_to_its_client`,
`expired_refresh_token_is_rejected`, `refresh_can_narrow_but_not_widen_scope`,
`revocation_endpoint_revokes_refresh_token_family`, `revocation_requires_client_authentication`.

**Known trade-off:** a legitimate client that sends two refresh requests at the
same moment triggers replay detection and loses its session. A short grace
period can be added later if real clients need it.

## JWTs and keys

| Threat | Defence | Code |
|---|---|---|
| `alg: none` / HS256 key-confusion forgery | Only RS256 accepted, forced in `verify` | `SigningKeys::verify` |
| ID token used as access token | `typ` header checked (`at+jwt` vs `JWT`) | `SigningKeys::verify` |
| Tampered payload | Signature verification | `SigningKeys::verify` |
| Long exposure of a leaked access token | 15-minute lifetime | `ACCESS_TOKEN_TTL` |
| Private key leak via JWKS | JWKS built from public parameters only | `SigningKeys::jwks` |
| Private key in Git | Keys loaded from `SIGNING_KEYS_DIR`; `keys/` and `.env` git-ignored | `.gitignore`, `signing.rs` |
| Breaking tokens during rotation | All keys published; `kid` selects; newest (or `SIGNING_ACTIVE_KID`) signs | `SigningKeys::from_pems` |
| Personal data in tokens | Access and ID tokens carry IDs only; profile data via UserInfo | `token/access.rs`, `oidc/id_token.rs` |

Tests: unit tests in `token/signing.rs` (tampering, wrong `typ`, rotation,
same-`kid`-different-key, JWKS has no private fields); integration tests
`id_token_cannot_be_used_as_access_token`, `expired_access_token_is_rejected`,
`jwks_publishes_public_key_only`.

**Key rotation procedure:**

1. `cargo run -- generate-signing-key` (or mount a new key from your secret manager).
2. To pre-publish before switching, set `SIGNING_ACTIVE_KID` to the *old* kid and restart.
3. After JWKS caches (5 minutes) have refreshed, remove `SIGNING_ACTIVE_KID` (or point it at the new kid) and restart.
4. After 15 minutes more, delete the old key file and restart.

## Identity claims

| Threat | Defence | Code |
|---|---|---|
| Account takeover via email change / reuse | `sub` is the immutable user UUID, never the email | `IdTokenClaims::new`, `claims_for` |
| Clients trusting unverified email | `email_verified` is reported truthfully (`false` until verification exists) | `authentication/services/user.rs` |
| Over-sharing | Claims filtered by granted scopes | `userinfo::claims_for` |
| Advertising unimplemented features | Discovery lists only what works; `request_uri_parameter_supported: false` explicitly | `oidc/discovery.rs` |

Tests: `userinfo_returns_claims_for_granted_scopes_only`, `userinfo_requires_openid_scope`,
`discovery_document_advertises_what_is_implemented`.

## Logging

Never logged: passwords, codes, access/refresh/ID tokens, client secrets,
session tokens, `Authorization` headers, query strings.

* Request logs contain the path only (`middlewares/security_headers.rs::log_requests`).
* Audit events (`target: "audit"`) contain event names and IDs.
* Structs holding secrets (`NewAccount`, `SignInForm`, `ClientCredentials`,
  `TokenResponse`) do not implement `Debug`. Stored hashes use the
  `SecretHash` column type, so `{:?}` on any row prints `<redacted>`
  (`debug_output_never_contains_the_hash`,
  `debug_output_does_not_contain_password_hash`).
* Internal errors are logged server-side and returned as `server_error`.

## CORS

API endpoints (`/oauth/token`, `/oauth/revoke`, `/oauth/userinfo`,
discovery, JWKS) allow any origin so browser-based public clients can call
them. That is safe because none of them read cookies. They authenticate with
client credentials or bearer tokens. Browser pages (`/signin`,
`/oauth/authorize`, `/oauth/consent`) get no CORS headers.

## Not yet implemented (plan phase 10)

* Rate limiting and login throttling
* `audit_events` table (events currently go to the log)
* Email verification
* Consent and session management UI (revoking an app from the account page)
* Automated key rotation
