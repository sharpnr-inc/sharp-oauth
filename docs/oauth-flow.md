# The flow, step by step

This walks through one complete "Sign in with Sharpnr", showing the HTTP
messages and the code that handles each step. Run `scripts/demo-flow.sh` to
see it live.

The cast:

* **User**: a person with a browser and a Sharpnr account.
* **Client**: a third-party app registered with Sharpnr (`client_id`
  `sharp_client_…`, redirect URI `http://localhost:4000/callback`).
* **Sharp-OAuth**: this server, at `http://localhost:3000`.

```text
 User's browser            Client app                   Sharp-OAuth
 ──────────────            ──────────                   ───────────
       │   click "Sign in     │                               │
       │   with Sharpnr"      │                               │
       │─────────────────────▶│ 0. make PKCE verifier,        │
       │                      │    state, nonce               │
       │◀──── 302 to /oauth/authorize?... ────                │
       │─────────────────────────────────────────────────────▶│ 1. validate request
       │◀─────────────────────────────── 303 /signin ─────────│ 2. not signed in
       │──── POST /signin (email, password) ─────────────────▶│
       │◀─────────────────────────────── 303 back to authorize│
       │─────────────────────────────────────────────────────▶│ 3. consent page
       │──── POST /oauth/consent decision=approve ───────────▶│ 4. store consent, issue code
       │◀──── 303 localhost:4000/callback?code=…&state=… ─────│
       │─────────────────────▶│ 5. check state                │
       │                      │── POST /oauth/token ─────────▶│ 6. verify client, code, PKCE
       │                      │◀── access, id, refresh token ─│
       │                      │ 7. validate ID token (JWKS)   │
       │                      │── GET /oauth/userinfo ───────▶│ 8. claims
       │                      │── POST /oauth/token (refresh)▶│ 9. rotate refresh token
```

---

## 0. The client prepares

Before redirecting, the client creates three random values and remembers
them (e.g. in its own session):

| Value           | Purpose                                                                  |
|-----------------|--------------------------------------------------------------------------|
| `code_verifier` | PKCE secret. Never leaves the client until step 6.                        |
| `state`         | Ties the callback to *this* browser session (CSRF protection for the client). |
| `nonce`         | Ties the ID token to *this* request (replay protection).                  |

It derives `code_challenge = BASE64URL(SHA256(code_verifier))`.

## 1. The client sends the user to `/oauth/authorize`

```http
GET /oauth/authorize
    ?response_type=code
    &client_id=sharp_client_mKN7RxhQm6wuhW0uBo-ltpG2
    &redirect_uri=http%3A%2F%2Flocalhost%3A4000%2Fcallback
    &scope=openid%20profile%20email%20offline_access
    &state=kxPz2xh-hTiJPc_81iP4Gg
    &nonce=T7dldFLRzwijHVD4N-viXA
    &code_challenge=2GcqHsFs11r1CfbXWiPKcQuqIgtZCAAzOGQXnqgvArQ
    &code_challenge_method=S256
```

**Code:** `http::oauth::authorize_get` → `oauth::authorization::decide` →
`validate`.

`validate` checks in two phases:

1. **Can we trust the redirect URI?** `client_id` must be a registered,
   enabled client, and `redirect_uri` must *exactly equal* one of its
   registered URIs. If not, the user sees an error page. We do **not**
   redirect, because the redirect target is exactly what is in doubt.
2. **Everything else**, reported by redirecting to the (now trusted)
   redirect URI with `?error=…&state=…`:

| Check                                            | Error                        |
|--------------------------------------------------|------------------------------|
| `response_type` is `code`                        | `unsupported_response_type`  |
| `state` present                                  | `invalid_request`            |
| `scope` parses and ⊆ client's allowed scopes     | `invalid_scope`              |
| `code_challenge` present, method is `S256`, well-formed | `invalid_request`     |
| `prompt`, `max_age`, `nonce` valid               | `invalid_request`            |
| no `request` / `request_uri` objects             | `request_not_supported` / `request_uri_not_supported` |

Parameters are read through `oauth::params::Params`, which rejects any
parameter that appears twice.

## 2. Sign in (if needed)

`decide` looks at the `sharp_session` cookie (resolved by the
`http::extract::CurrentSession` extractor).

* No session, or `prompt=login`, or the session is older than `max_age` →
  `303 /signin?return_to=/oauth/authorize?...`
* With `prompt=none`, instead of showing UI → error `login_required`.

The sign-in page (`http::pages::sign_in`) checks the CSRF token, verifies the
password with Argon2id (`identity::user::authenticate`), creates a session
(`identity::session::create`), sets the cookie and redirects back to
`return_to`, but only if it is a local path (`safe_return_to`).

## 3. Consent

Back at `/oauth/authorize`, now signed in. `decide` loads the user's stored
consent for this client (`oauth::consent::granted_scopes`):

* Everything requested was approved before (and no `prompt=consent`) → skip
  straight to step 4.
* Otherwise → render the consent page (`http::html::consent_page`) listing
  each scope's description from `oauth_scopes`. With `prompt=none` →
  `consent_required` instead.

The consent form carries the original authorization parameters as hidden
fields, plus a CSRF token.

## 4. The code is issued

```http
POST /oauth/consent
csrf_token=…&client_id=…&redirect_uri=…&scope=…&state=…&code_challenge=…&…&decision=approve
```

**Code:** `http::oauth::consent` → `authorization::complete_consent`.

1. CSRF token must match the cookie, otherwise 403.
2. The whole request is **validated again** (hidden fields came back from
   the browser; they are input like any other).
3. `decision=deny` → redirect with `error=access_denied`.
4. Store consent, then `issue_code`:
   * 256-bit random code; only `SHA-256(code)` is stored,
   * bound to client, user, redirect URI, scope, PKCE challenge, nonce and
     `auth_time`,
   * expires in **60 seconds**.

```http
HTTP/1.1 303 See Other
Location: http://localhost:4000/callback?code=-uLWLPFY…&state=kxPz2xh-hTiJPc_81iP4Gg&iss=http%3A%2F%2Flocalhost%3A3000
```

`iss` (RFC 9207) lets a client that uses several identity providers confirm
which one answered.

## 5. The client checks the callback

The client must verify that `state` equals what it stored in step 0 and that
`iss` is `http://localhost:3000`. Otherwise it must stop. (This happens in
the client, not in Sharp-OAuth.)

## 6. Code exchange at `/oauth/token`

```http
POST /oauth/token
Authorization: Basic base64(client_id:client_secret)
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=-uLWLPFY…
&redirect_uri=http%3A%2F%2Flocalhost%3A4000%2Fcallback
&code_verifier=-Axl3_sUZTym1xJT21yRRUfn9JBjtGrNjADQXX0Dryk
```

A public client (no secret) omits the header and sends `client_id` in the body.

**Code:** `http::oauth::token` → `oauth::token::handle` →
`exchange_authorization_code`.

1. **Authenticate the client** (`oauth::client::authenticate`): Basic header,
   form secret, or none for public clients. Any failure is `401 invalid_client`.
2. **Consume the code** in a transaction:
   `UPDATE … SET used_at = now() WHERE code_hash = $1 AND used_at IS NULL RETURNING *`.
   * No row but the code exists → it was **already used**. Revoke every
     refresh token issued from it, log `authorization_code_replayed`, return
     `invalid_grant`.
3. **Check bindings** (`check_code_bindings`). Any failure is `invalid_grant`,
   and the code stays consumed:
   * issued to this client,
   * not expired,
   * `redirect_uri` identical to step 1,
   * `BASE64URL(SHA256(code_verifier)) == code_challenge`.
4. **Issue tokens**: sign the JWTs, insert a refresh token if
   `offline_access` was granted, commit.

```json
{
  "access_token": "eyJ0eXAiOiJhdCtqd3QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjIwMjYw…",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "email offline_access openid profile",
  "refresh_token": "uwJSTXtT2lZP…",
  "id_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjIwMjYw…"
}
```

| Token          | Format        | Lifetime | Issued when          | Stored?          |
|----------------|---------------|----------|----------------------|------------------|
| access token   | JWT, `typ: at+jwt` | 15 min | always               | no               |
| ID token       | JWT, `typ: JWT`    | 15 min | scope has `openid`   | no               |
| refresh token  | opaque random | 30 days  | scope has `offline_access` | SHA-256 hash |

## 7. The client validates the ID token

```json
{
  "iss": "http://localhost:3000",
  "sub": "01a09ef6-09bc-737f-9719-28abc4a273c6",
  "aud": "sharp_client_mKN7RxhQm6wuhW0uBo-ltpG2",
  "exp": 1789374219,
  "iat": 1789373319,
  "auth_time": 1789373319,
  "nonce": "T7dldFLRzwijHVD4N-viXA"
}
```

A client (normally its OIDC library) must:

1. Fetch `/.well-known/openid-configuration`, then `jwks_uri`.
2. Pick the key whose `kid` matches the token header; verify the RS256 signature.
3. Check `iss`, that `aud` is its own `client_id`, `exp`, and that `nonce`
   equals the one from step 0.
4. Use **`sub`** as the user's identifier. Not the email: emails change.

The integration test `complete_flow_sign_in_consent_code_tokens_userinfo`
in `tests/oauth_flow.rs` does exactly this.

**Code:** claims are built in `oidc::id_token::IdTokenClaims::new`; signing
is `token::signing::SigningKeys::sign`.

## 8. UserInfo

```http
GET /oauth/userinfo
Authorization: Bearer eyJ0eXAiOiJhdCtqd3Qi…
```

```json
{ "sub": "01a09ef6-…", "name": "Demo User", "updated_at": 1789373319,
  "email": "demo@example.com", "email_verified": false }
```

**Code:** `oidc::userinfo::userinfo` verifies the access token
(`token::access::verify`: signature, `typ`, `iss`, `aud`, `exp`), requires
the `openid` scope, loads the user and returns only the claims its scopes
allow (`claims_for`):

| Scope     | Claims                         |
|-----------|--------------------------------|
| `openid`  | `sub`                          |
| `profile` | `name` (if set), `updated_at`  |
| `email`   | `email`, `email_verified`      |

## 9. Refresh with rotation

```http
POST /oauth/token
Authorization: Basic …

grant_type=refresh_token&refresh_token=uwJSTXtT2lZP…
```

**Code:** `oauth::token::exchange_refresh_token`.

1. Authenticate the client.
2. `SELECT … FOR UPDATE` the token by hash (serialises concurrent use).
3. `RefreshToken::check_usable`:
   * wrong client → `invalid_grant`,
   * revoked → `invalid_grant`,
   * **already rotated → replay!** Revoke the entire family, log
     `refresh_token_replayed`, `invalid_grant`,
   * expired → `invalid_grant`.
4. Optional `scope` may narrow the new access token, never widen it.
5. Insert the new refresh token (same family, original scope), point the old
   one at it (`rotated_to_id`), commit, and return a new access token, ID token
   (without `nonce`) and refresh token.

```text
RT1 ──refresh──▶ RT2 ──refresh──▶ RT3
 │
 └── RT1 presented again ⇒ RT1, RT2, RT3 all revoked
```

## 10. Revocation

```http
POST /oauth/revoke
Authorization: Basic …

token=<refresh token>
```

Revokes the refresh token's whole family (`oauth::revocation::handle`).
Unknown tokens, including access tokens, still return `200 OK` (RFC 7009
§2.2). Access tokens are JWTs and simply expire within 15 minutes.

---

## Discovery: how a client library finds all of this

```http
GET /.well-known/openid-configuration
```

returns the endpoint URLs and capabilities (`oidc::discovery::document`).
Most OIDC libraries need only the issuer URL (`http://localhost:3000`) plus
`client_id`/`client_secret`, and configure everything else from this document.
