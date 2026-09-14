-- Short-lived, one-time authorization codes issued by /oauth/authorize and
-- redeemed at /oauth/token.
--
-- Every column after `code_hash` is a *binding*: the token endpoint checks
-- that the redeeming request matches what was approved here.
CREATE TABLE oauth_authorization_codes (
    id                    UUID PRIMARY KEY,
    code_hash             TEXT NOT NULL UNIQUE,
    client_id             UUID NOT NULL REFERENCES oauth_clients (id) ON DELETE CASCADE,
    user_id               UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    redirect_uri          TEXT NOT NULL,
    -- Space-delimited granted scopes, e.g. "openid profile".
    scope                 TEXT NOT NULL,
    -- PKCE. Sharp-OAuth requires S256 for every client, so both are NOT NULL.
    code_challenge        TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL,
    -- OIDC: echoed into the ID token so the client can detect replay.
    nonce                 TEXT,
    -- OIDC: when the user authenticated (from the browser session).
    auth_time             TIMESTAMPTZ NOT NULL,
    expires_at            TIMESTAMPTZ NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL,
    -- Set on first redemption. A second redemption is an attack signal.
    used_at               TIMESTAMPTZ
);
