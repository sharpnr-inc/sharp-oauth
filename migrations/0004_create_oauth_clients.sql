-- Registered third-party applications ("clients" in OAuth terminology).
CREATE TABLE oauth_clients (
    id                 UUID PRIMARY KEY,
    -- Public identifier sent in requests, e.g. "sharp_client_...".
    client_id          TEXT NOT NULL UNIQUE,
    -- SHA-256 of the client secret. NULL means a *public* client (SPA,
    -- mobile or desktop app) that cannot keep a secret and relies on PKCE.
    client_secret_hash TEXT,
    name               TEXT NOT NULL,
    -- Exact redirect URIs. Requests must match one of these byte-for-byte.
    redirect_uris      TEXT[] NOT NULL,
    -- Scopes this client may request. Validated against oauth_scopes on
    -- registration.
    allowed_scopes     TEXT[] NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL,
    updated_at         TIMESTAMPTZ NOT NULL,
    disabled_at        TIMESTAMPTZ
);
