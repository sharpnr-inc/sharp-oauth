-- A user's approval for a client to access a set of scopes.
--
-- Stored so the user is not asked again for scopes they already approved.
CREATE TABLE oauth_consents (
    id         UUID PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    client_id  UUID NOT NULL REFERENCES oauth_clients (id) ON DELETE CASCADE,
    scopes     TEXT[] NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    UNIQUE (user_id, client_id)
);
