-- Refresh tokens with rotation and replay detection.
--
-- Every successful refresh creates a new row and points the old one at it via
-- `rotated_to_id`. All tokens descending from one authorization share a
-- `family_id`. If an already-rotated token is presented again, someone has a
-- copy they should not have, so the whole family is revoked.
CREATE TABLE oauth_refresh_tokens (
    id                    UUID PRIMARY KEY,
    token_hash            TEXT NOT NULL UNIQUE,
    family_id             UUID NOT NULL,
    -- The authorization code this family was born from. Lets us revoke the
    -- family if that code is replayed (RFC 6749 section 4.1.2).
    authorization_code_id UUID REFERENCES oauth_authorization_codes (id) ON DELETE SET NULL,
    client_id             UUID NOT NULL REFERENCES oauth_clients (id) ON DELETE CASCADE,
    user_id               UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    scope                 TEXT NOT NULL,
    auth_time             TIMESTAMPTZ NOT NULL,
    expires_at            TIMESTAMPTZ NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL,
    revoked_at            TIMESTAMPTZ,
    rotated_to_id         UUID REFERENCES oauth_refresh_tokens (id)
);

CREATE INDEX oauth_refresh_tokens_family_id_idx ON oauth_refresh_tokens (family_id);
CREATE INDEX oauth_refresh_tokens_authorization_code_id_idx ON oauth_refresh_tokens (authorization_code_id);
