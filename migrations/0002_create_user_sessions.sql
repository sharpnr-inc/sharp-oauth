-- Browser sessions on the Sharpnr sign-in site.
--
-- The authorization endpoint uses this to know which user is signed in.
-- The raw session token lives only in the user's cookie; we store its
-- SHA-256 hash so a database leak does not hand out live sessions.
CREATE TABLE user_sessions (
    id                 UUID PRIMARY KEY,
    user_id            UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    session_token_hash TEXT NOT NULL UNIQUE,
    expires_at         TIMESTAMPTZ NOT NULL,
    -- When the user typed their password. Becomes the OIDC `auth_time` claim.
    created_at         TIMESTAMPTZ NOT NULL,
    revoked_at         TIMESTAMPTZ
);

CREATE INDEX user_sessions_user_id_idx ON user_sessions (user_id);
