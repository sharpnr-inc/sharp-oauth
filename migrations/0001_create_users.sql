-- Sharpnr user accounts.
--
-- `id` is the stable, never-reused identifier that becomes the OIDC `sub`
-- claim. Email is mutable and must never be used as the external identity key.
CREATE TABLE users (
    id             UUID PRIMARY KEY,
    -- Stored lower-cased by the application so the UNIQUE constraint is
    -- effectively case-insensitive.
    email          TEXT NOT NULL UNIQUE,
    -- Argon2id PHC string ("$argon2id$v=19$..."). Never a plaintext password.
    password_hash  TEXT NOT NULL,
    display_name   TEXT,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at     TIMESTAMPTZ NOT NULL,
    updated_at     TIMESTAMPTZ NOT NULL
);
