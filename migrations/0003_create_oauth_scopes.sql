-- The registry of scopes Sharp-OAuth understands.
--
-- Clients may only be registered with scopes from this table, so a scope can
-- never appear "out of nowhere". Adding a scope is a deliberate migration.
CREATE TABLE oauth_scopes (
    name        TEXT PRIMARY KEY,
    -- Human readable text shown to the user on the consent screen.
    description TEXT NOT NULL
);

INSERT INTO oauth_scopes (name, description) VALUES
    ('openid',         'Sign you in with your Sharpnr account'),
    ('profile',        'See your display name'),
    ('email',          'See your email address'),
    ('offline_access', 'Stay connected when you are not using the app');
