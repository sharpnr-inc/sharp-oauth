-- Which Sharpnr user registered a client through the developer portal.
--
-- NULL for clients created with the `create-client` CLI: those belong to the
-- operator and never show up in anyone's portal. Deleting the owner's account
-- deletes their applications (and, through the existing cascades, every code,
-- consent and refresh token issued to them).
ALTER TABLE oauth_clients
    ADD COLUMN owner_user_id UUID REFERENCES users (id) ON DELETE CASCADE;

CREATE INDEX oauth_clients_owner_user_id_idx ON oauth_clients (owner_user_id);
