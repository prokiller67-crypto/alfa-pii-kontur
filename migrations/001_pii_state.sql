CREATE TABLE IF NOT EXISTS pii_state (
    key TEXT PRIMARY KEY,
    ciphertext BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS pii_state_expiry_idx ON pii_state (expires_at);
