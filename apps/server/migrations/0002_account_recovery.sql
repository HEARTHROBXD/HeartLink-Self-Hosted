ALTER TABLE users ADD COLUMN phone TEXT;
CREATE UNIQUE INDEX users_phone_unique ON users(phone);

CREATE TABLE recovery_challenges (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose TEXT NOT NULL,
    channel TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    consumed_at INTEGER,
    created_at INTEGER NOT NULL
);

CREATE TABLE recovery_tokens (
    token_hash TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER,
    created_at INTEGER NOT NULL
);

CREATE INDEX recovery_challenges_user_created
    ON recovery_challenges(user_id, purpose, channel, created_at);
CREATE INDEX recovery_challenges_expiry ON recovery_challenges(expires_at);
CREATE INDEX recovery_tokens_expiry ON recovery_tokens(expires_at);
