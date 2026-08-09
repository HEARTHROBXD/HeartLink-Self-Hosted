PRAGMA foreign_keys = ON;

CREATE TABLE users (
    id TEXT PRIMARY KEY NOT NULL,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    next_revision INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);

CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
);

CREATE TABLE devices (
    id TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    platform TEXT NOT NULL,
    revoked_at INTEGER,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (id, user_id)
);

CREATE TABLE records (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    record_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    ciphertext TEXT NOT NULL,
    data_version INTEGER NOT NULL,
    current_revision INTEGER NOT NULL,
    deleted INTEGER NOT NULL CHECK (deleted IN (0, 1)),
    device_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, record_id)
);

CREATE TABLE revision_events (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    revision INTEGER NOT NULL,
    record_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    ciphertext TEXT NOT NULL,
    data_version INTEGER NOT NULL,
    base_revision INTEGER NOT NULL,
    deleted INTEGER NOT NULL CHECK (deleted IN (0, 1)),
    device_id TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, revision)
);

CREATE TABLE conflict_versions (
    conflict_id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    record_id TEXT NOT NULL,
    submitted_kind TEXT NOT NULL,
    submitted_ciphertext TEXT NOT NULL,
    submitted_data_version INTEGER NOT NULL,
    submitted_base_revision INTEGER NOT NULL,
    submitted_deleted INTEGER NOT NULL CHECK (submitted_deleted IN (0, 1)),
    current_revision INTEGER NOT NULL,
    device_id TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX revision_events_cursor ON revision_events(user_id, revision);
CREATE INDEX sessions_user ON sessions(user_id);
