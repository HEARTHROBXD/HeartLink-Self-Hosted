ALTER TABLE devices ADD COLUMN last_seen_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN device_id TEXT;
ALTER TABLE sessions ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0;

CREATE INDEX devices_user_last_seen ON devices(user_id, last_seen_at);
CREATE INDEX sessions_device ON sessions(user_id, device_id);
