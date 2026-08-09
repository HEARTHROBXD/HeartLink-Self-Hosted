ALTER TABLE devices ADD COLUMN control_token_hash TEXT;

CREATE TABLE device_commands (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('wipe_local_data_and_logout')),
    issued_at INTEGER NOT NULL,
    delivered_at INTEGER,
    acknowledged_at INTEGER,
    FOREIGN KEY (device_id, user_id) REFERENCES devices(id, user_id) ON DELETE CASCADE
);

CREATE INDEX device_commands_pending
    ON device_commands(device_id, acknowledged_at, issued_at);
CREATE INDEX device_commands_user
    ON device_commands(user_id, issued_at);
