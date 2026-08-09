ALTER TABLE devices
    ADD COLUMN last_seen_at BIGINT NOT NULL DEFAULT 0,
    ADD INDEX devices_user_last_seen (user_id, last_seen_at);

ALTER TABLE sessions
    ADD COLUMN device_id CHAR(36) NULL,
    ADD COLUMN created_at BIGINT NOT NULL DEFAULT 0,
    ADD INDEX sessions_device (user_id, device_id);
