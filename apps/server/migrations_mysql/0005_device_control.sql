ALTER TABLE devices
    ADD COLUMN control_token_hash CHAR(64) NULL,
    ADD INDEX devices_control_token (id, control_token_hash);

CREATE TABLE device_commands (
    id CHAR(36) PRIMARY KEY NOT NULL,
    user_id CHAR(36) NOT NULL,
    device_id CHAR(36) NOT NULL,
    action VARCHAR(48) NOT NULL,
    issued_at BIGINT NOT NULL,
    delivered_at BIGINT NULL,
    acknowledged_at BIGINT NULL,
    CONSTRAINT device_commands_device_fk
        FOREIGN KEY (device_id, user_id)
        REFERENCES devices(id, user_id)
        ON DELETE CASCADE,
    INDEX device_commands_pending (device_id, acknowledged_at, issued_at),
    INDEX device_commands_user (user_id, issued_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
