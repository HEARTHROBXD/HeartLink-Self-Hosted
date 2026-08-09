CREATE TABLE service_settings (
    setting_key VARCHAR(80) PRIMARY KEY NOT NULL,
    setting_value MEDIUMTEXT NOT NULL,
    is_secret BOOLEAN NOT NULL,
    updated_at BIGINT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE admin_audit_events (
    id CHAR(36) PRIMARY KEY NOT NULL,
    action VARCHAR(80) NOT NULL,
    target VARCHAR(255) NOT NULL,
    created_at BIGINT NOT NULL,
    INDEX admin_audit_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
