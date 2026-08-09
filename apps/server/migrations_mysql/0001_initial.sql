CREATE TABLE users (
    id CHAR(36) PRIMARY KEY NOT NULL,
    email VARCHAR(254) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    next_revision BIGINT NOT NULL DEFAULT 0,
    created_at BIGINT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE sessions (
    token_hash CHAR(64) PRIMARY KEY NOT NULL,
    user_id CHAR(36) NOT NULL,
    expires_at BIGINT NOT NULL,
    CONSTRAINT sessions_user_fk FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX sessions_user (user_id),
    INDEX sessions_expiry (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE devices (
    id CHAR(36) NOT NULL,
    user_id CHAR(36) NOT NULL,
    name VARCHAR(120) NOT NULL,
    platform VARCHAR(40) NOT NULL,
    revoked_at BIGINT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (id, user_id),
    CONSTRAINT devices_user_fk FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX devices_user_created (user_id, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE records (
    user_id CHAR(36) NOT NULL,
    record_id CHAR(36) NOT NULL,
    kind VARCHAR(40) NOT NULL,
    ciphertext MEDIUMTEXT NOT NULL,
    data_version BIGINT UNSIGNED NOT NULL,
    current_revision BIGINT NOT NULL,
    deleted BOOLEAN NOT NULL,
    device_id CHAR(36) NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (user_id, record_id),
    CONSTRAINT records_user_fk FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE revision_events (
    user_id CHAR(36) NOT NULL,
    revision BIGINT NOT NULL,
    record_id CHAR(36) NOT NULL,
    kind VARCHAR(40) NOT NULL,
    ciphertext MEDIUMTEXT NOT NULL,
    data_version BIGINT UNSIGNED NOT NULL,
    base_revision BIGINT NOT NULL,
    deleted BOOLEAN NOT NULL,
    device_id CHAR(36) NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (user_id, revision),
    CONSTRAINT revision_events_user_fk FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX revision_events_record (user_id, record_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE conflict_versions (
    conflict_id CHAR(36) PRIMARY KEY NOT NULL,
    user_id CHAR(36) NOT NULL,
    record_id CHAR(36) NOT NULL,
    submitted_kind VARCHAR(40) NOT NULL,
    submitted_ciphertext MEDIUMTEXT NOT NULL,
    submitted_data_version BIGINT UNSIGNED NOT NULL,
    submitted_base_revision BIGINT NOT NULL,
    submitted_deleted BOOLEAN NOT NULL,
    current_revision BIGINT NOT NULL,
    device_id CHAR(36) NOT NULL,
    created_at BIGINT NOT NULL,
    CONSTRAINT conflict_versions_user_fk FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX conflict_versions_record (user_id, record_id, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
