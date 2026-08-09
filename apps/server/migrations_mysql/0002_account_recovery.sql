ALTER TABLE users
    ADD COLUMN phone VARCHAR(20) NULL,
    ADD UNIQUE INDEX users_phone_unique (phone);

CREATE TABLE recovery_challenges (
    id CHAR(36) PRIMARY KEY NOT NULL,
    user_id CHAR(36) NOT NULL,
    purpose VARCHAR(32) NOT NULL,
    channel VARCHAR(16) NOT NULL,
    code_hash CHAR(64) NOT NULL,
    expires_at BIGINT NOT NULL,
    attempts INT NOT NULL DEFAULT 0,
    consumed_at BIGINT NULL,
    created_at BIGINT NOT NULL,
    CONSTRAINT recovery_challenges_user_fk
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX recovery_challenges_user_created
        (user_id, purpose, channel, created_at),
    INDEX recovery_challenges_expiry (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE recovery_tokens (
    token_hash CHAR(64) PRIMARY KEY NOT NULL,
    user_id CHAR(36) NOT NULL,
    purpose VARCHAR(32) NOT NULL,
    expires_at BIGINT NOT NULL,
    consumed_at BIGINT NULL,
    created_at BIGINT NOT NULL,
    CONSTRAINT recovery_tokens_user_fk
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX recovery_tokens_expiry (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
