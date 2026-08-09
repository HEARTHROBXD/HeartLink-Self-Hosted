CREATE TABLE external_identities (
    provider VARCHAR(40) NOT NULL,
    provider_subject VARCHAR(191) NOT NULL,
    user_id CHAR(36) NOT NULL,
    display_identifier VARCHAR(254) NOT NULL,
    profile_json TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (provider, provider_subject),
    UNIQUE KEY external_identities_provider_user (provider, user_id),
    INDEX external_identities_user (user_id),
    CONSTRAINT external_identities_user_fk FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
