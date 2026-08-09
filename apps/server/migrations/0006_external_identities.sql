CREATE TABLE external_identities (
    provider TEXT NOT NULL,
    provider_subject TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    display_identifier TEXT NOT NULL,
    profile_json TEXT NOT NULL DEFAULT '{}',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (provider, provider_subject),
    UNIQUE (provider, user_id)
);

CREATE INDEX external_identities_user ON external_identities(user_id);
