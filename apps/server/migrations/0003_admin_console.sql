CREATE TABLE service_settings (
    setting_key TEXT PRIMARY KEY NOT NULL,
    setting_value TEXT NOT NULL,
    is_secret INTEGER NOT NULL CHECK (is_secret IN (0, 1)),
    updated_at INTEGER NOT NULL
);

CREATE TABLE admin_audit_events (
    id TEXT PRIMARY KEY NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX admin_audit_created ON admin_audit_events(created_at);
