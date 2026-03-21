-- New clean schema for axess-example-sqlite
-- Replaces the old auth_factors / factor_states / auth_methods / method_states tables.

-- tenants
CREATE TABLE IF NOT EXISTS tenants (
    id          TEXT PRIMARY KEY,
    identifier  TEXT NOT NULL UNIQUE,  -- slug used for lookup
    name        TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'active',
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- users
CREATE TABLE IF NOT EXISTS users (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL REFERENCES tenants(id),
    identifier      TEXT NOT NULL,          -- username or email
    display_name    TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'active',
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT,                   -- nullable ISO8601 datetime
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(tenant_id, identifier)
);

-- factor_configs — typed factor configuration per user/tenant/global scope
-- Scope: user_id + tenant_id = user scope; tenant_id only = tenant scope; both NULL = global
CREATE TABLE IF NOT EXISTS factor_configs (
    id          TEXT PRIMARY KEY,
    user_id     TEXT REFERENCES users(id),
    tenant_id   TEXT REFERENCES tenants(id),
    kind        TEXT NOT NULL,              -- 'password', 'totp', 'hotp', 'email_otp'
    config_json TEXT NOT NULL,             -- JSON-encoded FactorConfig enum value
    enabled     INTEGER NOT NULL DEFAULT 1,
    updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(user_id, tenant_id, kind)
);

-- auth_methods — ordered factor sequences available per user
-- One row per method; factors_json is a JSON array of FactorKind strings
CREATE TABLE IF NOT EXISTS auth_methods (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,            -- e.g. 'password+totp'
    factors_json TEXT NOT NULL,            -- JSON: ["Password","Totp"]
    user_id      TEXT REFERENCES users(id),
    tenant_id    TEXT REFERENCES tenants(id),
    enabled      INTEGER NOT NULL DEFAULT 1
);

-- auth_events — audit log
CREATE TABLE IF NOT EXISTS auth_events (
    id           TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    user_id      TEXT NOT NULL,
    tenant_id    TEXT NOT NULL,
    session_id   TEXT,
    event_type   TEXT NOT NULL,
    event_status TEXT NOT NULL,
    event_time   TEXT NOT NULL DEFAULT (datetime('now')),
    factor_kind  TEXT,
    ip_address   TEXT,
    user_agent   TEXT,
    error        TEXT
);

-- sessions — managed by SqliteSessionStore
CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,          -- UUID as string
    data        TEXT NOT NULL,             -- JSON-encoded SessionData
    expires_at  INTEGER NOT NULL           -- Unix timestamp (seconds)
);
