-- Consolidated schema for axess-example-sqlite.
--
-- Single migration covering every table the example needs:
--   * core entities (tenants, users)
--   * factor configuration + auth method composition
--   * audit log (auth_events)
--   * session storage (sessions; managed by SqliteSessionStore)
--   * IdentityAdmin password-history + password-reset state
--   * RefreshTokenStore backing
--
-- Example DBs are recreated on every dev iteration; historical
-- migration sequencing has no value here. If a feature later requires
-- a schema change, add a new dated migration and keep this file as the
-- baseline (or fold it in once devs drop their existing dev DBs).

-- ── Core entities ───────────────────────────────────────────────────

-- tenants
CREATE TABLE IF NOT EXISTS tenants (
    id          TEXT PRIMARY KEY,
    identifier  TEXT NOT NULL UNIQUE,  -- slug used for lookup
    name        TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'active',
    created_by  TEXT NOT NULL,         -- UserId of the creating actor
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_by  TEXT NOT NULL,         -- UserId of the last updater
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
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
    created_by      TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_by      TEXT NOT NULL,
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(tenant_id, identifier)
);

-- ── Factor + method composition ─────────────────────────────────────

-- factor_configs — typed factor configuration per user/tenant/system scope.
-- Scope encoding:
--   user_id set,  tenant_id = <tenant>          → User { tenant, user }
--   user_id NULL, tenant_id = <tenant>          → Tenant(tenant)
--   user_id NULL, tenant_id = TenantId::SYSTEM  → System
-- `tenant_id` is NEVER NULL for configuration scope; system-owned rows
-- live under the reserved SYSTEM tenant (seeded below).
CREATE TABLE IF NOT EXISTS factor_configs (
    id          TEXT PRIMARY KEY,
    user_id     TEXT REFERENCES users(id),
    tenant_id   TEXT NOT NULL REFERENCES tenants(id),
    kind        TEXT NOT NULL,              -- 'password', 'totp', 'hotp', 'email_otp'
    config_json TEXT NOT NULL,              -- JSON-encoded FactorConfig enum value
    enabled     INTEGER NOT NULL DEFAULT 1,
    updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(user_id, tenant_id, kind)
);

-- auth_methods — ordered factor sequences available per user or tenant.
-- One row per method. `steps_json` serialises a full `Vec<FactorStep>` so
-- both simple sequential flows and `FactorStep::AnyOf(..)` compositions
-- round-trip through storage.
--
-- Scope encoding matches factor_configs; there is no runtime System-scope
-- auth method (the SQLite `FactorStore` impl rejects System scope on
-- save/remove/set_enabled).
CREATE TABLE IF NOT EXISTS auth_methods (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,            -- e.g. 'password+totp'
    steps_json  TEXT NOT NULL,            -- JSON: [{"Required":"Password"},{"Required":"Totp"}]
    user_id     TEXT REFERENCES users(id),
    tenant_id   TEXT NOT NULL REFERENCES tenants(id),
    enabled     INTEGER NOT NULL DEFAULT 1,
    UNIQUE(user_id, tenant_id, name)
);

-- ── System-tenant bootstrap ─────────────────────────────────────────
--
-- The reserved SYSTEM tenant is the storage anchor for AuthnScope::System
-- rows in factor_configs. The row must exist before any system-scope
-- factor is inserted (FK integrity). UUID is `TenantId::SYSTEM` /
-- `Uuid::nil()`.
INSERT OR IGNORE INTO tenants (id, identifier, name, status, created_by, updated_by)
VALUES (
    '00000000-0000-0000-0000-000000000000',
    'system',
    'System',
    'active',
    '00000000-0000-0000-0000-000000000001',   -- UserId::SYSTEM
    '00000000-0000-0000-0000-000000000001'
);

-- ── Audit + sessions ────────────────────────────────────────────────

-- auth_events — audit log.
-- user_id / tenant_id are nullable so pre-auth events (failed login for an
-- unknown user, OAuth callback with a malformed subject claim) can be
-- recorded honestly with NULL attribution rather than a sentinel principal.
CREATE TABLE IF NOT EXISTS auth_events (
    id           TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    user_id      TEXT REFERENCES users(id),
    tenant_id    TEXT REFERENCES tenants(id),
    session_id   TEXT,
    event_type   TEXT NOT NULL,
    event_status TEXT NOT NULL,
    event_time   TEXT NOT NULL DEFAULT (datetime('now')),
    factor_kind  TEXT,
    ip_address   TEXT,
    -- How `ip_address` was arrived at: unknown, peer, forwarded, supplied.
    -- An address alone is not evidence; a row saying `supplied` where the
    -- rest say `forwarded` is the one to ask about.
    ip_source    TEXT NOT NULL DEFAULT 'unknown',
    user_agent   TEXT,
    request_id   TEXT,
    -- W3C trace id. The request id joins this row to one service's logs;
    -- this joins it to the trace that crosses them.
    trace_id     TEXT,
    geo_country  TEXT,
    error        TEXT
);

-- sessions — managed by SqliteSessionStore.
CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,          -- UUID as string
    data        TEXT NOT NULL,             -- JSON-encoded SessionData
    expires_at  INTEGER NOT NULL           -- Unix timestamp (seconds)
);

-- ── IdentityAdmin + RefreshTokenStore backing ──────────────────────

-- password_history — per-user record of every prior password hash.
-- Required by SOC2 / PCI-DSS / NIST SP 800-63B §5.1.1.2 password-reuse
-- prevention. New entries are appended on every successful password
-- change; the verifier consults the most recent N entries.
CREATE TABLE IF NOT EXISTS password_history (
    user_id    TEXT NOT NULL,
    hash       TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (user_id, hash),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_password_history_user_created
    ON password_history(user_id, created_at DESC);

-- password_reset_tokens — out-of-band password-recovery state.
-- One token per user at a time (an issuing call upserts so prior tokens
-- are invalidated). `verify_reset_token` deletes the row on a successful
-- match, enforcing single-use semantics.
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    user_id    TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- refresh_tokens — long-lived refresh-token records backing
-- `RefreshTokenStore`. The trait's atomic primitives
-- (revoke_family / issue_with_eviction / rotate_token) are required:
-- each is implemented as a single UPDATE … WHERE statement or as a
-- sqlx::Pool::begin() transaction that combines an UPDATE with an
-- INSERT inside one commit boundary.
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id   TEXT NOT NULL REFERENCES tenants(id),
    token_hash  TEXT NOT NULL UNIQUE,
    family_id   TEXT,
    device_id   TEXT,
    device_info TEXT,
    issued_at   TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    revoked     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user
    ON refresh_tokens(user_id, revoked);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family
    ON refresh_tokens(user_id, family_id);
