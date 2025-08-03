-- SQLite-compatible migration file
CREATE TABLE IF NOT EXISTS tenants (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    state TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    created_by TEXT NOT NULL,
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    auth_hash TEXT  NOT NULL DEFAULT '',
    username TEXT NOT NULL,
    fullname TEXT NOT NULL DEFAULT '',
    email TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL,
    last_login_at INTEGER,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    created_by TEXT NOT NULL,
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_by TEXT NOT NULL,
    UNIQUE(tenant_id, username),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS auth_factors (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    created_by TEXT NOT NULL,
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_by TEXT NOT NULL,
    UNIQUE(name, kind)
);

CREATE TABLE IF NOT EXISTS factor_states (
    id TEXT PRIMARY KEY,
    factor_id TEXT NOT NULL,
    tenant_id TEXT, -- NULL for global-level methods
    user_id TEXT, -- NULL for tenant-level and global-level methods
    state TEXT NOT NULL, -- e.g., 'pending', 'verified', 'failed'
    config TEXT NOT NULL DEFAULT '{}',
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    created_by TEXT NOT NULL,
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_by TEXT NOT NULL,
    UNIQUE(factor_id, tenant_id, user_id),
    FOREIGN KEY (factor_id) REFERENCES auth_factors(id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS auth_methods (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    factors TEXT NOT NULL DEFAULT '[]', -- JSON array of auth_factor IDs
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    created_by TEXT NOT NULL,
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS method_states (
    id TEXT PRIMARY KEY,
    method_id TEXT NOT NULL,
    tenant_id TEXT, -- NULL for global-level methods
    user_id TEXT, -- NULL for tenant-level and global-level methods
    state TEXT NOT NULL, -- e.g., 'pending', 'completed', 'failed'
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    created_by TEXT NOT NULL,
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_by TEXT NOT NULL,
    UNIQUE(method_id, tenant_id, user_id),
    FOREIGN KEY (method_id) REFERENCES auth_methods(id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Insert default tenants
INSERT INTO tenants (id, name, description, state, created_at, created_by, updated_at, updated_by) VALUES
    ('b7e1e7c2-1a2b-4c3d-8e9f-1234567890ab', 'Default Tenant', 'The default system tenant for all users', 'Active', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000'),
    ('c8f2f8d3-2b3c-5d4e-9f0a-2345678901bc', 'Gnomes', 'Tenant for the Gnomes organization', 'Active', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000');

-- Insert example users
INSERT INTO users (id, tenant_id, auth_hash, username, fullname, email, state, last_login_at, created_at, created_by, updated_at, updated_by) VALUES
    -- System super user (global, not tied to a tenant)
    ('00000000-0000-0000-0000-000000000000', 'b7e1e7c2-1a2b-4c3d-8e9f-1234567890ab', '{"password":"$argon2id$v=19$..."}', 'system', 'System Superuser', 'system@example.com', 'Active', NULL, strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000'),
    -- System user for Default Tenant
    ('00000000-0000-0000-0000-000000000001', 'b7e1e7c2-1a2b-4c3d-8e9f-1234567890ab', '{"password":"$argon2id$v=19$..."}', 'tenant', 'Default Tenant Super User', 'default@example.com', 'Active', NULL, strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000'),
    -- System user for Gnomes Tenant
    ('00000000-0000-0000-0000-000000000002', 'c8f2f8d3-2b3c-5d4e-9f0a-2345678901bc', '{"password":"$argon2id$v=19$..."}', 'tenant', 'Gnomes Tenant Super User', 'gnomes@example.com', 'Active', NULL, strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000'),
    -- Default Tenant: admin user
    ('d9a3a9e4-3c4d-6e5f-0a1b-3456789012cd', 'b7e1e7c2-1a2b-4c3d-8e9f-1234567890ab', '{"password":"$argon2id$v=19$..."}', 'admin', 'Admin User', 'admin@example.com', 'Active', NULL, strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000'),
    -- Default Tenant: regular user
    ('f1c5cbe6-5e6f-8g7h-2c3d-5678901234ef', 'b7e1e7c2-1a2b-4c3d-8e9f-1234567890ab', '{"password":"$argon2id$v=19$..."}', 'user1', 'User One', 'user1@example.com', 'Active', NULL, strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000'),
    -- Default Tenant: second regular user
    ('f2d6dce7-6f7g-9h8i-3d4e-6789012345fb', 'b7e1e7c2-1a2b-4c3d-8e9f-1234567890ab', '{"password":"$argon2id$v=19$..."}', 'user2', 'User Two', 'user2@example.com', 'Active', NULL, strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000'),
    -- Gnomes Tenant: chief user
    ('e0b4bae5-4d5e-7f6a-1b2c-4567890123de', 'c8f2f8d3-2b3c-5d4e-9f0a-2345678901bc', '{"password":"$argon2id$v=19$..."}', 'gnomes1', 'Chief Gnome', 'gnomes1@example.com', 'Active', NULL, strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000'),
    -- Gnomes Tenant: secondary user
    ('a2d6dcf7-6f7g-9h8i-3d4e-6789012345fa', 'c8f2f8d3-2b3c-5d4e-9f0a-2345678901bc', '{"password":"$argon2id$v=19$..."}', 'gnomes2', 'Second Gnome', 'gnomes2@example.com', 'Active', NULL, strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000'),
    -- Gnomes Tenant: third user
    ('a3e7edf8-7g8h-0i9j-4e5f-7890123456fc', 'c8f2f8d3-2b3c-5d4e-9f0a-2345678901bc', '{"password":"$argon2id$v=19$..."}', 'gnomes3', 'Third Gnome', 'gnomes3@example.com', 'Active', NULL, strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000');

-- Insert example authentication factors
-- 'password' is a global factor, 'totp' is tenant-specific (Gnomes only)
INSERT INTO auth_factors (id, kind, name, description, created_at, created_by, updated_at, updated_by) VALUES
    ('00000000-0000-0000-0000-000000000101', 'password', 'Password', 'Standard password authentication', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000'),
    ('00000000-0000-0000-0000-000000000102', 'totp', 'TOTP', 'Time-based One-Time Password', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000');

-- Insert example factor states
-- password is global (tenant_id/user_id NULL), totp is tenant-specific (Gnomes)
-- Add a user-specific factor state for 'gnomesecond' in Gnomes
INSERT INTO factor_states (id, factor_id, tenant_id, user_id, state, config, created_at, created_by, updated_at, updated_by) VALUES
    -- Global password factor for all users (no tenant_id/user_id)
    ('10000000000000000000000000000001', '00000000-0000-0000-0000-000000000101', NULL, NULL, 'Active', '{}', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000'),
    -- Gnomes tenant TOTP factor (tenant-specific, no user)
    ('10000000000000000000000000000002', '00000000-0000-0000-0000-000000000102', 'c8f2f8d3-2b3c-5d4e-9f0a-2345678901bc', NULL, 'Active', '{}', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000'),
     -- Admin user with password factor and totp factor
    ('10000000000000000000000000000004', '00000000-0000-0000-0000-000000000101', 'b7e1e7c2-1a2b-4c3d-8e9f-1234567890ab', 'd9a3a9e4-3c4d-6e5f-0a1b-3456789012cd', 'Active', '{"password":"1234567890abdefg"}', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000'),
    ('10000000000000000000000000000005', '00000000-0000-0000-0000-000000000102', 'b7e1e7c2-1a2b-4c3d-8e9f-1234567890ab', 'd9a3a9e4-3c4d-6e5f-0a1b-3456789012cd', 'Inactive', '{"totp":""}', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000'),
    -- Regular use one with password factor only
    ('10000000000000000000000000000006', '00000000-0000-0000-0000-000000000101', 'b7e1e7c2-1a2b-4c3d-8e9f-1234567890ab', 'f1c5cbe6-5e6f-8g7h-2c3d-5678901234ef', 'Active', '{"password":"1234567890abdefg"}', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000'),
    -- Regular user one with password factor only
    ('10000000000000000000000000000007', '00000000-0000-0000-0000-000000000101', 'b7e1e7c2-1a2b-4c3d-8e9f-1234567890ab', 'f2d6dce7-6f7g-9h8i-3d4e-6789012345fb', 'Active', '{"password":"1234567890abdefg"}', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000'),
    -- Gnomes chief user with password factor and totp factor
    ('10000000000000000000000000000008', '00000000-0000-0000-0000-000000000101', 'c8f2f8d3-2b3c-5d4e-9f0a-2345678901bc', 'e0b4bae5-4d5e-7f6a-1b2c-4567890123de', 'Active', '{"password":"1234567890abdefg"}', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000'),
    ('10000000000000000000000000000009', '00000000-0000-0000-0000-000000000102', 'c8f2f8d3-2b3c-5d4e-9f0a-2345678901bc', 'e0b4bae5-4d5e-7f6a-1b2c-4567890123de', 'Inactive', '{"totp":""}', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000001', strftime('%s', 'now'), '10001000-1001-1002-1003-100410051006'),
    -- Gnomes second user with password factor and totp factor
    ('10000000000000000000000000000010', '00000000-0000-0000-0000-000000000101', 'c8f2f8d3-2b3c-5d4e-9f0a-2345678901bc', 'a2d6dcf7-6f7g-9h8i-3d4e-6789012345fa', 'Active', '{"password":"1234567890abdefg"}', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000001', strftime('%s', 'now'), '10001000-1001-1002-1003-100410051006'),
    ('10000000000000000000000000000011', '00000000-0000-0000-0000-000000000102', 'c8f2f8d3-2b3c-5d4e-9f0a-2345678901bc', 'a2d6dcf7-6f7g-9h8i-3d4e-6789012345fa', 'Inactive', '{"totp":""}', strftime('%s', 'now'), '10001000-1001-1002-1003-100410051006', strftime('%s', 'now'), '10001000-1001-1002-1003-100410051006'),
    -- Gnomes third user with password factor only
    ('10000000000000000000000000000012', '00000000-0000-0000-0000-000000000101', 'c8f2f8d3-2b3c-5d4e-9f0a-2345678901bc', 'a3e7edf8-7g8h-0i9j-4e5f-7890123456fc', 'Active', '{"password":"1234567890abdefg"}', strftime('%s', 'now'), '10001000-1001-1002-1003-100410051006', strftime('%s', 'now'), '10001000-1001-1002-1003-100410051006');

-- Insert example authentication methods
-- Password Only (global), Password + TOTP (Gnomes only)
INSERT INTO auth_methods (id, name, description, factors, created_at, created_by, updated_at, updated_by) VALUES
    ('00000000-0000-0000-0000-000000000201', 'Password Only', 'Single factor password authentication', '["00000000-0000-0000-0000-000000000001"]', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000'),
    ('00000000-0000-0000-0000-000000000202', 'Password + TOTP', 'Two-factor authentication with password and TOTP (Gnomes only)', '["00000000-0000-0000-0000-000000000001","00000000-0000-0000-0000-000000000002"]', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000');

-- Insert example method states
-- admin (Default Tenant) completed Password Only
-- gnomechief (Gnomes) completed Password + TOTP
-- gnomesecond (Gnomes) pending Password + TOTP
INSERT INTO method_states (id, method_id, tenant_id, user_id, state, created_at, created_by, updated_at, updated_by) VALUES
    -- Password Only for the default tenant
    ('20000000000000000000000000000001', '00000000-0000-0000-0000-000000000201', 'b7e1e7c2-1a2b-4c3d-8e9f-1234567890ab', NULL, 'Active', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000'),
    -- Password and TOTP for the Gnomes tenant
    ('20000000000000000000000000000002', '00000000-0000-0000-0000-000000000202', 'c8f2f8d3-2b3c-5d4e-9f0a-2345678901bc', NULL, 'Active', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000001'),
    -- gnomechief@gnomes.org (Password + TOTP)
    ('20000000000000000000000000000003', '00000000-0000-0000-0000-000000000202', 'c8f2f8d3-2b3c-5d4e-9f0a-2345678901bc', 'e0b4bae5-4d5e-7f6a-1b2c-4567890123de', 'Active', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000'),
    -- gnomesecond@gnomes.org (Password + TOTP, pending)
    ('20000000000000000000000000000004', '00000000-0000-0000-0000-000000000202', 'c8f2f8d3-2b3c-5d4e-9f0a-2345678901bc', 'a2d6dcf7-6f7g-9h8i-3d4e-6789012345fa', 'Pending', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000', strftime('%s', 'now'), '00000000-0000-0000-0000-000000000000');
