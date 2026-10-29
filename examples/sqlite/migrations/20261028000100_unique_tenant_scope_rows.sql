-- UNIQUE(user_id, tenant_id, kind) never matches a tenant- or system-scope
-- row: those store user_id NULL, and SQLite treats NULLs as distinct in a
-- UNIQUE constraint. So ON CONFLICT never fired for them, every save added a
-- row and a lookup with LIMIT 1 could return the stale one.
--
-- First remove the duplicates that accumulated (keep the newest row per
-- scope, by rowid), then enforce uniqueness for the NULL-user scopes with
-- partial unique indexes. The writers in `factors.rs` name the matching
-- index as their ON CONFLICT target.

DELETE FROM factor_configs
 WHERE user_id IS NULL
   AND rowid NOT IN (
       SELECT MAX(rowid) FROM factor_configs
        WHERE user_id IS NULL
        GROUP BY tenant_id, kind);

DELETE FROM auth_methods
 WHERE user_id IS NULL
   AND rowid NOT IN (
       SELECT MAX(rowid) FROM auth_methods
        WHERE user_id IS NULL
        GROUP BY tenant_id, name);

CREATE UNIQUE INDEX IF NOT EXISTS factor_configs_tenant_scope_unique
    ON factor_configs (tenant_id, kind) WHERE user_id IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS auth_methods_tenant_scope_unique
    ON auth_methods (tenant_id, name) WHERE user_id IS NULL;
