//! The SQLite schema and the call that applies it.

use super::SqliteDeviceStore;

impl SqliteDeviceStore {
    /// Create the `devices` and `device_bindings_refresh` tables and
    /// supporting indexes. Idempotent: safe to call on every startup.
    pub async fn init_schema(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS devices (
                tenant_id        TEXT    NOT NULL,
                id               TEXT    NOT NULL,
                user_id          TEXT,
                trust_level      TEXT    NOT NULL,
                fingerprint_hash BLOB    NOT NULL,
                first_seen_at    INTEGER NOT NULL,
                last_seen_at     INTEGER NOT NULL,
                revoked_at       INTEGER,
                demoted_at       INTEGER,
                bindings         TEXT    NOT NULL,
                PRIMARY KEY (tenant_id, id)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Serves `find_by_fingerprint` in sorted order, so the newest sighting
        // is the first entry of the range instead of the winner of a sort over
        // every device that shares the fingerprint. It replaces the plain
        // `(tenant_id, fingerprint_hash)` index of earlier releases, which it
        // covers as a prefix.
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_devices_fingerprint_seen \
             ON devices (tenant_id, fingerprint_hash, last_seen_at DESC, id)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("DROP INDEX IF EXISTS idx_devices_fingerprint")
            .execute(&self.pool)
            .await?;
        // The retention sweep reads by level and age: `Trusted` and `Seen`
        // rows by `last_seen_at`, `Revoked` rows by `revoked_at`.
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_devices_sweep \
             ON devices (tenant_id, trust_level, last_seen_at)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_devices_revoked_at \
             ON devices (tenant_id, revoked_at) WHERE trust_level = 'Revoked'",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_devices_user \
             ON devices (tenant_id, user_id, last_seen_at DESC)",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_devices_user_fingerprint \
             ON devices (tenant_id, user_id, fingerprint_hash, last_seen_at DESC)",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS device_bindings_refresh (
                tenant_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                family_id TEXT NOT NULL,
                PRIMARY KEY (tenant_id, device_id, family_id),
                FOREIGN KEY (tenant_id, device_id)
                    REFERENCES devices (tenant_id, id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_device_bindings_refresh_family \
             ON device_bindings_refresh (tenant_id, family_id)",
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}
