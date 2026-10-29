//! The MySQL schema: the DDL and the call that applies it.

use super::MysqlDeviceStore;

impl MysqlDeviceStore {
    /// Create tables + indexes. Idempotent.
    pub async fn init_schema(&self) -> Result<(), sqlx::Error> {
        sqlx::query(DEVICES_DDL).execute(&self.pool).await?;
        sqlx::query(DEVICE_BINDINGS_REFRESH_DDL)
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}

/// `devices` table. The id columns (`tenant_id`, `id`, `user_id`) compare
/// byte for byte (`utf8mb4_bin`): they are case-sensitive opaque ids, and
/// the server's default case-insensitive collation would resolve device `Ab`
/// as device `aB`, find another tenant's or user's row by a differently
/// cased id, and make two distinct ids collide on the primary key.
pub(super) const DEVICES_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS devices (
    tenant_id        VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    id               VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    user_id          VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin,
    trust_level      VARCHAR(16)    NOT NULL,
    fingerprint_hash VARBINARY(32)  NOT NULL,
    first_seen_at    BIGINT         NOT NULL,
    last_seen_at     BIGINT         NOT NULL,
    revoked_at       BIGINT,
    demoted_at       BIGINT,
    bindings         MEDIUMTEXT     NOT NULL,
    PRIMARY KEY (tenant_id, id),
    INDEX idx_devices_fingerprint_seen (tenant_id, fingerprint_hash, last_seen_at, id),
    INDEX idx_devices_sweep (tenant_id, trust_level, last_seen_at),
    INDEX idx_devices_revoked_at (tenant_id, trust_level, revoked_at),
    INDEX idx_devices_user (tenant_id, user_id, last_seen_at),
    INDEX idx_devices_user_fingerprint (tenant_id, user_id, fingerprint_hash, last_seen_at)
)
"#;

/// Refresh-family index table. `tenant_id` and `device_id` carry the same
/// binary collation as the `devices` columns they reference, which a
/// foreign key requires.
pub(super) const DEVICE_BINDINGS_REFRESH_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS device_bindings_refresh (
    tenant_id VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    device_id VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    family_id VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    PRIMARY KEY (tenant_id, device_id, family_id),
    INDEX idx_device_bindings_refresh_family (tenant_id, family_id),
    CONSTRAINT fk_device_bindings_refresh_device
        FOREIGN KEY (tenant_id, device_id)
        REFERENCES devices (tenant_id, id) ON DELETE CASCADE
)
"#;
