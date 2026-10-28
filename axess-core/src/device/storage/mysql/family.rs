//! Small statements the MySQL device store shares between its operations: the
//! trust-level re-read after a missed conditional write, and the refresh-family
//! index rewrite.

use sqlx::MySqlPool;

use crate::device::storage::sql_common::{
    FAMILY_INSERT_CHUNK, SqlDeviceStoreError, parse_stored_trust, push_family_rows,
};
use crate::device::types::DeviceTrustLevel;

/// Current trust level of a device row, `None` when the row is absent.
pub(super) async fn fetch_trust_level(
    pool: &MySqlPool,
    tenant: &str,
    device_id: &str,
) -> Result<Option<DeviceTrustLevel>, SqlDeviceStoreError> {
    let stored: Option<String> =
        sqlx::query_scalar("SELECT trust_level FROM devices WHERE tenant_id = ? AND id = ?")
            .bind(tenant)
            .bind(device_id)
            .fetch_optional(pool)
            .await?;
    parse_stored_trust(stored)
}

/// Replace a device's refresh-family index rows inside `tx`. The family
/// ids are already distinct ([`refresh_family_ids`]) and the insert is
/// idempotent as well, so a repeated family can never violate the primary
/// key and abort the surrounding transaction.
pub(super) async fn rewrite_family_index(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    tenant: &str,
    device_id: &str,
    family_ids: &[String],
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM device_bindings_refresh WHERE tenant_id = ? AND device_id = ?")
        .bind(tenant)
        .bind(device_id)
        .execute(&mut **tx)
        .await?;
    // One multi-row insert per chunk keeps a device with many families to a
    // handful of statements, well under every dialect's bind-parameter cap.
    for chunk in family_ids.chunks(FAMILY_INSERT_CHUNK) {
        let mut insert = sqlx::QueryBuilder::<sqlx::MySql>::new(
            "INSERT INTO device_bindings_refresh (tenant_id, device_id, family_id) ",
        );
        push_family_rows(&mut insert, chunk, tenant, device_id);
        insert.push(" ON DUPLICATE KEY UPDATE family_id = family_id");
        insert.build().execute(&mut **tx).await?;
    }
    Ok(())
}
