//! Reads by fingerprint: the newest entries of a fingerprint's sorted-set
//! index, and, under `with_legacy_fingerprint_keys`, the plain set and the
//! single-id key earlier releases wrote, each tidied when it points at a row
//! that no longer carries the fingerprint.

use fred::prelude::*;

use super::row::{
    device_key, fingerprint_hex, fingerprint_key, fingerprint_set_key, fingerprint_zset_key,
};
use super::scripts::{DROP_ABSENT_FINGERPRINT, DROP_STALE_FINGERPRINT};
use super::{FINGERPRINT_READ_LIMIT, ValkeyDeviceStore, ValkeyDeviceStoreError};
use crate::device::types::{Device, FingerprintHash};

impl ValkeyDeviceStore {
    /// Remove the single-id fingerprint key of an earlier release when it
    /// names `id` and `id`'s row no longer exists.
    async fn drop_absent_fingerprint(
        &self,
        fp_key: &str,
        tenant: &str,
        id: &str,
    ) -> Result<(), ValkeyDeviceStoreError> {
        let _: i64 = self
            .client
            .eval(
                DROP_ABSENT_FINGERPRINT,
                vec![fp_key.to_string(), device_key(&self.prefix, tenant, id)],
                vec![Value::from(id)],
            )
            .await?;
        Ok(())
    }

    /// The device the single-id key of an earlier release names, added to
    /// `found` when it is not there yet and its row still carries the
    /// fingerprint; a key whose device no longer carries it, or whose row is
    /// gone, is dropped.
    async fn add_legacy_candidate(
        &self,
        tenant: &str,
        hex: &str,
        hash: &FingerprintHash,
        found: &mut Vec<Device>,
    ) -> Result<(), ValkeyDeviceStoreError> {
        let legacy_key = fingerprint_key(&self.prefix, tenant, hex);
        let Some(id) = self.client.get::<Option<String>, _>(&legacy_key).await? else {
            return Ok(());
        };
        if found.iter().any(|d| d.id.to_string() == id) {
            return Ok(());
        }
        match self.get_row_checked(tenant, &id).await? {
            Some((d, raw, stale)) if d.fingerprint_hash == *hash => {
                if stale {
                    self.reseal_row(&d, &raw).await;
                }
                found.push(d);
            }
            Some((_, raw, _)) => {
                if let Err(e) = self
                    .drop_stale_fingerprint(&legacy_key, tenant, &id, &raw)
                    .await
                {
                    tracing::warn!(error = %e, "stale fingerprint entry not dropped");
                }
            }
            // The row expired natively, which leaves the key behind;
            // nothing else would ever remove it.
            None => {
                if let Err(e) = self.drop_absent_fingerprint(&legacy_key, tenant, &id).await {
                    tracing::warn!(error = %e, "stale fingerprint entry not dropped");
                }
            }
        }
        Ok(())
    }

    /// The devices whose row still carries `hash`, from the
    /// `FINGERPRINT_READ_LIMIT` newest entries of its fingerprint index (and,
    /// with `with_legacy_fingerprint_keys`, the layouts of earlier releases),
    /// in no particular order. The index is a hint, so only rows that still
    /// carry the fingerprint are returned, and the read tidies the entries
    /// that do not.
    pub(super) async fn devices_with_fingerprint(
        &self,
        tenant: &str,
        hash: &FingerprintHash,
    ) -> Result<Vec<Device>, ValkeyDeviceStoreError> {
        let hex = fingerprint_hex(hash);
        let index_key = fingerprint_zset_key(&self.prefix, tenant, &hex);
        let mut members: Vec<String> = self
            .client
            .zrevrange(&index_key, 0, FINGERPRINT_READ_LIMIT as i64 - 1, false)
            .await?;
        let mut index_keys = vec![index_key];
        if self.legacy_fingerprint_keys {
            // The plain set of the release before the sorted set lists
            // devices not written since; they are candidates too.
            let set_key = fingerprint_set_key(&self.prefix, tenant, &hex);
            let listed: Vec<String> = self.client.smembers(&set_key).await?;
            let more: Vec<String> = listed
                .into_iter()
                .filter(|id| !members.contains(id))
                .collect();
            members.extend(more);
            index_keys.push(set_key);
        }
        let keys: Vec<&str> = index_keys.iter().map(String::as_str).collect();
        let mut found = self
            .read_members(&keys, tenant, &members, |d| d.fingerprint_hash == *hash)
            .await?;
        if self.legacy_fingerprint_keys {
            self.add_legacy_candidate(tenant, &hex, hash, &mut found)
                .await?;
        }
        Ok(found)
    }

    /// Remove a fingerprint index entry that points at `id`, but only while
    /// `id`'s row still holds the bytes (`raw`) that were found not to carry
    /// the fingerprint.
    async fn drop_stale_fingerprint(
        &self,
        fp_key: &str,
        tenant: &str,
        id: &str,
        raw: &[u8],
    ) -> Result<(), ValkeyDeviceStoreError> {
        let _: i64 = self
            .client
            .eval(
                DROP_STALE_FINGERPRINT,
                vec![fp_key.to_string(), device_key(&self.prefix, tenant, id)],
                vec![
                    Value::from(id),
                    Value::Bytes(fred::bytes::Bytes::copy_from_slice(raw)),
                ],
            )
            .await?;
        Ok(())
    }
}
