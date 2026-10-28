//! Reads through the membership indexes.
//!
//! An index is a hint about which rows to read, never proof that a row
//! belongs to it: a reader keeps only the rows that still match what it asked
//! for, and tidies the entries that do not.

use fred::prelude::*;

use super::scripts::{
    PRUNE_ABSENT, PRUNE_MISMATCH, RESEAL_ROW, ScriptStatus, pair_replies, prune_args,
    prune_mismatch_args, reseal_args, row_keys,
};
use super::{MGET_CHUNK, ValkeyDeviceStore, ValkeyDeviceStoreError, device_key};
use crate::device::types::Device;

/// A decoded row with the exact bytes it was read as.
pub(super) struct StoredRow {
    pub(super) id: String,
    pub(super) device: Device,
    /// The stored bytes the row was decoded from, the comparand of any
    /// conditional write or prune decided on this read.
    pub(super) raw: Vec<u8>,
    /// The bytes are in an older format than a write seals.
    pub(super) stale: bool,
}

/// The result of reading the rows behind a list of index members.
#[derive(Default)]
pub(super) struct RowsRead {
    /// Rows that exist and decode, in index order.
    pub(super) live: Vec<StoredRow>,
    /// Members whose row is gone (expired or deleted).
    pub(super) gone: Vec<String>,
    /// Members whose row exists and cannot be decoded (a damaged row, or one
    /// sealed under another key), with the reason.
    pub(super) undecodable: Vec<(String, ValkeyDeviceStoreError)>,
}

impl ValkeyDeviceStore {
    /// Read the row `(tenant, id)` with the bytes it was decoded from.
    pub(super) async fn get_row(
        &self,
        tenant: &str,
        id: &str,
    ) -> Result<Option<(Device, Vec<u8>)>, ValkeyDeviceStoreError> {
        Ok(self
            .get_row_checked(tenant, id)
            .await?
            .map(|(device, raw, _)| (device, raw)))
    }

    /// [`get_row`](Self::get_row), and whether the bytes are stale.
    pub(super) async fn get_row_checked(
        &self,
        tenant: &str,
        id: &str,
    ) -> Result<Option<(Device, Vec<u8>, bool)>, ValkeyDeviceStoreError> {
        let raw: Option<Vec<u8>> = self
            .client
            .get(device_key(&self.prefix, tenant, id))
            .await?;
        match raw {
            Some(raw) => {
                let (device, stale) = self.decode_row_checked(tenant, id, &raw)?;
                Ok(Some((device, raw, stale)))
            }
            None => Ok(None),
        }
    }

    /// Replace a row read in an older format with the same device sealed in
    /// the current one. The write is conditional on the exact bytes that
    /// were read and keeps the key's expiry, so a save that landed since is
    /// never overwritten and the retention ladder is not disturbed. This is
    /// housekeeping: a lost race or a failure is logged and the read that
    /// found the stale row still succeeds.
    pub(super) async fn reseal_row(&self, device: &Device, raw: &[u8]) {
        let (tenant, id) = (device.tenant_id.to_string(), device.id.to_string());
        let sealed = match self.encode_row(device) {
            Ok(sealed) => sealed,
            Err(error) => {
                tracing::warn!(%tenant, device = %id, %error, "device row re-seal failed; the row keeps its older format");
                return;
            }
        };
        let key = device_key(&self.prefix, &tenant, &id);
        match self
            .run_script(RESEAL_ROW, vec![key], reseal_args(raw, &sealed))
            .await
        {
            Ok(ScriptStatus::Ok) => {}
            Ok(_) => tracing::debug!(
                %tenant, device = %id,
                "device row re-seal skipped: the row changed after it was read"
            ),
            Err(error) => tracing::warn!(
                %tenant, device = %id, %error,
                "device row re-seal failed; the row keeps its older format"
            ),
        }
    }

    /// Read the rows behind `members` with one `MGET` per [`MGET_CHUNK`]
    /// members, sorting them into live rows, missing rows and rows that do
    /// not decode.
    pub(super) async fn read_rows(
        &self,
        tenant: &str,
        members: &[String],
    ) -> Result<RowsRead, ValkeyDeviceStoreError> {
        let mut out = RowsRead::default();
        for chunk in members.chunks(MGET_CHUNK) {
            let replies: Vec<Value> = self
                .client
                .mget(row_keys(&self.prefix, tenant, chunk))
                .await?;
            let paired = pair_replies(chunk, replies).map_err(|msg| {
                ValkeyDeviceStoreError::Connection(fred::error::Error::new(
                    fred::error::ErrorKind::Parse,
                    msg,
                ))
            })?;
            for (id, raw) in paired {
                match raw {
                    Some(raw) => match self.decode_row_checked(tenant, &id, &raw) {
                        Ok((device, stale)) => out.live.push(StoredRow {
                            id,
                            device,
                            raw,
                            stale,
                        }),
                        Err(e) => out.undecodable.push((id, e)),
                    },
                    None => out.gone.push(id),
                }
            }
        }
        Ok(out)
    }

    /// Drop `gone` from the membership set `index_key`, each only if its row
    /// is still absent when the script runs. Housekeeping: a failure is
    /// logged and the next read tries again.
    pub(super) async fn prune_absent(&self, index_key: &str, tenant: &str, gone: &[String]) {
        if gone.is_empty() {
            return;
        }
        let mut keys = Vec::with_capacity(gone.len() + 1);
        keys.push(index_key.to_string());
        keys.extend(row_keys(&self.prefix, tenant, gone));
        let reply: Result<i64, _> = self.client.eval(PRUNE_ABSENT, keys, prune_args(gone)).await;
        if let Err(e) = reply {
            tracing::warn!(error = %e, "device index prune failed; retried on the next read");
        }
    }

    /// Drop members whose row does not belong in `index_key`, each only if
    /// its row still holds the bytes it was judged on. Housekeeping, like
    /// [`prune_absent`](Self::prune_absent).
    pub(super) async fn prune_mismatched(
        &self,
        index_key: &str,
        tenant: &str,
        judged: &[(String, Vec<u8>)],
    ) {
        if judged.is_empty() {
            return;
        }
        let members: Vec<String> = judged.iter().map(|(m, _)| m.clone()).collect();
        let mut keys = Vec::with_capacity(members.len() + 1);
        keys.push(index_key.to_string());
        keys.extend(row_keys(&self.prefix, tenant, &members));
        let reply: Result<i64, _> = self
            .client
            .eval(PRUNE_MISMATCH, keys, prune_mismatch_args(judged))
            .await;
        if let Err(e) = reply {
            tracing::warn!(error = %e, "device index prune failed; retried on the next read");
        }
    }

    /// The devices listed in `index_key` whose row still satisfies
    /// `belongs`. Members whose row is gone, and members whose row no longer
    /// matches, are removed from the index; a row that does not decode fails
    /// the read, since a lookup that skipped it would answer as if the
    /// device did not exist.
    pub(super) async fn read_index(
        &self,
        index_key: &str,
        tenant: &str,
        belongs: impl Fn(&Device) -> bool,
    ) -> Result<Vec<Device>, ValkeyDeviceStoreError> {
        let members: Vec<String> = self.client.smembers(index_key).await?;
        let read = self.read_rows(tenant, &members).await?;
        self.prune_absent(index_key, tenant, &read.gone).await;
        if let Some((_, e)) = read.undecodable.into_iter().next() {
            return Err(e);
        }
        let (kept, stale): (Vec<StoredRow>, Vec<StoredRow>) =
            read.live.into_iter().partition(|r| belongs(&r.device));
        let judged: Vec<(String, Vec<u8>)> = stale.into_iter().map(|r| (r.id, r.raw)).collect();
        self.prune_mismatched(index_key, tenant, &judged).await;
        for row in kept.iter().filter(|r| r.stale) {
            self.reseal_row(&row.device, &row.raw).await;
        }
        Ok(kept.into_iter().map(|r| r.device).collect())
    }
}
