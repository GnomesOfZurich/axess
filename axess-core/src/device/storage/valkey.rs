//! Valkey-backed [`DeviceStore`].
//!
//! Mirrors the shape of [`super::sqlite::SqliteDeviceStore`] over a
//! Redis-compatible KV store. Uses native key TTLs to back the
//! retention ladder so revoked devices can age out without an
//! application-side cron.
//!
//! # Key layout
//!
//! All keys live under a configurable prefix (default `axess`).
//!
//! | Pattern | Type | Purpose |
//! |---------|------|---------|
//! | `{prefix}:dev:{tenant}:{id}` | string (msgpack, optionally encrypted) | the device row |
//! | `{prefix}:dev:fp:{tenant}:{hex_hash}` | string (device_id) | `find_by_fingerprint` index |
//! | `{prefix}:dev:user:{tenant}:{user}` | set of device_ids | `find_for_user` / `find_by_fingerprint_for_user` index |
//! | `{prefix}:dev:fam:{tenant}:{family}` | set of device_ids | `find_by_refresh_family` index |
//! | `{prefix}:dev:tenant:{tenant}` | set of device_ids | sweep walker (avoids `SCAN *`) |
//!
//! # TTL policy
//!
//! The per-device key carries a native TTL that is a backstop covering the
//! whole retention ladder (see `policy::ttl_seconds`):
//!
//! | Trust level | Native TTL |
//! |-------------|-----------|
//! | `Unknown` | none: never removed by retention |
//! | `Trusted` | `last_seen_at + trusted_idle + seen_idle + revoked_grace` |
//! | `Seen` | `max(last_seen_at, demoted_at) + seen_idle + revoked_grace` |
//! | `Revoked` | `revoked_at + revoked_grace` |
//!
//! `record_sighting` and `set_trust_level` re-set the TTL accordingly.
//! Native expiry handles Stage 3 of the retention ladder
//! (Revoked → purged); the explicit `sweep` walks for Stages 1 and 2 (the
//! demotion transitions Valkey can't infer on its own), and counts Stage 3
//! deletions it physically performs.
//!
//! # Reads
//!
//! `find_for_user`, `find_by_fingerprint_for_user`, `find_by_refresh_family`
//! and the sweep read the rows an index lists with one `MGET` per 512
//! members, not one `GET` per member. A member whose row is gone (expired or
//! deleted) is removed from the index by a script that re-checks that the
//! row is still absent, so a device saved again in the meantime keeps its
//! entry. `find_for_user` still reads the user's whole set and sorts it in
//! process; a per-user sorted set scored by `last_seen_at` would bound that
//! read but changes the index layout.
//!
//! # Atomicity
//!
//! The row is an opaque (optionally encrypted) blob, so field-level edits
//! happen in Rust and are applied with an optimistic compare-and-swap Lua
//! script: the write lands only if the stored bytes are still the bytes that
//! were read, otherwise the operation re-reads and decides again (at most
//! `MAX_ATTEMPTS` times, then fails with
//! [`ValkeyDeviceStoreError::Contended`]).
//!
//! | Operation | Guarantee |
//! |-----------|-----------|
//! | `record_sighting` | Atomic CAS. Never writes to a `Revoked` row (a sighting cannot undo a revocation). Missing row: `NotFound`. |
//! | `set_trust_level` | Atomic CAS against every other writer; the explicit level wins over the row it read. Missing row: `NotFound`. |
//! | `set_trust_level_if` | The expected level is checked against the bytes the CAS then replaces; a row at another level (a revocation that won) is refused, never overwritten. |
//! | `replace_bindings` | Atomic CAS on the row, and only while the bindings are still the ones the caller read (`Conflict` otherwise); a `Revoked` row is refused and never gains a binding. The refresh-family index is brought in line after the swap. |
//! | `claim_owner` | Atomic CAS; sets the owner only on a row that has none, and adds the device to the owner's index. |
//! | `sweep` | Per row, atomic CAS demotion or CAS purge. Only ever demotes, so it cannot resurrect a `Revoked` row; a row changed under it is re-planned from its new state. |
//! | `delete` | Row delete is unconditional; the fingerprint index is removed only if it still points at this device. |
//! | `save` | Whole-row last-writer-wins `SET` (not a CAS); stale fingerprint index entries are removed only if they still point at this device. |
//!
//! The scripts address two keys (row and fingerprint index); on a Valkey
//! cluster give them one hash slot with a prefix such as `{axess}`.
//!
//! The fingerprint index is only ever removed, re-pointed or re-expired by an
//! operation on the device it points at, so two devices sharing a fingerprint
//! never drop each other's lookup.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use fred::prelude::*;

use crate::authn::ids::{DeviceId, TenantId, UserId};
use crate::device::store::{
    BindingsUpdate, DeviceStore, OwnerClaim, SweepConfig, SweepCounts, TrustTransition,
    demotion_stamp,
};
use crate::device::types::{Device, DeviceBinding, DeviceTrustLevel, FingerprintHash};
use crate::session::crypto::SessionCrypto;
use std::future::Future;

mod policy;
mod row;
mod scripts;
#[cfg(test)]
mod tests;

use policy::{SweepStep, plan_sweep};
use row::{
    device_key, family_index_key, fingerprint_hex, fingerprint_key, tenant_index_key,
    user_index_key,
};
use scripts::{
    CAS_WRITE, DELETE_IF_POINTS_AT, PRUNE_ABSENT, REMOVE_DEVICE, ScriptStatus, cas_write_args,
    pair_replies, parse_status, prune_args, remove_args, row_keys,
};

/// Bound on re-read/retry rounds when a concurrent writer keeps changing a
/// row between our read and our compare-and-swap.
const MAX_ATTEMPTS: usize = 8;

/// Most rows read by one batched `MGET`; a longer index is read in several.
const MGET_CHUNK: usize = 512;

const DEFAULT_PREFIX: &str = "axess";

/// Errors from [`ValkeyDeviceStore`].
///
/// Distinct type from
/// [`session::storage::valkey::ValkeyStoreError`](crate::session::storage::valkey::ValkeyStoreError)
/// so the device-store error surface doesn't widen when the
/// session-store one does (and vice versa).
#[derive(Debug, thiserror::Error)]
pub enum ValkeyDeviceStoreError {
    /// Network or protocol error talking to Valkey.
    #[error("connection error: {0}")]
    Connection(#[source] fred::error::Error),

    /// MessagePack encoding of the row failed.
    #[error("device row MessagePack encoding failed: {0}")]
    Encode(#[source] rmp_serde::encode::Error),

    /// MessagePack decoding of a stored row failed.
    #[error("device row MessagePack decoding failed: {0}")]
    Decode(#[source] rmp_serde::decode::Error),

    /// AES-256-GCM encryption or decryption of a row failed.
    #[error("encryption/decryption error: {0}")]
    Crypto(#[source] crate::session::crypto::CryptoError),

    /// The targeted device id was not present in the store.
    #[error("device not found: tenant={tenant_id} id={device_id}")]
    NotFound {
        /// Tenant scope of the missed lookup.
        tenant_id: String,
        /// Opaque device id whose lookup missed.
        device_id: String,
    },

    /// Concurrent writers changed the row on every attempt; nothing was
    /// written. Safe to retry.
    #[error("device row kept changing under concurrent writers: tenant={tenant_id} id={device_id}")]
    Contended {
        /// Tenant scope of the row.
        tenant_id: String,
        /// Opaque device id of the row.
        device_id: String,
    },

    /// A store script answered with a reply this version does not know.
    #[error("unexpected device script reply: {0}")]
    UnexpectedScriptReply(String),
}

impl From<fred::error::Error> for ValkeyDeviceStoreError {
    fn from(e: fred::error::Error) -> Self {
        Self::Connection(e)
    }
}

impl From<rmp_serde::encode::Error> for ValkeyDeviceStoreError {
    fn from(e: rmp_serde::encode::Error) -> Self {
        Self::Encode(e)
    }
}

impl From<rmp_serde::decode::Error> for ValkeyDeviceStoreError {
    fn from(e: rmp_serde::decode::Error) -> Self {
        Self::Decode(e)
    }
}

impl From<crate::session::crypto::CryptoError> for ValkeyDeviceStoreError {
    fn from(e: crate::session::crypto::CryptoError) -> Self {
        Self::Crypto(e)
    }
}

/// Valkey-backed [`DeviceStore`].
///
/// Cheap to clone (the inner `fred::Client` is `Arc`-based); construct
/// once at startup and share across handlers / tasks.
#[derive(Clone)]
pub struct ValkeyDeviceStore {
    client: Client,
    prefix: Arc<str>,
    /// Optional whole-row AES-256-GCM envelope. The Valkey row is an
    /// opaque blob from the store's perspective, so encrypting the
    /// whole serialised row gives defence-in-depth on user_id and
    /// fingerprint_hash without losing any query primitive (Valkey
    /// reads / writes the whole blob in one shot regardless).
    crypto: Option<SessionCrypto>,
    sweep_config: SweepConfig,
}

impl ValkeyDeviceStore {
    /// Create an encrypted store (recommended for production).
    pub fn new(client: Client, key: [u8; 32]) -> Self {
        Self {
            client,
            prefix: DEFAULT_PREFIX.into(),
            crypto: Some(SessionCrypto::new(key)),
            sweep_config: SweepConfig::default(),
        }
    }

    /// Create a plaintext store (development/testing only). Logs a
    /// warning so production builds don't accidentally pick this path.
    pub fn plaintext(client: Client) -> Self {
        tracing::warn!(
            "ValkeyDeviceStore created without encryption; \
             do not use in production"
        );
        Self {
            client,
            prefix: DEFAULT_PREFIX.into(),
            crypto: None,
            sweep_config: SweepConfig::default(),
        }
    }

    /// Override the key prefix (default `axess`).
    pub fn with_prefix(mut self, prefix: impl Into<Arc<str>>) -> Self {
        self.prefix = prefix.into();
        self
    }

    /// Override the [`SweepConfig`] driving the retention ladder.
    pub fn with_sweep_config(mut self, config: SweepConfig) -> Self {
        self.sweep_config = config;
        self
    }

    /// Helper: do a single round-trip GET for a device by composite key.
    async fn get_device(
        &self,
        tenant: &str,
        id: &str,
    ) -> Result<Option<Device>, ValkeyDeviceStoreError> {
        let key = device_key(&self.prefix, tenant, id);
        let bytes: Option<Vec<u8>> = self.client.get(&key).await?;
        match bytes {
            Some(b) => Ok(Some(self.decode_row(tenant, id, &b)?)),
            None => Ok(None),
        }
    }
}

impl ValkeyDeviceStore {
    fn not_found(tenant: &str, id: &str) -> ValkeyDeviceStoreError {
        ValkeyDeviceStoreError::NotFound {
            tenant_id: tenant.to_string(),
            device_id: id.to_string(),
        }
    }

    /// Read the rows behind `members` with one `MGET` per [`MGET_CHUNK`]
    /// members. Returns the rows that exist, paired with their member id in
    /// index order, and the members whose row is gone.
    async fn get_rows(
        &self,
        tenant: &str,
        members: &[String],
    ) -> Result<(Vec<(String, Device)>, Vec<String>), ValkeyDeviceStoreError> {
        let mut live = Vec::with_capacity(members.len());
        let mut gone = Vec::new();
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
                    Some(raw) => {
                        let device = self.decode_row(tenant, &id, &raw)?;
                        live.push((id, device));
                    }
                    None => gone.push(id),
                }
            }
        }
        Ok((live, gone))
    }

    /// Drop `gone` from the membership set `index_key`, each only if its row
    /// is still absent when the script runs. Housekeeping: a failure is
    /// logged and the next read tries again.
    async fn prune_absent(&self, index_key: &str, tenant: &str, gone: &[String]) {
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

    async fn run_script(
        &self,
        script: &'static str,
        keys: Vec<String>,
        args: Vec<Value>,
    ) -> Result<ScriptStatus, ValkeyDeviceStoreError> {
        let reply: String = self.client.eval(script, keys, args).await?;
        parse_status(&reply).ok_or(ValkeyDeviceStoreError::UnexpectedScriptReply(reply))
    }

    /// Remove a fingerprint index entry only if it still points at `id`.
    async fn delete_fingerprint_if_points_at(
        &self,
        fp_key: &str,
        id: &str,
    ) -> Result<(), ValkeyDeviceStoreError> {
        let _: i64 = self
            .client
            .eval(
                DELETE_IF_POINTS_AT,
                vec![fp_key.to_string()],
                vec![Value::from(id)],
            )
            .await?;
        Ok(())
    }

    /// Read a row, let `decide` choose what to do with it, and apply that
    /// decision atomically; on a concurrent change re-read and decide again.
    async fn apply<F>(
        &self,
        tenant: &str,
        id: &str,
        now: DateTime<Utc>,
        decide: F,
    ) -> Result<Applied, ValkeyDeviceStoreError>
    where
        F: Fn(&Device) -> Step,
    {
        let row_key = device_key(&self.prefix, tenant, id);
        for _ in 0..MAX_ATTEMPTS {
            let raw: Option<Vec<u8>> = self.client.get(&row_key).await?;
            let Some(raw) = raw else {
                return Ok(Applied::Missing);
            };
            let device = self.decode_row(tenant, id, &raw)?;
            let fp_key = fingerprint_key(
                &self.prefix,
                tenant,
                &fingerprint_hex(&device.fingerprint_hash),
            );
            let keys = vec![row_key.clone(), fp_key];
            let (status, outcome) = match decide(&device) {
                Step::Skip => return Ok(Applied::Skipped(device)),
                Step::Write(new) => {
                    let payload = self.encode_row(&new)?;
                    let ttl = self.ttl_seconds_for(&new, now);
                    let args = cas_write_args(&raw, &payload, ttl, id);
                    (
                        self.run_script(CAS_WRITE, keys, args).await?,
                        Applied::Written { before: device },
                    )
                }
                Step::Remove => {
                    let args = remove_args(Some(&raw), id);
                    (
                        self.run_script(REMOVE_DEVICE, keys, args).await?,
                        Applied::Removed(device),
                    )
                }
            };
            match status {
                ScriptStatus::Ok => return Ok(outcome),
                ScriptStatus::Missing => return Ok(Applied::Missing),
                ScriptStatus::Conflict => continue,
            }
        }
        Err(ValkeyDeviceStoreError::Contended {
            tenant_id: tenant.to_string(),
            device_id: id.to_string(),
        })
    }

    /// Bring the refresh-family index in line with a device's new bindings:
    /// add the families it now carries, drop the ones it no longer does.
    async fn reindex_families(
        &self,
        tenant: &str,
        id: &str,
        before: &[DeviceBinding],
        after: &[DeviceBinding],
    ) -> Result<(), ValkeyDeviceStoreError> {
        let families = |bs: &[DeviceBinding]| -> Vec<String> {
            bs.iter()
                .filter_map(|b| match b {
                    DeviceBinding::Refresh { family_id, .. } => Some(family_id.clone()),
                    _ => None,
                })
                .collect()
        };
        let (old, new) = (families(before), families(after));
        for family in &new {
            let idx = family_index_key(&self.prefix, tenant, family);
            let _: () = self.client.sadd(&idx, id).await?;
        }
        for family in old.iter().filter(|f| !new.contains(f)) {
            let idx = family_index_key(&self.prefix, tenant, family);
            let _: () = self.client.srem(&idx, id).await?;
        }
        Ok(())
    }

    /// Drop the secondary index entries that pointed at a removed device.
    async fn remove_index_entries(
        &self,
        tenant: &str,
        id: &str,
        device: &Device,
    ) -> Result<(), ValkeyDeviceStoreError> {
        let tenant_idx = tenant_index_key(&self.prefix, tenant);
        let _: () = self.client.srem(&tenant_idx, id).await?;
        if let Some(uid) = &device.user_id {
            let user_idx = user_index_key(&self.prefix, tenant, &uid.to_string());
            let _: () = self.client.srem(&user_idx, id).await?;
        }
        for binding in &device.bindings {
            if let DeviceBinding::Refresh { family_id, .. } = binding {
                let fam_idx = family_index_key(&self.prefix, tenant, family_id);
                let _: () = self.client.srem(&fam_idx, id).await?;
            }
        }
        Ok(())
    }
}

/// The decision [`ValkeyDeviceStore::apply`] takes for the row it read.
enum Step {
    /// Leave the row alone (the caller learns the row it was decided on).
    Skip,
    /// Replace the row with this value.
    Write(Device),
    /// Delete the row.
    Remove,
}

/// What [`ValkeyDeviceStore::apply`] did.
enum Applied {
    /// The row does not exist (or vanished before the write).
    Missing,
    /// The decision was to leave the row; carries the row as read.
    Skipped(Device),
    /// The new row was stored; carries the row as it was read.
    Written { before: Device },
    /// The row was deleted; carries the row as read.
    Removed(Device),
}

impl DeviceStore for ValkeyDeviceStore {
    type Error = ValkeyDeviceStoreError;

    fn load(
        &self,
        tenant_id: &TenantId,
        id: &DeviceId,
    ) -> impl Future<Output = Result<Option<Device>, Self::Error>> + Send {
        let store = self.clone();
        let tenant = tenant_id.to_string();
        let device_id = id.to_string();
        async move { store.get_device(&tenant, &device_id).await }
    }

    fn find_by_fingerprint(
        &self,
        tenant_id: &TenantId,
        hash: &FingerprintHash,
    ) -> impl Future<Output = Result<Option<Device>, Self::Error>> + Send {
        let store = self.clone();
        let tenant = tenant_id.to_string();
        let hex = fingerprint_hex(hash);
        async move {
            let fp_key = fingerprint_key(&store.prefix, &tenant, &hex);
            let device_id: Option<String> = store.client.get(&fp_key).await?;
            match device_id {
                Some(id) => store.get_device(&tenant, &id).await,
                None => Ok(None),
            }
        }
    }

    fn find_for_user(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<Device>, Self::Error>> + Send {
        let store = self.clone();
        let tenant = tenant_id.to_string();
        let user = user_id.to_string();
        async move {
            let idx = user_index_key(&store.prefix, &tenant, &user);
            let members: Vec<String> = store.client.smembers(&idx).await?;
            let (rows, gone) = store.get_rows(&tenant, &members).await?;
            store.prune_absent(&idx, &tenant, &gone).await;
            let mut out: Vec<Device> = rows.into_iter().map(|(_, d)| d).collect();
            // Newest-sighted first; matches Memory + SQL impls.
            out.sort_by_key(|d| std::cmp::Reverse(d.last_seen_at));
            out.truncate(limit);
            Ok(out)
        }
    }

    fn find_by_fingerprint_for_user(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        hash: &FingerprintHash,
    ) -> impl Future<Output = Result<Option<Device>, Self::Error>> + Send {
        let store = self.clone();
        let tenant = tenant_id.to_string();
        let user = user_id.to_string();
        let hash = *hash;
        async move {
            // The user's whole index is read (no scan limit), so a user with
            // many devices never misses an older match.
            let idx = user_index_key(&store.prefix, &tenant, &user);
            let members: Vec<String> = store.client.smembers(&idx).await?;
            let (rows, gone) = store.get_rows(&tenant, &members).await?;
            store.prune_absent(&idx, &tenant, &gone).await;
            Ok(rows
                .into_iter()
                .map(|(_, d)| d)
                .filter(|d| d.fingerprint_hash == hash)
                .max_by_key(|d| d.last_seen_at))
        }
    }

    fn find_by_refresh_family(
        &self,
        tenant_id: &TenantId,
        family_id: &str,
    ) -> impl Future<Output = Result<Vec<Device>, Self::Error>> + Send {
        let store = self.clone();
        let tenant = tenant_id.to_string();
        let family = family_id.to_string();
        async move {
            let idx = family_index_key(&store.prefix, &tenant, &family);
            let members: Vec<String> = store.client.smembers(&idx).await?;
            let (rows, gone) = store.get_rows(&tenant, &members).await?;
            store.prune_absent(&idx, &tenant, &gone).await;
            let mut out: Vec<Device> = rows.into_iter().map(|(_, d)| d).collect();
            out.sort_by_key(|d| std::cmp::Reverse(d.last_seen_at));
            Ok(out)
        }
    }

    fn save(
        &self,
        device: &Device,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let store = self.clone();
        let device = device.clone();
        async move {
            let ttl_secs = store.ttl_seconds_for(&device, now);
            let payload = store.encode_row(&device)?;
            let tenant = device.tenant_id.to_string();
            let id = device.id.to_string();

            let row_key = device_key(&store.prefix, &tenant, &id);
            let fp_key = fingerprint_key(
                &store.prefix,
                &tenant,
                &fingerprint_hex(&device.fingerprint_hash),
            );
            let tenant_idx = tenant_index_key(&store.prefix, &tenant);

            // Resolve existing fingerprint to handle re-keys: when the
            // saved row has a different fingerprint than what's currently
            // stored, drop the stale fingerprint index entry.
            if let Some(prev) = store.get_device(&tenant, &id).await? {
                let prev_hex = fingerprint_hex(&prev.fingerprint_hash);
                if prev_hex != fingerprint_hex(&device.fingerprint_hash) {
                    let stale_fp = fingerprint_key(&store.prefix, &tenant, &prev_hex);
                    store
                        .delete_fingerprint_if_points_at(&stale_fp, &id)
                        .await?;
                }
                // Remove stale family-index entries for any Refresh
                // bindings that are no longer present in the new device.
                let new_families: Vec<&str> = device
                    .bindings
                    .iter()
                    .filter_map(|b| match b {
                        DeviceBinding::Refresh { family_id, .. } => Some(family_id.as_str()),
                        _ => None,
                    })
                    .collect();
                for binding in &prev.bindings {
                    if let DeviceBinding::Refresh { family_id, .. } = binding
                        && !new_families.contains(&family_id.as_str())
                    {
                        let stale_idx = family_index_key(&store.prefix, &tenant, family_id);
                        let _: () = store.client.srem(&stale_idx, &id).await?;
                    }
                }
                // Remove stale user-index entry if user_id changed.
                if let Some(prev_user) = &prev.user_id
                    && device.user_id.as_ref() != Some(prev_user)
                {
                    let stale_user_idx =
                        user_index_key(&store.prefix, &tenant, &prev_user.to_string());
                    let _: () = store.client.srem(&stale_user_idx, &id).await?;
                }
            }

            // Write the row with its TTL (none for an Unknown row).
            let expiration = ttl_secs.map(Expiration::EX);
            let _: () = store
                .client
                .set(&row_key, payload, expiration.clone(), None, false)
                .await?;
            // Fingerprint index → device id. Same TTL so it ages out
            // alongside the row.
            let _: () = store
                .client
                .set(&fp_key, &id, expiration, None, false)
                .await?;

            // Tenant + user + family indexes (sets, no TTL; pruned by
            // the sweep when the rows they reference are gone).
            let _: () = store.client.sadd(&tenant_idx, &id).await?;
            if let Some(uid) = &device.user_id {
                let user_idx = user_index_key(&store.prefix, &tenant, &uid.to_string());
                let _: () = store.client.sadd(&user_idx, &id).await?;
            }
            for binding in &device.bindings {
                if let DeviceBinding::Refresh { family_id, .. } = binding {
                    let fam_idx = family_index_key(&store.prefix, &tenant, family_id);
                    let _: () = store.client.sadd(&fam_idx, &id).await?;
                }
            }

            Ok(())
        }
    }

    fn record_sighting(
        &self,
        tenant_id: &TenantId,
        id: &DeviceId,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let store = self.clone();
        let tenant = tenant_id.to_string();
        let device_id = id.to_string();
        async move {
            // Atomic compare-and-swap: only last_seen_at (and with it the
            // TTL) changes, and a Revoked row is never written.
            let applied = store
                .apply(&tenant, &device_id, now, |d| {
                    if d.trust_level == DeviceTrustLevel::Revoked {
                        return Step::Skip;
                    }
                    let mut next = d.clone();
                    next.last_seen_at = now;
                    Step::Write(next)
                })
                .await?;
            match applied {
                Applied::Missing => Err(Self::not_found(&tenant, &device_id)),
                _ => Ok(()),
            }
        }
    }

    fn set_trust_level(
        &self,
        tenant_id: &TenantId,
        id: &DeviceId,
        level: DeviceTrustLevel,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let store = self.clone();
        let tenant = tenant_id.to_string();
        let device_id = id.to_string();
        async move {
            let applied = store
                .apply(&tenant, &device_id, now, |d| {
                    let mut next = d.clone();
                    next.demoted_at = demotion_stamp(d.trust_level, level, d.demoted_at, now);
                    next.trust_level = level;
                    next.revoked_at = matches!(level, DeviceTrustLevel::Revoked).then_some(now);
                    Step::Write(next)
                })
                .await?;
            match applied {
                Applied::Missing => Err(Self::not_found(&tenant, &device_id)),
                _ => Ok(()),
            }
        }
    }

    fn set_trust_level_if(
        &self,
        tenant_id: &TenantId,
        id: &DeviceId,
        expected: DeviceTrustLevel,
        level: DeviceTrustLevel,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<TrustTransition, Self::Error>> + Send {
        let store = self.clone();
        let tenant = tenant_id.to_string();
        let device_id = id.to_string();
        async move {
            // The level is checked against the very bytes the compare-and-swap
            // then replaces, so a revocation that lands between the read and
            // the write makes the swap conflict and the check run again on
            // the revoked row; it is refused, never overwritten.
            let applied = store
                .apply(&tenant, &device_id, now, |d| {
                    if d.trust_level != expected {
                        return Step::Skip;
                    }
                    let mut next = d.clone();
                    next.demoted_at = demotion_stamp(d.trust_level, level, d.demoted_at, now);
                    next.trust_level = level;
                    next.revoked_at = matches!(level, DeviceTrustLevel::Revoked).then_some(now);
                    Step::Write(next)
                })
                .await?;
            Ok(match applied {
                Applied::Missing => TrustTransition::Missing,
                Applied::Skipped(found) => TrustTransition::Refused {
                    current: found.trust_level,
                },
                Applied::Written { .. } | Applied::Removed(_) => TrustTransition::Applied,
            })
        }
    }

    fn replace_bindings(
        &self,
        tenant_id: &TenantId,
        id: &DeviceId,
        expected: &[DeviceBinding],
        bindings: &[DeviceBinding],
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<BindingsUpdate, Self::Error>> + Send {
        let store = self.clone();
        let tenant = tenant_id.to_string();
        let device_id = id.to_string();
        let expected = expected.to_vec();
        let bindings = bindings.to_vec();
        async move {
            // Only the bindings change, never on a Revoked row, and only if
            // they are still `expected`. The swap is conditional on the
            // bytes that were read, so a revocation or another bindings
            // edit that lands first conflicts the swap; the decision is
            // then taken again on the fresh row and refused.
            let applied = store
                .apply(&tenant, &device_id, now, |d| {
                    if d.trust_level == DeviceTrustLevel::Revoked || d.bindings != expected {
                        return Step::Skip;
                    }
                    let mut next = d.clone();
                    next.bindings = bindings.clone();
                    Step::Write(next)
                })
                .await?;
            match applied {
                Applied::Missing => Ok(BindingsUpdate::Missing),
                Applied::Skipped(found) if found.trust_level == DeviceTrustLevel::Revoked => {
                    Ok(BindingsUpdate::Revoked)
                }
                Applied::Skipped(_) => Ok(BindingsUpdate::Conflict),
                Applied::Written { before } => {
                    store
                        .reindex_families(&tenant, &device_id, &before.bindings, &bindings)
                        .await?;
                    Ok(BindingsUpdate::Written)
                }
                Applied::Removed(_) => Ok(BindingsUpdate::Written),
            }
        }
    }

    fn claim_owner(
        &self,
        tenant_id: &TenantId,
        id: &DeviceId,
        user: &UserId,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<OwnerClaim, Self::Error>> + Send {
        let store = self.clone();
        let tenant = tenant_id.to_string();
        let device_id = id.to_string();
        let user = *user;
        async move {
            // The owner is set only on a row that still has none: the swap
            // is conditional on the bytes that were read, so of two users
            // racing for one device the loser re-reads, sees the winner and
            // is refused.
            let applied = store
                .apply(&tenant, &device_id, now, |d| {
                    if d.user_id.is_some() {
                        return Step::Skip;
                    }
                    let mut next = d.clone();
                    next.user_id = Some(user);
                    Step::Write(next)
                })
                .await?;
            match applied {
                Applied::Missing => Ok(OwnerClaim::Missing),
                Applied::Skipped(found) if found.user_id == Some(user) => Ok(OwnerClaim::Claimed),
                Applied::Skipped(_) => Ok(OwnerClaim::OwnedByOther),
                Applied::Written { .. } | Applied::Removed(_) => {
                    let idx = user_index_key(&store.prefix, &tenant, &user.to_string());
                    let _: () = store.client.sadd(&idx, &device_id).await?;
                    Ok(OwnerClaim::Claimed)
                }
            }
        }
    }

    fn delete(
        &self,
        tenant_id: &TenantId,
        id: &DeviceId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let store = self.clone();
        let tenant = tenant_id.to_string();
        let device_id = id.to_string();
        async move {
            // Read first so we can also drop the fingerprint and family
            // index entries. Cheaper than scanning every fingerprint
            // index for matches.
            let device = store.get_device(&tenant, &device_id).await?;
            let row_key = device_key(&store.prefix, &tenant, &device_id);
            let tenant_idx = tenant_index_key(&store.prefix, &tenant);

            let Some(d) = device else {
                let _: () = store.client.del(&row_key).await?;
                let _: () = store.client.srem(&tenant_idx, &device_id).await?;
                return Ok(());
            };
            // Row delete is unconditional; the fingerprint index is
            // removed only if it still points at this device.
            let fp_key = fingerprint_key(
                &store.prefix,
                &tenant,
                &fingerprint_hex(&d.fingerprint_hash),
            );
            store
                .run_script(
                    REMOVE_DEVICE,
                    vec![row_key, fp_key],
                    remove_args(None, &device_id),
                )
                .await?;
            store.remove_index_entries(&tenant, &device_id, &d).await
        }
    }

    fn sweep(
        &self,
        tenant_id: &TenantId,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<SweepCounts, Self::Error>> + Send {
        let store = self.clone();
        let tenant = tenant_id.to_string();
        async move {
            let mut counts = SweepCounts::default();
            // Walk the per-tenant device-id index. Native key TTLs would
            // eventually evict stale rows on their own, but TTL alone
            // can't move a Trusted device to Seen; only the explicit
            // demotion ladder can. Hence the walk.
            let tenant_idx = tenant_index_key(&store.prefix, &tenant);
            let members: Vec<String> = store.client.smembers(&tenant_idx).await?;
            let cfg = store.sweep_config;

            for chunk in members.chunks(MGET_CHUNK) {
                // Rows are read a chunk at a time. A row that needs no change
                // is settled by that read alone; only a row that must be
                // demoted or purged goes on to its own compare-and-swap, which
                // reads it again.
                let (rows, gone) = store.get_rows(&tenant, chunk).await?;
                // Rows already TTL-evicted: clean the tenant index.
                store.prune_absent(&tenant_idx, &tenant, &gone).await;
                for (member, row) in rows {
                    if matches!(plan_sweep(&row, &cfg, now), SweepStep::Keep) {
                        continue;
                    }
                    // Each row is planned against the bytes it is then
                    // swapped or deleted under, so a revocation that lands
                    // mid-sweep re-plans the row instead of being overwritten.
                    let applied = store
                        .apply(&tenant, &member, now, |d| match plan_sweep(d, &cfg, now) {
                            SweepStep::Keep => Step::Skip,
                            SweepStep::Purge => Step::Remove,
                            SweepStep::Demote { level, .. } => {
                                let mut next = d.clone();
                                next.demoted_at =
                                    demotion_stamp(d.trust_level, level, d.demoted_at, now);
                                next.trust_level = level;
                                if level == DeviceTrustLevel::Revoked {
                                    next.revoked_at = Some(now);
                                }
                                Step::Write(next)
                            }
                        })
                        .await;
                    match applied {
                        // Vanished between the chunk read and the swap.
                        Ok(Applied::Missing) => {
                            store
                                .prune_absent(&tenant_idx, &tenant, std::slice::from_ref(&member))
                                .await;
                        }
                        Ok(Applied::Skipped(_)) => {}
                        Ok(Applied::Written { before, .. }) => {
                            if let SweepStep::Demote {
                                trusted_to_seen,
                                seen_to_revoked,
                                ..
                            } = plan_sweep(&before, &cfg, now)
                            {
                                counts.trusted_to_seen += u64::from(trusted_to_seen);
                                counts.seen_to_revoked += u64::from(seen_to_revoked);
                            }
                        }
                        Ok(Applied::Removed(d)) => {
                            counts.revoked_purged += 1;
                            store.remove_index_entries(&tenant, &member, &d).await?;
                        }
                        // A row that stays contended is retried by the next
                        // sweep; it must not abort the rest of the walk.
                        Err(ValkeyDeviceStoreError::Contended { .. }) => {}
                        Err(e) => return Err(e),
                    }
                }
            }

            Ok(counts)
        }
    }
}

// ── HealthCheck ──────────────────────────────────────────────────────

use crate::health::{HealthCheck, HealthStatus};

impl HealthCheck for ValkeyDeviceStore {
    fn check(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HealthStatus> + Send + '_>> {
        Box::pin(async {
            match tokio::time::timeout(Duration::from_secs(2), self.client.ping::<()>(None)).await {
                Ok(Ok(_)) => HealthStatus::Healthy,
                Ok(Err(e)) => HealthStatus::Unhealthy(format!("valkey PING failed: {e}")),
                Err(_) => HealthStatus::Unhealthy("valkey PING timeout (2s)".into()),
            }
        })
    }
}

// Integration tests live in `axess-core/tests/valkey_device_store.rs`
//; they require a running Valkey/Redis at `redis://localhost:6379`
// and run with `cargo test -- --ignored`.
