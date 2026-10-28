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
//! | `{prefix}:dev:fps:{tenant}:{hex_hash}` | set of device_ids | `find_by_fingerprint` index |
//! | `{prefix}:dev:fp:{tenant}:{hex_hash}` | string (device_id) | the single-id fingerprint index of earlier releases; read when present, removed by the next write of the device it names, never created |
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
//! members, not one `GET` per member. An index is a hint, never proof: each
//! reader keeps only the rows that still match what it asked for (the user
//! owns the device, the device is still bound to the family), so a stale
//! entry can neither return another user's device nor make a refresh-family
//! cascade revoke a device that has left the family. `find_by_fingerprint`
//! likewise reads the devices its fingerprint set lists and returns only
//! those whose row still carries the fingerprint, the newest sighting first
//! and the smaller id on a tie, as every other backend does.
//!
//! Stale entries are tidied by scripts that re-check before they remove: a
//! member whose row is gone is removed only if the row is still absent, so a
//! device saved again in the meantime keeps its entry; a member whose row
//! does not match is removed only while the row still holds the bytes that
//! were judged (the fingerprint set is pruned the same way as the others, and
//! a single-id key of an earlier release only while it points at that device
//! and its row is unchanged). `find_for_user` still reads the user's whole set
//! and sorts it in process (newest first, ties by device id); a per-user
//! sorted set scored by `last_seen_at` would bound that read but changes the
//! index layout.
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
//! The same script that writes (or deletes) the row also moves the row in
//! and out of the tenant, user and refresh-family indexes and re-points the
//! fingerprint index. Two writers therefore cannot apply their index
//! changes in the opposite order to their row writes: the one whose script
//! runs second sees the first one's row and conflicts instead.
//!
//! | Operation | Guarantee |
//! |-----------|-----------|
//! | `record_sighting` | Atomic CAS. `last_seen_at` only moves forward. Never writes to a `Revoked` row (a sighting cannot undo a revocation) and still succeeds. Missing row: `NotFound`. |
//! | `set_trust_level` | Atomic CAS against every other writer; the explicit level wins over the row it read. Missing row: `NotFound`. |
//! | `set_trust_level_if` | The expected level is checked against the bytes the CAS then replaces; a row at another level (a revocation that won) is refused, never overwritten. |
//! | `replace_bindings` | Atomic CAS on the row, and only while the bindings are still the ones the caller read (`Conflict` otherwise); a `Revoked` row is refused and never gains a binding. The refresh-family indexes change in the same script. |
//! | `claim_owner` | Atomic CAS; sets the owner only on a row that has none, and adds the device to the owner's index in the same script. |
//! | `sweep` | Per row, atomic CAS demotion or CAS purge. Only ever demotes, so it cannot resurrect a `Revoked` row; a row changed under it is re-planned from its new state. A row that cannot be decoded is logged and skipped. A revoked row with no `revoked_at` is stamped. |
//! | `delete` | One script removes the row, its fingerprint entry (only while it points at this device) and its index entries, conditional on the row as read; a writer that changed it meanwhile makes the delete run again on the fresh row. |
//! | `save` | A CAS against the row as read (or its absence), retried on a conflict, so the last writer wins without two saves interleaving their index changes. A stored `Revoked` row is left as it is by a save that is not itself revoked; a revoked row saved without `revoked_at` gets the write time. |
//!
//! The scripts address several keys (row, fingerprint index, membership
//! indexes); on a Valkey cluster give them one hash slot with a prefix such
//! as `{axess}`.
//!
//! The fingerprint index is a set of the ids of every device that carries the
//! fingerprint, so deleting or purging one of several devices that share it
//! leaves the others findable, owned or not. Only an operation on a device
//! adds or removes that device's id, in the script that writes its row.
//!
//! # Upgrading the fingerprint index
//!
//! Earlier releases kept one device id under a string key
//! (`{prefix}:dev:fp:...`). The set lives under a different key
//! (`{prefix}:dev:fps:...`), so the two layouts never meet in one key and
//! a read cannot fail on a key of the wrong type. `find_by_fingerprint` reads
//! the set and the old key and treats the old key's device as one more
//! candidate, so nothing stored by an older release goes missing. The next
//! write of a device (a sighting, a trust change, a save) adds it to the set
//! and deletes the old key if that points at it; a delete does the same.
//! There is no migration step to run. A device that an old key never named
//! stays unlisted until its next write, as it was before.
//!
//! The set has no expiry of its own (a key's expiry cannot cover some of its
//! members). A member whose row has expired is dropped by the first read that
//! finds the row gone, like the other membership indexes.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use fred::prelude::*;

use crate::authn::ids::{DeviceId, TenantId, UserId};
use crate::device::store::{
    BindingsUpdate, DeviceStore, OwnerClaim, SweepConfig, SweepCounts, TrustTransition,
    demotion_stamp, order_newest_first,
};
use crate::device::types::{Device, DeviceBinding, DeviceTrustLevel, FingerprintHash};
use crate::session::crypto::SessionCrypto;
use std::future::Future;

mod apply;
mod index;
mod policy;
mod read;
mod row;
mod scripts;
mod sweep;
#[cfg(test)]
mod tests;

use apply::{Applied, Step};
use row::{
    device_key, family_index_key, fingerprint_hex, fingerprint_key, fingerprint_set_key,
    tenant_index_key, user_index_key,
};
use scripts::DROP_STALE_FINGERPRINT;

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
        match self.get_row_checked(tenant, id).await? {
            Some((device, raw, stale)) => {
                if stale {
                    self.reseal_row(&device, &raw).await;
                }
                Ok(Some(device))
            }
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
        let hash = *hash;
        async move {
            let hex = fingerprint_hex(&hash);
            let set_key = fingerprint_set_key(&store.prefix, &tenant, &hex);
            // The set lists every device that carries the fingerprint. It is
            // a hint: only rows that still carry it are returned, and the
            // read tidies the entries that do not.
            let mut found = store
                .read_index(&set_key, &tenant, |d| d.fingerprint_hash == hash)
                .await?;
            // An earlier release kept one id under a string key. It names a
            // device the set may not list yet (the next write of that device
            // moves it), so it is read as one more candidate.
            let legacy_key = fingerprint_key(&store.prefix, &tenant, &hex);
            let legacy: Option<String> = store.client.get(&legacy_key).await?;
            if let Some(id) = legacy
                && !found.iter().any(|d| d.id.to_string() == id)
            {
                match store.get_row_checked(&tenant, &id).await? {
                    Some((d, raw, stale)) if d.fingerprint_hash == hash => {
                        if stale {
                            store.reseal_row(&d, &raw).await;
                        }
                        found.push(d);
                    }
                    Some((_, raw, _)) => {
                        if let Err(e) = store
                            .drop_stale_fingerprint(&legacy_key, &tenant, &id, &raw)
                            .await
                        {
                            tracing::warn!(error = %e, "stale fingerprint entry not dropped");
                        }
                    }
                    None => {}
                }
            }
            // The same device every other backend returns: newest sighting,
            // then the smaller id.
            Ok(found.into_iter().min_by(order_newest_first))
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
        let user = *user_id;
        async move {
            let idx = user_index_key(&store.prefix, &tenant, &user.to_string());
            let mut out = store
                .read_index(&idx, &tenant, |d| d.user_id.as_ref() == Some(&user))
                .await?;
            // Newest-sighted first; matches Memory + SQL impls.
            out.sort_by(order_newest_first);
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
        let user = *user_id;
        let hash = *hash;
        async move {
            // The user's whole index is read (no scan limit), so a user with
            // many devices never misses an older match.
            let idx = user_index_key(&store.prefix, &tenant, &user.to_string());
            let owned = store
                .read_index(&idx, &tenant, |d| d.user_id.as_ref() == Some(&user))
                .await?;
            Ok(owned
                .into_iter()
                .filter(|d| d.fingerprint_hash == hash)
                .min_by(order_newest_first))
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
            let mut out = store
                .read_index(&idx, &tenant, |d| {
                    d.bindings.iter().any(|b| {
                        matches!(b, DeviceBinding::Refresh { family_id: f, .. } if *f == family)
                    })
                })
                .await?;
            out.sort_by(order_newest_first);
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
        async move { store.save_row(&device, now).await }
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
            // TTL) changes, a Revoked row is never written, and the time
            // never moves backwards.
            let applied = store
                .apply(&tenant, &device_id, now, |d| {
                    if d.trust_level == DeviceTrustLevel::Revoked || now <= d.last_seen_at {
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
                Applied::Written { .. } | Applied::Removed => TrustTransition::Applied,
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
                Applied::Written { .. } | Applied::Removed => Ok(BindingsUpdate::Written),
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
                Applied::Written { .. } | Applied::Removed => Ok(OwnerClaim::Claimed),
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
            // The row, its fingerprint entry (only while it points at this
            // device) and its index entries go in one script.
            let applied = store.remove_row(&tenant, &device_id).await?;
            if matches!(applied, Applied::Missing) {
                let tenant_idx = tenant_index_key(&store.prefix, &tenant);
                let _: () = store.client.srem(&tenant_idx, &device_id).await?;
            }
            Ok(())
        }
    }

    fn sweep(
        &self,
        tenant_id: &TenantId,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<SweepCounts, Self::Error>> + Send {
        let store = self.clone();
        let tenant = tenant_id.to_string();
        async move { store.sweep_tenant(&tenant, now).await }
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
