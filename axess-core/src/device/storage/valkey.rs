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
//! | `{prefix}:dev:user:{tenant}:{user}` | set of device_ids | `find_for_user` index |
//! | `{prefix}:dev:fam:{tenant}:{family}` | set of device_ids | `find_by_refresh_family` index |
//! | `{prefix}:dev:tenant:{tenant}` | set of device_ids | sweep walker (avoids `SCAN *`) |
//!
//! # TTL policy
//!
//! The per-device key carries a TTL derived from its trust level and
//! the configured [`SweepConfig`]:
//!
//! | Trust level | TTL anchor |
//! |-------------|-----------|
//! | `Unknown`, `Seen` | `last_seen_at + seen_idle` |
//! | `Trusted` | `last_seen_at + trusted_idle` |
//! | `Revoked` | `revoked_at + revoked_grace` |
//!
//! `record_sighting` and `set_trust_level` re-set the TTL accordingly.
//! Native expiry handles Stage 3 of the retention ladder
//! (Revoked → purged); the explicit `sweep` only walks for
//! Stages 1 and 2 (the demotion transitions Valkey can't infer on
//! its own), and only counts Stage 3 deletions it physically performs.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use fred::prelude::*;

use crate::authn::ids::{DeviceId, TenantId, UserId};
use crate::device::store::{DeviceStore, SweepConfig, SweepCounts};
use crate::device::types::{Device, DeviceBinding, DeviceTrustLevel, FingerprintHash};
use crate::session::crypto::SessionCrypto;
use std::future::Future;

const DEFAULT_PREFIX: &str = "axess";

fn device_key(prefix: &str, tenant: &str, id: &str) -> String {
    format!("{prefix}:dev:{tenant}:{id}")
}

fn fingerprint_key(prefix: &str, tenant: &str, hex_hash: &str) -> String {
    format!("{prefix}:dev:fp:{tenant}:{hex_hash}")
}

fn user_index_key(prefix: &str, tenant: &str, user: &str) -> String {
    format!("{prefix}:dev:user:{tenant}:{user}")
}

fn family_index_key(prefix: &str, tenant: &str, family: &str) -> String {
    format!("{prefix}:dev:fam:{tenant}:{family}")
}

fn tenant_index_key(prefix: &str, tenant: &str) -> String {
    format!("{prefix}:dev:tenant:{tenant}")
}

/// Convert a [`FingerprintHash`] to its 64-char hex representation.
fn fingerprint_hex(h: &FingerprintHash) -> String {
    use std::fmt::Write as _;
    let bytes = h.as_bytes();
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(s, "{:02x}", b).expect("writing into a String never fails");
    }
    s
}

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

    /// TTL (seconds) the device row should carry given its trust level.
    ///
    /// `Trusted` rows live for `trusted_idle` from `last_seen_at`;
    /// `Unknown` and `Seen` for `seen_idle` from `last_seen_at`; and
    /// `Revoked` for `revoked_grace` from `revoked_at`. The returned
    /// value clamps to `>= 1` so we never write a key with TTL 0
    /// (which Valkey treats as "no expire" in some `SET EX` paths).
    fn ttl_seconds_for(&self, device: &Device, now: DateTime<Utc>) -> i64 {
        let cfg = &self.sweep_config;
        let (anchor, window) = match device.trust_level {
            DeviceTrustLevel::Trusted => (device.last_seen_at, cfg.trusted_idle),
            DeviceTrustLevel::Unknown | DeviceTrustLevel::Seen => {
                (device.last_seen_at, cfg.seen_idle)
            }
            DeviceTrustLevel::Revoked => (device.revoked_at.unwrap_or(now), cfg.revoked_grace),
        };
        let expiry = anchor + window;
        let remaining = expiry.signed_duration_since(now).num_seconds();
        // Floor at 1s; Valkey's PEXPIRE rejects 0 / negative; we want
        // soon-to-expire keys to actually exist briefly so the sweep
        // can count their purge if it runs immediately.
        remaining.max(1)
    }

    /// Encode a `Device` for storage: msgpack the row, then optionally
    /// AES-256-GCM-encrypt the result. Valkey's binary-safe values
    /// store the bytes directly; no base64 hop.
    fn encode_row(&self, device: &Device) -> Result<Vec<u8>, ValkeyDeviceStoreError> {
        let bytes = rmp_serde::to_vec_named(device)?;
        match &self.crypto {
            Some(c) => Ok(c.encrypt(&bytes)?),
            None => Ok(bytes),
        }
    }

    fn decode_row(&self, payload: &[u8]) -> Result<Device, ValkeyDeviceStoreError> {
        let plaintext = match &self.crypto {
            Some(c) => c.decrypt(payload)?,
            None => payload.to_vec(),
        };
        Ok(rmp_serde::from_slice(&plaintext)?)
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
            Some(b) => Ok(Some(self.decode_row(&b)?)),
            None => Ok(None),
        }
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
        let tenant = tenant_id.to_string().to_string();
        let device_id = id.to_string().to_string();
        async move { store.get_device(&tenant, &device_id).await }
    }

    fn find_by_fingerprint(
        &self,
        tenant_id: &TenantId,
        hash: &FingerprintHash,
    ) -> impl Future<Output = Result<Option<Device>, Self::Error>> + Send {
        let store = self.clone();
        let tenant = tenant_id.to_string().to_string();
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
        let tenant = tenant_id.to_string().to_string();
        let user = user_id.to_string().to_string();
        async move {
            let idx = user_index_key(&store.prefix, &tenant, &user);
            let members: Vec<String> = store.client.smembers(&idx).await?;
            let mut out = Vec::with_capacity(members.len().min(limit));
            for member in members {
                if let Some(device) = store.get_device(&tenant, &member).await? {
                    out.push(device);
                }
            }
            // Newest-sighted first; matches Memory + SQL impls.
            out.sort_by_key(|d| std::cmp::Reverse(d.last_seen_at));
            out.truncate(limit);
            Ok(out)
        }
    }

    fn find_by_refresh_family(
        &self,
        tenant_id: &TenantId,
        family_id: &str,
    ) -> impl Future<Output = Result<Vec<Device>, Self::Error>> + Send {
        let store = self.clone();
        let tenant = tenant_id.to_string().to_string();
        let family = family_id.to_string();
        async move {
            let idx = family_index_key(&store.prefix, &tenant, &family);
            let members: Vec<String> = store.client.smembers(&idx).await?;
            let mut out = Vec::with_capacity(members.len());
            for member in members {
                if let Some(device) = store.get_device(&tenant, &member).await? {
                    out.push(device);
                }
            }
            out.sort_by_key(|d| std::cmp::Reverse(d.last_seen_at));
            Ok(out)
        }
    }

    fn save(&self, device: &Device) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let store = self.clone();
        let device = device.clone();
        async move {
            let now = Utc::now();
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
                    let _: () = store.client.del(&stale_fp).await?;
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

            // Write the row with TTL.
            let _: () = store
                .client
                .set(
                    &row_key,
                    payload,
                    Some(Expiration::EX(ttl_secs)),
                    None,
                    false,
                )
                .await?;
            // Fingerprint index → device id. Same TTL so it ages out
            // alongside the row.
            let _: () = store
                .client
                .set(&fp_key, &id, Some(Expiration::EX(ttl_secs)), None, false)
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
        let tenant = tenant_id.to_string().to_string();
        let device_id = id.to_string().to_string();
        async move {
            // Read-modify-write so the TTL gets recomputed against the
            // new last_seen_at. Acceptable on a per-request hot path
            // because the row is small and the operation is rare
            // relative to load (callers typically call once per
            // authenticated request).
            let Some(mut device) = store.get_device(&tenant, &device_id).await? else {
                return Ok(());
            };
            device.last_seen_at = now;
            let payload = store.encode_row(&device)?;
            let ttl = store.ttl_seconds_for(&device, now);
            let row_key = device_key(&store.prefix, &tenant, &device_id);
            let _: () = store
                .client
                .set(&row_key, payload, Some(Expiration::EX(ttl)), None, false)
                .await?;
            // Refresh the fingerprint index TTL so it ages out with the row.
            let fp_key = fingerprint_key(
                &store.prefix,
                &tenant,
                &fingerprint_hex(&device.fingerprint_hash),
            );
            let _: () = store.client.expire(&fp_key, ttl, None).await?;
            Ok(())
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
        let tenant = tenant_id.to_string().to_string();
        let device_id = id.to_string().to_string();
        async move {
            let Some(mut device) = store.get_device(&tenant, &device_id).await? else {
                return Ok(());
            };
            device.trust_level = level;
            device.revoked_at = matches!(level, DeviceTrustLevel::Revoked).then_some(now);
            let payload = store.encode_row(&device)?;
            let ttl = store.ttl_seconds_for(&device, now);
            let row_key = device_key(&store.prefix, &tenant, &device_id);
            let _: () = store
                .client
                .set(&row_key, payload, Some(Expiration::EX(ttl)), None, false)
                .await?;
            let fp_key = fingerprint_key(
                &store.prefix,
                &tenant,
                &fingerprint_hex(&device.fingerprint_hash),
            );
            let _: () = store.client.expire(&fp_key, ttl, None).await?;
            Ok(())
        }
    }

    fn delete(
        &self,
        tenant_id: &TenantId,
        id: &DeviceId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let store = self.clone();
        let tenant = tenant_id.to_string().to_string();
        let device_id = id.to_string().to_string();
        async move {
            // Read first so we can also drop the fingerprint and family
            // index entries. Cheaper than scanning every fingerprint
            // index for matches.
            let device = store.get_device(&tenant, &device_id).await?;
            let row_key = device_key(&store.prefix, &tenant, &device_id);
            let _: () = store.client.del(&row_key).await?;

            let tenant_idx = tenant_index_key(&store.prefix, &tenant);
            let _: () = store.client.srem(&tenant_idx, &device_id).await?;

            if let Some(d) = device {
                let fp_key = fingerprint_key(
                    &store.prefix,
                    &tenant,
                    &fingerprint_hex(&d.fingerprint_hash),
                );
                let _: () = store.client.del(&fp_key).await?;
                if let Some(uid) = &d.user_id {
                    let user_idx = user_index_key(&store.prefix, &tenant, &uid.to_string());
                    let _: () = store.client.srem(&user_idx, &device_id).await?;
                }
                for binding in &d.bindings {
                    if let DeviceBinding::Refresh { family_id, .. } = binding {
                        let fam_idx = family_index_key(&store.prefix, &tenant, family_id);
                        let _: () = store.client.srem(&fam_idx, &device_id).await?;
                    }
                }
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
        let tenant = tenant_id.to_string().to_string();
        async move {
            let mut counts = SweepCounts::default();
            // Walk the per-tenant device-id index. Native key TTLs would
            // eventually evict stale rows on their own, but TTL alone
            // can't move a Trusted device to Seen; only the explicit
            // demotion ladder can. Hence the walk.
            let tenant_idx = tenant_index_key(&store.prefix, &tenant);
            let members: Vec<String> = store.client.smembers(&tenant_idx).await?;
            let cfg = store.sweep_config;

            for member in members {
                let Some(mut device) = store.get_device(&tenant, &member).await? else {
                    // Row already TTL-evicted; clean the tenant index lazily.
                    let _: () = store.client.srem(&tenant_idx, &member).await?;
                    continue;
                };

                let mut changed = false;

                // Stage 1: Trusted → Seen
                if device.trust_level == DeviceTrustLevel::Trusted
                    && now.signed_duration_since(device.last_seen_at) > cfg.trusted_idle
                {
                    device.trust_level = DeviceTrustLevel::Seen;
                    counts.trusted_to_seen += 1;
                    changed = true;
                }

                // Stage 2: Seen → Revoked (cascades from stage 1 in the
                // same pass when the original last_seen_at also clears
                // seen_idle).
                if device.trust_level == DeviceTrustLevel::Seen
                    && now.signed_duration_since(device.last_seen_at) > cfg.seen_idle
                {
                    device.trust_level = DeviceTrustLevel::Revoked;
                    device.revoked_at = Some(now);
                    counts.seen_to_revoked += 1;
                    changed = true;
                }

                // Stage 3: Revoked → purge (uses pre-existing
                // revoked_at, NOT the one stage 2 just stamped, so the
                // grace clock starts fresh on demotion).
                let should_purge = device.trust_level == DeviceTrustLevel::Revoked
                    && device
                        .revoked_at
                        .map(|r| now.signed_duration_since(r) > cfg.revoked_grace)
                        .unwrap_or(false)
                    // Don't purge a row demoted in *this* sweep call;
                    // its grace clock starts now.
                    && !(counts.seen_to_revoked > 0 && device.revoked_at == Some(now));

                if should_purge {
                    counts.revoked_purged += 1;
                    let row_key = device_key(&store.prefix, &tenant, &member);
                    let _: () = store.client.del(&row_key).await?;
                    let _: () = store.client.srem(&tenant_idx, &member).await?;
                    let fp_key = fingerprint_key(
                        &store.prefix,
                        &tenant,
                        &fingerprint_hex(&device.fingerprint_hash),
                    );
                    let _: () = store.client.del(&fp_key).await?;
                    if let Some(uid) = &device.user_id {
                        let user_idx = user_index_key(&store.prefix, &tenant, &uid.to_string());
                        let _: () = store.client.srem(&user_idx, &member).await?;
                    }
                    for binding in &device.bindings {
                        if let DeviceBinding::Refresh { family_id, .. } = binding {
                            let fam_idx = family_index_key(&store.prefix, &tenant, family_id);
                            let _: () = store.client.srem(&fam_idx, &member).await?;
                        }
                    }
                } else if changed {
                    let payload = store.encode_row(&device)?;
                    let ttl = store.ttl_seconds_for(&device, now);
                    let row_key = device_key(&store.prefix, &tenant, &member);
                    let _: () = store
                        .client
                        .set(&row_key, payload, Some(Expiration::EX(ttl)), None, false)
                        .await?;
                    let fp_key = fingerprint_key(
                        &store.prefix,
                        &tenant,
                        &fingerprint_hex(&device.fingerprint_hash),
                    );
                    let _: () = store.client.expire(&fp_key, ttl, None).await?;
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
