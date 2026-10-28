//! Shared logic for SQL-backed device stores (SQLite, PostgreSQL, MySQL).
//!
//! Everything that does not depend on a dialect lives here: row decoding,
//! the sweep thresholds, the compare-and-swap decisions (trust level,
//! bindings, owner claim) and the column values each write binds. A
//! backend keeps only its DDL, its placeholders and bind order, its upsert
//! syntax and its collation notes.
//!
//! Mirrors the shape of
//! [`session::storage::session_codec`](crate::session::storage::session_codec):
//! a small codec that handles the bindings-blob serialisation + optional
//! AES-256-GCM envelope encryption, and a shared error type so each
//! backend doesn't reinvent the failure surface.
//!
//! # What's encrypted, what isn't
//!
//! Only the **bindings blob** runs through the optional codec. The
//! structured columns (tenant_id, id, user_id, trust_level,
//! fingerprint_hash, first_seen_at, last_seen_at, revoked_at) stay
//! plaintext because every one of them is either a tenant-scoped
//! opaque id, a keyed HMAC, or a timestamp the indexes need to be
//! able to range-scan. Encrypting the bindings blob covers the
//! material that *could* leak something operationally interesting
//! (refresh-token family identifiers, WebAuthn credential references)
//! without giving up the tenant-scoped query primitives that drive
//! the rest of the device subsystem.

use chrono::{DateTime, TimeZone, Utc};

use crate::authn::ids::{DeviceId, TenantId, UserId};
use crate::device::store::{BindingsUpdate, OwnerClaim, SweepConfig, TrustTransition};
use crate::device::types::{Device, DeviceBinding, DeviceTrustLevel, FingerprintHash};
use crate::session::crypto::{
    BoundFormat, CryptoError, SessionCrypto, device_row_id, device_row_id_v1,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

/// Codec for the bindings column on a device row.
///
/// Serialises `Vec<DeviceBinding>` with `rmp-serde` (MessagePack) and
/// optionally encrypts with AES-256-GCM. The encrypted output is then
/// base64-encoded so the column stays TEXT: same shape as the
/// session store, intentionally.
///
/// # Binding to the device row
///
/// An encrypted blob is `AXD 0x02 || nonce(12) || ciphertext+tag` (marker
/// bytes `0x41 0x58 0x44 0x02`) with AES-GCM additional authenticated data
/// `"axess.device-bindings.v2" || 0x00 || len(tenant_id) || tenant_id ||
/// len(device_id) || device_id`, each length a big-endian `u32` and each id
/// its UTF-8 bytes, so two different id pairs can never produce the same
/// AAD. The ids are supplied again on every read, so a bindings blob copied
/// into another device's row fails authentication. A blob with a marker is
/// never opened under an empty AAD. The 0.11.0 form (`AXD 0x01`, the ids
/// joined by one zero byte) is still read. A blob without any marker
/// predates binding and is opened under the empty AAD unless the crypto was
/// set to reject such blobs ([`LegacyBlobs`](crate::session::crypto::LegacyBlobs)).
/// A bindings write seals the current form, and so does a read that finds an
/// older form (a conditional write of the exact bytes it read), so the older
/// forms age out as devices are written or read. Plaintext codecs have
/// nothing to bind.
///
/// `SessionCrypto` is reused as a *generic* AES-256-GCM envelope
/// primitive. The "session" prefix in its name is historical; the
/// implementation has no session-specific behaviour. Renaming to
/// `EnvelopeCrypto` is a separate refactor (would touch every
/// session-store call site).
#[derive(Clone)]
pub(crate) struct BindingsCodec {
    crypto: Option<SessionCrypto>,
}

impl BindingsCodec {
    pub fn encrypted(crypto: SessionCrypto) -> Self {
        Self {
            crypto: Some(crypto),
        }
    }

    pub fn plaintext() -> Self {
        Self { crypto: None }
    }

    /// Serialise (and optionally encrypt) the bindings vector.
    pub fn encode(
        &self,
        tenant_id: &str,
        device_id: &str,
        bindings: &[DeviceBinding],
    ) -> Result<String, SqlDeviceStoreError> {
        let bytes = rmp_serde::to_vec_named(bindings)?;
        let payload = match &self.crypto {
            Some(crypto) => crypto.seal_bound(
                BoundFormat::DEVICE_BINDINGS,
                &device_row_id(tenant_id, device_id),
                &bytes,
            )?,
            None => bytes,
        };
        Ok(BASE64.encode(payload))
    }

    /// Deserialise (and optionally decrypt) the bindings vector.
    /// Empty input is treated as `Vec::new()` so legacy NULL columns
    /// or rows written before the bindings column existed still load.
    pub fn decode(
        &self,
        tenant_id: &str,
        device_id: &str,
        stored: &str,
    ) -> Result<Vec<DeviceBinding>, SqlDeviceStoreError> {
        self.decode_checked(tenant_id, device_id, stored)
            .map(|(bindings, _)| bindings)
    }

    /// Like [`decode`](Self::decode), and also reports whether the stored
    /// blob is in an older format than the one a write seals, so a reader
    /// can re-seal it. An empty column and a plaintext codec are never
    /// stale.
    pub fn decode_checked(
        &self,
        tenant_id: &str,
        device_id: &str,
        stored: &str,
    ) -> Result<(Vec<DeviceBinding>, bool), SqlDeviceStoreError> {
        if stored.is_empty() {
            return Ok((Vec::new(), false));
        }
        let payload = BASE64
            .decode(stored)
            .map_err(|_| SqlDeviceStoreError::Crypto(CryptoError))?;
        let (plaintext, stale) = match &self.crypto {
            Some(crypto) => {
                let opened = crypto.open_bound(
                    BoundFormat::DEVICE_BINDINGS,
                    &device_row_id(tenant_id, device_id),
                    &[(
                        BoundFormat::DEVICE_BINDINGS_V1,
                        device_row_id_v1(tenant_id, device_id),
                    )],
                    &payload,
                )?;
                (opened.plaintext, opened.stale)
            }
            None => (payload, false),
        };
        Ok((rmp_serde::from_slice(&plaintext)?, stale))
    }
}

/// A stale bindings blob read from a row, with the current-format blob
/// that should replace it. The write is conditional on the exact bytes
/// that were read, so it never overwrites a save that landed meanwhile.
pub(crate) struct Reseal {
    pub tenant: String,
    pub id: String,
    /// The stored bytes the read saw: the comparand of the write.
    pub stored: String,
    /// The same bindings sealed in the current format.
    pub blob: String,
}

/// Log the outcome of a re-seal attempt. A re-seal is housekeeping: it
/// never fails the read that found the stale blob.
pub(crate) fn note_reseal(result: Result<u64, sqlx::Error>, reseal: &Reseal) {
    match result {
        Ok(0) => tracing::debug!(
            tenant_id = %reseal.tenant,
            device_id = %reseal.id,
            "bindings re-seal skipped: the row changed after it was read"
        ),
        Ok(_) => {}
        Err(error) => tracing::warn!(
            tenant_id = %reseal.tenant,
            device_id = %reseal.id,
            %error,
            "bindings re-seal failed; the row keeps its older format"
        ),
    }
}

/// Most refresh-family rows written by one `INSERT`: three binds per row
/// keeps a statement far below the 32 766 variable cap of the tightest
/// dialect (SQLite).
pub(crate) const FAMILY_INSERT_CHUNK: usize = 500;

/// The distinct refresh-family ids carried by `bindings`, in first-seen
/// order. The `device_bindings_refresh` index is keyed on
/// `(tenant, device, family)`, so a device that carries the same family
/// twice must contribute it once: inserting it twice would violate that
/// key and abort the whole transaction.
pub(crate) fn refresh_family_ids(bindings: &[DeviceBinding]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    bindings
        .iter()
        .filter_map(|b| match b {
            DeviceBinding::Refresh { family_id, .. } => Some(family_id),
            _ => None,
        })
        .filter(|family_id| seen.insert(family_id.as_str()))
        .cloned()
        .collect()
}

/// Wire-form trust-level identifiers persisted in the `trust_level`
/// column. Stable across schema changes: bump the schema version
/// before changing these.
pub(crate) mod trust_level_codec {
    use crate::device::types::DeviceTrustLevel;

    pub fn to_str(level: DeviceTrustLevel) -> &'static str {
        match level {
            DeviceTrustLevel::Unknown => "Unknown",
            DeviceTrustLevel::Seen => "Seen",
            DeviceTrustLevel::Trusted => "Trusted",
            DeviceTrustLevel::Revoked => "Revoked",
        }
    }

    pub fn from_str(s: &str) -> Option<DeviceTrustLevel> {
        match s {
            "Unknown" => Some(DeviceTrustLevel::Unknown),
            "Seen" => Some(DeviceTrustLevel::Seen),
            "Trusted" => Some(DeviceTrustLevel::Trusted),
            "Revoked" => Some(DeviceTrustLevel::Revoked),
            _ => None,
        }
    }
}

/// Errors from SQL-backed device stores.
///
/// Same shape as [`SqlStoreError`](crate::session::storage::session_codec::SqlStoreError)
/// Distinct type so the device-store error surface doesn't widen
/// when the session-store one does (and vice versa).
#[derive(Debug, thiserror::Error)]
pub enum SqlDeviceStoreError {
    /// Underlying database driver returned an error.
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),

    /// The targeted device does not exist in the tenant. Returned by
    /// `record_sighting` and `set_trust_level`, as the in-memory store
    /// does, so a write to a missing device is never reported as success.
    #[error("device not found: tenant={tenant_id} id={device_id}")]
    NotFound {
        /// Tenant scope of the missed lookup.
        tenant_id: String,
        /// Opaque device id whose lookup missed.
        device_id: String,
    },

    /// MessagePack encoding of the bindings vector failed.
    #[error("device-bindings MessagePack encoding failed: {0}")]
    Encode(#[from] rmp_serde::encode::Error),

    /// MessagePack decoding of a stored bindings blob failed.
    #[error("device-bindings MessagePack decoding failed: {0}")]
    Decode(#[from] rmp_serde::decode::Error),

    /// AES-256-GCM encryption or decryption of the bindings blob failed.
    #[error("encryption/decryption error: {0}")]
    Crypto(#[from] CryptoError),

    /// Stored row carried a trust-level string the codec doesn't
    /// recognise. Indicates schema drift (a future trust level was
    /// written by a newer process and an older one is now reading it).
    #[error("unrecognised trust_level value: {0}")]
    UnknownTrustLevel(String),

    /// Stored row carried a value that couldn't be parsed into the
    /// expected newtype (e.g. `tenant_id` / `device_id` validation
    /// rejected the bytes). Indicates row corruption: the value was
    /// either written by a buggy producer or hand-edited.
    #[error("malformed stored value: {0}")]
    MalformedRow(String),
}

/// Seconds since the Unix epoch back to a UTC instant; a value chrono
/// cannot represent is a corrupt row, not a panic.
pub(crate) fn unix_to_utc(secs: i64) -> Result<DateTime<Utc>, SqlDeviceStoreError> {
    Utc.timestamp_opt(secs, 0).single().ok_or_else(|| {
        SqlDeviceStoreError::MalformedRow(format!("unrepresentable Unix timestamp: {secs}"))
    })
}

/// The whole-second Unix form every timestamp column stores.
pub(crate) fn utc_to_unix(dt: DateTime<Utc>) -> i64 {
    dt.timestamp()
}

/// `SELECT` of every `devices` column, in [`DeviceRow`] field order,
/// followed by `$tail` (the `WHERE`/`ORDER BY` part, which carries the
/// dialect's placeholders).
macro_rules! select_devices {
    ($tail:literal) => {
        concat!(
            "SELECT tenant_id, id, user_id, trust_level, fingerprint_hash, \
             first_seen_at, last_seen_at, revoked_at, demoted_at, bindings \
             FROM devices ",
            $tail
        )
    };
}
pub(crate) use select_devices;

/// Raw row shape for the `devices` table. Mirrors the column order in
/// the schema so `query_as` works without column-name binding.
#[derive(sqlx::FromRow)]
pub(crate) struct DeviceRow {
    tenant_id: String,
    id: String,
    user_id: Option<String>,
    trust_level: String,
    fingerprint_hash: Vec<u8>,
    first_seen_at: i64,
    last_seen_at: i64,
    revoked_at: Option<i64>,
    demoted_at: Option<i64>,
    bindings: String,
}

impl DeviceRow {
    /// Decode a stored row into a [`Device`], validating every id,
    /// timestamp and the trust level, and opening the bindings blob. When
    /// the blob is in an older format the [`Reseal`] that replaces it is
    /// returned beside the device.
    pub(crate) fn into_device(
        self,
        codec: &BindingsCodec,
    ) -> Result<(Device, Option<Reseal>), SqlDeviceStoreError> {
        let Self {
            tenant_id,
            id,
            user_id,
            trust_level,
            fingerprint_hash,
            first_seen_at,
            last_seen_at,
            revoked_at,
            demoted_at,
            bindings,
        } = self;

        let tenant = TenantId::try_new(&tenant_id)
            .map_err(|e| SqlDeviceStoreError::MalformedRow(format!("tenant_id: {e}")))?;
        let device_id = DeviceId::try_new(&id)
            .map_err(|e| SqlDeviceStoreError::MalformedRow(format!("device id: {e}")))?;
        let user = match user_id {
            Some(u) => Some(
                UserId::try_new(&u)
                    .map_err(|e| SqlDeviceStoreError::MalformedRow(format!("user_id: {e}")))?,
            ),
            None => None,
        };

        let trust = trust_level_codec::from_str(&trust_level)
            .ok_or(SqlDeviceStoreError::UnknownTrustLevel(trust_level))?;

        let fp_bytes: [u8; 32] = fingerprint_hash
            .try_into()
            .map_err(|_| SqlDeviceStoreError::MalformedRow("fingerprint_hash length".into()))?;

        let first = unix_to_utc(first_seen_at)?;
        let last = unix_to_utc(last_seen_at)?;
        let revoked = revoked_at.map(unix_to_utc).transpose()?;
        let demoted = demoted_at.map(unix_to_utc).transpose()?;

        let (decoded, stale) = codec.decode_checked(&tenant_id, &id, &bindings)?;
        let reseal = if stale {
            Some(Reseal {
                blob: codec.encode(&tenant_id, &id, &decoded)?,
                tenant: tenant_id,
                id,
                stored: bindings,
            })
        } else {
            None
        };
        let bindings = decoded;

        let device = Device {
            id: device_id,
            tenant_id: tenant,
            user_id: user,
            trust_level: trust,
            fingerprint_hash: FingerprintHash::from_bytes(fp_bytes),
            first_seen_at: first,
            last_seen_at: last,
            revoked_at: revoked,
            demoted_at: demoted,
            bindings,
        };
        Ok((device, reseal))
    }
}

/// Decode at most one fetched row, with the re-seal its blob needs.
pub(crate) fn decode_optional(
    codec: &BindingsCodec,
    row: Option<DeviceRow>,
) -> Result<(Option<Device>, Option<Reseal>), SqlDeviceStoreError> {
    match row.map(|r| r.into_device(codec)).transpose()? {
        Some((device, reseal)) => Ok((Some(device), reseal)),
        None => Ok((None, None)),
    }
}

/// Decode fetched rows in order, stopping at the first that fails, with
/// the re-seals the stale blobs among them need.
pub(crate) fn decode_all(
    codec: &BindingsCodec,
    rows: Vec<DeviceRow>,
) -> Result<(Vec<Device>, Vec<Reseal>), SqlDeviceStoreError> {
    let mut devices = Vec::with_capacity(rows.len());
    let mut reseals = Vec::new();
    for row in rows {
        let (device, reseal) = row.into_device(codec)?;
        devices.push(device);
        reseals.extend(reseal);
    }
    Ok((devices, reseals))
}

/// A stored `trust_level` column value read back as a level; `None` when
/// the row is absent.
pub(crate) fn parse_stored_trust(
    stored: Option<String>,
) -> Result<Option<DeviceTrustLevel>, SqlDeviceStoreError> {
    match stored {
        None => Ok(None),
        Some(s) => trust_level_codec::from_str(&s)
            .map(Some)
            .ok_or(SqlDeviceStoreError::UnknownTrustLevel(s)),
    }
}

/// An `UPDATE` that must hit a row: zero rows affected is a missing device.
pub(crate) fn require_row(
    rows_affected: u64,
    tenant: String,
    device_id: String,
) -> Result<(), SqlDeviceStoreError> {
    if rows_affected == 0 {
        return Err(SqlDeviceStoreError::NotFound {
            tenant_id: tenant,
            device_id,
        });
    }
    Ok(())
}

/// Every column value of a device row, already converted to what the
/// backends bind, plus the refresh families its index rows need.
pub(crate) struct DeviceWrite {
    pub tenant: String,
    pub id: String,
    pub user_id: Option<String>,
    pub trust: &'static str,
    pub fingerprint: Vec<u8>,
    pub first_seen_at: i64,
    pub last_seen_at: i64,
    pub revoked_at: Option<i64>,
    pub demoted_at: Option<i64>,
    pub bindings: String,
    pub family_ids: Vec<String>,
}

impl DeviceWrite {
    /// Encode `device` for storage.
    pub(crate) fn new(codec: &BindingsCodec, device: &Device) -> Result<Self, SqlDeviceStoreError> {
        let tenant = device.tenant_id.to_string();
        let id = device.id.to_string();
        Ok(Self {
            bindings: codec.encode(&tenant, &id, &device.bindings)?,
            trust: trust_level_codec::to_str(device.trust_level),
            fingerprint: device.fingerprint_hash.as_bytes().to_vec(),
            user_id: device.user_id.as_ref().map(|u| u.to_string()),
            first_seen_at: utc_to_unix(device.first_seen_at),
            last_seen_at: utc_to_unix(device.last_seen_at),
            revoked_at: device.revoked_at.map(utc_to_unix),
            demoted_at: device.demoted_at.map(utc_to_unix),
            family_ids: refresh_family_ids(&device.bindings),
            tenant,
            id,
        })
    }
}

/// Column values of an unconditional trust-level change.
///
/// `revoked_at` is set and cleared symmetrically with the transition so
/// every backend matches the in-memory store. `to_seen` drives the
/// `demoted_at` rule of `demotion_stamp`: a Trusted row moving to Seen is
/// stamped, a Seen target otherwise keeps the column, any other target
/// clears it. The statement reads the row's level from before its own
/// assignments.
pub(crate) struct TrustWrite {
    pub trust: &'static str,
    pub revoked_at: Option<i64>,
    pub to_seen: i64,
    pub now: i64,
}

impl TrustWrite {
    pub(crate) fn new(level: DeviceTrustLevel, now: DateTime<Utc>) -> Self {
        let now = utc_to_unix(now);
        Self {
            trust: trust_level_codec::to_str(level),
            revoked_at: (level == DeviceTrustLevel::Revoked).then_some(now),
            to_seen: i64::from(level == DeviceTrustLevel::Seen),
            now,
        }
    }
}

/// Column values of a compare-and-swap trust-level change.
///
/// The row is at `expected` whenever the `UPDATE` matches, so the rule of
/// `demotion_stamp` is decided before the statement runs: stamp on Trusted
/// to Seen, keep the stored value for any other move to Seen, clear
/// otherwise.
pub(crate) struct GuardedTrustWrite {
    pub expected: &'static str,
    pub new: &'static str,
    pub revoked_at: Option<i64>,
    pub keep_demoted: i64,
    pub demoted_at: Option<i64>,
}

impl GuardedTrustWrite {
    pub(crate) fn new(
        expected: DeviceTrustLevel,
        level: DeviceTrustLevel,
        now: DateTime<Utc>,
    ) -> Self {
        let now = utc_to_unix(now);
        let to_seen = level == DeviceTrustLevel::Seen;
        Self {
            expected: trust_level_codec::to_str(expected),
            new: trust_level_codec::to_str(level),
            revoked_at: (level == DeviceTrustLevel::Revoked).then_some(now),
            keep_demoted: i64::from(to_seen && expected != DeviceTrustLevel::Trusted),
            demoted_at: (to_seen && expected == DeviceTrustLevel::Trusted).then_some(now),
        }
    }
}

/// How often a guarded trust change is tried when it keeps missing a row
/// that a re-read finds at the expected level.
pub(crate) const TRANSITION_ATTEMPTS: usize = 4;

/// The outcome of a guarded trust change that matched no row, given the
/// level a re-read found. `None` means the row is at `expected` after all:
/// the write lost a race with a change that has since been undone, nothing
/// was written, and the caller must try the write again rather than report
/// a transition that did not happen.
pub(crate) fn transition_after_miss(
    current: Option<DeviceTrustLevel>,
    expected: DeviceTrustLevel,
) -> Option<TrustTransition> {
    match current {
        None => Some(TrustTransition::Missing),
        Some(current) if current == expected => None,
        Some(current) => Some(TrustTransition::Refused { current }),
    }
}

/// What a bindings compare-and-swap does after reading the row.
pub(crate) enum SwapPlan {
    /// The read already settles the outcome; nothing is written.
    Settled(BindingsUpdate),
    /// Write `blob` where the column still holds `stored`, then rewrite
    /// the family index to `family_ids`.
    Write(BindingsSwap),
}

/// Inputs of the conditional bindings write.
pub(crate) struct BindingsSwap {
    /// The stored bytes the read saw: the comparand of the write.
    pub stored: String,
    /// The new encoded bindings blob.
    pub blob: String,
    /// Distinct refresh families of the new bindings.
    pub family_ids: Vec<String>,
}

/// Decide a bindings compare-and-swap from the `(trust_level, bindings)`
/// pair read for the row. The write is conditional on exactly the stored
/// bytes, so it is a compare-and-swap on the bindings column: ciphertext
/// differs on every encode, which is why the stored bytes themselves, not
/// a re-encoding of `expected`, are the comparand.
pub(crate) fn plan_bindings_swap(
    codec: &BindingsCodec,
    tenant: &str,
    device_id: &str,
    row: Option<(String, String)>,
    expected: &[DeviceBinding],
    bindings: &[DeviceBinding],
) -> Result<SwapPlan, SqlDeviceStoreError> {
    let Some((level, stored)) = row else {
        return Ok(SwapPlan::Settled(BindingsUpdate::Missing));
    };
    match trust_level_codec::from_str(&level) {
        Some(DeviceTrustLevel::Revoked) => {
            return Ok(SwapPlan::Settled(BindingsUpdate::Revoked));
        }
        Some(_) => {}
        None => return Err(SqlDeviceStoreError::UnknownTrustLevel(level)),
    }
    if codec.decode(tenant, device_id, &stored)? != expected {
        return Ok(SwapPlan::Settled(BindingsUpdate::Conflict));
    }
    Ok(SwapPlan::Write(BindingsSwap {
        blob: codec.encode(tenant, device_id, bindings)?,
        family_ids: refresh_family_ids(bindings),
        stored,
    }))
}

/// The outcome of a bindings write that matched no row, given the level a
/// re-read found: the row vanished, was revoked, or its bindings changed.
pub(crate) fn bindings_update_after_miss(current: Option<DeviceTrustLevel>) -> BindingsUpdate {
    match current {
        None => BindingsUpdate::Missing,
        Some(DeviceTrustLevel::Revoked) => BindingsUpdate::Revoked,
        Some(_) => BindingsUpdate::Conflict,
    }
}

/// The outcome of an owner claim that matched no row, given the owner a
/// re-read found. A NULL owner here would mean the row was released
/// between the two statements; it fails closed.
pub(crate) fn claim_after_miss(owner: Option<Option<String>>, user: &str) -> OwnerClaim {
    match owner {
        None => OwnerClaim::Missing,
        Some(Some(owner)) if owner == user => OwnerClaim::Claimed,
        Some(_) => OwnerClaim::OwnedByOther,
    }
}

/// Sweep thresholds as Unix seconds. Every timestamp column holds whole
/// seconds, and `SweepConfig::level_after` compares whole seconds too:
/// `now_s - last_seen_s > window_s` is `last_seen_s < now_s - window_s`, so
/// the bind-side comparison takes exactly the decision the in-memory store
/// takes, whatever the sub-second part of the instants.
pub(crate) struct SweepCutoffs {
    pub now: i64,
    pub trusted: i64,
    pub seen: i64,
    pub grace: i64,
}

impl SweepCutoffs {
    pub(crate) fn new(cfg: &SweepConfig, now: DateTime<Utc>) -> Self {
        let now = utc_to_unix(now);
        Self {
            now,
            trusted: now - cfg.trusted_idle.num_seconds(),
            seen: now - cfg.seen_idle.num_seconds(),
            grace: now - cfg.revoked_grace.num_seconds(),
        }
    }
}

/// Append the value rows of one family-index `INSERT` chunk: one
/// `(tenant, device, family)` tuple per family id.
pub(crate) fn push_family_rows<DB>(
    insert: &mut sqlx::QueryBuilder<DB>,
    chunk: &[String],
    tenant: &str,
    device_id: &str,
) where
    DB: sqlx::Database,
    for<'q> &'q str: sqlx::Encode<'q, DB> + sqlx::Type<DB>,
{
    insert.push_values(chunk, |mut row, family_id| {
        row.push_bind(tenant)
            .push_bind(device_id)
            .push_bind(family_id.as_str());
    });
}

#[cfg(test)]
mod device_sql_common_tests {
    use super::*;
    use crate::device::types::{
        AttestationClass, DeviceBinding, DeviceTrustLevel, FingerprintHash,
    };
    use chrono::Utc;

    /// line 68: `decode -> Ok(vec![])` body replacement.
    /// Discriminator: encode a non-empty bindings vector and confirm
    /// decode round-trips the same content. Mutation returns an empty
    /// Vec for any non-empty input.
    #[test]
    fn bindings_codec_round_trips_non_empty_vector() {
        let codec = BindingsCodec::plaintext();
        let now = Utc::now();
        let bindings = vec![
            DeviceBinding::Cookie {
                token_hash: FingerprintHash::from_bytes([0xAA; 32]),
                issued_at: now,
                last_used_at: now,
            },
            DeviceBinding::WebAuthn {
                credential_id: "cred-AX028".to_string(),
                attestation_class: AttestationClass::None,
                bound_at: now,
                last_used_at: now,
            },
        ];
        let encoded = codec.encode("t", "d", &bindings).expect("encode");
        let decoded = codec.decode("t", "d", &encoded).expect("decode");
        assert_eq!(
            decoded.len(),
            2,
            "decode must round-trip 2 bindings, not return empty"
        );
        assert_eq!(decoded, bindings, "round-trip must preserve content");
    }

    /// line 89: `to_str` body replacement (`""`, `"xyzzy"`).
    /// Pin every variant's wire-form value.
    #[test]
    fn trust_level_to_str_pins_variant_strings() {
        assert_eq!(
            trust_level_codec::to_str(DeviceTrustLevel::Unknown),
            "Unknown"
        );
        assert_eq!(trust_level_codec::to_str(DeviceTrustLevel::Seen), "Seen");
        assert_eq!(
            trust_level_codec::to_str(DeviceTrustLevel::Trusted),
            "Trusted"
        );
        assert_eq!(
            trust_level_codec::to_str(DeviceTrustLevel::Revoked),
            "Revoked"
        );
    }

    /// line 98 + 99-102: `from_str` body replacement and arm
    /// deletions. Each variant string must round-trip; an unknown
    /// string must yield None.
    #[test]
    fn trust_level_from_str_round_trips_each_variant() {
        assert_eq!(
            trust_level_codec::from_str("Unknown"),
            Some(DeviceTrustLevel::Unknown)
        );
        assert_eq!(
            trust_level_codec::from_str("Seen"),
            Some(DeviceTrustLevel::Seen)
        );
        assert_eq!(
            trust_level_codec::from_str("Trusted"),
            Some(DeviceTrustLevel::Trusted)
        );
        assert_eq!(
            trust_level_codec::from_str("Revoked"),
            Some(DeviceTrustLevel::Revoked)
        );
        assert_eq!(
            trust_level_codec::from_str("not-a-level"),
            None,
            "unknown input must yield None, not Some(Default)"
        );
    }

    /// A device carrying the same refresh family twice contributes it to
    /// the index once, and the order of first appearance is kept.
    #[test]
    fn refresh_family_ids_are_distinct_and_keep_first_seen_order() {
        let now = Utc::now();
        let refresh = |f: &str| DeviceBinding::Refresh {
            family_id: f.to_string(),
            issued_at: now,
            last_used_at: now,
        };
        let bindings = vec![refresh("b"), refresh("a"), refresh("b"), refresh("a")];
        assert_eq!(refresh_family_ids(&bindings), vec!["b", "a"]);
        assert!(refresh_family_ids(&[]).is_empty());
    }

    /// Belt-and-suspenders: `to_str` and `from_str` form a
    /// bijection on the four variants. Pins both directions in one go.
    #[test]
    fn trust_level_codec_is_a_bijection_on_known_variants() {
        for level in [
            DeviceTrustLevel::Unknown,
            DeviceTrustLevel::Seen,
            DeviceTrustLevel::Trusted,
            DeviceTrustLevel::Revoked,
        ] {
            let s = trust_level_codec::to_str(level);
            assert_eq!(
                trust_level_codec::from_str(s),
                Some(level),
                "{level:?} must round-trip via to_str/from_str"
            );
        }
    }
}

#[cfg(test)]
mod binding_tests;
