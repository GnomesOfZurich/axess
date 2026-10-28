//! The key schema and the row codec of the Valkey device store.

use chrono::{DateTime, Utc};

use super::policy::ttl_seconds;
use super::{ValkeyDeviceStore, ValkeyDeviceStoreError};
use crate::device::types::{Device, FingerprintHash};
use crate::session::crypto::{BoundFormat, device_row_id, device_row_id_v1};

pub(super) fn device_key(prefix: &str, tenant: &str, id: &str) -> String {
    format!("{prefix}:dev:{tenant}:{id}")
}

/// The single-id string key earlier releases pointed at one device with.
/// It is read when present and removed by the next write of the device it
/// names; nothing creates it any more.
pub(super) fn fingerprint_key(prefix: &str, tenant: &str, hex_hash: &str) -> String {
    format!("{prefix}:dev:fp:{tenant}:{hex_hash}")
}

/// The set of ids of the devices that carry a fingerprint.
pub(super) fn fingerprint_set_key(prefix: &str, tenant: &str, hex_hash: &str) -> String {
    format!("{prefix}:dev:fps:{tenant}:{hex_hash}")
}

pub(super) fn user_index_key(prefix: &str, tenant: &str, user: &str) -> String {
    format!("{prefix}:dev:user:{tenant}:{user}")
}

pub(super) fn family_index_key(prefix: &str, tenant: &str, family: &str) -> String {
    format!("{prefix}:dev:fam:{tenant}:{family}")
}

pub(super) fn tenant_index_key(prefix: &str, tenant: &str) -> String {
    format!("{prefix}:dev:tenant:{tenant}")
}

/// Convert a [`FingerprintHash`] to its 64-char hex representation.
pub(super) fn fingerprint_hex(h: &FingerprintHash) -> String {
    use std::fmt::Write as _;
    let bytes = h.as_bytes();
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(s, "{:02x}", b).expect("writing into a String never fails");
    }
    s
}

impl ValkeyDeviceStore {
    /// Choose whether sealed rows written before row binding (no format
    /// marker) are read; see [`LegacyBlobs`](crate::session::crypto::LegacyBlobs).
    /// The default reads them and every write seals the current format. Has
    /// no effect on a plaintext store.
    pub fn with_legacy_blobs(mut self, policy: crate::session::crypto::LegacyBlobs) -> Self {
        self.crypto = self.crypto.map(|c| c.with_legacy_blobs(policy));
        self
    }

    /// Native TTL for a row; `None` means the row never expires.
    pub(super) fn ttl_seconds_for(&self, device: &Device, now: DateTime<Utc>) -> Option<i64> {
        ttl_seconds(&self.sweep_config, device, now)
    }

    /// Encode a `Device` for storage: msgpack the row, then optionally
    /// seal it with AES-256-GCM bound to the row's tenant and device id.
    /// Valkey's binary-safe values store the bytes directly; no base64 hop.
    ///
    /// A sealed row is `AXR 0x02 || nonce(12) || ciphertext+tag` with AAD
    /// `"axess.device-row.v2" || 0x00 || len(tenant_id) || tenant_id ||
    /// len(device_id) || device_id` (each length a big-endian `u32`), so a
    /// row copied under another device's key fails authentication and two
    /// different id pairs can never produce the same AAD. The 0.11.0 form
    /// (`AXR 0x01`, ids joined by a zero byte) is still read, and a blob
    /// without any marker predates binding and is read under the empty AAD
    /// unless the store's crypto was set to reject such blobs; every write
    /// seals the current form, and so does a read that finds an older form (a
    /// conditional write of the exact bytes it read), so the older forms age
    /// out as devices are written or read. A plaintext store has nothing to bind.
    pub(super) fn encode_row(&self, device: &Device) -> Result<Vec<u8>, ValkeyDeviceStoreError> {
        let bytes = rmp_serde::to_vec_named(device)?;
        match &self.crypto {
            Some(c) => Ok(c.seal_bound(
                BoundFormat::DEVICE_ROW,
                &device_row_id(&device.tenant_id.to_string(), &device.id.to_string()),
                &bytes,
            )?),
            None => Ok(bytes),
        }
    }

    /// Decode the row stored under `(tenant, id)`.
    #[cfg(test)]
    pub(super) fn decode_row(
        &self,
        tenant: &str,
        id: &str,
        payload: &[u8],
    ) -> Result<Device, ValkeyDeviceStoreError> {
        self.decode_row_checked(tenant, id, payload)
            .map(|(device, _)| device)
    }

    /// Like [`decode_row`](Self::decode_row), and also reports whether the
    /// stored bytes are in an older format than the one a write seals, so a
    /// reader can re-seal them. A plaintext store is never stale.
    pub(super) fn decode_row_checked(
        &self,
        tenant: &str,
        id: &str,
        payload: &[u8],
    ) -> Result<(Device, bool), ValkeyDeviceStoreError> {
        let (plaintext, stale) = match &self.crypto {
            Some(c) => {
                let opened = c.open_bound(
                    BoundFormat::DEVICE_ROW,
                    &device_row_id(tenant, id),
                    &[(BoundFormat::DEVICE_ROW_V1, device_row_id_v1(tenant, id))],
                    payload,
                )?;
                (opened.plaintext, opened.stale)
            }
            None => (payload.to_vec(), false),
        };
        Ok((rmp_serde::from_slice(&plaintext)?, stale))
    }
}
