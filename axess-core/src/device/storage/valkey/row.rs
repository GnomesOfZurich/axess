//! The key schema and the row codec of the Valkey device store.

use chrono::{DateTime, Utc};

use super::policy::ttl_seconds;
use super::{ValkeyDeviceStore, ValkeyDeviceStoreError};
use crate::device::types::{Device, FingerprintHash};
use crate::session::crypto::BoundFormat;

pub(super) fn device_key(prefix: &str, tenant: &str, id: &str) -> String {
    format!("{prefix}:dev:{tenant}:{id}")
}

/// Row identity authenticated into a sealed device row.
pub(super) fn row_id(tenant: &str, id: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(tenant.len() + 1 + id.len());
    out.extend_from_slice(tenant.as_bytes());
    out.push(0);
    out.extend_from_slice(id.as_bytes());
    out
}

pub(super) fn fingerprint_key(prefix: &str, tenant: &str, hex_hash: &str) -> String {
    format!("{prefix}:dev:fp:{tenant}:{hex_hash}")
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
    /// Native TTL for a row; `None` means the row never expires.
    pub(super) fn ttl_seconds_for(&self, device: &Device, now: DateTime<Utc>) -> Option<i64> {
        ttl_seconds(&self.sweep_config, device, now)
    }

    /// Encode a `Device` for storage: msgpack the row, then optionally
    /// seal it with AES-256-GCM bound to the row's tenant and device id.
    /// Valkey's binary-safe values store the bytes directly; no base64 hop.
    ///
    /// A sealed row is `AXR 0x01 || nonce(12) || ciphertext+tag` with AAD
    /// `"axess.device-row.v1" || 0x00 || tenant_id || 0x00 || device_id`, so
    /// a row copied under another device's key fails authentication. A
    /// stored blob without the marker predates binding: it is still read
    /// (under the empty AAD) and every write seals the bound form, so the
    /// legacy form ages out as devices are written. A plaintext store has
    /// nothing to bind.
    pub(super) fn encode_row(&self, device: &Device) -> Result<Vec<u8>, ValkeyDeviceStoreError> {
        let bytes = rmp_serde::to_vec_named(device)?;
        match &self.crypto {
            Some(c) => Ok(c.seal_bound(
                BoundFormat::DEVICE_ROW,
                &row_id(&device.tenant_id.to_string(), &device.id.to_string()),
                &bytes,
            )?),
            None => Ok(bytes),
        }
    }

    /// Decode the row stored under `(tenant, id)`.
    pub(super) fn decode_row(
        &self,
        tenant: &str,
        id: &str,
        payload: &[u8],
    ) -> Result<Device, ValkeyDeviceStoreError> {
        let plaintext = match &self.crypto {
            Some(c) => {
                let opened = c.open_bound(BoundFormat::DEVICE_ROW, &row_id(tenant, id), payload)?;
                if opened.legacy {
                    tracing::debug!("device row predates row binding; re-sealed on next write");
                }
                opened.plaintext
            }
            None => payload.to_vec(),
        };
        Ok(rmp_serde::from_slice(&plaintext)?)
    }
}
