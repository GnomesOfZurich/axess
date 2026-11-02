//! The lookup of one user's device by fingerprint.
//!
//! A request from an identified user asks for the device that user owns with
//! the request's fingerprint. Reading the user's whole index to answer it
//! decrypts every device they have; the per-(tenant, fingerprint, user) set
//! lists only the devices that can match, which is usually one. A miss is
//! answered from the set alone, as a miss is what every first sighting of a
//! device is; the user's index is read as a fallback only while the store
//! is told to read the layouts of earlier releases, which kept no such set.

use fred::prelude::*;

use super::row::{fingerprint_hex, fingerprint_user_key, user_index_key};
use super::{ValkeyDeviceStore, ValkeyDeviceStoreError};
use crate::authn::ids::UserId;
use crate::device::types::{Device, FingerprintHash};

impl ValkeyDeviceStore {
    /// The devices `user` owns with fingerprint `hash` that `keep` accepts,
    /// in no particular order.
    ///
    /// The per-user fingerprint set is read first. A row written before that
    /// set existed is listed only in the user's own index, so while the store
    /// reads the layouts of earlier releases, a set that yields nothing has
    /// the user's index read once as well (every device they own), and what
    /// it finds is added to the set, so the next lookup is served by the set
    /// alone. Otherwise a miss is a miss, and reads nothing more.
    pub(super) async fn owned_with_fingerprint(
        &self,
        tenant: &str,
        user: &UserId,
        hash: &FingerprintHash,
        keep: impl Fn(&Device) -> bool,
    ) -> Result<Vec<Device>, ValkeyDeviceStoreError> {
        let hex = fingerprint_hex(hash);
        let user_s = user.to_string();
        let set_key = fingerprint_user_key(&self.prefix, tenant, &hex, &user_s);
        let matches = |d: &Device| d.user_id.as_ref() == Some(user) && d.fingerprint_hash == *hash;

        let listed = self.read_index(&set_key, tenant, matches).await?;
        if !listed.is_empty() {
            return Ok(listed.into_iter().filter(|d| keep(d)).collect());
        }

        // Not listed: the user has no device with this fingerprint yet (the
        // caller is about to create one), or has one written by an earlier
        // release, which is in the user's index only. The index is every
        // device the user owns, so it is read only while the store is told
        // to read the earlier layouts, for the transition after an upgrade.
        if !self.legacy_fingerprint_keys {
            return Ok(Vec::new());
        }
        let idx = user_index_key(&self.prefix, tenant, &user_s);
        let owned = self
            .read_index(&idx, tenant, |d| d.user_id.as_ref() == Some(user))
            .await?;
        let found: Vec<Device> = owned.into_iter().filter(|d| matches(d)).collect();
        for device in &found {
            let added: Result<i64, _> = self.client.sadd(&set_key, device.id.to_string()).await;
            if let Err(e) = added {
                tracing::warn!(error = %e, "per-user fingerprint index not backfilled");
            }
        }
        Ok(found.into_iter().filter(|d| keep(d)).collect())
    }
}
