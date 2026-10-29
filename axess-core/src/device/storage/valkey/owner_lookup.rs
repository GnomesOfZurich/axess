//! The lookup of one user's device by fingerprint.
//!
//! A request from an identified user asks for the device that user owns with
//! the request's fingerprint. Reading the user's whole index to answer it
//! decrypts every device they have; the per-(tenant, fingerprint, user) set
//! lists only the devices that can match, which is usually one.

use fred::prelude::*;

use super::row::{fingerprint_hex, fingerprint_user_key, user_index_key};
use super::{ValkeyDeviceStore, ValkeyDeviceStoreError};
use crate::authn::ids::UserId;
use crate::device::store::order_newest_first;
use crate::device::types::{Device, FingerprintHash};

impl ValkeyDeviceStore {
    /// The newest device `user` owns with fingerprint `hash`.
    ///
    /// The per-user fingerprint set is read first. A row written before that
    /// set existed is listed only in the user's own index, so when the set
    /// yields nothing the user's index is read once as well, and what it finds
    /// is added to the set, so the next lookup is served by the set alone.
    pub(super) async fn find_owned_by_fingerprint(
        &self,
        tenant: &str,
        user: &UserId,
        hash: &FingerprintHash,
    ) -> Result<Option<Device>, ValkeyDeviceStoreError> {
        let hex = fingerprint_hex(hash);
        let user_s = user.to_string();
        let set_key = fingerprint_user_key(&self.prefix, tenant, &hex, &user_s);
        let matches = |d: &Device| d.user_id.as_ref() == Some(user) && d.fingerprint_hash == *hash;

        let listed = self.read_index(&set_key, tenant, matches).await?;
        if let Some(best) = listed.into_iter().min_by(order_newest_first) {
            return Ok(Some(best));
        }

        // Not listed: devices written by an earlier release are in the user's
        // index only. This runs when the user has no device with this
        // fingerprint yet (the caller is about to create one) or has one the
        // set does not list yet.
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
        Ok(found.into_iter().min_by(order_newest_first))
    }
}
