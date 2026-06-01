//! Cascade primitives: operations that span the device subsystem and
//! adjacent crates (refresh tokens, sessions) and revoke or invalidate
//! devices in response to upstream events.
//!
//! Lives outside the refresh-token path so a single
//! [`DeviceStore`] reference can serve every cascade trigger
//! (refresh-token-family compromise, admin-driven revocation, GDPR
//! Art 17 erasure) without each path having to plumb its own
//! `DeviceStore` generic.

use crate::authn::ids::{DeviceId, TenantId};
use crate::device::store::DeviceStore;
use crate::device::types::DeviceTrustLevel;
use chrono::{DateTime, Utc};

/// Transition a list of devices to [`DeviceTrustLevel::Revoked`].
///
/// Designed to be called from a refresh-token-store override of
/// [`RefreshTokenStore::on_token_compromise`](crate::session::refresh::RefreshTokenStore::on_token_compromise).
/// Each `(tenant, device)` pair triggers an independent
/// [`DeviceStore::set_trust_level`] call; per-target failures are logged
/// at `warn` level and do not abort the overall cascade. The
/// compromise signal is treated as critical-but-best-effort, mirroring
/// how [`refresh_session`](crate::session::refresh::refresh_session)
/// proceeds with the family revocation even if device-side gathering
/// hit an error.
///
/// Returns the count of targets the underlying [`DeviceStore`] reported
/// as successfully revoked (i.e. did not return an error). The count is
/// upper-bounded by `targets.len()` and equals it on a healthy backend.
///
/// # Idempotency
///
/// Re-revoking a device that is already
/// [`DeviceTrustLevel::Revoked`] is a no-op at the trust-level layer
/// (the store will simply re-stamp `revoked_at`). Idempotency at the
/// audit-event level (do not emit duplicate `DeviceRevoked` events) is
/// the responsibility of the audit-event integration.
pub async fn cascade_revoke_devices<D: DeviceStore>(
    device_store: &D,
    targets: &[(TenantId, DeviceId)],
    now: DateTime<Utc>,
) -> u64 {
    let mut revoked = 0u64;
    for (tenant_id, device_id) in targets {
        match device_store
            .set_trust_level(tenant_id, device_id, DeviceTrustLevel::Revoked, now)
            .await
        {
            Ok(()) => revoked += 1,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    %tenant_id,
                    %device_id,
                    "cascade_revoke_devices: per-target revoke failed; continuing"
                );
            }
        }
    }
    revoked
}

/// Revoke every device bound to a given refresh-token family.
///
/// Composes [`DeviceStore::find_by_refresh_family`] +
/// [`cascade_revoke_devices`]: the canonical wiring for refresh-token-
/// family compromise. Designed to be called from a
/// [`RefreshTokenStore`](crate::session::refresh::RefreshTokenStore)
/// override of `on_token_compromise` (or equivalent application hook)
/// once a rotated-out refresh token is detected being reused.
///
/// Returns `Ok(count)` where `count` is the number of devices the
/// underlying [`DeviceStore`] reported as successfully revoked. Errors
/// from the lookup are propagated; errors from individual revoke calls
/// are logged and counted as misses (same best-effort semantic as
/// [`cascade_revoke_devices`]).
///
/// `family_id` is `&str` rather than
/// [`TokenFamilyId`](crate::session::refresh::TokenFamilyId) to keep
/// the device subsystem free of a refresh-token-store import. Callers
/// convert via `family_id.to_string().as_str()` or similar.
pub async fn cascade_revoke_by_refresh_family<D: DeviceStore>(
    device_store: &D,
    tenant_id: &TenantId,
    family_id: &str,
    now: DateTime<Utc>,
) -> Result<u64, D::Error> {
    let devices = device_store
        .find_by_refresh_family(tenant_id, family_id)
        .await?;
    let targets: Vec<(TenantId, DeviceId)> = devices.iter().map(|d| (d.tenant_id, d.id)).collect();
    Ok(cascade_revoke_devices(device_store, &targets, now).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::store::MemoryDeviceStore;
    use crate::device::types::{Device, DeviceBinding, FingerprintHash};

    fn t(s: &str) -> TenantId {
        axess_identity::testing::tenant(s)
    }

    fn d(id: &str, fp: u8, tenant: &TenantId) -> Device {
        let now = Utc::now();
        Device {
            id: axess_identity::testing::device(id),
            tenant_id: *tenant,
            user_id: Some(axess_identity::testing::user("u")),
            trust_level: DeviceTrustLevel::Trusted,
            fingerprint_hash: FingerprintHash::from_bytes([fp; 32]),
            first_seen_at: now,
            last_seen_at: now,
            revoked_at: None,
            bindings: Vec::<DeviceBinding>::new(),
        }
    }

    #[tokio::test]
    async fn cascade_revokes_all_targets_and_returns_count() {
        let store = MemoryDeviceStore::new();
        let tenant = t("tenant-1");
        let dev_a = d("dev-a", 0xaa, &tenant);
        let dev_b = d("dev-b", 0xbb, &tenant);
        store.save(&dev_a).await.unwrap();
        store.save(&dev_b).await.unwrap();

        let targets = vec![(tenant, dev_a.id), (tenant, dev_b.id)];
        let now = Utc::now();
        let count = cascade_revoke_devices(&store, &targets, now).await;
        assert_eq!(count, 2);

        let after_a = store.load(&tenant, &dev_a.id).await.unwrap().unwrap();
        let after_b = store.load(&tenant, &dev_b.id).await.unwrap().unwrap();
        assert_eq!(after_a.trust_level, DeviceTrustLevel::Revoked);
        assert_eq!(after_b.trust_level, DeviceTrustLevel::Revoked);
        assert_eq!(after_a.revoked_at, Some(now));
        assert_eq!(after_b.revoked_at, Some(now));
    }

    #[tokio::test]
    async fn cascade_skips_unknown_devices_without_aborting() {
        // The store has dev-a but not dev-b. The cascade must revoke
        // dev-a and log+continue past dev-b.
        let store = MemoryDeviceStore::new();
        let tenant = t("tenant-1");
        let dev_a = d("dev-a", 0xaa, &tenant);
        store.save(&dev_a).await.unwrap();

        let targets = vec![
            (tenant, dev_a.id),
            (tenant, axess_identity::testing::device("dev-missing")),
        ];
        let count = cascade_revoke_devices(&store, &targets, Utc::now()).await;
        assert_eq!(count, 1, "only dev-a was actually present in the store");

        let after_a = store.load(&tenant, &dev_a.id).await.unwrap().unwrap();
        assert_eq!(after_a.trust_level, DeviceTrustLevel::Revoked);
    }

    #[tokio::test]
    async fn cascade_handles_empty_target_list() {
        let store = MemoryDeviceStore::new();
        let count = cascade_revoke_devices::<MemoryDeviceStore>(&store, &[], Utc::now()).await;
        assert_eq!(count, 0);
    }
}
