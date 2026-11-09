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
use crate::session::refresh::{DeviceTokenRevocation, RefreshTokenStore};
use chrono::{DateTime, Utc};

/// Why [`revoke_device`] could not finish. Either failure leaves the other
/// half done, so the call is safe to repeat.
#[derive(Debug, thiserror::Error)]
pub enum RevokeDeviceError<DE, RE>
where
    DE: std::error::Error + Send + Sync + 'static,
    RE: std::error::Error + Send + Sync + 'static,
{
    /// The device store could not mark the device revoked (a missing device
    /// is among the causes). Its tokens were revoked all the same.
    #[error("device revocation failed: {0}")]
    Device(#[source] DE),

    /// The refresh-token store failed while revoking the device's tokens.
    /// The device is marked revoked.
    #[error("revoking the device's refresh tokens failed: {0}")]
    Tokens(#[source] RE),

    /// The refresh-token store has no revoke-by-device operation (see
    /// [`RefreshTokenStore::revoke_device_tokens`]); the device is marked
    /// revoked and its tokens are untouched. Check the device on refresh
    /// with
    /// [`Refresh::device_store`](crate::session::refresh::Refresh::device_store)
    /// or implement the method.
    #[error("the refresh-token store cannot revoke tokens by device")]
    TokensUnsupported,
}

/// Revoke a device and the refresh tokens issued to it.
///
/// Marks the device [`DeviceTrustLevel::Revoked`] and then revokes every
/// token whose `device_id` is `device_id` in `tenant_id`, whatever user or
/// family it belongs to. Setting the trust level alone does neither: it
/// changes the device row and leaves its tokens refreshing. This is the one
/// call that means "revoke this device".
///
/// Both halves are attempted even if the first fails, so a device whose row
/// is already gone still has its tokens revoked, and the first failure is
/// returned. Returns the number of tokens revoked.
///
/// Sessions already issued to the device are not touched: a session ends
/// at its own expiry or when it is revoked through the session store, and
/// carries the device id (`SessionData::device_id`) for an application that
/// wants to check the device on each request.
pub async fn revoke_device<D, R>(
    device_store: &D,
    refresh_store: &R,
    tenant_id: &TenantId,
    device_id: &DeviceId,
    now: DateTime<Utc>,
) -> Result<u64, RevokeDeviceError<D::Error, R::Error>>
where
    D: DeviceStore,
    R: RefreshTokenStore,
{
    let device = device_store
        .set_trust_level(tenant_id, device_id, DeviceTrustLevel::Revoked, now)
        .await;
    let tokens = refresh_store
        .revoke_device_tokens(tenant_id, device_id)
        .await;
    device.map_err(RevokeDeviceError::Device)?;
    match tokens.map_err(RevokeDeviceError::Tokens)? {
        DeviceTokenRevocation::Revoked { tokens } => Ok(tokens),
        DeviceTokenRevocation::Unsupported => Err(RevokeDeviceError::TokensUnsupported),
    }
}

/// Transition a list of devices to [`DeviceTrustLevel::Revoked`].
///
/// Designed to be called from a refresh-token-store override of
/// [`RefreshTokenStore::on_token_compromise`].
/// Each `(tenant, device)` pair triggers an independent
/// [`DeviceStore::set_trust_level`] call; per-target failures are logged
/// at `warn` level and do not abort the overall cascade. The
/// compromise signal is treated as critical-but-best-effort, mirroring
/// how [`Refresh::run`](crate::session::refresh::Refresh::run)
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

/// Revoke each device in `targets` and the refresh tokens issued to it, as
/// [`revoke_device`] does for one. This is what to call from
/// [`RefreshTokenStore::on_token_compromise`]: it is what
/// [`CascadingRefreshStore`](crate::device::CascadingRefreshStore) runs, so a
/// store that wires it by hand revokes as much as the decorator.
///
/// A failure on one target is logged at `warn` and does not stop the others.
/// Returns the number of targets whose device and tokens were both revoked.
/// A refresh store that cannot revoke tokens
/// ([`DeviceTokenRevocation::Unsupported`]) fails every target; use
/// [`cascade_revoke_devices`] there.
pub async fn cascade_revoke_devices_and_tokens<D, R>(
    device_store: &D,
    refresh_store: &R,
    targets: &[(TenantId, DeviceId)],
    now: DateTime<Utc>,
) -> u64
where
    D: DeviceStore,
    R: RefreshTokenStore,
{
    let mut revoked = 0u64;
    for (tenant_id, device_id) in targets {
        match revoke_device(device_store, refresh_store, tenant_id, device_id, now).await {
            Ok(_) => revoked += 1,
            Err(e) => tracing::warn!(
                error = %e,
                %tenant_id,
                %device_id,
                "cascade_revoke_devices_and_tokens: per-target revoke failed; continuing"
            ),
        }
    }
    revoked
}

/// Revoke every device bound to a given refresh-token family, and only the
/// devices.
///
/// Composes [`DeviceStore::find_by_refresh_family`] +
/// [`cascade_revoke_devices`]. It marks each device
/// [`Revoked`](DeviceTrustLevel::Revoked) and nothing else: a refresh token
/// of another family bound to the same device keeps refreshing unless the
/// refresh is checked against the device
/// ([`Refresh::device_store`](crate::session::refresh::Refresh::device_store)).
/// What to wire into [`RefreshTokenStore::on_token_compromise`] is
/// [`cascade_revoke_by_refresh_family_and_tokens`], which also revokes the
/// tokens.
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

/// Revoke every device bound to a given refresh-token family, and every
/// refresh token bound to those devices.
///
/// Composes [`DeviceStore::find_by_refresh_family`] +
/// [`cascade_revoke_devices_and_tokens`]: the canonical wiring for
/// refresh-token-family compromise, called from an override of
/// [`RefreshTokenStore::on_token_compromise`] once a rotated-out refresh
/// token is detected being reused. A token of another family issued to the
/// same device is revoked with it, so the thief holding a second family on
/// the device does not keep access.
///
/// Returns `Ok(count)`, the number of devices whose row and tokens were both
/// revoked. A lookup error is propagated; a failure on one device is logged
/// and counted as a miss. A refresh store that cannot revoke by device
/// ([`DeviceTokenRevocation::Unsupported`]) fails every device; use
/// [`cascade_revoke_by_refresh_family`] there. See that function for why
/// `family_id` is a `&str`.
pub async fn cascade_revoke_by_refresh_family_and_tokens<D, R>(
    device_store: &D,
    refresh_store: &R,
    tenant_id: &TenantId,
    family_id: &str,
    now: DateTime<Utc>,
) -> Result<u64, D::Error>
where
    D: DeviceStore,
    R: RefreshTokenStore,
{
    let devices = device_store
        .find_by_refresh_family(tenant_id, family_id)
        .await?;
    let targets: Vec<(TenantId, DeviceId)> = devices.iter().map(|d| (d.tenant_id, d.id)).collect();
    Ok(cascade_revoke_devices_and_tokens(device_store, refresh_store, &targets, now).await)
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
        let now = crate::device::store::whole_second(Utc::now());
        Device {
            id: axess_identity::testing::device(id),
            tenant_id: *tenant,
            user_id: Some(axess_identity::testing::user("u")),
            trust_level: DeviceTrustLevel::Trusted,
            fingerprint_hash: FingerprintHash::from_bytes([fp; 32]),
            first_seen_at: now,
            last_seen_at: now,
            revoked_at: None,
            demoted_at: None,
            bindings: Vec::<DeviceBinding>::new(),
        }
    }

    #[tokio::test]
    async fn cascade_revokes_all_targets_and_returns_count() {
        let store = MemoryDeviceStore::new();
        let tenant = t("tenant-1");
        let dev_a = d("dev-a", 0xaa, &tenant);
        let dev_b = d("dev-b", 0xbb, &tenant);
        store.save(&dev_a, crate::device::test_now()).await.unwrap();
        store.save(&dev_b, crate::device::test_now()).await.unwrap();

        let targets = vec![(tenant, dev_a.id), (tenant, dev_b.id)];
        let now = crate::device::store::whole_second(Utc::now());
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
        store.save(&dev_a, crate::device::test_now()).await.unwrap();

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
