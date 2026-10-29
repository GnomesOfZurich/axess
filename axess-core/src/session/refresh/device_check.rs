//! Refreshing a session only while the device the token was issued to is
//! still trusted.

use super::rotation::{config_for, locate, refresh_session_from_record};
use super::store::RefreshTokenStore;
use super::types::{RefreshError, RefreshToken, RefreshTokenConfig};
use crate::device::{DeviceStore, DeviceTrustLevel};
use crate::session::data::SessionData;
use axess_rng::SecureRng;
use chrono::{DateTime, Utc};

/// [`refresh_session`](super::refresh_session) that first checks the device
/// the token was issued to.
///
/// A token carries the id of its device (`RefreshToken::device_id`). When it
/// has one, the device is loaded from `device_store` before anything is
/// rotated, and the refresh is refused with [`RefreshError::DeviceRevoked`]
/// when the device is `Revoked` or no longer exists (the retention sweep
/// purges revoked rows, so a purged device is a revoked one). A token with no
/// device id is refreshed as [`refresh_session`](super::refresh_session)
/// would.
///
/// This closes the gap that setting a device's trust level leaves open:
/// [`set_trust_level`](crate::device::DeviceStore::set_trust_level) changes
/// the device row and touches no token, so a lost device's tokens keep
/// refreshing until something revokes them.
/// [`revoke_device`](crate::device::revoke_device) revokes the device and its
/// tokens together; this check is the second line for tokens that
/// escaped it, and the only one for a store that cannot revoke by device.
/// It costs one device-store read per refresh, so put a
/// [`CachedDeviceStore`](crate::device::CachedDeviceStore) in front of a slow
/// store.
///
/// A token that is already revoked skips the device check and goes through
/// the ordinary path, so reuse of a rotated-out token still revokes its
/// family. When the device store cannot answer, the refresh fails with
/// [`RefreshError::DeviceStore`]: the check does not fail open.
pub async fn refresh_session_with_device_check<S: RefreshTokenStore, D: DeviceStore>(
    plaintext: &str,
    store: &S,
    config: &RefreshTokenConfig,
    rng: &impl SecureRng,
    now: DateTime<Utc>,
    device_info: Option<&str>,
    device_store: &D,
) -> Result<(SessionData, Option<(String, RefreshToken)>), RefreshError<S::Error>> {
    config.check()?;
    let found = locate(plaintext, store, config)
        .await
        .map_err(RefreshError::Store)?
        .ok_or(RefreshError::NotFound)?;
    let config = &*config_for(config, &found);
    let record = found.record;

    if !record.revoked
        && let Some(device_id) = record.device_id.as_ref()
    {
        match device_store.load(&record.tenant_id, device_id).await {
            Ok(Some(device)) if device.trust_level != DeviceTrustLevel::Revoked => {}
            Ok(_) => return Err(RefreshError::DeviceRevoked),
            Err(error) => return Err(RefreshError::DeviceStore(error.to_string())),
        }
    }

    // The untenanted path, like `refresh_session`: a tenant rail is the
    // `_in_tenant` family's job.
    refresh_session_from_record(record, store, config, rng, now, device_info, None).await
}
