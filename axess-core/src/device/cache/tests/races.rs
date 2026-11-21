//! Interleavings between a cached read and a write, built
//! deterministically with a store that runs a hook inside the window.

use super::*;
use crate::device::store::MemoryDeviceStore;
use crate::device::types::{Device, FingerprintHash};
use axess_clock::Timestamp;
use axess_clock::testing::MockClock;
use axess_clock::testing::Shift;
use std::pin::Pin;
use std::sync::Mutex;

type Hook = Box<dyn FnOnce() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send>;

/// Wraps a memory store; each hook fires once, right before the write
/// reaches storage (`before_write`) or right after a load has read its
/// row but before it returns (`after_load`).
#[derive(Clone, Default)]
struct HookedStore {
    inner: MemoryDeviceStore,
    before_write: Arc<Mutex<Option<Hook>>>,
    after_load: Arc<Mutex<Option<Hook>>>,
    /// Fires once, right after a trust-level write has reached storage.
    after_write: Arc<Mutex<Option<Hook>>>,
}

async fn fire(slot: &Mutex<Option<Hook>>) {
    let hook = slot.lock().unwrap().take();
    if let Some(h) = hook {
        h().await;
    }
}

impl DeviceStore for HookedStore {
    type Error = <MemoryDeviceStore as DeviceStore>::Error;

    async fn load_fresh(&self, t: &TenantId, id: &DeviceId) -> Result<Option<Device>, Self::Error> {
        self.inner.load_fresh(t, id).await
    }

    async fn load(&self, t: &TenantId, id: &DeviceId) -> Result<Option<Device>, Self::Error> {
        let row = self.inner.load(t, id).await?;
        fire(&self.after_load).await;
        Ok(row)
    }
    fn find_by_fingerprint(
        &self,
        t: &TenantId,
        h: &FingerprintHash,
    ) -> impl Future<Output = Result<Option<Device>, Self::Error>> + Send {
        self.inner.find_by_fingerprint(t, h)
    }
    fn find_for_user(
        &self,
        t: &TenantId,
        u: &UserId,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<Device>, Self::Error>> + Send {
        self.inner.find_for_user(t, u, limit)
    }
    fn find_by_refresh_family(
        &self,
        t: &TenantId,
        f: &str,
    ) -> impl Future<Output = Result<Vec<Device>, Self::Error>> + Send {
        self.inner.find_by_refresh_family(t, f)
    }
    async fn save(&self, d: &Device, now: Timestamp) -> Result<(), Self::Error> {
        fire(&self.before_write).await;
        self.inner.save(d, now).await
    }
    async fn create_or_find(&self, d: &Device, now: Timestamp) -> Result<Device, Self::Error> {
        fire(&self.before_write).await;
        self.inner.create_or_find(d, now).await
    }
    fn record_sighting(
        &self,
        t: &TenantId,
        id: &DeviceId,
        now: Timestamp,
    ) -> impl Future<Output = Result<DeviceTrustLevel, Self::Error>> + Send {
        self.inner.record_sighting(t, id, now)
    }
    async fn set_trust_level(
        &self,
        t: &TenantId,
        id: &DeviceId,
        level: DeviceTrustLevel,
        now: Timestamp,
    ) -> Result<(), Self::Error> {
        fire(&self.before_write).await;
        let result = self.inner.set_trust_level(t, id, level, now).await;
        fire(&self.after_write).await;
        result
    }
    async fn set_trust_level_if(
        &self,
        t: &TenantId,
        id: &DeviceId,
        expected: DeviceTrustLevel,
        level: DeviceTrustLevel,
        now: Timestamp,
    ) -> Result<crate::device::store::TrustTransition, Self::Error> {
        fire(&self.before_write).await;
        let result = self
            .inner
            .set_trust_level_if(t, id, expected, level, now)
            .await;
        fire(&self.after_write).await;
        result
    }
    async fn claim_owner(
        &self,
        t: &TenantId,
        id: &DeviceId,
        user: &UserId,
        now: Timestamp,
    ) -> Result<crate::device::store::OwnerClaim, Self::Error> {
        fire(&self.before_write).await;
        self.inner.claim_owner(t, id, user, now).await
    }
    async fn replace_bindings(
        &self,
        t: &TenantId,
        id: &DeviceId,
        expected: &[crate::device::types::DeviceBinding],
        bindings: &[crate::device::types::DeviceBinding],
        now: Timestamp,
    ) -> Result<crate::device::store::BindingsUpdate, Self::Error> {
        fire(&self.before_write).await;
        self.inner
            .replace_bindings(t, id, expected, bindings, now)
            .await
    }
    async fn delete(&self, t: &TenantId, id: &DeviceId) -> Result<(), Self::Error> {
        fire(&self.before_write).await;
        self.inner.delete(t, id).await
    }
    fn sweep(
        &self,
        t: &TenantId,
        now: Timestamp,
    ) -> impl Future<Output = Result<SweepCounts, Self::Error>> + Send {
        self.inner.sweep(t, now)
    }
}

fn now() -> Timestamp {
    Timestamp::from_utc(2026, 1, 1, 0, 0, 0).unwrap()
}

fn device(level: DeviceTrustLevel) -> Device {
    Device {
        id: crate::authn::ids::testing::device("device-1"),
        tenant_id: crate::authn::ids::testing::tenant("tenant-1"),
        user_id: Some(crate::authn::ids::testing::user("user-1")),
        trust_level: level,
        fingerprint_hash: FingerprintHash::from_bytes([1u8; 32]),
        first_seen_at: now(),
        last_seen_at: now(),
        revoked_at: None,
        demoted_at: None,
        bindings: Vec::new(),
    }
}

/// Cached store over a `HookedStore` holding one Trusted device.
async fn setup() -> (CachedDeviceStore<HookedStore>, HookedStore, Device) {
    setup_holding(device(DeviceTrustLevel::Trusted)).await
}

/// Cached store over a `HookedStore` holding `d`.
async fn setup_holding(d: Device) -> (CachedDeviceStore<HookedStore>, HookedStore, Device) {
    let hooked = HookedStore::default();
    hooked
        .inner
        .save(&d, crate::device::test_now())
        .await
        .unwrap();
    let cached =
        CachedDeviceStore::new(hooked.clone()).with_clock(Arc::new(MockClock::at(now())) as _);
    (cached, hooked, d)
}

/// Hook: a concurrent reader loads the device through the cache.
fn reader(cached: &CachedDeviceStore<HookedStore>, d: &Device) -> Hook {
    let (c, t, id) = (cached.clone(), d.tenant_id, d.id);
    Box::new(move || {
        Box::pin(async move {
            drop(c.load(&t, &id).await.unwrap());
        })
    })
}

#[tokio::test]
async fn set_trust_level_revocation_is_not_undone_by_a_load_during_the_write() {
    let (cached, hooked, d) = setup().await;
    *hooked.before_write.lock().unwrap() = Some(reader(&cached, &d));
    cached
        .set_trust_level(&d.tenant_id, &d.id, DeviceTrustLevel::Revoked, now())
        .await
        .unwrap();
    let seen = cached.load(&d.tenant_id, &d.id).await.unwrap().unwrap();
    assert_eq!(seen.trust_level, DeviceTrustLevel::Revoked);
}

#[tokio::test]
async fn save_is_not_undone_by_a_load_during_the_write() {
    let (cached, hooked, d) = setup().await;
    *hooked.before_write.lock().unwrap() = Some(reader(&cached, &d));
    let mut revoked = d.clone();
    revoked.trust_level = DeviceTrustLevel::Revoked;
    cached
        .save(&revoked, crate::device::test_now())
        .await
        .unwrap();
    let seen = cached.load(&d.tenant_id, &d.id).await.unwrap().unwrap();
    assert_eq!(seen.trust_level, DeviceTrustLevel::Revoked);
}

#[tokio::test]
async fn delete_is_not_undone_by_a_load_during_the_write() {
    let (cached, hooked, d) = setup().await;
    *hooked.before_write.lock().unwrap() = Some(reader(&cached, &d));
    cached.delete(&d.tenant_id, &d.id).await.unwrap();
    assert!(cached.load(&d.tenant_id, &d.id).await.unwrap().is_none());
}

// The conditional writes, each raced the same way: a load that lands while
// the write is under way caches the row as it was, and the write's
// invalidation, which comes after the write, drops it again.

#[tokio::test]
async fn a_conditional_trust_change_is_not_undone_by_a_load_during_the_write() {
    use crate::device::store::TrustTransition;
    let (cached, hooked, d) = setup().await;
    *hooked.before_write.lock().unwrap() = Some(reader(&cached, &d));
    let changed = cached
        .set_trust_level_if(
            &d.tenant_id,
            &d.id,
            DeviceTrustLevel::Trusted,
            DeviceTrustLevel::Revoked,
            now(),
        )
        .await
        .unwrap();
    assert_eq!(changed, TrustTransition::Applied);
    let seen = cached.load(&d.tenant_id, &d.id).await.unwrap().unwrap();
    assert_eq!(seen.trust_level, DeviceTrustLevel::Revoked);
}

#[tokio::test]
async fn a_bindings_swap_is_not_undone_by_a_load_during_the_write() {
    use crate::device::store::BindingsUpdate;
    use crate::device::types::DeviceBinding;
    let (cached, hooked, d) = setup().await;
    *hooked.before_write.lock().unwrap() = Some(reader(&cached, &d));
    let bound = vec![DeviceBinding::Refresh {
        family_id: "family-1".into(),
        issued_at: now(),
        last_used_at: now(),
    }];
    let swapped = cached
        .replace_bindings(&d.tenant_id, &d.id, &[], &bound, now())
        .await
        .unwrap();
    assert_eq!(swapped, BindingsUpdate::Written);
    let seen = cached.load(&d.tenant_id, &d.id).await.unwrap().unwrap();
    assert_eq!(seen.bindings, bound);
}

#[tokio::test]
async fn an_owner_claim_is_not_undone_by_a_load_during_the_write() {
    use crate::device::store::OwnerClaim;
    let unowned = Device {
        user_id: None,
        ..device(DeviceTrustLevel::Seen)
    };
    let (cached, hooked, d) = setup_holding(unowned).await;
    *hooked.before_write.lock().unwrap() = Some(reader(&cached, &d));
    let user = crate::authn::ids::testing::user("user-2");
    let claimed = cached
        .claim_owner(&d.tenant_id, &d.id, &user, now())
        .await
        .unwrap();
    assert_eq!(claimed, OwnerClaim::Claimed);
    let seen = cached.load(&d.tenant_id, &d.id).await.unwrap().unwrap();
    assert_eq!(seen.user_id, Some(user));
}

/// A create that finds no live device of its fingerprint and owner writes
/// its row, here over the device's earlier row under another fingerprint.
#[tokio::test]
async fn a_create_is_not_undone_by_a_load_during_the_write() {
    let (cached, hooked, d) = setup().await;
    *hooked.before_write.lock().unwrap() = Some(reader(&cached, &d));
    let refingerprinted = Device {
        fingerprint_hash: FingerprintHash::from_bytes([2u8; 32]),
        ..d.clone()
    };
    let created = cached
        .create_or_find(&refingerprinted, crate::device::test_now())
        .await
        .unwrap();
    assert_eq!(created.fingerprint_hash, refingerprinted.fingerprint_hash);
    let seen = cached.load(&d.tenant_id, &d.id).await.unwrap().unwrap();
    assert_eq!(seen.fingerprint_hash, refingerprinted.fingerprint_hash);
}

/// The load reads the Trusted row, then a full revocation lands before the
/// load returns. The stale row must not be promoted into the cache.
#[tokio::test]
async fn load_in_flight_across_a_revocation_does_not_cache_the_old_row() {
    let (cached, hooked, d) = setup().await;
    let (c, t, id) = (cached.clone(), d.tenant_id, d.id);
    *hooked.after_load.lock().unwrap() = Some(Box::new(move || {
        Box::pin(async move {
            c.set_trust_level(&t, &id, DeviceTrustLevel::Revoked, now())
                .await
                .unwrap();
        })
    }));
    drop(cached.load(&d.tenant_id, &d.id).await.unwrap());
    let seen = cached.load(&d.tenant_id, &d.id).await.unwrap().unwrap();
    assert_eq!(seen.trust_level, DeviceTrustLevel::Revoked);
}

#[tokio::test]
async fn sweep_drops_cached_rows_of_the_tenant() {
    let hooked = HookedStore {
        inner: MemoryDeviceStore::new().with_sweep_config(
            crate::device::store::SweepConfig::builder()
                .trusted_idle(std::time::Duration::from_hours(24))
                .build()
                .unwrap(),
        ),
        ..HookedStore::default()
    };
    let d = device(DeviceTrustLevel::Trusted);
    hooked
        .inner
        .save(&d, crate::device::test_now())
        .await
        .unwrap();
    let cached = CachedDeviceStore::new(hooked).with_clock(Arc::new(MockClock::at(now())) as _);
    drop(cached.load(&d.tenant_id, &d.id).await.unwrap());

    let later = now().plus(axess_clock::SignedDuration::days(2));
    let counts = cached.sweep(&d.tenant_id, later).await.unwrap();
    assert_eq!(counts.trusted_to_seen, 1);
    let seen = cached.load(&d.tenant_id, &d.id).await.unwrap().unwrap();
    assert_eq!(seen.trust_level, DeviceTrustLevel::Seen);
}

/// `with_clock` after `with_ttl` must keep the TTL: an entry outlives a
/// shorter window and is gone after the configured one.
#[tokio::test]
async fn builders_keep_each_others_settings() {
    let clock = Arc::new(MockClock::at(now()));
    let hooked = HookedStore::default();
    let d = device(DeviceTrustLevel::Trusted);
    hooked
        .inner
        .save(&d, crate::device::test_now())
        .await
        .unwrap();
    let cached = CachedDeviceStore::new(hooked)
        .with_ttl(Duration::from_secs(5))
        .with_capacity(7)
        .with_clock(clock.clone() as _);
    drop(cached.load(&d.tenant_id, &d.id).await.unwrap());
    clock.advance_secs(3);
    drop(cached.load(&d.tenant_id, &d.id).await.unwrap());
    assert_eq!(cached.stats().hits, 1, "entry lives within the 5 s TTL");
    clock.advance_secs(3);
    drop(cached.load(&d.tenant_id, &d.id).await.unwrap());
    assert_eq!(cached.stats().hits, 1, "entry expires after the 5 s TTL");
}

/// The conditional writes drop the cached row like every other write, so
/// the next load sees the new state rather than a cached Trusted one.
#[tokio::test]
async fn conditional_writes_invalidate_the_cached_row() {
    use crate::device::store::{BindingsUpdate, TrustTransition};
    let (cached, _, d) = setup().await;
    let (t, id) = (d.tenant_id, d.id);
    assert_eq!(
        cached.load(&t, &id).await.unwrap().unwrap().trust_level,
        DeviceTrustLevel::Trusted
    );

    let got = cached
        .set_trust_level_if(
            &t,
            &id,
            DeviceTrustLevel::Trusted,
            DeviceTrustLevel::Revoked,
            now(),
        )
        .await
        .unwrap();
    assert_eq!(got, TrustTransition::Applied);
    assert_eq!(
        cached.load(&t, &id).await.unwrap().unwrap().trust_level,
        DeviceTrustLevel::Revoked,
        "a cached Trusted row must not outlive the revocation"
    );
    assert_eq!(
        cached
            .replace_bindings(&t, &id, &[], &[], crate::device::test_now())
            .await
            .unwrap(),
        BindingsUpdate::Revoked
    );
}

/// A revocation whose future is dropped after the store committed it (a
/// request cancelled, a timeout) still drops the cached row: without the
/// drop guard the cache would keep serving the Trusted row for a full TTL
/// although the device is revoked in storage. A load also lands while the
/// write is under way, so the row it caches then is dropped too: the guard
/// is dropped with the cancelled future, after the write, not before it.
#[tokio::test]
async fn a_revocation_cancelled_after_the_write_still_drops_the_cached_row() {
    let (cached, hooked, d) = setup().await;
    assert_eq!(
        cached
            .load(&d.tenant_id, &d.id)
            .await
            .unwrap()
            .unwrap()
            .trust_level,
        DeviceTrustLevel::Trusted,
        "the Trusted row is cached"
    );
    *hooked.before_write.lock().unwrap() = Some(reader(&cached, &d));
    *hooked.after_write.lock().unwrap() = Some(Box::new(|| Box::pin(std::future::pending::<()>())));
    let revoke = cached.set_trust_level(&d.tenant_id, &d.id, DeviceTrustLevel::Revoked, now());
    let outcome = tokio::time::timeout(Duration::from_millis(50), revoke).await;
    assert!(outcome.is_err(), "the write was cancelled while it waited");
    let seen = cached.load(&d.tenant_id, &d.id).await.unwrap().unwrap();
    assert_eq!(seen.trust_level, DeviceTrustLevel::Revoked);
}
