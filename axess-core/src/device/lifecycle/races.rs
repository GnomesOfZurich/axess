//! A revocation that lands between the lifecycle's read and its write.
//!
//! [`AfterLoad`] wraps any store and runs a hook once, right after a
//! `load` has read its row and before it returns: the exact window in
//! which a concurrent request can revoke the device the caller is about
//! to promote or bind to.

use super::*;
use crate::device::store::{
    BindingsUpdate, MemoryDeviceStore, OwnerClaim, SweepCounts, TrustTransition,
};
use crate::device::types::DeviceBinding;
use chrono::TimeZone;
use std::pin::Pin;
use std::sync::Mutex;

/// The operation name and `now` of one store write.
pub(crate) type WriteTime = (&'static str, DateTime<Utc>);

pub(crate) type Hook = Box<dyn FnOnce() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send>;

/// Delegates every operation to `inner`; the hook fires once after a load.
#[derive(Clone)]
pub(crate) struct AfterLoad<S: DeviceStore> {
    pub(crate) inner: S,
    hook: Arc<Mutex<Option<Hook>>>,
    /// Fires once after a `find_by_fingerprint` has read its answer and
    /// before it returns: the window between the lifecycle's lookup and its
    /// create, in which a competing first sighting can land.
    find_hook: Arc<Mutex<Option<Hook>>>,
    /// The `now` each write (`save`, `replace_bindings`, `claim_owner`) was
    /// given, in call order.
    pub(crate) write_times: Arc<Mutex<Vec<WriteTime>>>,
}

impl<S: DeviceStore> AfterLoad<S> {
    pub(crate) fn new(inner: S) -> Self {
        Self {
            inner,
            hook: Arc::new(Mutex::new(None)),
            find_hook: Arc::new(Mutex::new(None)),
            write_times: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Arm the hook that runs after the next `find_by_fingerprint` answer.
    pub(crate) fn after_next_find(&self, hook: Hook) {
        *self.find_hook.lock().unwrap() = Some(hook);
    }

    /// Arm the hook: `revoke` the device the next time it is loaded.
    pub(crate) fn revoke_after_next_load(
        &self,
        tenant: TenantId,
        id: DeviceId,
        now: DateTime<Utc>,
    ) {
        let inner = self.inner.clone();
        *self.hook.lock().unwrap() = Some(Box::new(move || {
            Box::pin(async move {
                inner
                    .set_trust_level(&tenant, &id, DeviceTrustLevel::Revoked, now)
                    .await
                    .unwrap();
            })
        }));
    }

    /// Arm the hook: another editor appends `binding` to the device the next
    /// time it is loaded, i.e. after the caller has read the old bindings.
    #[cfg(feature = "fido2")]
    pub(crate) fn add_binding_after_next_load(
        &self,
        tenant: TenantId,
        id: DeviceId,
        binding: DeviceBinding,
    ) {
        let inner = self.inner.clone();
        *self.hook.lock().unwrap() = Some(Box::new(move || {
            Box::pin(async move {
                let mut bindings = inner.load(&tenant, &id).await.unwrap().unwrap().bindings;
                let before = bindings.clone();
                bindings.push(binding);
                let done = inner
                    .replace_bindings(&tenant, &id, &before, &bindings, crate::device::test_now())
                    .await
                    .unwrap();
                assert_eq!(done, BindingsUpdate::Written);
            })
        }));
    }
}

impl<S: DeviceStore> DeviceStore for AfterLoad<S> {
    type Error = S::Error;

    async fn load(&self, t: &TenantId, id: &DeviceId) -> Result<Option<Device>, Self::Error> {
        let row = self.inner.load(t, id).await?;
        let hook = self.hook.lock().unwrap().take();
        if let Some(h) = hook {
            h().await;
        }
        Ok(row)
    }
    async fn find_by_fingerprint(
        &self,
        t: &TenantId,
        h: &FingerprintHash,
    ) -> Result<Option<Device>, Self::Error> {
        let row = self.inner.find_by_fingerprint(t, h).await?;
        let hook = self.find_hook.lock().unwrap().take();
        if let Some(hook) = hook {
            hook().await;
        }
        Ok(row)
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
    fn save(
        &self,
        d: &Device,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        self.write_times.lock().unwrap().push(("save", now));
        self.inner.save(d, now)
    }
    fn record_sighting(
        &self,
        t: &TenantId,
        id: &DeviceId,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<DeviceTrustLevel, Self::Error>> + Send {
        self.inner.record_sighting(t, id, now)
    }
    fn set_trust_level(
        &self,
        t: &TenantId,
        id: &DeviceId,
        level: DeviceTrustLevel,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        self.inner.set_trust_level(t, id, level, now)
    }
    fn set_trust_level_if(
        &self,
        t: &TenantId,
        id: &DeviceId,
        expected: DeviceTrustLevel,
        level: DeviceTrustLevel,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<TrustTransition, Self::Error>> + Send {
        self.inner.set_trust_level_if(t, id, expected, level, now)
    }
    fn replace_bindings(
        &self,
        t: &TenantId,
        id: &DeviceId,
        expected: &[DeviceBinding],
        bindings: &[DeviceBinding],
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<BindingsUpdate, Self::Error>> + Send {
        self.write_times
            .lock()
            .unwrap()
            .push(("replace_bindings", now));
        self.inner.replace_bindings(t, id, expected, bindings, now)
    }
    fn claim_owner(
        &self,
        t: &TenantId,
        id: &DeviceId,
        user: &UserId,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<OwnerClaim, Self::Error>> + Send {
        self.write_times.lock().unwrap().push(("claim_owner", now));
        self.inner.claim_owner(t, id, user, now)
    }
    fn delete(
        &self,
        t: &TenantId,
        id: &DeviceId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        self.inner.delete(t, id)
    }
    fn sweep(
        &self,
        t: &TenantId,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<SweepCounts, Self::Error>> + Send {
        self.inner.sweep(t, now)
    }
}

fn at() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 1, 9, 0, 0).unwrap()
}

fn tenant() -> TenantId {
    crate::authn::ids::testing::tenant("tenant-1")
}

fn device_id() -> DeviceId {
    crate::authn::ids::testing::device("device-1")
}

/// An Unknown device owned by a user, with its fingerprint.
async fn unknown_device<S: DeviceStore>(store: &S) {
    let device = Device {
        id: device_id(),
        tenant_id: tenant(),
        user_id: Some(crate::authn::ids::testing::user("user-1")),
        trust_level: DeviceTrustLevel::Unknown,
        fingerprint_hash: FingerprintHash::from_bytes([3u8; 32]),
        first_seen_at: at(),
        last_seen_at: at(),
        revoked_at: None,
        demoted_at: None,
        bindings: Vec::new(),
    };
    store
        .save(&device, crate::device::test_now())
        .await
        .unwrap();
}

/// The promotion that loses to a revocation must report Revoked and leave
/// the revocation, and its timestamp, in place.
async fn promotion_never_undoes_a_revocation<S: DeviceStore>(store: S) {
    let racing = AfterLoad::new(store);
    unknown_device(&racing).await;
    let revoked_at = at() + chrono::Duration::minutes(5);
    racing.revoke_after_next_load(tenant(), device_id(), revoked_at);

    let svc = DeviceLifecycleService::new(racing.clone());
    let outcome = svc
        .promote_on_authn(&tenant(), &device_id(), at() + chrono::Duration::minutes(6))
        .await
        .unwrap();

    assert_eq!(
        outcome,
        Some(DeviceTrustLevel::Revoked),
        "a promotion that lost to a revocation is reported as revoked, not as Seen"
    );
    let row = racing
        .inner
        .load(&tenant(), &device_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.trust_level, DeviceTrustLevel::Revoked);
    assert_eq!(
        row.revoked_at,
        Some(revoked_at),
        "the revocation timestamp must not be cleared"
    );
}

#[tokio::test]
async fn memory_promotion_never_undoes_a_revocation() {
    promotion_never_undoes_a_revocation(MemoryDeviceStore::new()).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn sqlite_promotion_never_undoes_a_revocation() {
    promotion_never_undoes_a_revocation(
        crate::device::storage::sqlite::tests_support::store().await,
    )
    .await;
}

/// Binding a credential or recording its use must not write the trust
/// level, so a revocation made after the load survives and no binding is
/// added to the revoked device.
#[cfg(feature = "fido2")]
async fn webauthn_writes_never_undo_a_revocation<S: DeviceStore>(store: S) {
    use crate::device::types::AttestationClass;
    let racing = AfterLoad::new(store);
    unknown_device(&racing).await;
    let svc = DeviceLifecycleService::new(racing.clone());
    assert!(
        svc.bind_webauthn_credential(
            &tenant(),
            &device_id(),
            "cred-1".into(),
            AttestationClass::None,
            at()
        )
        .await
        .unwrap()
    );

    // Revoked between the load and the write of a second binding.
    let revoked_at = at() + chrono::Duration::minutes(5);
    racing.revoke_after_next_load(tenant(), device_id(), revoked_at);
    let added = svc
        .bind_webauthn_credential(
            &tenant(),
            &device_id(),
            "cred-2".into(),
            AttestationClass::None,
            at(),
        )
        .await
        .unwrap();
    assert!(
        !added,
        "a binding must not be added to a device revoked meanwhile"
    );
    let row = racing
        .inner
        .load(&tenant(), &device_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.trust_level, DeviceTrustLevel::Revoked);
    assert_eq!(row.revoked_at, Some(revoked_at));
    assert_eq!(row.bindings.len(), 1, "only the first credential is bound");

    // The same window for a usage update.
    let fresh = tenant();
    let id2 = crate::authn::ids::testing::device("device-2");
    let mut d2 = row.clone();
    d2.id = id2;
    d2.trust_level = DeviceTrustLevel::Seen;
    d2.revoked_at = None;
    d2.fingerprint_hash = FingerprintHash::from_bytes([4u8; 32]);
    racing.save(&d2, crate::device::test_now()).await.unwrap();
    racing.revoke_after_next_load(fresh, id2, revoked_at);
    svc.record_webauthn_usage(&fresh, &id2, "cred-1", at() + chrono::Duration::minutes(9))
        .await
        .unwrap();
    let row2 = racing.inner.load(&fresh, &id2).await.unwrap().unwrap();
    assert_eq!(row2.trust_level, DeviceTrustLevel::Revoked);
    assert_eq!(row2.revoked_at, Some(revoked_at));
}

#[cfg(feature = "fido2")]
#[tokio::test]
async fn memory_webauthn_writes_never_undo_a_revocation() {
    webauthn_writes_never_undo_a_revocation(MemoryDeviceStore::new()).await;
}

#[cfg(all(feature = "fido2", feature = "sqlite"))]
#[tokio::test]
async fn sqlite_webauthn_writes_never_undo_a_revocation() {
    webauthn_writes_never_undo_a_revocation(
        crate::device::storage::sqlite::tests_support::store().await,
    )
    .await;
}

/// Two bindings edits that both read the row before either wrote it: the
/// second must notice, re-read, and keep the first one's binding too.
#[cfg(feature = "fido2")]
async fn concurrent_binding_edits_both_survive<S: DeviceStore>(store: S) {
    use crate::device::types::AttestationClass;
    let racing = AfterLoad::new(store);
    unknown_device(&racing).await;
    let other = DeviceBinding::Refresh {
        family_id: "fam-other".into(),
        issued_at: at(),
        last_used_at: at(),
    };
    racing.add_binding_after_next_load(tenant(), device_id(), other.clone());

    let svc = DeviceLifecycleService::new(racing.clone());
    let added = svc
        .bind_webauthn_credential(
            &tenant(),
            &device_id(),
            "cred-1".into(),
            AttestationClass::None,
            at(),
        )
        .await
        .unwrap();

    assert!(added, "the binding is recorded after the retry");
    let row = racing
        .inner
        .load(&tenant(), &device_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.bindings.len(), 2, "neither edit was lost: {row:?}");
    assert!(row.bindings.contains(&other));
}

#[cfg(feature = "fido2")]
#[tokio::test]
async fn memory_concurrent_binding_edits_both_survive() {
    concurrent_binding_edits_both_survive(MemoryDeviceStore::new()).await;
}

#[cfg(all(feature = "fido2", feature = "sqlite"))]
#[tokio::test]
async fn sqlite_concurrent_binding_edits_both_survive() {
    concurrent_binding_edits_both_survive(
        crate::device::storage::sqlite::tests_support::store().await,
    )
    .await;
}

/// Every write the lifecycle makes carries the `now` the caller gave it,
/// so a backend that expires rows by age never has to read the wall clock.
#[tokio::test]
async fn writes_carry_the_callers_now() {
    let store = AfterLoad::new(MemoryDeviceStore::new());
    let svc = DeviceLifecycleService::new(store.clone());
    let fp = FingerprintHash::from_bytes([9u8; 32]);
    let guest_time = at();
    let claim_time = at() + chrono::Duration::minutes(7);
    let user = crate::authn::ids::testing::user("user-1");

    // A guest request creates the device: one `save` at the guest's time.
    svc.ensure_device(&tenant(), None, fp, guest_time, device_id_fn)
        .await
        .unwrap();
    // The first authenticated user claims it: one `claim_owner`.
    svc.ensure_device(&tenant(), Some(&user), fp, claim_time, device_id_fn)
        .await
        .unwrap();

    assert_eq!(
        *store.write_times.lock().unwrap(),
        vec![("save", guest_time), ("claim_owner", claim_time)]
    );
}

fn device_id_fn() -> DeviceId {
    device_id()
}
