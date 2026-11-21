//! A request that carries a user and yields no tenant is reported, and a
//! guest's is not: without a tenant no device is created and no cookie is
//! issued, which must not pass unnoticed.

use super::*;

/// The default hooks cannot produce the fault: the session layer hands the
/// resolver the tenant the session authenticated into beside its user, so an
/// authenticated request with no tenant extension still gets a device and
/// its cookie.
#[tokio::test]
async fn the_default_tenant_hook_reads_the_sessions_tenant_and_mints_a_device() {
    let store = MemoryDeviceStore::new();
    let clock = MockClock::at(Timestamp::from_utc(2026, 1, 1, 0, 0, 0).unwrap());
    let resolver = LifecycleDeviceResolver::new(
        DefaultFingerprintExtractor::new(fixed_pepper()),
        DeviceLifecycleService::new(store),
        clock,
    );
    let mut parts = req_with(Some("Mozilla/5.0"), None, None);
    parts.extensions.insert(crate::device::SessionUser(
        crate::authn::ids::testing::user("u1"),
    ));
    parts.extensions.insert(crate::device::SessionTenant(
        crate::authn::ids::testing::tenant("t1"),
    ));
    let resolved = resolver.resolve(&parts).await.unwrap();
    assert!(resolved.is_some(), "a device is created for the user");
    assert!(issued_cookie(&parts).is_some(), "and its cookie is issued");
    assert!(!resolver.reported_missing_tenant());
}

/// A `tenant_fn` that answers nothing for an authenticated request mints
/// nothing, and says so: the resolution fails, so the session keeps the
/// device it has, and the report is made on the first such request.
#[tokio::test]
async fn a_user_without_a_tenant_is_reported_and_mints_nothing() {
    let resolver = make_resolver().with_tenant_fn(|_| None);
    assert!(!resolver.reported_missing_tenant());
    let parts = req_with(Some("Mozilla/5.0"), None, None);
    assert!(matches!(
        resolver.resolve(&parts).await,
        Err(LifecycleResolveError::TenantMissing)
    ));
    assert!(
        issued_cookie(&parts).is_none(),
        "no cookie without a tenant"
    );
    assert!(
        resolver.reported_missing_tenant(),
        "the first authenticated request with no tenant is reported"
    );
    // A clone shares the report, so it is made once per resolver.
    assert!(resolver.clone().reported_missing_tenant());
}

/// A guest has no tenant by the default hook, and that is not a fault.
#[tokio::test]
async fn a_guest_without_a_tenant_is_not_reported() {
    let resolver = make_resolver().with_user_fn(|_| None);
    let parts = req_with(Some("Mozilla/5.0"), None, None);
    assert_eq!(resolver.resolve(&parts).await.unwrap(), None);
    assert!(!resolver.reported_missing_tenant());
}
