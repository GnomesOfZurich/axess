//! A browser profile several accounts sign in on: the cookie holds one entry
//! per device, so an account switch finds the account's own device again
//! instead of minting a new one.

use super::*;
use crate::device::proof::PresentedDevice;

fn tenant() -> TenantId {
    crate::authn::ids::testing::tenant("t1")
}

type Resolver = LifecycleDeviceResolver<DefaultFingerprintExtractor, MemoryDeviceStore, MockClock>;

/// A resolver that sees `who` as the authenticated user (`None`: a guest),
/// on the store of `lifecycle`.
fn as_user(
    lifecycle: &DeviceLifecycleService<MemoryDeviceStore>,
    who: Option<&'static str>,
) -> Resolver {
    LifecycleDeviceResolver::new(
        DefaultFingerprintExtractor::new(fixed_pepper()),
        lifecycle.clone(),
        MockClock::at(Timestamp::from_utc(2026, 1, 1, 0, 0, 0).unwrap()),
    )
    .with_user_fn(move |_| who.map(crate::authn::ids::testing::user))
}

/// A request of the profile, sending `cookie` (a `Set-Cookie` value it was
/// handed) when there is one.
fn request(cookie: Option<&str>) -> Parts {
    let mut parts = req_with(Some("UA"), Some(tenant()), None);
    if let Some(cookie) = cookie {
        parts
            .headers
            .insert(axum::http::header::COOKIE, cookie_header(cookie));
    }
    parts
}

fn entries(set_cookie: &str) -> Vec<PresentedDevice> {
    let pair = set_cookie.split(';').next().unwrap();
    PresentedDevice::parse_all(pair.split_once('=').unwrap().1)
}

#[tokio::test]
async fn an_account_switch_reuses_the_accounts_own_device() {
    let lifecycle = DeviceLifecycleService::new(MemoryDeviceStore::new());
    let (alice, bob) = (
        as_user(&lifecycle, Some("alice")),
        as_user(&lifecycle, Some("bob")),
    );

    // Alice signs in first: a device and a one-entry cookie.
    let first = request(None);
    let alices = alice.resolve(&first).await.unwrap().expect("created").id();
    let cookie = issued_cookie(&first).expect("the cookie is issued");

    // Bob signs in on the same profile: his own device, and the cookie keeps
    // Alice's entry behind his.
    let second = request(Some(&cookie));
    let bobs = bob.resolve(&second).await.unwrap().expect("created").id();
    assert_ne!(bobs, alices);
    let cookie = issued_cookie(&second).expect("the cookie is rewritten");
    let held: Vec<DeviceId> = entries(&cookie).iter().map(|e| e.id).collect();
    assert_eq!(held, vec![bobs, alices]);

    // Each account switch from here finds the account's own device, proven,
    // and mints nothing.
    for (resolver, own) in [(&alice, alices), (&bob, bobs), (&alice, alices)] {
        let parts = request(Some(&cookie));
        let resolved = resolver.resolve(&parts).await.unwrap().expect("a device");
        assert!(matches!(resolved, BoundDevice::Proven(_)), "{resolved:?}");
        assert_eq!(resolved.id(), own);
        assert!(
            issued_cookie(&parts).is_none(),
            "no new device, no new cookie"
        );
    }
    assert_eq!(lifecycle.store().len(), 2, "one device per account");
}

/// Before sign-in nothing says which account of a shared profile is
/// signing in, so a guest is recognised only when the cookie proves one
/// device.
#[tokio::test]
async fn a_guest_is_recognised_only_by_a_cookie_that_proves_one_device() {
    let lifecycle = DeviceLifecycleService::new(MemoryDeviceStore::new());
    let (alice, bob) = (
        as_user(&lifecycle, Some("alice")),
        as_user(&lifecycle, Some("bob")),
    );
    let guest = as_user(&lifecycle, None);

    let first = request(None);
    let alices = alice.resolve(&first).await.unwrap().expect("created").id();
    let one = issued_cookie(&first).unwrap();
    let parts = request(Some(&one));
    assert_eq!(
        guest.resolve(&parts).await.unwrap().map(|d| d.id()),
        Some(alices)
    );

    let second = request(Some(&one));
    bob.resolve(&second).await.unwrap().expect("created");
    let two = issued_cookie(&second).unwrap();
    assert_eq!(guest.resolve(&request(Some(&two))).await.unwrap(), None);
}
