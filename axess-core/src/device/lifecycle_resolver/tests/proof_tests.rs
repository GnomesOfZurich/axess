//! A device is found by the token its cookie presents, never by the headers
//! that produce its fingerprint.

use super::*;
use crate::device::proof::{DeviceToken, PresentedDevice, cookie_value};
use crate::device::resolver::SessionDevice;
use crate::device::types::{Device, DeviceBinding};

fn tenant() -> TenantId {
    crate::authn::ids::testing::tenant("t1")
}

fn user(label: &str) -> UserId {
    crate::authn::ids::testing::user(label)
}

/// A resolver that sees `who` as the authenticated user (`None`: a guest).
fn resolver_for(who: Option<&'static str>) -> LifecycleResolver {
    make_resolver().with_user_fn(move |_| who.map(user))
}

type LifecycleResolver =
    LifecycleDeviceResolver<DefaultFingerprintExtractor, MemoryDeviceStore, MockClock>;

fn with_cookie(mut parts: Parts, value: &str) -> Parts {
    parts.headers.insert(
        axum::http::header::COOKIE,
        axum::http::HeaderValue::from_str(&format!("__Host-axess_device={value}")).unwrap(),
    );
    parts
}

#[tokio::test]
async fn a_guest_without_a_cookie_has_no_device_and_writes_nothing() {
    let resolver = resolver_for(None);
    let parts = req_with(Some("UA"), Some(tenant()), None);

    assert_eq!(resolver.resolve(&parts).await.unwrap(), None);

    assert!(resolver.lifecycle.store().is_empty());
    assert!(issued(&parts).is_none());
}

fn issued(parts: &Parts) -> Option<String> {
    parts
        .extensions
        .get::<DeviceCookieSlot>()
        .and_then(DeviceCookieSlot::take)
        .map(|v| v.to_str().unwrap().to_string())
}

#[tokio::test]
async fn a_new_device_stores_the_digest_of_its_token_and_sends_the_strict_cookie() {
    let resolver = resolver_for(Some("alice"));
    let parts = req_with(Some("UA"), Some(tenant()), None);

    let id = resolver.resolve(&parts).await.unwrap().expect("created");

    let set_cookie = issued(&parts).expect("a cookie is issued with a new device");
    for attribute in [
        "__Host-axess_device=",
        "HttpOnly",
        "Secure",
        "SameSite=Strict",
        "Path=/",
    ] {
        assert!(
            set_cookie.contains(attribute),
            "{attribute} in {set_cookie}"
        );
    }
    assert!(!set_cookie.contains("Domain"), "{set_cookie}");

    let value = set_cookie
        .split(';')
        .next()
        .unwrap()
        .split_once('=')
        .unwrap()
        .1;
    let presented = PresentedDevice::parse(value).expect("the cookie parses");
    assert_eq!(presented.id, id);

    let row = resolver
        .lifecycle
        .store()
        .load(&tenant(), &id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.user_id, Some(user("alice")));
    assert_eq!(row.bindings.len(), 1);
    match &row.bindings[0] {
        DeviceBinding::Cookie { token_hash, .. } => {
            assert_eq!(*token_hash, presented.token.digest());
            assert_ne!(
                token_hash.as_bytes(),
                presented.token.raw_for_tests(),
                "the row holds a digest, not the token"
            );
        }
        other => panic!("expected a cookie binding, found {other:?}"),
    }
}

/// The attack the token exists to stop: copying a victim's headers must not
/// hand over the victim's trusted device, even when it has no owner.
#[tokio::test]
async fn copied_headers_do_not_inherit_a_trusted_device() {
    let resolver = resolver_for(Some("attacker"));
    let parts = req_with(Some("UA"), Some(tenant()), None);

    // The victim's device, made earlier by a guest request, same fingerprint.
    let fingerprint = {
        let extractor = DefaultFingerprintExtractor::new(fixed_pepper());
        extractor
            .extract(&tenant(), &parts, None)
            .expect("fingerprint")
    };
    let victim = Device {
        id: crate::authn::ids::testing::device("victim-device"),
        tenant_id: tenant(),
        user_id: None,
        trust_level: DeviceTrustLevel::Trusted,
        fingerprint_hash: fingerprint,
        first_seen_at: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
        last_seen_at: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
        revoked_at: None,
        demoted_at: None,
        bindings: Vec::new(),
    };
    resolver
        .lifecycle
        .store()
        .save(&victim, victim.first_seen_at)
        .await
        .unwrap();

    let id = resolver.resolve(&parts).await.unwrap().expect("a device");

    assert_ne!(
        id, victim.id,
        "the attacker must not get the victim's device"
    );
    let row = resolver
        .lifecycle
        .store()
        .load(&tenant(), &id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.trust_level, DeviceTrustLevel::Unknown);
    let victim_row = resolver
        .lifecycle
        .store()
        .load(&tenant(), &victim.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(victim_row.trust_level, DeviceTrustLevel::Trusted);
    assert_eq!(victim_row.user_id, None, "and must not claim it either");
}

#[tokio::test]
async fn the_right_id_with_the_wrong_token_is_not_the_device() {
    let resolver = resolver_for(Some("alice"));
    let first = req_with(Some("UA"), Some(tenant()), None);
    let id = resolver.resolve(&first).await.unwrap().expect("created");
    let _ = issued(&first);

    let forged = cookie_value(
        &id,
        &DeviceToken::mint(&axess_rng::testing::MockRng::new(9)),
    );
    let parts = with_cookie(req_with(Some("UA"), Some(tenant()), None), &forged);
    let resolved = resolver.resolve(&parts).await.unwrap().expect("a device");

    assert_ne!(resolved, id);
    assert!(
        issued(&parts).is_some(),
        "the forger is given a device of its own"
    );
}

#[tokio::test]
async fn a_guest_presenting_a_valid_cookie_is_recognised_without_a_write() {
    let user_resolver = resolver_for(Some("alice"));
    let first = req_with(Some("UA"), Some(tenant()), None);
    let id = user_resolver
        .resolve(&first)
        .await
        .unwrap()
        .expect("created");
    let cookie = issued(&first).unwrap();
    let value = cookie
        .split(';')
        .next()
        .unwrap()
        .split_once('=')
        .unwrap()
        .1
        .to_string();
    let seen_before = user_resolver
        .lifecycle
        .store()
        .load(&tenant(), &id)
        .await
        .unwrap()
        .unwrap()
        .last_seen_at;

    // The same store, a request with no authenticated user (a login in flight).
    let guest = LifecycleDeviceResolver::new(
        DefaultFingerprintExtractor::new(fixed_pepper()),
        user_resolver.lifecycle.clone(),
        MockClock::at(Utc.with_ymd_and_hms(2026, 3, 1, 0, 0, 0).unwrap()),
    );
    let parts = with_cookie(req_with(Some("UA"), Some(tenant()), None), &value);
    assert_eq!(guest.resolve(&parts).await.unwrap(), Some(id));
    assert!(issued(&parts).is_none());

    let seen_after = guest
        .lifecycle
        .store()
        .load(&tenant(), &id)
        .await
        .unwrap()
        .unwrap()
        .last_seen_at;
    assert_eq!(
        seen_before, seen_after,
        "a guest request records no sighting"
    );
}

#[tokio::test]
async fn a_valid_cookie_does_not_open_another_users_device() {
    let alice = resolver_for(Some("alice"));
    let first = req_with(Some("UA"), Some(tenant()), None);
    let id = alice.resolve(&first).await.unwrap().expect("created");
    let value = issued(&first)
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .split_once('=')
        .unwrap()
        .1
        .to_string();

    let bob = LifecycleDeviceResolver::new(
        DefaultFingerprintExtractor::new(fixed_pepper()),
        alice.lifecycle.clone(),
        MockClock::at(Utc.with_ymd_and_hms(2026, 1, 2, 0, 0, 0).unwrap()),
    )
    .with_user_fn(|_| Some(user("bob")));
    let parts = with_cookie(req_with(Some("UA"), Some(tenant()), None), &value);
    let resolved = bob.resolve(&parts).await.unwrap().expect("a device");
    assert_ne!(resolved, id, "alice's cookie names alice's device only");
}

#[tokio::test]
async fn a_revoked_device_is_not_recognised_by_its_token() {
    let resolver = resolver_for(Some("alice"));
    let first = req_with(Some("UA"), Some(tenant()), None);
    let id = resolver.resolve(&first).await.unwrap().expect("created");
    let value = issued(&first)
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .split_once('=')
        .unwrap()
        .1
        .to_string();
    resolver
        .lifecycle
        .store()
        .set_trust_level(&tenant(), &id, DeviceTrustLevel::Revoked, Utc::now())
        .await
        .unwrap();

    let parts = with_cookie(req_with(Some("UA"), Some(tenant()), None), &value);
    let resolved = resolver.resolve(&parts).await.unwrap().expect("a device");
    assert_ne!(resolved, id);
}

/// A cross-site navigation sends the session cookie and not the strict
/// device cookie: the device the session already had is kept.
#[tokio::test]
async fn the_session_device_is_kept_when_no_token_is_presented() {
    let resolver = resolver_for(Some("alice"));
    let first = req_with(Some("UA"), Some(tenant()), None);
    let id = resolver.resolve(&first).await.unwrap().expect("created");

    let mut parts = req_with(Some("UA"), Some(tenant()), None);
    parts.extensions.insert(SessionDevice(id));
    assert_eq!(resolver.resolve(&parts).await.unwrap(), Some(id));
    assert!(issued(&parts).is_none());
    assert_eq!(resolver.lifecycle.store().len(), 1, "no second device");
}

#[tokio::test]
async fn the_session_device_of_another_user_is_not_kept() {
    let alice = resolver_for(Some("alice"));
    let first = req_with(Some("UA"), Some(tenant()), None);
    let id = alice.resolve(&first).await.unwrap().expect("created");

    let bob = LifecycleDeviceResolver::new(
        DefaultFingerprintExtractor::new(fixed_pepper()),
        alice.lifecycle.clone(),
        MockClock::at(Utc.with_ymd_and_hms(2026, 1, 2, 0, 0, 0).unwrap()),
    )
    .with_user_fn(|_| Some(user("bob")));
    let mut parts = req_with(Some("UA"), Some(tenant()), None);
    parts.extensions.insert(SessionDevice(id));
    let resolved = bob.resolve(&parts).await.unwrap().expect("a device");
    assert_ne!(resolved, id);
}

#[test]
fn a_cookie_value_that_is_not_ours_does_not_parse() {
    for bad in [
        "",
        "no-dot",
        "not-a-uuid.AAAA",
        &format!("{}.short", crate::authn::ids::testing::device("d")),
    ] {
        assert!(PresentedDevice::parse(bad).is_none(), "{bad}");
    }
}
