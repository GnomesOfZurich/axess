//! A trust write lands on the device the request proved, never on a row
//! that shares its fingerprint, and never on a revoked one.

use super::*;
use crate::device::store::MemoryDeviceStore;
use crate::device::types::Device;

fn tenant() -> TenantId {
    crate::authn::ids::testing::tenant("trust-tenant")
}

fn user() -> UserId {
    crate::authn::ids::testing::user("trust-user")
}

fn at(minutes: u32) -> Timestamp {
    now_at(9, u8::try_from(minutes).unwrap())
}

/// A request of `user` that presents no device token and has no session
/// device: the lifecycle creates a device for it and issues its token.
async fn first_request(
    service: &DeviceLifecycleService<MemoryDeviceStore>,
    label: &str,
    seed: u64,
) -> ResolvedDevice {
    let rng = crate::testing::mock_random::MockRng::new(seed);
    let (tenant, user) = (tenant(), user());
    let fresh = crate::authn::ids::testing::device(label);
    let request = DeviceRequest {
        tenant: &tenant,
        user: Some(&user),
        fingerprint: Some(fingerprint(3)),
        presented: &[],
        session_device: None,
        keys: crate::device_key::KeyEnforcement::none_for_tests(),
    };
    service
        .resolve_proven(request, at(0), &rng, || fresh)
        .await
        .unwrap()
        .expect("a device is created for an authenticated user")
}

async fn level(service: &DeviceLifecycleService<MemoryDeviceStore>, id: &DeviceId) -> Device {
    service.store.load(&tenant(), id).await.unwrap().unwrap()
}

/// Two devices of one user share a fingerprint (two browsers behind one
/// address with the same headers). Trusting the one the request proved
/// leaves the other exactly as it was.
#[tokio::test]
async fn grant_trust_marks_the_proven_device_and_not_its_fingerprint_twin() {
    let service = DeviceLifecycleService::new(MemoryDeviceStore::new());
    let proven = first_request(&service, "proven", 1).await;
    let twin = first_request(&service, "twin", 2).await;
    assert_ne!(proven.id, twin.id);
    assert_eq!(
        level(&service, &proven.id).await.fingerprint_hash,
        level(&service, &twin.id).await.fingerprint_hash,
        "the two rows share a fingerprint"
    );

    let after = service
        .grant_trust(
            &UserDevice::for_tests(tenant(), user(), proven.proven()),
            at(1),
        )
        .await
        .unwrap();
    assert_eq!(after, Some(DeviceTrustLevel::Trusted));
    assert_eq!(
        level(&service, &proven.id).await.trust_level,
        DeviceTrustLevel::Trusted
    );
    assert_eq!(
        level(&service, &twin.id).await.trust_level,
        DeviceTrustLevel::Unknown,
        "the row that only shares the fingerprint gained nothing"
    );
}

/// The same for the promotion a login makes.
#[tokio::test]
async fn promote_on_authn_marks_the_proven_device_and_not_its_fingerprint_twin() {
    let service = DeviceLifecycleService::new(MemoryDeviceStore::new());
    let proven = first_request(&service, "proven", 1).await;
    let twin = first_request(&service, "twin", 2).await;

    let after = service
        .promote_on_authn(
            &UserDevice::for_tests(tenant(), user(), proven.proven()),
            at(1),
        )
        .await
        .unwrap();
    assert_eq!(after, Some(DeviceTrustLevel::Seen));
    assert_eq!(
        level(&service, &twin.id).await.trust_level,
        DeviceTrustLevel::Unknown
    );
}

/// A request that presents no token for the device its session names gets
/// that device back as kept, and nothing a trust write accepts: the only
/// answer that carries a `ProvenDevice` is `None` for it.
#[tokio::test]
async fn a_request_that_proves_no_device_has_nothing_to_trust() {
    let service = DeviceLifecycleService::new(MemoryDeviceStore::new());
    let existing = first_request(&service, "existing", 1).await;
    let rng = crate::testing::mock_random::MockRng::new(9);
    let (tenant, user) = (tenant(), user());
    let request = DeviceRequest {
        tenant: &tenant,
        user: Some(&user),
        fingerprint: Some(fingerprint(3)),
        presented: &[],
        session_device: Some(&existing.id),
        keys: crate::device_key::KeyEnforcement::none_for_tests(),
    };
    let kept = service
        .resolve_or_keep(request, at(1), &rng, || {
            panic!("no device is created for a session that has one")
        })
        .await
        .unwrap()
        .expect("the session's device");
    assert_eq!(kept, ResolvedOrKept::Kept(existing.id));
    assert_eq!(
        kept.bound(),
        crate::device::BoundDevice::Unproven(existing.id)
    );
    let proven = service
        .resolve_proven(request, at(1), &rng, || {
            panic!("no device is created for a session that has one")
        })
        .await
        .unwrap();
    assert_eq!(
        proven, None,
        "nothing was proven, so nothing can be trusted"
    );
    assert_eq!(
        level(&service, &existing.id).await.trust_level,
        DeviceTrustLevel::Unknown
    );
}

/// A revoked device is never trusted, a trusted one stays, a missing one is
/// `None`, and one row is written for the one grant that changed something.
#[tokio::test]
async fn grant_trust_respects_the_ladder_and_records_the_grant() {
    let sink = std::sync::Arc::new(LifecycleCaptureSink::new());
    let service =
        DeviceLifecycleService::new(MemoryDeviceStore::new()).with_event_sink(sink.clone());
    let device = first_request(&service, "ladder", 1).await;
    let granted = |sink: &LifecycleCaptureSink| {
        sink.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.event_type == AuthEventType::DeviceTrustGranted)
            .count()
    };

    assert_eq!(
        service
            .grant_trust(
                &UserDevice::for_tests(tenant(), user(), device.proven()),
                at(1)
            )
            .await
            .unwrap(),
        Some(DeviceTrustLevel::Trusted)
    );
    assert_eq!(granted(&sink), 1);
    // Already trusted: nothing changes and nothing is recorded again.
    assert_eq!(
        service
            .grant_trust(
                &UserDevice::for_tests(tenant(), user(), device.proven()),
                at(2)
            )
            .await
            .unwrap(),
        Some(DeviceTrustLevel::Trusted)
    );
    assert_eq!(granted(&sink), 1);

    service
        .store
        .set_trust_level(&tenant(), &device.id, DeviceTrustLevel::Revoked, at(3))
        .await
        .unwrap();
    assert_eq!(
        service
            .grant_trust(
                &UserDevice::for_tests(tenant(), user(), device.proven()),
                at(4)
            )
            .await
            .unwrap(),
        Some(DeviceTrustLevel::Revoked),
        "a revoked device is never trusted again"
    );
    assert_eq!(
        level(&service, &device.id).await.trust_level,
        DeviceTrustLevel::Revoked
    );
    assert_eq!(granted(&sink), 1);

    let gone = ProvenDevice::for_tests(crate::authn::ids::testing::device("gone"));
    assert_eq!(
        service
            .grant_trust(&UserDevice::for_tests(tenant(), user(), gone), at(5))
            .await
            .unwrap(),
        None
    );
}

/// The request that completes a login proved its device before anyone was
/// signed in, so on a shared browser profile it may be another account's.
/// A trust write for the account that signed in leaves that device as it
/// was: no promotion, no grant, no new owner, no audit row.
#[tokio::test]
async fn a_login_writes_no_trust_onto_another_accounts_device() {
    let sink = std::sync::Arc::new(LifecycleCaptureSink::new());
    let service =
        DeviceLifecycleService::new(MemoryDeviceStore::new()).with_event_sink(sink.clone());
    let theirs = first_request(&service, "theirs", 1).await;
    let rows_before = sink.events.lock().unwrap().len();
    let before = level(&service, &theirs.id).await;
    let intruder = crate::authn::ids::testing::user("another-user");
    let paired = UserDevice::for_tests(tenant(), intruder, theirs.proven());

    assert_eq!(
        service.promote_on_authn(&paired, at(1)).await.unwrap(),
        None
    );
    assert_eq!(
        service
            .promote_if_authenticated(&FactorOutcome::Authenticated, &paired, at(2))
            .await
            .unwrap(),
        None
    );
    assert_eq!(service.grant_trust(&paired, at(3)).await.unwrap(), None);
    assert_eq!(level(&service, &theirs.id).await, before);
    assert_eq!(sink.events.lock().unwrap().len(), rows_before);
}

/// A device with no owner is claimed for the user the trust write is made
/// for, in the store's own conditional write, and then promoted.
#[tokio::test]
async fn a_trust_write_claims_an_unowned_device_for_its_user() {
    let service = DeviceLifecycleService::new(MemoryDeviceStore::new());
    let id = crate::authn::ids::testing::device("guest-made");
    service
        .ensure_device(&tenant(), None, fingerprint(4), at(0), || id)
        .await
        .unwrap();
    let paired = UserDevice::for_tests(tenant(), user(), ProvenDevice::for_tests(id));
    assert_eq!(
        service.promote_on_authn(&paired, at(1)).await.unwrap(),
        Some(DeviceTrustLevel::Seen)
    );
    assert_eq!(level(&service, &id).await.user_id, Some(user()));
}

/// Under enforcement a device that has a key is proven only by a proof of
/// exactly that key, for that tenant: its token beside a proof of another
/// key (one forgotten and replaced inside the proof's life), or beside the
/// same key proven for another tenant, proves nothing, and the session keeps
/// the device as recognised. Without enforcement the token proves it.
#[tokio::test]
async fn a_keyed_device_is_proven_only_by_its_own_key_for_its_own_tenant() {
    use crate::device::proof::{DeviceToken, PresentedDevice};
    use crate::device_key::{
        DeviceProof, KeyChallenge, KeyCheck, KeyEnforcement, KeyProofShape, KeyThumbprint,
        P256PublicKey, ProvenKey,
    };
    let rng = crate::testing::mock_random::MockRng::new(9);
    let service = DeviceLifecycleService::new(MemoryDeviceStore::new());
    let token = DeviceToken::mint(&rng);
    let id = crate::authn::ids::testing::device("keyed");
    let thumbprint = KeyThumbprint::from_bytes([7; 32]);
    let row = Device {
        id,
        tenant_id: tenant(),
        user_id: Some(user()),
        trust_level: DeviceTrustLevel::Seen,
        fingerprint_hash: fingerprint(3),
        first_seen_at: at(0),
        last_seen_at: at(0),
        revoked_at: None,
        demoted_at: None,
        bindings: vec![
            token.binding(at(0)),
            crate::device::types::DeviceBinding::Key {
                thumbprint,
                public_key: P256PublicKey {
                    x: [1; 32],
                    y: [2; 32],
                },
                shape: KeyProofShape::Browser,
                bound_at: at(0),
                proven_at: at(0),
                challenge: KeyChallenge::from_bytes([3; 32]),
                challenge_issued_at: at(0),
            },
        ],
    };
    service.store.save(&row, at(0)).await.unwrap();
    let presented = PresentedDevice { id, token };
    let (tenant, user) = (tenant(), user());
    let proven_for = |tenant: TenantId, thumbprint: KeyThumbprint| {
        KeyCheck::for_tests(vec![ProvenKey {
            tenant,
            device: id,
            thumbprint,
        }])
    };
    let own = proven_for(tenant, thumbprint);
    let another_key = proven_for(tenant, KeyThumbprint::from_bytes([8; 32]));
    let another_tenant = proven_for(crate::authn::ids::testing::tenant("other"), thumbprint);
    let nothing = KeyCheck::for_tests(Vec::new());
    let cases = [
        (
            KeyEnforcement::for_tests(&own),
            Some(DeviceProof::Key(thumbprint)),
        ),
        (KeyEnforcement::for_tests(&another_key), None),
        (KeyEnforcement::for_tests(&another_tenant), None),
        (KeyEnforcement::for_tests(&nothing), None),
        (KeyEnforcement::none_for_tests(), Some(DeviceProof::Token)),
    ];
    for (keys, expected) in cases {
        let request = DeviceRequest {
            tenant: &tenant,
            user: Some(&user),
            fingerprint: Some(fingerprint(3)),
            presented: std::slice::from_ref(&presented),
            session_device: Some(&id),
            keys,
        };
        let resolved = service
            .resolve_or_keep(request, at(1), &rng, || {
                crate::authn::ids::testing::device("never-made")
            })
            .await
            .unwrap()
            .expect("the session's device stands");
        // Proven, and how; or kept as recognised, which proves nothing.
        let proof = match resolved {
            ResolvedOrKept::Proven(resolved) => Some(resolved.proven().proof()),
            ResolvedOrKept::Kept(kept) => {
                assert_eq!(kept, id);
                None
            }
        };
        assert_eq!(proof, expected, "{keys:?}");
    }
}
