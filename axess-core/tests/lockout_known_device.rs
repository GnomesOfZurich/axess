//! A per-account lockout keeps strangers out but not the account's own
//! known devices: a login from a device the account has `Seen` or `Trusted`
//! still works while the account is locked.

#![cfg(all(feature = "testing", feature = "device"))]

mod common;

use axess_core::authn::AuditContext;
use axess_core::authn::ids::{DeviceId, TenantId};
use axess_core::{
    DeviceStore, DeviceTrustLevel, MemoryDeviceStore,
    authn::{
        factor::{FactorCredential, ZeroizedString},
        service::{AuthnService, FactorOutcome, LoginOutcome, RequestAuthnService},
        types::LockoutPolicy,
    },
    device::types::{Device, FingerprintHash},
    testing::{
        mock_authn::{MockFactorStore, MockIdentityStore},
        test_session, test_session_on_device, test_session_on_unproven_device,
    },
};
use chrono::Utc;
use common::{password_config, password_method, test_tenant, test_user, uid, user_scope};

fn device_id(label: &str) -> DeviceId {
    axess_core::authn::ids::testing::device(label)
}

fn tenant() -> TenantId {
    test_tenant().id
}

async fn put(
    store: &MemoryDeviceStore,
    id: DeviceId,
    owner: Option<&str>,
    level: DeviceTrustLevel,
    fp: u8,
) {
    let now = Utc::now();
    let device = Device {
        id,
        tenant_id: tenant(),
        user_id: owner.map(uid),
        trust_level: level,
        fingerprint_hash: FingerprintHash::from_bytes([fp; 32]),
        first_seen_at: now,
        last_seen_at: now,
        revoked_at: None,
        demoted_at: None,
        bindings: Vec::new(),
    };
    store.save(&device, now).await.expect("saved");
}

struct World {
    service: RequestAuthnService<MockIdentityStore, MockFactorStore>,
    identity: MockIdentityStore,
    devices: MemoryDeviceStore,
}

/// A request from one of the attacker's addresses, each used once, so the
/// throttle between quick guesses from one address never refuses a guess
/// before the lock does.
fn attacker_address(n: u8) -> AuditContext {
    AuditContext {
        ip_address: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            203, 0, 113, n,
        ))),
        ip_source: axess_core::client_ip::Source::Peer,
        ..AuditContext::default()
    }
}

/// An account locked by three wrong passwords from unknown browsers.
async fn locked_world(with_device_store: bool) -> World {
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"))
        .with_lockout_policy(LockoutPolicy {
            max_attempts: 3,
            duration: Some(std::time::Duration::from_secs(900)),
            ..LockoutPolicy::default()
        });
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config("Gnomes2+"))
        .with_method(&uid("u1"), password_method());
    let devices = MemoryDeviceStore::new();
    let mut builder = AuthnService::builder(identity.clone(), factors);
    if with_device_store {
        builder = builder.with_device_store(devices.clone());
    }
    let service = builder.build();
    for n in 1..=3 {
        let from_attacker = service.with_audit_context(attacker_address(n));
        let attacker = test_session();
        from_attacker
            .begin_login("alice", "default", &attacker)
            .await
            .unwrap();
        let wrong = FactorCredential::Password(ZeroizedString::new("wrong"));
        from_attacker
            .verify_factor(&wrong, &attacker)
            .await
            .unwrap();
    }
    let service = service.with_audit_context(AuditContext::default());
    assert_eq!(
        identity.failed_attempts_for("u1"),
        3,
        "the account is locked"
    );
    World {
        service,
        identity,
        devices,
    }
}

async fn login_from(
    world: &World,
    session: &axess_core::session::extractor::AuthSession,
) -> (LoginOutcome, Option<FactorOutcome>) {
    let begun = world
        .service
        .begin_login("alice", "default", session)
        .await
        .unwrap();
    if !matches!(begun, LoginOutcome::FactorRequired(_)) {
        return (begun, None);
    }
    let right = FactorCredential::Password(ZeroizedString::new("Gnomes2+"));
    let verified = world.service.verify_factor(&right, session).await.unwrap();
    (begun, Some(verified))
}

/// The account's own `Seen` and `Trusted` devices log in during the lock.
#[tokio::test]
async fn a_known_device_still_logs_in_while_the_account_is_locked() {
    for (label, level) in [
        ("seen", DeviceTrustLevel::Seen),
        ("trusted", DeviceTrustLevel::Trusted),
    ] {
        let world = locked_world(true).await;
        let id = device_id(label);
        put(&world.devices, id, Some("u1"), level, 1).await;

        let session = test_session_on_device(id);
        let (begun, verified) = login_from(&world, &session).await;
        assert!(
            matches!(begun, LoginOutcome::FactorRequired(_)),
            "{label}: {begun:?}"
        );
        assert!(
            matches!(verified, Some(FactorOutcome::Authenticated)),
            "{label}: {verified:?}"
        );
        assert!(session.is_authenticated().await);
        assert_eq!(
            world.identity.failed_attempts_for("u1"),
            0,
            "a login resets the count"
        );
    }
}

/// The account's own `Seen` device, bound to the session by a resolver that
/// found it by fingerprint alone, is no way past the lock: only a device the
/// client proved holds the exemption.
#[tokio::test]
async fn a_device_found_by_fingerprint_alone_does_not_lift_the_lock() {
    let world = locked_world(true).await;
    let id = device_id("seen");
    put(&world.devices, id, Some("u1"), DeviceTrustLevel::Seen, 1).await;

    let session = test_session_on_unproven_device(id);
    let (begun, verified) = login_from(&world, &session).await;

    assert!(
        !matches!(verified, Some(FactorOutcome::Authenticated)),
        "{begun:?} {verified:?}"
    );
    assert!(!session.is_authenticated().await);
}

/// Every other origin stays out: no device, an unknown one, one that is not
/// the account's, one that is only `Unknown` or `Revoked`, and a service with
/// no device store.
#[tokio::test]
async fn every_other_origin_is_kept_out_by_the_lock() {
    let world = locked_world(true).await;
    let strangers = [
        ("no device", test_session()),
        (
            "a device nobody stored",
            test_session_on_device(device_id("ghost")),
        ),
        ("another user's device", {
            put(
                &world.devices,
                device_id("bobs"),
                Some("u2"),
                DeviceTrustLevel::Trusted,
                2,
            )
            .await;
            test_session_on_device(device_id("bobs"))
        }),
        ("an unowned device", {
            put(
                &world.devices,
                device_id("loose"),
                None,
                DeviceTrustLevel::Trusted,
                3,
            )
            .await;
            test_session_on_device(device_id("loose"))
        }),
        ("an Unknown device", {
            put(
                &world.devices,
                device_id("new"),
                Some("u1"),
                DeviceTrustLevel::Unknown,
                4,
            )
            .await;
            test_session_on_device(device_id("new"))
        }),
        ("a Revoked device", {
            put(
                &world.devices,
                device_id("gone"),
                Some("u1"),
                DeviceTrustLevel::Revoked,
                5,
            )
            .await;
            test_session_on_device(device_id("gone"))
        }),
    ];
    for (label, session) in strangers {
        let (begun, verified) = login_from(&world, &session).await;
        assert!(
            matches!(begun, LoginOutcome::InvalidCredentials),
            "{label}: {begun:?}"
        );
        assert!(verified.is_none());
        assert!(!session.is_authenticated().await, "{label}");
    }

    let plain = locked_world(false).await;
    let id = device_id("seen");
    put(&plain.devices, id, Some("u1"), DeviceTrustLevel::Seen, 1).await;
    let (begun, _) = login_from(&plain, &test_session_on_device(id)).await;
    assert!(
        matches!(begun, LoginOutcome::InvalidCredentials),
        "without a device store the lock holds for everyone: {begun:?}"
    );
}
