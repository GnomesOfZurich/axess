//! Consecutive wrong guesses are slowed down before the per-account lock is
//! reached: the delay doubles per failure under a key of account and client
//! address, a guess inside the delay is refused with the time left, a right
//! guess clears the key, and the lock still caps everything.

#![cfg(feature = "testing")]

mod common;

use axess_clock::testing::MockClock;
use axess_core::authn::AuditContext;
use axess_core::authn::ids::TenantId;
use axess_core::authn::{
    error::AuthnError,
    factor::{FactorCredential, ZeroizedString},
    service::{AuthnService, FactorOutcome, LoginOutcome, RequestAuthnService},
    types::{LockoutPolicy, Throttle, ThrottleKey},
};
use axess_core::blocking::KdfExecutor;
use axess_core::client_ip::Source;
use axess_core::testing::mock_authn::{MockFactorStore, MockIdentityStore};
use axess_core::testing::mock_tracing::TracingCapture;
use axess_core::testing::test_session;
use chrono::{TimeZone, Utc};
use common::{password_config, password_method, test_tenant, test_user, uid, user_scope};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

const ADDRESS_A: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
const ADDRESS_B: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2));

fn tenant() -> TenantId {
    test_tenant().id
}

/// A service and the stores behind it, on a clock the test moves.
struct World {
    service: AuthnService<MockIdentityStore, MockFactorStore>,
    identity: MockIdentityStore,
    clock: MockClock,
    kdf: std::sync::Arc<KdfExecutor>,
}

impl World {
    fn new(policy: LockoutPolicy) -> Self {
        let clock = MockClock::at(Utc.timestamp_opt(1_700_000_000, 0).unwrap());
        let identity = MockIdentityStore::new()
            .with_tenant(test_tenant())
            .with_user(test_user("u1", "alice"))
            .with_lockout_policy(policy)
            .with_clock(clock.clone());
        let factors = MockFactorStore::new()
            .with_factor(user_scope(), password_config("Gnomes2+"))
            .with_method(&uid("u1"), password_method());
        let kdf = std::sync::Arc::new(KdfExecutor::inline());
        let service = AuthnService::builder(identity.clone(), factors)
            .with_clock(clock.clone())
            .with_kdf_executor(kdf.clone())
            .build();
        Self {
            service,
            identity,
            clock,
            kdf,
        }
    }

    /// A handle for a request from `address`, resolved by the peer.
    fn from(&self, address: IpAddr) -> RequestAuthnService<MockIdentityStore, MockFactorStore> {
        self.service.with_audit_context(AuditContext {
            ip_address: Some(address),
            ip_source: Source::Peer,
            ..AuditContext::default()
        })
    }

    /// A handle for a request whose address nothing resolved.
    fn unresolved(&self) -> RequestAuthnService<MockIdentityStore, MockFactorStore> {
        self.service.with_audit_context(AuditContext::default())
    }

    fn advance_secs(&self, secs: i64) {
        self.clock.advance(chrono::Duration::seconds(secs));
    }
}

/// A fresh login that guesses `password`.
async fn guess(
    service: &RequestAuthnService<MockIdentityStore, MockFactorStore>,
    password: &str,
) -> FactorOutcome {
    let session = test_session();
    let begun = service
        .begin_login("alice", "default", &session)
        .await
        .unwrap();
    assert!(
        matches!(begun, LoginOutcome::FactorRequired(_)),
        "begin_login: {begun:?}"
    );
    service
        .verify_factor(
            &FactorCredential::Password(ZeroizedString::new(password)),
            &session,
        )
        .await
        .unwrap()
}

async fn wrong(service: &RequestAuthnService<MockIdentityStore, MockFactorStore>) -> FactorOutcome {
    guess(service, "wrong").await
}

fn throttled_for(outcome: &FactorOutcome) -> Option<Duration> {
    match outcome {
        FactorOutcome::Throttled { retry_after } => Some(*retry_after),
        _ => None,
    }
}

/// A lock far enough away that only the throttle answers.
fn throttle_only() -> LockoutPolicy {
    LockoutPolicy {
        max_attempts: 100,
        ..LockoutPolicy::default()
    }
}

#[tokio::test]
async fn the_delay_doubles_per_consecutive_failure_and_caps_at_sixty_four_seconds() {
    let world = World::new(throttle_only());
    let from_a = world.from(ADDRESS_A);
    assert!(matches!(
        wrong(&from_a).await,
        FactorOutcome::InvalidCredential
    ));
    for expected in [1u64, 2, 4, 8, 16, 32, 64, 64, 64] {
        let refused = wrong(&from_a).await;
        assert_eq!(
            throttled_for(&refused),
            Some(Duration::from_secs(expected)),
            "right after a failure the next guess waits {expected} s: {refused:?}"
        );
        world.advance_secs(expected as i64 - 1);
        let still = wrong(&from_a).await;
        assert_eq!(
            throttled_for(&still),
            Some(Duration::from_secs(1)),
            "one second before the retry time: {still:?}"
        );
        world.advance_secs(1);
        assert!(
            matches!(wrong(&from_a).await, FactorOutcome::InvalidCredential),
            "at the retry time the guess runs and is simply wrong"
        );
    }
}

#[tokio::test]
async fn a_throttled_guess_costs_no_counter_write_and_no_hash() {
    let world = World::new(throttle_only());
    let from_a = world.from(ADDRESS_A);
    wrong(&from_a).await;
    assert_eq!(world.identity.failed_attempts_for("u1"), 1);
    let hashes = world.kdf.jobs_started();
    for _ in 0..5 {
        assert!(throttled_for(&wrong(&from_a).await).is_some());
    }
    assert_eq!(
        world.identity.failed_attempts_for("u1"),
        1,
        "a refused guess reserves nothing against the account"
    );
    assert_eq!(world.kdf.jobs_started(), hashes, "and runs no verifier");
}

#[tokio::test]
async fn login_with_password_conceals_the_throttle_and_still_spends_one_hash() {
    let world = World::new(throttle_only());
    let from_a = world.from(ADDRESS_A);
    wrong(&from_a).await;
    let hashes = world.kdf.jobs_started();
    let concealed = from_a
        .login_with_password("alice", "default", "Gnomes2+", &test_session())
        .await
        .unwrap();
    assert!(
        matches!(concealed, FactorOutcome::InvalidCredential),
        "the combined entry point says what a wrong password says: {concealed:?}"
    );
    assert_eq!(
        world.kdf.jobs_started(),
        hashes + 1,
        "one dummy hash, as on every path that checks no password"
    );
}

#[tokio::test]
async fn another_address_is_not_throttled_by_the_first_ones_failures() {
    let world = World::new(throttle_only());
    let from_a = world.from(ADDRESS_A);
    let from_b = world.from(ADDRESS_B);
    wrong(&from_a).await;
    assert!(
        matches!(wrong(&from_b).await, FactorOutcome::InvalidCredential),
        "B has not failed yet"
    );
    assert_eq!(
        throttled_for(&wrong(&from_a).await),
        Some(Duration::from_secs(1))
    );
    assert_eq!(
        throttled_for(&wrong(&from_b).await),
        Some(Duration::from_secs(1)),
        "B's own count is one, not A's two"
    );
}

#[tokio::test]
async fn under_the_account_key_every_address_shares_the_delay() {
    let world = World::new(LockoutPolicy {
        throttle: Some(Throttle {
            key: ThrottleKey::Account,
            ..Throttle::default()
        }),
        ..throttle_only()
    });
    wrong(&world.from(ADDRESS_A)).await;
    assert_eq!(
        throttled_for(&wrong(&world.from(ADDRESS_B)).await),
        Some(Duration::from_secs(1))
    );
}

#[tokio::test]
async fn a_right_guess_clears_the_key() {
    let world = World::new(throttle_only());
    let from_a = world.from(ADDRESS_A);
    wrong(&from_a).await;
    world.advance_secs(1);
    wrong(&from_a).await;
    world.advance_secs(2);
    assert!(matches!(
        guess(&from_a, "Gnomes2+").await,
        FactorOutcome::Authenticated
    ));
    assert!(
        matches!(wrong(&from_a).await, FactorOutcome::InvalidCredential),
        "the first failure after a success is not delayed"
    );
    assert_eq!(
        throttled_for(&wrong(&from_a).await),
        Some(Duration::from_secs(1)),
        "and the count started over at one"
    );
}

#[tokio::test]
async fn the_per_account_lock_still_caps_everything() {
    let world = World::new(LockoutPolicy {
        max_attempts: 3,
        ..LockoutPolicy::default()
    });
    // Patient guessing from one address meets the lock.
    let from_a = world.from(ADDRESS_A);
    wrong(&from_a).await;
    world.advance_secs(1);
    wrong(&from_a).await;
    world.advance_secs(2);
    assert!(matches!(wrong(&from_a).await, FactorOutcome::Locked { .. }));
    // Once locked, the account is hidden at `begin_login` as an unknown
    // identifier is; the lock answers, not the throttle.
    let begun = from_a
        .begin_login("alice", "default", &test_session())
        .await
        .unwrap();
    assert!(
        matches!(begun, LoginOutcome::InvalidCredentials),
        "{begun:?}"
    );

    // Cycling addresses meets the same lock.
    let world = World::new(LockoutPolicy {
        max_attempts: 3,
        ..LockoutPolicy::default()
    });
    wrong(&world.from(ADDRESS_A)).await;
    wrong(&world.from(ADDRESS_B)).await;
    assert!(matches!(
        wrong(&world.from(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 3)))).await,
        FactorOutcome::Locked { .. }
    ));
}

#[tokio::test]
async fn without_throttle_rapid_wrong_guesses_are_only_wrong() {
    let world = World::new(throttle_only().without_throttle());
    let from_a = world.from(ADDRESS_A);
    for _ in 0..4 {
        assert!(matches!(
            wrong(&from_a).await,
            FactorOutcome::InvalidCredential
        ));
    }
    assert_eq!(world.identity.failed_attempts_for("u1"), 4);
}

#[tokio::test]
async fn an_unresolved_address_falls_back_to_the_account_and_logs_an_error_once() {
    let capture = TracingCapture::install();
    let world = World::new(throttle_only());
    let unresolved = world.unresolved();
    wrong(&unresolved).await;
    assert_eq!(
        throttled_for(&wrong(&world.unresolved()).await),
        Some(Duration::from_secs(1)),
        "every unresolved request shares the account's key"
    );
    world.advance_secs(1);
    wrong(&unresolved).await;
    let errors: Vec<_> = capture
        .events()
        .into_iter()
        .filter(|e| e.level == tracing::Level::ERROR && e.message.contains("client address"))
        .collect();
    assert_eq!(
        errors.len(),
        1,
        "the missing layer is reported once, not per request: {errors:?}"
    );
    assert!(
        errors[0].message.contains("axess::client_ip::layer"),
        "the error names the fix: {}",
        errors[0].message
    );
}

#[tokio::test]
async fn a_resolved_request_with_no_address_is_not_a_deployment_fault() {
    let capture = TracingCapture::install();
    let world = World::new(throttle_only());
    let no_peer = world.service.with_audit_context(AuditContext {
        ip_address: None,
        ip_source: Source::Peer,
        ..AuditContext::default()
    });
    wrong(&no_peer).await;
    assert!(throttled_for(&wrong(&no_peer).await).is_some());
    assert!(
        !capture.contains_at_level(tracing::Level::ERROR, "client address"),
        "the layer is installed; the transport had no address to give"
    );
}

#[tokio::test]
async fn prepare_factor_is_refused_while_throttled() {
    let world = World::new(throttle_only());
    let from_a = world.from(ADDRESS_A);
    wrong(&from_a).await;
    let session = test_session();
    from_a
        .begin_login("alice", "default", &session)
        .await
        .unwrap();
    let refused = from_a.prepare_factor(&session).await;
    assert!(
        matches!(
            refused,
            Err(AuthnError::Throttled { retry_after }) if retry_after == Duration::from_secs(1)
        ),
        "{refused:?}"
    );
}

#[tokio::test]
async fn a_throttled_refusal_is_audited_as_such() {
    let world = World::new(throttle_only());
    let from_a = world.from(ADDRESS_A);
    wrong(&from_a).await;
    wrong(&from_a).await;
    let throttled: Vec<_> = world
        .identity
        .events()
        .into_iter()
        .filter(|e| {
            e.error.as_ref().is_some_and(|r| r.as_str() == "throttled")
                && e.user_id == Some(uid("u1"))
                && e.tenant_id == Some(tenant())
        })
        .collect();
    assert_eq!(throttled.len(), 1, "{:?}", world.identity.events());
}

#[cfg(feature = "device")]
mod known_device {
    //! A session on a device the account has used is not throttled, as it
    //! is not locked: the delay keeps strangers out, not the owner.

    use super::*;
    use axess_core::authn::ids::DeviceId;
    use axess_core::device::types::{Device, FingerprintHash};
    use axess_core::testing::test_session_on_device;
    use axess_core::{DeviceStore, DeviceTrustLevel, MemoryDeviceStore};

    async fn seen_device(devices: &MemoryDeviceStore) -> DeviceId {
        let id = axess_core::authn::ids::testing::device("seen");
        let now = Utc::now();
        devices
            .save(
                &Device {
                    id,
                    tenant_id: tenant(),
                    user_id: Some(uid("u1")),
                    trust_level: DeviceTrustLevel::Seen,
                    fingerprint_hash: FingerprintHash::from_bytes([1; 32]),
                    first_seen_at: now,
                    last_seen_at: now,
                    revoked_at: None,
                    demoted_at: None,
                    bindings: Vec::new(),
                },
                now,
            )
            .await
            .expect("saved");
        id
    }

    #[tokio::test]
    async fn a_known_device_is_not_throttled() {
        let clock = MockClock::at(Utc.timestamp_opt(1_700_000_000, 0).unwrap());
        let identity = MockIdentityStore::new()
            .with_tenant(test_tenant())
            .with_user(test_user("u1", "alice"))
            .with_lockout_policy(throttle_only())
            .with_clock(clock.clone());
        let factors = MockFactorStore::new()
            .with_factor(user_scope(), password_config("Gnomes2+"))
            .with_method(&uid("u1"), password_method());
        let devices = MemoryDeviceStore::new();
        let device = seen_device(&devices).await;
        let service = AuthnService::builder(identity, factors)
            .with_clock(clock)
            .with_device_store(devices)
            .build()
            .with_audit_context(AuditContext {
                ip_address: Some(ADDRESS_A),
                ip_source: Source::Peer,
                ..AuditContext::default()
            });

        wrong(&service).await;
        assert!(throttled_for(&wrong(&service).await).is_some());

        let owner = test_session_on_device(device);
        service
            .begin_login("alice", "default", &owner)
            .await
            .unwrap();
        let verified = service
            .verify_factor(
                &FactorCredential::Password(ZeroizedString::new("Gnomes2+")),
                &owner,
            )
            .await
            .unwrap();
        assert!(
            matches!(verified, FactorOutcome::Authenticated),
            "{verified:?}"
        );
    }
}
