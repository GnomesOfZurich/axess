#![cfg(feature = "testing")]
//! A counter outage does not switch the per-key guess throttle off.

mod common;

use axess_clock::testing::MockClock;
use axess_core::authn::AuditContext;
use axess_core::authn::factor::{FactorCredential, ZeroizedString};
use axess_core::authn::service::{AuthnService, FactorOutcome, LoginOutcome, RequestAuthnService};
use axess_core::authn::types::{CounterUnavailable, LockoutPolicy};
use axess_core::blocking::KdfExecutor;
use axess_core::testing::mock_authn::{MockFactorStore, MockIdentityStore};
use axess_core::testing::test_session;
use chrono::{TimeZone, Utc};
use common::{password_config, password_method, test_tenant, test_user, uid, user_scope};

type Svc = RequestAuthnService<MockIdentityStore, MockFactorStore>;

fn rig(policy: LockoutPolicy) -> (Svc, MockIdentityStore) {
    let clock = MockClock::at(Utc.timestamp_opt(1_700_000_000, 0).unwrap());
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"))
        .with_lockout_policy(policy)
        .with_clock(clock.clone());
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config("Gnomes2+"))
        .with_method(&uid("u1"), password_method());
    let svc = AuthnService::builder(identity.clone(), factors)
        .with_clock(clock)
        .with_kdf_executor(std::sync::Arc::new(KdfExecutor::inline()))
        .build()
        .with_audit_context(AuditContext::default());
    (svc, identity)
}

#[tokio::test]
async fn a_counter_outage_under_allow_still_builds_the_throttle_delay() {
    let (svc, identity) = rig(LockoutPolicy {
        max_attempts: 100,
        on_counter_unavailable: CounterUnavailable::Allow,
        ..LockoutPolicy::default()
    });
    identity.arm_record_failed_attempt_failure();
    let guess = || async {
        let session = test_session();
        let begun = svc.begin_login("alice", "default", &session).await.unwrap();
        assert!(
            matches!(begun, LoginOutcome::FactorRequired(_)),
            "{begun:?}"
        );
        svc.verify_factor(
            &FactorCredential::Password(ZeroizedString::new("wrong")),
            &session,
        )
        .await
        .unwrap()
    };

    assert!(matches!(guess().await, FactorOutcome::InvalidCredential));
    let second = guess().await;

    assert!(
        matches!(second, FactorOutcome::Throttled { .. }),
        "the throttle fails on its own terms while the counter is down: {second:?}"
    );
}
