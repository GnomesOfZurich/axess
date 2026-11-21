#![cfg(feature = "testing")]
//! A tenant's lockout policy past a bound is served under the bound: a
//! lockout asked to last longer than the longest allowed ends at the bound,
//! and the service reports the fault once, however many requests read it.

use axess_clock::testing::Shift;
use axess_core::testing::fixtures as common;

use axess_clock::testing::MockClock;
use axess_core::authn::AuditContext;
use axess_core::authn::factor::{FactorCredential, ZeroizedString};
use axess_core::authn::service::{AuthnService, FactorOutcome, LoginOutcome, RequestAuthnService};
use axess_core::authn::types::LockoutPolicy;
use axess_core::session::AuthSession;
use axess_core::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use axess_testing::mock_tracing::TracingCapture;
use common::{password_config, password_method, test_tenant, test_user, uid, user_scope};
use std::time::Duration;

type Service = RequestAuthnService<MockIdentityStore, MockFactorStore>;

/// A service whose tenant locks after one wrong password for longer than
/// the longest lockout allowed.
fn service(clock: &MockClock) -> Service {
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"))
        .with_lockout_policy(
            LockoutPolicy {
                max_attempts: 1,
                duration: Some(Duration::MAX),
                ..LockoutPolicy::default()
            }
            .without_throttle(),
        );
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config("Sample2+"))
        .with_method(&uid("u1"), password_method());
    AuthnService::builder(identity, factors)
        .with_clock(clock.clone())
        .build()
        .with_audit_context(AuditContext::default())
}

fn pw(password: &str) -> FactorCredential {
    FactorCredential::Password(ZeroizedString::new(password))
}

/// A login flow for `alice` begun now, at the password step.
async fn begun(svc: &Service) -> AuthSession {
    let session = test_session();
    let outcome = svc
        .begin_login("alice", "default", &session)
        .await
        .expect("begin_login");
    assert!(
        matches!(outcome, LoginOutcome::FactorRequired(_)),
        "{outcome:?}"
    );
    session
}

/// The fault is counted after the first request that reads the policy and
/// again after three more, so a service that reports it on every read but
/// the first (or on every read) fails at one of the two counts, however
/// many times each request reads it.
#[tokio::test]
async fn a_lockout_past_the_bound_ends_at_the_bound_and_the_fault_is_reported_once() {
    let clock = common::test_clock();
    let capture = TracingCapture::install();
    let svc = service(&clock);
    let reported = || {
        capture
            .events()
            .iter()
            .filter(|e| {
                e.level == tracing::Level::ERROR
                    && e.message.contains("lockout policy is past a bound")
            })
            .count()
    };
    // Flows begun before the lock, so the verify gate (which names the
    // lock and its end) answers the right password afterwards.
    let mut early = Vec::new();
    for _ in 0..3 {
        early.push(begun(&svc).await);
    }
    let session = begun(&svc).await;
    let first = svc.verify_factor(&pw("wrong"), &session).await;
    assert!(
        !matches!(first, Ok(FactorOutcome::Authenticated)),
        "a wrong password is refused: {first:?}"
    );
    assert_eq!(
        reported(),
        1,
        "reported at the first request that read the policy: {:?}",
        capture.events()
    );
    let bound = axess_clock::SignedDuration::try_from(LockoutPolicy::MAX_DURATION).expect("fits");
    let until = Some(common::start().plus(bound));
    for session in &early {
        let refused = svc
            .verify_factor(&pw("Sample2+"), session)
            .await
            .expect("verify_factor");
        assert!(
            matches!(refused, FactorOutcome::Locked { until: u } if u == until.map(axess_clock::Until::At)),
            "the right password on a locked account answers Locked until the bound \
             ({until:?}): {refused:?}"
        );
    }
    assert_eq!(
        reported(),
        1,
        "reported once per service, not again by the three later requests: {:?}",
        capture.events()
    );
}
