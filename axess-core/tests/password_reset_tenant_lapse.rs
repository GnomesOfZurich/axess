#![cfg(feature = "testing")]
//! A tenant's timed suspension bars a password reset while it runs and not
//! once it has run out, through the plain and the tenant-scoped entry
//! points alike, with the boundary read from the service's own clock.

use axess_clock::testing::Shift;
use axess_core::testing::fixtures as common;

use axess_clock::SignedDuration as ChronoDuration;
use axess_clock::Timestamp;
use axess_clock::testing::MockClock;
use axess_core::authn::AuditContext;
use axess_core::authn::service::{AuthnService, RequestAuthnService};
use axess_core::authn::types::{EntityState, StatusDetail, Tenant};
use axess_core::testing::mock_authn::{MockFactorStore, MockIdentityStore};
use common::{test_tenant, test_user, tid, uid};
use std::time::Duration;

const TTL: Duration = Duration::from_secs(300);
const NEW_PASSWORD: &str = "Another-password-2";

/// The end of the suspension every test is built around.
fn until() -> Timestamp {
    Timestamp::from_utc(2026, 3, 1, 12, 0, 0).unwrap()
}

/// The fixture tenant, suspended by an administrator two days before
/// [`until`] and until then.
fn suspended_tenant() -> Tenant {
    let mut tenant = test_tenant();
    tenant.status = EntityState::Suspended(
        StatusDetail::administrative("hold", until().minus(ChronoDuration::days(2)))
            .with_until(Some(axess_clock::Until::At(until()))),
    );
    tenant
}

/// A service over the suspended tenant and the user `alice`, reading `clock`.
fn service(clock: &MockClock) -> RequestAuthnService<MockIdentityStore, MockFactorStore> {
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(suspended_tenant())
        .with_user(test_user("u1", "alice"));
    AuthnService::builder(identity, MockFactorStore::new())
        .with_clock(clock.clone())
        .build()
        .with_audit_context(AuditContext::default())
}

async fn begin(svc: &RequestAuthnService<MockIdentityStore, MockFactorStore>) -> Option<String> {
    svc.begin_password_reset("alice", "default", TTL)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_lapsed_tenant_suspension_does_not_refuse_a_reset() {
    let clock = MockClock::at(until().plus(ChronoDuration::hours(1)));
    let svc = service(&clock);

    let token = begin(&svc)
        .await
        .expect("a lapsed suspension no longer bars the tenant");
    let done = svc
        .complete_password_reset(&uid("u1"), &token, NEW_PASSWORD)
        .await
        .unwrap();

    assert!(
        done,
        "the reset completes in a tenant whose suspension ended"
    );
}

#[tokio::test]
async fn an_active_tenant_suspension_refuses_to_begin_a_reset() {
    let clock = MockClock::at(until().minus(ChronoDuration::hours(1)));
    let svc = service(&clock);

    assert!(
        begin(&svc).await.is_none(),
        "a suspension still running bars the tenant from a reset"
    );
}

/// A token issued while the tenant was active is refused once the tenant is
/// suspended again, and is not spent by the refusal. The mock store holds
/// one tenant row, so the clock is what moves the tenant between the two
/// states: forward past the end of the suspension to issue the token, back
/// inside it to try the token.
#[tokio::test]
async fn an_active_tenant_suspension_refuses_to_complete_a_reset() {
    let clock = MockClock::at(until().plus(ChronoDuration::hours(1)));
    let svc = service(&clock);
    let token = begin(&svc)
        .await
        .expect("issued while the tenant is active");

    clock.set(until().minus(ChronoDuration::hours(1)));
    let refused = svc
        .complete_password_reset(&uid("u1"), &token, NEW_PASSWORD)
        .await
        .unwrap();
    assert!(!refused, "a suspension still running refuses the reset");

    clock.set(until().plus(ChronoDuration::hours(1)));
    let done = svc
        .complete_password_reset(&uid("u1"), &token, NEW_PASSWORD)
        .await
        .unwrap();
    assert!(done, "the refusal did not spend the token");
}

#[tokio::test]
async fn the_tenant_scoped_reset_completes_once_the_suspension_has_lapsed() {
    let clock = MockClock::at(until().plus(ChronoDuration::hours(1)));
    let svc = service(&clock);
    let token = begin(&svc)
        .await
        .expect("a lapsed suspension no longer bars the tenant");

    let done = svc
        .complete_password_reset_in_tenant(&uid("u1"), &tid("t1"), &token, NEW_PASSWORD)
        .await
        .unwrap();

    assert!(
        done,
        "the tenant-scoped reset completes in a tenant whose suspension ended"
    );
}

#[tokio::test]
async fn the_tenant_scoped_reset_is_refused_while_the_suspension_is_active() {
    let clock = MockClock::at(until().plus(ChronoDuration::hours(1)));
    let svc = service(&clock);
    let token = begin(&svc)
        .await
        .expect("issued while the tenant is active");

    clock.set(until().minus(ChronoDuration::hours(1)));
    let refused = svc
        .complete_password_reset_in_tenant(&uid("u1"), &tid("t1"), &token, NEW_PASSWORD)
        .await
        .unwrap();

    assert!(
        !refused,
        "a suspension still running refuses the tenant-scoped reset"
    );
}

/// `effective_at` reads a suspension whose `until` has passed as over, and
/// `until` itself has passed: the first instant the tenant is active again
/// is `until`, not the instant after it.
#[tokio::test]
async fn the_suspension_is_over_at_the_instant_it_ends() {
    let clock = MockClock::at(until());
    let svc = service(&clock);

    let token = begin(&svc)
        .await
        .expect("at until the suspension has ended and the reset begins");
    let done = svc
        .complete_password_reset_in_tenant(&uid("u1"), &tid("t1"), &token, NEW_PASSWORD)
        .await
        .unwrap();

    assert!(
        done,
        "at until the suspension has ended and the reset completes"
    );
}

/// One second before `until` the suspension still runs.
#[tokio::test]
async fn the_suspension_still_runs_a_second_before_it_ends() {
    let clock = MockClock::at(until().minus(ChronoDuration::seconds(1)));
    let svc = service(&clock);

    assert!(
        begin(&svc).await.is_none(),
        "one second before until the suspension still bars the tenant"
    );
}
