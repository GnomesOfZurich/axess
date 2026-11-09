#![cfg(feature = "testing")]
//! With a window set, an administrator whose authentication is older than it
//! cannot begin an impersonation; a recent one can.

mod common;

use axess_clock::{Clock, testing::MockClock};
use axess_core::authn::AuditContext;
use axess_core::authn::error::AuthnError;
use axess_core::authn::event::{AuthEventStatus, AuthEventType};
use axess_core::authn::service::AuthnService;
use axess_core::testing::AuthSessionTestExt;
use axess_core::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use common::{test_tenant, test_user};

#[tokio::test]
async fn an_impersonation_needs_a_recent_administrator_authentication_when_asked() {
    let clock = MockClock::now();
    let admin = test_user("admin", "ops");
    let target = test_user("u2", "bob");
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(admin.clone())
        .with_user(target.clone());
    let svc = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_clock(clock.clone())
        .with_impersonation_max_authn_age(std::time::Duration::from_secs(300))
        .build()
        .with_audit_context(AuditContext::default());
    let stale = test_session();
    stale
        .set_authenticated(
            admin.id,
            admin.tenant_id,
            clock.now() - chrono::Duration::minutes(10),
        )
        .await;

    let res = svc.begin_impersonation(&admin, &target, &stale).await;

    assert!(matches!(res, Err(AuthnError::NoFlow)), "{res:?}");
    assert!(stale.impersonator().await.is_none());
    assert!(
        identity.events().iter().any(|e| {
            e.event_type == AuthEventType::Impersonation
                && e.event_status == AuthEventStatus::Failure
                && e.error
                    .as_ref()
                    .is_some_and(|r| r.to_string() == "authn_too_old")
        }),
        "the refusal is audited"
    );

    let fresh = test_session();
    fresh
        .set_authenticated(
            admin.id,
            admin.tenant_id,
            clock.now() - chrono::Duration::minutes(1),
        )
        .await;
    svc.begin_impersonation(&admin, &target, &fresh)
        .await
        .expect("a minute-old authentication is recent enough");
}
