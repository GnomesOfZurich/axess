//! The impersonation rig shared by the impersonation test files: a service
//! over the mock stores with an administrator and a target, a session that
//! impersonates, and readers of the audit rows it writes.

use axess_clock::{Clock, testing::MockClock};
use axess_core::authn::AuditContext;
use axess_core::authn::event::{AuthEventStatus, AuthEventType};
use axess_core::authn::service::{AuthnService, RequestAuthnService};
use axess_core::session::extractor::AuthSession;
use axess_core::testing::AuthSessionTestExt;
use axess_core::testing::fixtures as common;
use axess_core::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use common::{test_tenant, test_user};

pub type Svc = RequestAuthnService<MockIdentityStore, MockFactorStore>;

pub struct Rig {
    pub svc: Svc,
    pub identity: MockIdentityStore,
    pub clock: MockClock,
    pub admin: axess_core::authn::types::User,
    pub target: axess_core::authn::types::User,
}

pub fn rig_with(configure: impl FnOnce(AuthnServiceBuilder) -> AuthnServiceBuilder) -> Rig {
    let clock = common::test_clock();
    let admin = test_user("admin", "ops");
    let target = test_user("u2", "bob");
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(admin.clone())
        .with_user(target.clone());
    let builder =
        AuthnService::builder(identity.clone(), MockFactorStore::new()).with_clock(clock.clone());
    let svc = configure(builder)
        .build()
        .with_audit_context(AuditContext::default());
    Rig {
        svc,
        identity,
        clock,
        admin,
        target,
    }
}

pub type AuthnServiceBuilder =
    axess_core::authn::service::AuthnServiceBuilder<MockIdentityStore, MockFactorStore>;
pub fn rig() -> Rig {
    rig_with(|b| b)
}

/// The admin's own authenticated session, impersonating the target.
pub async fn impersonating(r: &Rig) -> AuthSession {
    let session = test_session();
    session
        .set_authenticated(r.admin.id, r.admin.tenant_id, r.clock.now())
        .await;
    r.svc
        .begin_impersonation(&r.admin, &r.target, &session)
        .await
        .expect("the admin impersonates the target");
    assert_eq!(session.user_id().await, Some(r.target.id));
    assert_eq!(session.impersonator().await, Some(r.admin.id));
    session
}
pub fn rows(
    identity: &MockIdentityStore,
    kind: AuthEventType,
) -> Vec<axess_core::authn::event::AuthEvent> {
    identity
        .events()
        .into_iter()
        .filter(|e| e.event_type == kind)
        .collect()
}

/// The `Impersonation` failure rows carrying `reason`.
pub fn refusals(
    identity: &MockIdentityStore,
    reason: &str,
) -> Vec<axess_core::authn::event::AuthEvent> {
    rows(identity, AuthEventType::Impersonation)
        .into_iter()
        .filter(|e| {
            e.event_status == AuthEventStatus::Failure
                && e.error.as_ref().is_some_and(|r| r.to_string() == reason)
        })
        .collect()
}
