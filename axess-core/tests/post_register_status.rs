#![cfg(feature = "testing")]
//! The account status read again after a session is registered answers as
//! the check before the factor step does for the same state, and leaves the
//! same audit row: a suspension is `Locked` with a locked row, any other
//! state that may not log in is `NotActive` with a failed row naming
//! `not_active`, on either path.

use axess_core::testing::fixtures as common;

use axess_clock::testing::MockClock;
use axess_core::authn::AuditContext;
use axess_core::authn::error::AuthnError;
use axess_core::authn::event::{AuthEvent, AuthEventStatus, AuthEventType, AuthFailureReason};
use axess_core::authn::factor::{FactorCredential, ZeroizedString};
use axess_core::authn::service::{AuthnService, FactorOutcome};
use axess_core::authn::types::{EntityState, StatusDetail, User};
use axess_core::session::store::{MemorySessionRegistry, SessionRegistry};
use axess_core::testing::registry_double::{RegistryDouble, RegistryOp, Step};
use axess_core::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use common::{password_config, password_method, start, test_tenant, test_user, uid, user_scope};

/// A registry that puts `user` (with its new status) into the identity
/// store the moment a session is registered: after the check before the
/// step read `Active`, before the status is read again.
fn status_changing_registry(
    inner: MemorySessionRegistry,
    identity: MockIdentityStore,
    user: User,
) -> RegistryDouble {
    RegistryDouble::over(inner).before(move |call, _| {
        if call.op() == RegistryOp::Register {
            let _ = identity.clone().with_user(user.clone());
        }
        async { Step::Forward }
    })
}

/// Log in with the right password while the account moves to `status` at
/// the register; the verify's answer and the rows written.
async fn login_while_status_becomes(
    clock: &MockClock,
    status: EntityState,
) -> (
    Result<FactorOutcome, AuthnError<axess_core::testing::mock_authn::MockStoreError>>,
    Vec<axess_core::authn::event::AuthEvent>,
    MemorySessionRegistry,
) {
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config("Sample2+"))
        .with_method(&uid("u1"), password_method());
    let registry = MemorySessionRegistry::new().with_clock(std::sync::Arc::new(clock.clone()));
    let mut changed = test_user("u1", "alice");
    changed.status = status;
    let svc = AuthnService::builder(identity.clone(), factors)
        .with_clock(clock.clone())
        .with_registry(status_changing_registry(
            registry.clone(),
            identity.clone(),
            changed,
        ))
        .allow_plaintext_factor_secrets()
        .build()
        .with_audit_context(AuditContext::default());
    let session = test_session();
    svc.begin_login("alice", "default", &session).await.unwrap();
    let identity_events_before = identity.events().len();
    let cred = FactorCredential::Password(ZeroizedString::new("Sample2+"));
    let result = svc.verify_factor(&cred, &session).await;
    assert!(!session.is_authenticated().await, "the session is cleared");
    let rows = identity.events().split_off(identity_events_before);
    (result, rows, registry)
}

#[tokio::test]
async fn a_suspension_at_the_register_is_locked_with_a_locked_row() {
    let clock = common::test_clock();
    let held = StatusDetail::administrative("hold", start());
    let (result, rows, registry) =
        login_while_status_becomes(&clock, EntityState::Suspended(held)).await;
    assert!(
        matches!(result, Ok(FactorOutcome::Locked { until: None })),
        "{result:?}"
    );
    assert!(
        rows.iter()
            .any(|e| e.event_status == AuthEventStatus::Locked),
        "the refusal after the register leaves the locked row the check before the step does: {rows:?}"
    );
    let Ok(held) = registry.active_sessions(&uid("u1")).await;
    assert!(held.is_empty(), "the session is revoked");
}

#[tokio::test]
async fn another_inactive_state_at_the_register_is_not_active_with_a_failed_row() {
    let clock = common::test_clock();
    let ended = StatusDetail::closure("closed", start());
    let (result, rows, registry) =
        login_while_status_becomes(&clock, EntityState::Terminated(ended)).await;
    assert!(
        matches!(
            result,
            Err(AuthnError::NotActive(EntityState::Terminated(_)))
        ),
        "the check before the step answers NotActive for this state: {result:?}"
    );
    assert!(
        rows.iter()
            .any(|e| e.event_status == AuthEventStatus::Failure
                && e.error == Some(AuthFailureReason::NotActive)),
        "the refusal after the register leaves a row naming it: {rows:?}"
    );
    let Ok(held) = registry.active_sessions(&uid("u1")).await;
    assert!(held.is_empty(), "the session is revoked");
}

/// The shape of a refusal row both paths must agree on.
fn refusal_shape(
    rows: &[AuthEvent],
) -> Vec<(AuthEventType, AuthEventStatus, Option<AuthFailureReason>)> {
    rows.iter()
        .filter(|e| e.event_status != AuthEventStatus::Success)
        .map(|e| {
            (
                e.event_type.clone(),
                e.event_status.clone(),
                e.error.clone(),
            )
        })
        .collect()
}

/// The account is closed after `begin_login` and before the password: the
/// check before the step refuses it as `NotActive` and writes the failed
/// row naming `not_active`, the same row the read after the register writes
/// for the same state.
#[tokio::test]
async fn an_account_closed_before_the_step_is_not_active_with_the_same_row() {
    let clock = common::test_clock();
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config("Sample2+"))
        .with_method(&uid("u1"), password_method());
    let svc = AuthnService::builder(identity.clone(), factors)
        .with_clock(clock.clone())
        .allow_plaintext_factor_secrets()
        .build()
        .with_audit_context(AuditContext::default());
    let session = test_session();
    svc.begin_login("alice", "default", &session).await.unwrap();
    let mut closed = test_user("u1", "alice");
    closed.status = EntityState::Terminated(StatusDetail::closure("closed", start()));
    let _ = identity.clone().with_user(closed);
    let before = identity.events().len();
    let cred = FactorCredential::Password(ZeroizedString::new("Sample2+"));
    let result = svc.verify_factor(&cred, &session).await;
    assert!(
        matches!(
            result,
            Err(AuthnError::NotActive(EntityState::Terminated(_)))
        ),
        "{result:?}"
    );
    let rows = identity.events().split_off(before);
    let before_step = refusal_shape(&rows);
    assert_eq!(
        before_step,
        vec![(
            AuthEventType::FactorVerified,
            AuthEventStatus::Failure,
            Some(AuthFailureReason::NotActive)
        )],
        "the check before the step writes one failed row naming not_active: {rows:?}"
    );

    let ended = StatusDetail::closure("closed", start());
    let (_, rows, _) = login_while_status_becomes(&clock, EntityState::Terminated(ended)).await;
    assert_eq!(
        refusal_shape(&rows),
        before_step,
        "the read after the register writes the same row: {rows:?}"
    );
}
