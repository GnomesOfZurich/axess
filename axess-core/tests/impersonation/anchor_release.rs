//! The administrator's anchor entry of an impersonation that does not stand:
//! a release that fails is reported even when the refusal row fails too, and
//! an impersonation dropped before it stands ends the entries it registered.

use axess_core::session::SessionKey;
use axess_core::testing::fixtures as common;

use axess_clock::Clock;
use axess_core::authn::error::AuthnError;
use axess_core::testing::AuthSessionTestExt;
use axess_core::testing::registry_double::{RegistryCall, RegistryDouble, RegistryOp, Step};
use axess_core::testing::test_session;
use axess_testing::stall::Gate;
use common::test_user;

use super::fixture::*;

/// A registry that takes the administrator's anchor entry, refuses the
/// target's session, and cannot end anything: the shape of a registry that
/// went down between the two writes.
fn unreleasing_registry(admin: axess_core::authn::UserId) -> RegistryDouble {
    RegistryDouble::new().before(move |call, _| async move {
        match call {
            RegistryCall::Register { user, .. } if user == admin => Step::Forward,
            RegistryCall::Register { .. }
            | RegistryCall::InvalidateUser { .. }
            | RegistryCall::InvalidateSession { .. } => Step::Fail("registry unreachable"),
            _ => Step::Forward,
        }
    })
}

/// When the anchor entry of a failed impersonation cannot be ended, the
/// caller is told so, by an error naming the anchor, not by the refusal
/// alone: the entry may still count against the administrator's sessions
/// and an operator has to end it.
#[tokio::test]
async fn a_failed_impersonation_whose_anchor_was_not_released_says_so() {
    let admin = test_user("admin", "ops").id;
    let r = rig_with(|b| b.with_registry(unreleasing_registry(admin)));
    let session = test_session();
    session
        .set_authenticated(r.admin.id, r.admin.tenant_id, r.clock.now())
        .await;

    let res = r
        .svc
        .begin_impersonation(&r.admin, &r.target, &session)
        .await;

    assert!(
        matches!(&res, Err(AuthnError::ExternalService(m)) if m.contains("anchor")),
        "the caller was not told the anchor is still registered: {res:?}"
    );
    assert_eq!(
        session.impersonator().await,
        None,
        "the session was cleared"
    );
}

/// When the registry refuses the registration, the anchor cannot be ended
/// and the refusal's own row cannot be written either, the caller is still
/// told the anchor may be registered: the audit failure is logged beside
/// it, not returned in its place.
#[tokio::test]
async fn an_unreleased_anchor_is_reported_when_the_refusal_row_fails_too() {
    let admin = test_user("admin", "ops").id;
    let r = rig_with(|b| b.with_registry(unreleasing_registry(admin)));
    let session = test_session();
    session
        .set_authenticated(r.admin.id, r.admin.tenant_id, r.clock.now())
        .await;
    r.identity.arm_record_event_failure();

    let res = r
        .svc
        .begin_impersonation(&r.admin, &r.target, &session)
        .await;

    assert!(
        matches!(&res, Err(AuthnError::ExternalService(m)) if m.contains("anchor")),
        "the anchor state is hidden behind the audit error: {res:?}"
    );
}

/// A registry that takes the administrator's anchor entry and then never
/// answers the target's registration, parked on `gate`.
fn stalling_registry(admin: axess_core::authn::UserId, gate: Gate) -> RegistryDouble {
    RegistryDouble::new().before(move |call, _| {
        let gate = gate.clone();
        async move {
            match call {
                RegistryCall::Register { user, .. } if user != admin => {
                    gate.wait().await;
                    Step::Hang
                }
                _ => Step::Forward,
            }
        }
    })
}

/// The entries `registry` was asked to take (`op` [`RegistryOp::Register`])
/// or to end ([`RegistryOp::InvalidateSession`]).
fn entries(
    registry: &RegistryDouble,
    op: RegistryOp,
) -> Vec<(axess_core::authn::UserId, SessionKey)> {
    registry
        .calls()
        .into_iter()
        .filter(|call| call.op() == op)
        .filter_map(|call| Some((*call.user(), *call.session()?)))
        .collect()
}

/// An impersonation whose future is dropped after the administrator's
/// anchor entry was registered (a client that hangs up, a timeout) ends
/// that entry and the target's session on a task of its own: nothing it
/// registered outlives the call that did not finish.
#[tokio::test]
async fn a_dropped_impersonation_ends_the_entries_it_registered() {
    let admin = test_user("admin", "ops").id;
    let gate = Gate::new();
    let registry = stalling_registry(admin, gate.clone());
    let r = rig_with(|b| b.with_registry(registry.clone()));
    let session = test_session();
    session
        .set_authenticated(r.admin.id, r.admin.tenant_id, r.clock.now())
        .await;

    let (svc, admin_user, target) = (r.svc.clone(), r.admin.clone(), r.target.clone());
    let call = session.clone();
    let handle =
        tokio::spawn(async move { svc.begin_impersonation(&admin_user, &target, &call).await });
    axess_testing::stall::abort_inside(&gate, handle).await;

    let taken = entries(&registry, RegistryOp::Register);
    assert_eq!(
        taken.len(),
        2,
        "the anchor and the target's session: {taken:?}"
    );
    let all_ended = axess_testing::stall::eventually(|| {
        let ended = entries(&registry, RegistryOp::InvalidateSession);
        let taken = taken.clone();
        async move { taken.iter().all(|t| ended.contains(t)) }
    })
    .await;
    assert!(
        all_ended,
        "an entry outlived the dropped impersonation: taken {:?}, ended {:?}",
        taken,
        entries(&registry, RegistryOp::InvalidateSession)
    );
}
