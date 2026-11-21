//! The refusals of an impersonation and the gaps around them: who may not
//! impersonate whom, the audit row each refusal writes, and the session
//! entries a refused impersonation leaves behind.

use axess_clock::testing::Shift;
use axess_core::session::SessionKey;
use axess_core::testing::fixtures as common;

use axess_clock::Clock;
use axess_core::authn::AuditContext;
use axess_core::authn::error::AuthnError;
use axess_core::authn::service::AuthnService;
use axess_core::authn::store::{IdentityAdmin as _, IdentityLookup as _};
use axess_core::testing::AuthSessionTestExt;
use axess_core::testing::registry_double::{RegistryCall, RegistryDouble, RegistryOp, Step};
use axess_core::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use common::{test_tenant, test_user};

use super::fixture::*;

// ── The gaps around the refusals ────────────────────────────────────────────

/// A registry that refuses every registration but the administrator's when
/// `admin` names one.
fn refusing_registry(admin: Option<axess_core::authn::UserId>) -> RegistryDouble {
    RegistryDouble::new().before(move |call, _| async move {
        match call {
            RegistryCall::Register { user, .. } if Some(user) != admin => {
                Step::Fail("registry unreachable")
            }
            _ => Step::Forward,
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

/// An impersonation the registry would not take is refused and the session
/// ended, and the refusal leaves a failed audit row.
#[tokio::test]
async fn a_registry_that_refuses_the_session_leaves_a_failed_row() {
    let r = rig_with(|b| b.with_registry(refusing_registry(None)));
    let session = test_session();
    session
        .set_authenticated(r.admin.id, r.admin.tenant_id, r.clock.now())
        .await;

    let res = r
        .svc
        .begin_impersonation(&r.admin, &r.target, &session)
        .await;

    assert!(matches!(res, Err(AuthnError::NoFlow)), "{res:?}");
    assert!(!session.is_authenticated().await, "the session is ended");
    let refused = refusals(&r.identity, "session_not_registered");
    assert_eq!(refused.len(), 1, "the refusal is audited");
    assert_eq!(refused[0].user_id, Some(r.target.id));
    assert_eq!(refused[0].actor_id, Some(r.admin.id));
}

/// A refusal made before the target is read from the store names no
/// target: the caller's `User` value is whatever the caller built, and a
/// failed row carrying its ids would put a chosen user and tenant on the
/// trail.
#[tokio::test]
async fn a_refusal_before_the_target_is_read_names_no_target() {
    let r = rig();
    let invented = common::test_user_in_tenant("u77", "ghost", "t9");

    let res = r
        .svc
        .begin_impersonation_across_tenants(&r.admin.id, &invented, &test_session())
        .await;
    assert!(matches!(res, Err(AuthnError::NoFlow)), "{res:?}");
    let other = test_session();
    other
        .set_authenticated(r.target.id, r.target.tenant_id, r.clock.now())
        .await;
    let res = r
        .svc
        .begin_impersonation_across_tenants(&r.admin.id, &invented, &other)
        .await;
    assert!(matches!(res, Err(AuthnError::NoFlow)), "{res:?}");

    for reason in ["admin_not_authenticated", "session_is_not_admin"] {
        let rows = refusals(&r.identity, reason);
        assert_eq!(rows.len(), 1, "{reason}");
        assert_eq!(rows[0].actor_id, Some(r.admin.id), "{reason}");
        assert_eq!(rows[0].user_id, None, "{reason}: no target was read");
        assert_eq!(rows[0].tenant_id, None, "{reason}: no tenant was read");
    }
}

/// An administrator the store does not hold is refused before the target
/// is read, and the row names no target on the same terms: the caller's
/// record of the target is not a stored one.
#[tokio::test]
async fn an_unknown_admin_is_refused_with_a_row_naming_no_target() {
    let r = rig();
    let ghost = common::test_user_in_tenant("u88", "ghost-admin", "t9");
    let session = test_session();
    session
        .set_authenticated(ghost.id, ghost.tenant_id, r.clock.now())
        .await;

    let res = r.svc.begin_impersonation(&ghost, &r.target, &session).await;

    assert!(matches!(res, Err(AuthnError::NoFlow)), "{res:?}");
    let rows = refusals(&r.identity, "unknown_admin");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].user_id, None, "no target was read");
    assert_eq!(rows[0].tenant_id, None);
    assert_eq!(rows[0].actor_id, Some(ghost.id));
}

/// An unknown target is refused with a row that names no target either:
/// there is no stored user to name, and the caller's record is not one.
#[tokio::test]
async fn an_unknown_target_is_not_named_from_the_callers_record() {
    let r = rig();
    let invented = common::test_user_in_tenant("u77", "ghost", "t9");
    let session = test_session();
    session
        .set_authenticated(r.admin.id, r.admin.tenant_id, r.clock.now())
        .await;

    let res = r
        .svc
        .begin_impersonation(&r.admin, &invented, &session)
        .await;

    assert!(matches!(res, Err(AuthnError::CrossTenant)), "{res:?}");
    let rows = refusals(&r.identity, "unknown_target");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].user_id, None, "no stored target to name");
    assert_eq!(rows[0].tenant_id, None);
    assert_eq!(rows[0].actor_id, Some(r.admin.id));
}

/// A timed suspension of the tenant that has lapsed no longer blocks, as it
/// does not at a login: the status is read as of the service's clock.
#[tokio::test]
async fn a_tenant_whose_timed_suspension_has_lapsed_admits_an_impersonation() {
    use axess_core::authn::types::{EntityState, StatusDetail};
    let clock = common::test_clock();
    let admin = test_user("admin", "ops");
    let target = test_user("u2", "bob");
    let mut tenant = test_tenant();
    tenant.status = EntityState::Suspended(
        StatusDetail::administrative(
            "hold",
            clock.now().minus(axess_clock::SignedDuration::hours(2)),
        )
        .with_until(Some(axess_clock::Until::At(
            clock.now().minus(axess_clock::SignedDuration::hours(1)),
        ))),
    );
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(tenant)
        .with_user(admin.clone())
        .with_user(target.clone());
    let svc = AuthnService::builder(identity, MockFactorStore::new())
        .with_clock(clock.clone())
        .build()
        .with_audit_context(AuditContext::default());
    let session = test_session();
    session
        .set_authenticated(admin.id, admin.tenant_id, clock.now())
        .await;

    let res = svc.begin_impersonation(&admin, &target, &session).await;

    assert!(res.is_ok(), "{res:?}");
    assert_eq!(session.impersonator().await, Some(admin.id));
}

/// A tenant that does not load is neither a cross-tenant attempt nor in a
/// state: it is unknown, and the impersonation is refused.
#[tokio::test]
async fn a_tenant_that_does_not_load_refuses_an_impersonation_as_unknown() {
    let clock = common::test_clock();
    let admin = test_user("admin", "ops");
    let target = test_user("u2", "bob");
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_user(admin.clone())
        .with_user(target.clone());
    let svc = AuthnService::builder(identity, MockFactorStore::new())
        .with_clock(clock.clone())
        .build()
        .with_audit_context(AuditContext::default());
    let session = test_session();
    session
        .set_authenticated(admin.id, admin.tenant_id, clock.now())
        .await;

    let res = svc.begin_impersonation(&admin, &target, &session).await;

    assert!(matches!(res, Err(AuthnError::UnknownTenant)), "{res:?}");
    assert_eq!(session.impersonator().await, None);
}

/// A suspended administrator with a session that is still open cannot
/// take another identity through it.
/// The tenant's status gates impersonation as it gates a login: no one is
/// impersonated into a suspended tenant.
#[tokio::test]
async fn no_one_is_impersonated_into_a_suspended_tenant() {
    use axess_core::authn::types::{EntityState, StatusDetail};
    let clock = common::test_clock();
    let admin = test_user("admin", "ops");
    let target = test_user("u2", "bob");
    let mut tenant = test_tenant();
    tenant.status = EntityState::Suspended(StatusDetail::administrative("hold", clock.now()));
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(tenant)
        .with_user(admin.clone())
        .with_user(target.clone());
    let svc = AuthnService::builder(identity, MockFactorStore::new())
        .with_clock(clock.clone())
        .build()
        .with_audit_context(AuditContext::default());
    let session = test_session();
    session
        .set_authenticated(admin.id, admin.tenant_id, clock.now())
        .await;

    let res = svc.begin_impersonation(&admin, &target, &session).await;

    assert!(matches!(res, Err(AuthnError::NotActive(_))), "{res:?}");
    assert_eq!(session.impersonator().await, None);
    assert_eq!(
        session.user_id().await,
        Some(admin.id),
        "the session stays the admin's"
    );
}

#[tokio::test]
async fn a_suspended_admin_cannot_impersonate() {
    use axess_core::authn::types::{EntityState, StatusDetail};
    let r = rig();
    let session = test_session();
    session
        .set_authenticated(r.admin.id, r.admin.tenant_id, r.clock.now())
        .await;
    r.identity
        .suspend_user(
            &r.admin.id,
            StatusDetail::administrative("offboarded", r.clock.now()),
        )
        .await
        .unwrap();
    assert!(matches!(
        r.identity.account_status(&r.admin.id).await.unwrap(),
        EntityState::Suspended(_)
    ));

    let res = r
        .svc
        .begin_impersonation(&r.admin, &r.target, &session)
        .await;

    assert!(matches!(res, Err(AuthnError::NotActive(_))), "{res:?}");
    assert_eq!(
        session.user_id().await,
        Some(r.admin.id),
        "the session is left as the admin's"
    );
    assert_eq!(session.impersonator().await, None);
    let rows = refusals(&r.identity, "admin_not_active");
    assert_eq!(rows.len(), 1, "the refusal is audited");
    assert_eq!(rows[0].actor_id, Some(r.admin.id));
    assert_eq!(rows[0].user_id, Some(r.target.id));
}

/// A store that cannot answer the target lookup fails the impersonation
/// with a row saying so: the failure does not go without a trace.
#[tokio::test]
async fn a_target_lookup_that_fails_is_audited() {
    let r = rig();
    let session = test_session();
    session
        .set_authenticated(r.admin.id, r.admin.tenant_id, r.clock.now())
        .await;
    r.identity.arm_get_user_failure();

    let res = r
        .svc
        .begin_impersonation(&r.admin, &r.target, &session)
        .await;

    assert!(matches!(res, Err(AuthnError::Store(_))), "{res:?}");
    assert_eq!(session.user_id().await, Some(r.admin.id));
    let rows = refusals(&r.identity, "target_lookup_failed");
    assert_eq!(rows.len(), 1, "the failed lookup is audited");
    assert_eq!(rows[0].actor_id, Some(r.admin.id));
    assert_eq!(
        rows[0].user_id, None,
        "nothing was read, so no target is named"
    );
}

/// A session that is already an impersonation is refused as one whichever
/// administrator id the caller names.
#[tokio::test]
async fn a_nested_impersonation_is_refused_as_nested_whoever_the_caller_names() {
    let r = rig();
    let y = test_user("u3", "carol");
    r.identity.clone().with_user(y.clone());
    let session = impersonating(&r).await;

    // The caller names the real administrator, not the impersonated user.
    let res = r.svc.begin_impersonation(&r.admin, &y, &session).await;
    assert!(matches!(res, Err(AuthnError::Impersonated)), "{res:?}");
    assert_eq!(refusals(&r.identity, "nested_impersonation").len(), 1);

    let res = r
        .svc
        .begin_impersonation_across_tenants(&r.admin.id, &y, &session)
        .await;
    assert!(matches!(res, Err(AuthnError::Impersonated)), "{res:?}");
    assert_eq!(refusals(&r.identity, "nested_impersonation").len(), 2);
}

/// The administrator's session id is ended even when the registry refuses
/// the impersonated session: the cookie is cleared either way.
#[tokio::test]
async fn a_refused_impersonation_still_ends_the_administrators_session_id() {
    let registry = refusing_registry(None);
    let r = rig_with(|b| b.with_registry(registry.clone()));
    let session = test_session();
    session
        .set_authenticated(r.admin.id, r.admin.tenant_id, r.clock.now())
        .await;
    let admin_sid = session.session_key().await;

    let res = r
        .svc
        .begin_impersonation(&r.admin, &r.target, &session)
        .await;

    assert!(matches!(res, Err(AuthnError::NoFlow)), "{res:?}");
    assert!(
        entries(&registry, RegistryOp::InvalidateSession)
            .iter()
            .any(|(_, ended)| *ended == admin_sid),
        "the administrator's old session id is not left in the registry"
    );
}
/// What authorisation sees of an impersonated session: the principal names
/// the administrator, so a policy can forbid or require it.
#[cfg(feature = "authz")]
#[tokio::test]
async fn the_principal_of_an_impersonated_session_names_the_administrator() {
    use axess_core::{PrincipalResolver as _, SessionResolver, ToCedarEntity as _};
    let r = rig();
    let session = impersonating(&r).await;

    let principal = SessionResolver::new(session).resolve().await.unwrap();
    let axess_core::Principal::Human(human) = &principal else {
        panic!("a session resolves to a human");
    };
    assert_eq!(human.user_id, r.target.id);
    let entity = principal.to_cedar_entity().unwrap();
    assert!(
        entity.attr("impersonator").is_some(),
        "the Cedar principal carries who is acting in the user's name"
    );
}

/// The administrator's own tenant must be active, as the store holds it: a
/// session that names another, active, tenant does not stand in for it.
#[tokio::test]
async fn the_administrators_stored_tenant_gates_impersonation_not_the_sessions() {
    use axess_core::authn::types::{EntityState, StatusDetail};
    let clock = common::test_clock();
    let mut ops_tenant = test_tenant();
    ops_tenant.status = EntityState::Suspended(StatusDetail::administrative("hold", clock.now()));
    let mut other_tenant = test_tenant();
    other_tenant.id = common::tid("t2");
    other_tenant.identifier = "other".into();
    // The administrator is stored in the suspended tenant; the target lives
    // in an active one.
    let admin = test_user("admin", "ops");
    let target = common::test_user_in_tenant("u9", "zed", "t2");
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(ops_tenant)
        .with_tenant(other_tenant)
        .with_user(admin.clone())
        .with_user(target.clone());
    let svc = AuthnService::builder(identity, MockFactorStore::new())
        .with_clock(clock.clone())
        .build()
        .with_audit_context(AuditContext::default());
    // A session that claims the active tenant for the same administrator.
    let session = test_session();
    session
        .set_authenticated(admin.id, common::tid("t2"), clock.now())
        .await;

    let res = svc
        .begin_impersonation_across_tenants(&admin.id, &target, &session)
        .await;

    assert!(matches!(res, Err(AuthnError::NotActive(_))), "{res:?}");
    assert_eq!(session.impersonator().await, None);
}

/// An impersonation that fails after the administrator's anchor entry was
/// registered ends that entry too: nothing of it is left to count against
/// the administrator's sessions.
#[tokio::test]
async fn a_failed_impersonation_leaves_no_anchor_under_the_administrator() {
    let admin = test_user("admin", "ops").id;
    let registry = refusing_registry(Some(admin));
    let r = rig_with(|b| b.with_registry(registry.clone()));
    let session = test_session();
    session
        .set_authenticated(r.admin.id, r.admin.tenant_id, r.clock.now())
        .await;

    let res = r
        .svc
        .begin_impersonation(&r.admin, &r.target, &session)
        .await;

    assert!(matches!(res, Err(AuthnError::NoFlow)), "{res:?}");
    let taken: Vec<_> = entries(&registry, RegistryOp::Register)
        .into_iter()
        .filter(|(user, _)| *user == admin)
        .collect();
    let ended = entries(&registry, RegistryOp::InvalidateSession);
    assert_eq!(taken.len(), 1, "the anchor was registered: {taken:?}");
    assert!(
        ended.contains(&taken[0]),
        "the anchor {taken:?} outlived the failed impersonation: {ended:?}"
    );
}

/// An administrator cannot impersonate themselves: the session would carry an
/// impersonation marker on their own account, and the audit trail an
/// impersonation that never changed who acts.
#[tokio::test]
async fn an_administrator_cannot_impersonate_themselves() {
    let r = rig();
    let session = test_session();
    session
        .set_authenticated(r.admin.id, r.admin.tenant_id, r.clock.now())
        .await;

    let res = r
        .svc
        .begin_impersonation(&r.admin, &r.admin, &session)
        .await;

    assert!(matches!(res, Err(AuthnError::NoFlow)), "{res:?}");
    assert!(session.impersonator().await.is_none());
    assert_eq!(session.user_id().await, Some(r.admin.id));
    assert_eq!(refusals(&r.identity, "self_impersonation").len(), 1);
}
