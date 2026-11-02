#![cfg(feature = "testing")]
//! Impersonation: the marker is part of the authenticated state, so nothing
//! an application does to the custom bag erases it; an impersonated session
//! cannot issue refresh tokens or change factors unless the deployment opts
//! in; and every audit row a request under impersonation writes names the
//! administrator as actor.

mod common;

use axess_clock::{Clock, testing::MockClock};
use axess_core::authn::AuditContext;
use axess_core::authn::error::AuthnError;
use axess_core::authn::event::{AuthEventStatus, AuthEventType};
use axess_core::authn::service::{AuthnService, RequestAuthnService};
use axess_core::authn::store::{IdentityAdmin as _, IdentityLookup as _};
use axess_core::session::extractor::AuthSession;
use axess_core::session::refresh::RefreshTokenConfig;
use axess_core::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    mock_refresh_store::MemoryRefreshTokenStore,
    test_session,
};
use common::{test_tenant, test_user};

type Svc = RequestAuthnService<MockIdentityStore, MockFactorStore>;

struct Rig {
    svc: Svc,
    identity: MockIdentityStore,
    clock: MockClock,
    admin: axess_core::authn::types::User,
    target: axess_core::authn::types::User,
}

fn rig_with(configure: impl FnOnce(AuthnServiceBuilder) -> AuthnServiceBuilder) -> Rig {
    let clock = MockClock::now();
    let admin = test_user("admin", "ops");
    let target = test_user("u2", "bob");
    let identity = MockIdentityStore::new()
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

type AuthnServiceBuilder =
    axess_core::authn::service::AuthnServiceBuilder<MockIdentityStore, MockFactorStore>;

fn rig() -> Rig {
    rig_with(|b| b)
}

/// The admin's own authenticated session, impersonating the target.
async fn impersonating(r: &Rig) -> AuthSession {
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

fn rows(
    identity: &MockIdentityStore,
    kind: AuthEventType,
) -> Vec<axess_core::authn::event::AuthEvent> {
    identity
        .events()
        .into_iter()
        .filter(|e| e.event_type == kind)
        .collect()
}

#[tokio::test]
async fn the_marker_survives_a_cleared_custom_bag() {
    let r = rig();
    let session = impersonating(&r).await;

    // What the custom-data size cap does to an oversized bag, and what an
    // application may do at any time.
    session.clear_custom().await;

    assert_eq!(
        session.impersonator().await,
        Some(r.admin.id),
        "clearing the custom bag must not end the impersonation marker"
    );
    let axess_core::Impersonation {
        admin: actor,
        since,
    } = session
        .impersonation()
        .await
        .expect("the impersonation carries who and since when");
    assert_eq!(actor, r.admin.id);
    assert_eq!(since, r.clock.now());
}

#[tokio::test]
async fn an_impersonated_session_cannot_issue_a_refresh_token() {
    let r = rig();
    let session = impersonating(&r).await;
    let store = MemoryRefreshTokenStore::new();

    let res = r
        .svc
        .issue_refresh_token(&session, &store, &RefreshTokenConfig::default(), None, None)
        .await;

    assert!(matches!(res, Err(AuthnError::Impersonated)), "{res:?}");
    assert!(
        rows(&r.identity, AuthEventType::LoginAttempt)
            .iter()
            .any(|e| e.event_status == AuthEventStatus::Failure
                && e.actor_id == Some(r.admin.id)
                && e.user_id == Some(r.target.id)),
        "the refusal is audited against the target with the admin as actor"
    );
}

#[tokio::test]
async fn an_ordinary_session_issues_a_refresh_token() {
    let r = rig();
    let session = test_session();
    session
        .set_authenticated(r.target.id, r.target.tenant_id, r.clock.now())
        .await;
    let store = MemoryRefreshTokenStore::new();

    let (plaintext, record) = r
        .svc
        .issue_refresh_token(&session, &store, &RefreshTokenConfig::default(), None, None)
        .await
        .expect("an ordinary session gets a token");

    assert!(!plaintext.is_empty());
    assert_eq!(record.user_id, r.target.id);
    assert_eq!(record.tenant_id, r.target.tenant_id);
}

#[tokio::test]
async fn the_deployment_can_allow_an_impersonated_session_a_refresh_token() {
    let r = rig_with(|b| b.with_impersonated_credential_changes_allowed());
    let session = impersonating(&r).await;
    let store = MemoryRefreshTokenStore::new();

    let (_, record) = r
        .svc
        .issue_refresh_token(&session, &store, &RefreshTokenConfig::default(), None, None)
        .await
        .expect("allowed by the opt-in");
    assert_eq!(record.user_id, r.target.id);
}

#[tokio::test]
async fn audit_rows_of_an_impersonated_request_name_the_admin_as_actor() {
    let r = rig();
    let session = impersonating(&r).await;

    // What the extractor builds for a request carrying the impersonated
    // session: the context names the impersonator.
    let svc = r.svc.with_audit_context(AuditContext {
        impersonator: Some(r.admin.id),
        ..AuditContext::default()
    });
    svc.logout(&session).await.unwrap();

    let logout = rows(&r.identity, AuthEventType::LogoutAttempt);
    assert_eq!(logout.len(), 1);
    assert_eq!(logout[0].user_id, Some(r.target.id));
    assert_eq!(
        logout[0].actor_id,
        Some(r.admin.id),
        "the row names the administrator who acted in the target's name"
    );
}

#[tokio::test]
async fn the_marker_is_gone_once_the_session_is_the_users_own_again() {
    let r = rig();
    let session = impersonating(&r).await;

    r.svc.end_impersonation(&session).await.unwrap();
    assert!(!session.is_authenticated().await);
    assert_eq!(session.impersonator().await, None);

    // A fresh login of the target carries no marker.
    session
        .set_authenticated(r.target.id, r.target.tenant_id, r.clock.now())
        .await;
    assert_eq!(session.impersonator().await, None);
    assert_eq!(session.impersonation().await, None);
}

#[cfg(feature = "fido2")]
mod passkeys {
    use super::*;
    use axess_factors::fido2::DefaultFido2Provider;
    use url::Url;
    use webauthn_rs::prelude::WebauthnBuilder;

    fn fido2_rig(allow: bool) -> Rig {
        let rp_origin = Url::parse("https://localhost:8443").unwrap();
        let webauthn = WebauthnBuilder::new("localhost", &rp_origin)
            .unwrap()
            .build()
            .unwrap();
        rig_with(move |b| {
            let b = b.with_fido2(DefaultFido2Provider::new(webauthn));
            if allow {
                b.with_impersonated_credential_changes_allowed()
            } else {
                b
            }
        })
    }

    #[tokio::test]
    async fn an_impersonated_session_cannot_enrol_a_passkey() {
        let r = fido2_rig(false);
        let session = impersonating(&r).await;

        let res = r.svc.begin_fido2_registration(&r.target, &session).await;

        assert!(matches!(res, Err(AuthnError::Impersonated)), "{res:?}");
        assert!(
            rows(&r.identity, AuthEventType::FactorEnabled)
                .iter()
                .any(|e| e.event_status == AuthEventStatus::Failure
                    && e.user_id == Some(r.target.id)
                    && e.actor_id == Some(r.admin.id)),
            "the refusal is audited with the admin as actor"
        );
    }

    /// The two credential changes an impersonated session is refused (a
    /// refresh token, a passkey) are one policy, recorded under one reason.
    #[tokio::test]
    async fn both_impersonation_refusals_share_one_reason() {
        let r = fido2_rig(false);
        let session = impersonating(&r).await;
        let store = MemoryRefreshTokenStore::new();
        let refresh = r
            .svc
            .issue_refresh_token(&session, &store, &RefreshTokenConfig::default(), None, None)
            .await;
        let enrol = r.svc.begin_fido2_registration(&r.target, &session).await;
        assert!(refresh.is_err() && enrol.is_err(), "both refused");
        let reasons: Vec<String> = [AuthEventType::LoginAttempt, AuthEventType::FactorEnabled]
            .into_iter()
            .flat_map(|t| rows(&r.identity, t))
            .filter(|e| e.event_status == AuthEventStatus::Failure)
            .filter_map(|e| e.error.map(|reason| reason.to_string()))
            .collect();
        assert_eq!(reasons, ["impersonated", "impersonated"], "{reasons:?}");
        assert!(
            matches!(refresh, Err(AuthnError::Impersonated)),
            "{refresh:?}"
        );
        assert!(matches!(enrol, Err(AuthnError::Impersonated)), "{enrol:?}");
    }

    #[tokio::test]
    async fn an_impersonated_session_cannot_delete_a_passkey() {
        let r = fido2_rig(false);
        let session = impersonating(&r).await;
        let credential_id = webauthn_rs::prelude::CredentialID::from(vec![1u8, 2, 3]);

        let res = r
            .svc
            .delete_fido2_credential(&r.target, &session, &credential_id, 0)
            .await;

        assert!(matches!(res, Err(AuthnError::Impersonated)), "{res:?}");
        assert!(
            rows(&r.identity, AuthEventType::FactorDisabled)
                .iter()
                .any(|e| e.event_status == AuthEventStatus::Failure
                    && e.user_id == Some(r.target.id)),
        );
    }

    #[tokio::test]
    async fn the_deployment_can_allow_an_impersonated_session_to_enrol() {
        let r = fido2_rig(true);
        let session = impersonating(&r).await;

        let res = r.svc.begin_fido2_registration(&r.target, &session).await;
        assert!(res.is_ok(), "{res:?}");
    }
}

/// The `Impersonation` failure rows carrying `reason`.
fn refusals(
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

#[tokio::test]
async fn an_impersonated_session_cannot_impersonate_again() {
    let clock = MockClock::now();
    let admin = test_user("admin", "ops");
    let x = test_user("u2", "bob");
    let y = test_user("u3", "carol");
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(admin.clone())
        .with_user(x.clone())
        .with_user(y.clone());
    let svc = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_clock(clock.clone())
        .build()
        .with_audit_context(AuditContext::default());
    let session = test_session();
    session
        .set_authenticated(admin.id, admin.tenant_id, clock.now())
        .await;
    svc.begin_impersonation(&admin, &x, &session).await.unwrap();
    assert_eq!(session.user_id().await, Some(x.id));
    assert_eq!(session.impersonator().await, Some(admin.id));
    let sid = session.session_id().await;

    // The impersonated session, as X, tries to become Y.
    let res = svc.begin_impersonation(&x, &y, &session).await;

    assert!(matches!(res, Err(AuthnError::Impersonated)), "{res:?}");
    let nested = refusals(&identity, "nested_impersonation");
    assert_eq!(nested.len(), 1, "one failed row names the attempt");
    // The refusal comes before the target is read from the store, and the
    // caller's `User` value is whatever the caller built: a row carrying
    // its ids would put a chosen user and tenant on the trail.
    assert_eq!(nested[0].user_id, None, "no target was read");
    assert_eq!(nested[0].tenant_id, None, "no tenant was read");
    assert_eq!(
        nested[0].actor_id,
        Some(admin.id),
        "the row names the administrator who really holds the session"
    );
    assert_eq!(session.user_id().await, Some(x.id), "the session stays X");
    assert_eq!(
        session.impersonator().await,
        Some(admin.id),
        "and the marker still names the original administrator"
    );
    assert_eq!(session.session_id().await, sid, "nothing was rotated");
    assert_eq!(
        rows(&identity, AuthEventType::Impersonation)
            .iter()
            .filter(|e| e.event_status == AuthEventStatus::Success)
            .count(),
        1,
        "only the first impersonation succeeded"
    );
}

/// A tenant administrator asking to impersonate an id that does not exist
/// and one that exists in another tenant gets the same answer, so the
/// tenant-scoped form is not an oracle for which ids exist elsewhere.
#[tokio::test]
async fn an_unknown_target_and_a_foreign_target_are_refused_alike() {
    let clock = MockClock::now();
    let admin = test_user("admin", "ops");
    let foreign = common::test_user_in_tenant("u9", "zed", "t2");
    let mut other_tenant = test_tenant();
    other_tenant.id = common::tid("t2");
    other_tenant.identifier = "other".into();
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_tenant(other_tenant)
        .with_user(admin.clone())
        .with_user(foreign.clone());
    let svc = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_clock(clock.clone())
        .build()
        .with_audit_context(AuditContext::default());
    assert!(
        identity.get_user(&foreign.id).await.unwrap().is_some(),
        "the foreign user exists"
    );
    let ghost = test_user("u8", "nobody");
    assert!(identity.get_user(&ghost.id).await.unwrap().is_none());

    let session = test_session();
    session
        .set_authenticated(admin.id, admin.tenant_id, clock.now())
        .await;
    let unknown = svc.begin_impersonation(&admin, &ghost, &session).await;
    let cross = svc.begin_impersonation(&admin, &foreign, &session).await;

    let variant = |r: &Result<(), AuthnError<_>>| format!("{:?}", r.as_ref().err());
    assert_eq!(
        variant(&unknown),
        variant(&cross),
        "the caller cannot tell a missing id from a foreign one"
    );
    assert!(session.is_authenticated().await);
    assert_eq!(session.user_id().await, Some(admin.id));
    // The audit rows may differ: the operator sees which it was.
    assert_eq!(refusals(&identity, "unknown_target").len(), 1);
    assert_eq!(refusals(&identity, "cross_tenant_impersonation").len(), 1);
}

// ── The gaps around the refusals ────────────────────────────────────────────

/// A registry that refuses every registration.
#[derive(Clone)]
struct RefusingRegistry;

impl axess_core::session::store::SessionRegistry for RefusingRegistry {
    type Error = std::io::Error;
    async fn register(
        &self,
        _: &axess_core::authn::UserId,
        _: &axess_core::session::id::SessionId,
    ) -> Result<(), Self::Error> {
        Err(std::io::Error::other("registry unreachable"))
    }
    async fn is_valid(
        &self,
        _: &axess_core::authn::UserId,
        _: &axess_core::session::id::SessionId,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
    async fn invalidate_user(&self, _: &axess_core::authn::UserId) -> Result<(), Self::Error> {
        Ok(())
    }
    async fn invalidate_session(
        &self,
        _: &axess_core::authn::UserId,
        _: &axess_core::session::id::SessionId,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
    async fn active_sessions(
        &self,
        _: &axess_core::authn::UserId,
    ) -> Result<Vec<axess_core::session::id::SessionId>, Self::Error> {
        Ok(vec![])
    }
}

/// An impersonation the registry would not take is refused and the session
/// ended; the refusal used to leave no audit row at all.
#[tokio::test]
async fn a_registry_that_refuses_the_session_leaves_a_failed_row() {
    let r = rig_with(|b| b.with_registry(RefusingRegistry));
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

/// A suspended administrator with a session that is still open cannot
/// take another identity through it.
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
            StatusDetail {
                reason: "offboarded".into(),
                since: r.clock.now(),
                until: None,
            },
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
/// with a row saying so; the failure used to leave no trace.
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
