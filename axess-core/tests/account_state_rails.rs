#![cfg(feature = "testing")]
//! Account state and audit failures at the edges of a session: impersonation
//! of an account that cannot log in, a password reset on one, and an audit
//! store that is down while a session is being established.

mod common;

use axess_core::authn::Actor;
use axess_core::authn::factor::{FactorCredential, ZeroizedString};
use axess_core::authn::types::{EntityState, StatusDetail};
use axess_core::authn::{
    AuditContext, RequestAuthnService, error::AuthnError, service::AuthnService,
};
use axess_core::session::store::{MemorySessionRegistry, SessionRegistry};
use axess_core::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use chrono::Utc;
use common::{
    password_config, password_method, test_tenant, test_user, test_user_in_tenant, uid, user_scope,
};
use std::time::Duration;

fn service(identity: MockIdentityStore) -> RequestAuthnService<MockIdentityStore, MockFactorStore> {
    AuthnService::new(identity, MockFactorStore::new()).with_audit_context(AuditContext::default())
}

fn suspended_user(id: &str, identifier: &str) -> axess_core::authn::types::User {
    let mut u = test_user_in_tenant(id, identifier, "t1");
    u.status = EntityState::Suspended(StatusDetail {
        reason: "hold".into(),
        since: Utc::now(),
        until: None,
    });
    u
}

#[tokio::test]
async fn impersonation_refuses_a_suspended_target_and_leaves_the_session_alone() {
    let admin = test_user_in_tenant("admin", "ops", "t1");
    let target = suspended_user("u2", "bob");
    let svc = service(
        MockIdentityStore::new()
            .with_tenant(test_tenant())
            .with_user(admin.clone())
            .with_user(target.clone()),
    );
    let session = test_session();
    session
        .set_authenticated(admin.id, admin.tenant_id, Utc::now())
        .await;
    let res = svc
        .begin_impersonation_across_tenants(&admin.id, &target, &session)
        .await;
    assert!(matches!(res, Err(AuthnError::NotActive(_))), "{res:?}");
    assert_eq!(
        session.user_id().await,
        Some(admin.id),
        "the session is left as the admin's"
    );
}

#[tokio::test]
async fn impersonation_whose_audit_row_cannot_be_written_leaves_no_session() {
    let admin = test_user_in_tenant("admin", "ops", "t1");
    let target = test_user_in_tenant("u2", "bob", "t1");
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(admin.clone())
        .with_user(target.clone());
    identity.arm_record_event_failure();
    let svc = service(identity);
    let session = test_session();
    session
        .set_authenticated(admin.id, admin.tenant_id, Utc::now())
        .await;
    let res = svc
        .begin_impersonation_across_tenants(&admin.id, &target, &session)
        .await;
    assert!(res.is_err(), "the audit outage must fail the flow");
    assert!(
        !session.is_authenticated().await,
        "a failed flow must not leave the target's identity on the session"
    );
}

#[tokio::test]
async fn password_reset_is_refused_while_suspended_and_the_token_survives() {
    let user = test_user_in_tenant("u1", "alice", "t1");
    let svc = service(
        MockIdentityStore::new()
            .with_tenant(test_tenant())
            .with_user(user),
    );
    let token = svc
        .begin_password_reset("alice", "default", Duration::from_secs(300))
        .await
        .unwrap()
        .expect("token for an active user");

    svc.suspend_user_across_tenants(
        Actor::System,
        &uid("u1"),
        StatusDetail {
            reason: "hold".into(),
            since: Utc::now(),
            until: None,
        },
    )
    .await
    .unwrap();
    let refused = svc
        .complete_password_reset(&uid("u1"), &token, "A-long-new-passphrase-9!")
        .await
        .unwrap();
    assert!(!refused, "a suspended account's password must not change");

    svc.activate_user_across_tenants(Actor::System, &uid("u1"))
        .await
        .unwrap();
    let accepted = svc
        .complete_password_reset(&uid("u1"), &token, "A-long-new-passphrase-9!")
        .await
        .unwrap();
    assert!(
        accepted,
        "the refused attempt must not have spent the token"
    );
}

#[tokio::test]
async fn login_whose_authenticated_row_cannot_be_written_leaves_no_live_session() {
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config("Gnomes2+"))
        .with_method(&uid("u1"), password_method());
    let registry = MemorySessionRegistry::new();
    let svc = AuthnService::builder(identity.clone(), factors)
        .with_registry(registry.clone())
        .build()
        .with_audit_context(AuditContext::default());

    let session = test_session();
    svc.begin_login("alice", "default", &session).await.unwrap();
    let sid = session.session_id().await;

    identity.arm_record_event_failure();
    let res = svc
        .verify_factor(
            &FactorCredential::Password(ZeroizedString::new("Gnomes2+")),
            &session,
        )
        .await;
    assert!(res.is_err(), "the audit outage fails the flow: {res:?}");
    assert!(
        !session.is_authenticated().await,
        "a failed login must not leave an authenticated session behind"
    );
    assert!(
        !registry.is_valid(&uid("u1"), &sid).await.unwrap(),
        "nor a registry entry that vouches for one"
    );
}
