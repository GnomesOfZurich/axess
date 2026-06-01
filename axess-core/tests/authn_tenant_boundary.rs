#![cfg(feature = "testing")]
//! Tenant-boundary rails: `suspend_user_in_tenant`, `activate_user_in_tenant`,
//! and `begin_impersonation_in_tenant` must refuse cross-tenant targets with
//! `AuthnError::CrossTenant` and leave session state untouched on refusal.

mod common;

use axess_core::authn::{error::AuthnError, service::AuthnService, types::StatusDetail};
use axess_core::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use chrono::Utc;
use common::{test_tenant, test_user_in_tenant, tid, uid};

fn make_service_with_user_in(
    user_id: &str,
    identifier: &str,
    tenant: &str,
) -> AuthnService<MockIdentityStore, MockFactorStore> {
    let user = test_user_in_tenant(user_id, identifier, tenant);
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(user);
    AuthnService::new(identity, MockFactorStore::new())
}

#[tokio::test]
async fn suspend_user_in_tenant_rejects_cross_tenant_target() {
    // User u1 lives in tenant t1. Caller asserts expected_tenant=t2.
    // Library MUST refuse with CrossTenant.
    let svc = make_service_with_user_in("u1", "alice", "t1");
    let detail = StatusDetail {
        reason: "test".into(),
        since: Utc::now(),
        until: None,
    };
    let res = svc
        .suspend_user_in_tenant(&uid("u1"), &tid("t2"), detail)
        .await;
    assert!(matches!(res, Err(AuthnError::CrossTenant)));
}

#[tokio::test]
async fn suspend_user_in_tenant_accepts_matching_tenant() {
    let svc = make_service_with_user_in("u1", "alice", "t1");
    let detail = StatusDetail {
        reason: "test".into(),
        since: Utc::now(),
        until: None,
    };
    let res = svc
        .suspend_user_in_tenant(&uid("u1"), &tid("t1"), detail)
        .await;
    assert!(res.is_ok(), "got {res:?}");
}

#[tokio::test]
async fn activate_user_in_tenant_rejects_cross_tenant_target() {
    let svc = make_service_with_user_in("u1", "alice", "t1");
    let res = svc.activate_user_in_tenant(&uid("u1"), &tid("t2")).await;
    assert!(matches!(res, Err(AuthnError::CrossTenant)));
}

#[tokio::test]
async fn begin_impersonation_in_tenant_rejects_cross_tenant() {
    let admin = test_user_in_tenant("admin", "ops", "t1");
    let target = test_user_in_tenant("u2", "bob", "t2");
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(admin.clone())
        .with_user(target.clone());
    let svc = AuthnService::new(identity, MockFactorStore::new());
    let session = test_session();
    let res = svc
        .begin_impersonation_in_tenant(&admin, &target, &session)
        .await;
    assert!(matches!(res, Err(AuthnError::CrossTenant)));
    // Session must NOT have been mutated to target.
    assert!(!session.is_authenticated().await);
}

#[tokio::test]
async fn begin_impersonation_in_tenant_accepts_same_tenant() {
    let admin = test_user_in_tenant("admin", "ops", "t1");
    let target = test_user_in_tenant("u2", "bob", "t1");
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(admin.clone())
        .with_user(target.clone());
    let svc = AuthnService::new(identity, MockFactorStore::new());
    let session = test_session();
    svc.begin_impersonation_in_tenant(&admin, &target, &session)
        .await
        .expect("same-tenant impersonation should succeed");
    assert!(session.is_authenticated().await);
    assert_eq!(session.user_id().await.as_ref(), Some(&target.id));
}
