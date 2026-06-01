#![cfg(feature = "testing")]
//! Multi-tenant factor-scope resolution: user → tenant → global lookup
//! chain through `AuthnService::verify_factor`.

mod common;

use axess_core::authn::{
    factor::{FactorCredential, ZeroizedString},
    service::{AuthnService, FactorOutcome},
    types::AuthnScope,
};
use axess_core::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use common::{password_config, password_method, test_tenant, test_user, tid, uid};

/// Factor config at user scope should be found first.
#[tokio::test]
async fn user_scope_takes_priority() {
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new()
        .with_factor(
            AuthnScope::User {
                tenant_id: tid("t1"),
                user_id: uid("u1"),
            },
            password_config("user-password"),
        )
        .with_factor(
            AuthnScope::Tenant(tid("t1")),
            password_config("tenant-password"),
        )
        .with_factor(AuthnScope::Global, password_config("global-password"))
        .with_method(&uid("u1"), password_method());

    let service = AuthnService::new(identity, factors);
    let session = test_session();

    service
        .begin_login("alice", "default", &session, None)
        .await
        .unwrap();

    let r = service
        .verify_factor(
            &FactorCredential::Password(ZeroizedString::new("user-password")),
            &session,
        )
        .await
        .unwrap();
    assert!(matches!(r, FactorOutcome::Authenticated));
}

/// When user scope has no config, tenant scope should resolve.
#[tokio::test]
async fn tenant_scope_fallback() {
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new()
        .with_factor(
            AuthnScope::Tenant(tid("t1")),
            password_config("tenant-password"),
        )
        .with_method(&uid("u1"), password_method());

    let service = AuthnService::new(identity, factors);
    let session = test_session();

    service
        .begin_login("alice", "default", &session, None)
        .await
        .unwrap();
    let r = service
        .verify_factor(
            &FactorCredential::Password(ZeroizedString::new("tenant-password")),
            &session,
        )
        .await
        .unwrap();
    assert!(matches!(r, FactorOutcome::Authenticated));
}

/// Full chain: user miss → tenant miss → global hit.
#[tokio::test]
async fn user_tenant_global_fallback_chain() {
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new()
        .with_factor(AuthnScope::Global, password_config("global-password"))
        .with_method(&uid("u1"), password_method());

    let service = AuthnService::new(identity, factors);
    let session = test_session();

    service
        .begin_login("alice", "default", &session, None)
        .await
        .unwrap();
    let r = service
        .verify_factor(
            &FactorCredential::Password(ZeroizedString::new("global-password")),
            &session,
        )
        .await
        .unwrap();
    assert!(matches!(r, FactorOutcome::Authenticated));
}
