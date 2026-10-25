#![cfg(feature = "testing")]
//! `MockIdentityStore::delete_user` follows the erasure contract instead of
//! hitting the trait's panicking default.

mod common;

use axess_core::authn::factor::{
    FactorConfig, FactorKind, PasswordConfig, PasswordRules, ZeroizedString,
};
use axess_core::authn::store::{
    AuthMethod, FactorStore, IdentityAdmin, IdentityLookup, IdentityPasswordHistory,
};
use axess_core::authn::types::{AuthnScope, EntityState, User};
use axess_core::testing::mock_authn::{MockFactorStore, MockIdentityStore, MockStoreError};
use chrono::Utc;
use common::{test_tenant, tid, uid};

fn user(label: &str, identifier: &str) -> User {
    let now = Utc::now();
    User {
        id: uid(label),
        tenant_id: tid("t1"),
        identifier: identifier.into(),
        display_name: identifier.into(),
        status: EntityState::Active,
        webauthn_id: None,
        created_by: axess_core::authn::ids::UserId::system(),
        created_at: now,
        updated_by: axess_core::authn::ids::UserId::system(),
        updated_at: now,
    }
}

fn password_config() -> FactorConfig {
    FactorConfig::Password(PasswordConfig {
        hash: ZeroizedString::new(axess_factors::generate_password_hash("Old-password-1!")),
        rules: PasswordRules::default(),
    })
}

#[tokio::test]
async fn delete_user_erases_the_user_its_history_and_its_factors() {
    let (alice, bob) = (user("alice", "alice"), user("bob", "bob"));
    let scope = |u: &User| AuthnScope::User {
        tenant_id: u.tenant_id,
        user_id: u.id,
    };
    let factors = MockFactorStore::new()
        .with_factor(scope(&alice), password_config())
        .with_factor(scope(&bob), password_config())
        .with_method(
            &alice.id,
            AuthMethod::sequential("password", vec![FactorKind::Password], scope(&alice)),
        );
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(alice.clone())
        .with_user(bob.clone())
        .with_factor_store(&factors);
    identity
        .record_password_hash(&alice.id, "hash-a")
        .await
        .unwrap();
    identity
        .record_password_hash(&bob.id, "hash-b")
        .await
        .unwrap();

    identity.delete_user(&alice.id).await.unwrap();

    assert!(identity.get_user(&alice.id).await.unwrap().is_none());
    assert!(
        identity
            .find_user("alice", &alice.tenant_id)
            .await
            .unwrap()
            .is_none(),
        "the identifier is free again"
    );
    assert!(
        identity
            .password_history(&alice.id, 10)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        factors
            .load_factor(&scope(&alice), FactorKind::Password)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        factors
            .available_methods(&alice.id, &alice.tenant_id)
            .await
            .unwrap()
            .is_empty()
    );

    // Another user is untouched.
    assert!(identity.get_user(&bob.id).await.unwrap().is_some());
    assert_eq!(
        identity.password_history(&bob.id, 10).await.unwrap().len(),
        1
    );
    assert!(
        factors
            .load_factor(&scope(&bob), FactorKind::Password)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn delete_user_of_a_missing_user_is_not_found() {
    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let err = identity.delete_user(&uid("ghost")).await.unwrap_err();
    assert!(matches!(err, MockStoreError::NotFound), "{err:?}");

    identity.create_user(user("alice", "alice")).await.unwrap();
    identity.delete_user(&uid("alice")).await.unwrap();
    let again = identity.delete_user(&uid("alice")).await.unwrap_err();
    assert!(matches!(again, MockStoreError::NotFound), "{again:?}");
}
