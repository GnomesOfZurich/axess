//! The mock stores honour the uniqueness and single-use contracts of the
//! traits they stand in for, so a test that passes against them has
//! exercised the same refusals a real store gives.

use super::*;
use crate::authn::store::{IdentityAdmin, IdentityPasswordReset};
use crate::testing::{tenant_record, user_record};
use std::sync::Arc;

#[tokio::test]
async fn create_tenant_refuses_a_duplicate_identifier() {
    let store = MockIdentityStore::new();
    store.create_tenant(tenant_record("acme")).await.unwrap();
    let mut other = tenant_record("acme");
    other.id = axess_identity::testing::tenant("a-different-id");
    assert!(matches!(
        store.create_tenant(other).await,
        Err(MockStoreError::AlreadyExists)
    ));
}

#[tokio::test]
async fn create_user_refuses_a_duplicate_id_under_a_new_identifier() {
    let store = MockIdentityStore::new();
    let user = user_record("u1", "t1");
    store.create_user(user.clone()).await.unwrap();
    let mut clash = user;
    clash.identifier = "someone-else".into();
    assert!(matches!(
        store.create_user(clash).await,
        Err(MockStoreError::AlreadyExists)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reset_token_verifies_once_under_concurrent_attempts() {
    let store = Arc::new(MockIdentityStore::new());
    let user = axess_identity::testing::user("u1");
    for round in 0..200 {
        let hash = format!("hash-{round}");
        store
            .store_reset_token(
                &user,
                &hash,
                chrono::Utc::now() + chrono::Duration::hours(1),
            )
            .await
            .unwrap();
        let attempts: Vec<_> = (0..8)
            .map(|_| {
                let store = store.clone();
                let hash = hash.clone();
                tokio::spawn(async move {
                    store
                        .verify_reset_token(&user, &hash, chrono::Utc::now())
                        .await
                        .unwrap()
                })
            })
            .collect();
        let mut winners = 0;
        for attempt in attempts {
            winners += usize::from(attempt.await.unwrap());
        }
        assert_eq!(
            winners, 1,
            "round {round}: a single-use token verified {winners} times"
        );
    }
}

#[tokio::test]
async fn a_wrong_hash_does_not_consume_the_reset_token() {
    let store = MockIdentityStore::new();
    let user = axess_identity::testing::user("u1");
    store
        .store_reset_token(
            &user,
            "right",
            chrono::Utc::now() + chrono::Duration::hours(1),
        )
        .await
        .unwrap();
    assert!(
        !store
            .verify_reset_token(&user, "wrong", chrono::Utc::now())
            .await
            .unwrap()
    );
    assert!(
        store
            .verify_reset_token(&user, "right", chrono::Utc::now())
            .await
            .unwrap()
    );
    assert!(
        !store
            .verify_reset_token(&user, "right", chrono::Utc::now())
            .await
            .unwrap()
    );
}

/// Expiry is judged on the `now` the caller passes, not on the machine's
/// clock: a token issued on a mock clock far from real time verifies up to its
/// expiry and is refused from that instant, one second later included.
#[tokio::test]
async fn a_reset_token_expires_on_the_instant_passed_in() {
    use chrono::TimeZone;
    let origin = chrono::Utc.with_ymd_and_hms(2031, 3, 1, 12, 0, 0).unwrap();
    let ttl = chrono::Duration::minutes(30);
    let store = MockIdentityStore::new();
    let user = axess_identity::testing::user("u1");
    let issue = |hash: &'static str| store.store_reset_token(&user, hash, origin + ttl);

    issue("h1").await.unwrap();
    let before = origin + ttl - chrono::Duration::minutes(1);
    assert!(store.verify_reset_token(&user, "h1", before).await.unwrap());

    issue("h2").await.unwrap();
    assert!(
        !store
            .verify_reset_token(&user, "h2", origin + ttl)
            .await
            .unwrap(),
        "the token is refused at its expiry instant"
    );
    assert!(
        !store
            .verify_reset_token(&user, "h2", origin + ttl + chrono::Duration::seconds(1))
            .await
            .unwrap(),
        "and stays refused after it"
    );
}
