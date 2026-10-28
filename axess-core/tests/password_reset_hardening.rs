#![cfg(feature = "testing")]
//! Password reset: a refused password keeps the link, an unknown user id
//! looks like a bad token, a bad ttl is refused for everyone alike, and an
//! unknown identifier costs the same store calls as a known one.

mod common;

use std::time::Duration;

use axess_core::authn::factor::PasswordRules;
use axess_core::authn::store::IdentityPasswordHistory;
use axess_core::authn::{AuditContext, RequestAuthnService};
use axess_core::authn::{error::AuthnError, service::AuthnService};
use axess_core::testing::mock_authn::{CallLog, MockFactorStore, MockIdentityStore};
use common::{test_tenant, test_user, uid};

type Svc = RequestAuthnService<MockIdentityStore, MockFactorStore>;

fn world(log: Option<&CallLog>) -> (Svc, MockIdentityStore) {
    let user = test_user("u1", "alice");
    let mut identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(user.clone())
        .with_password_rules(
            &user.tenant_id,
            PasswordRules {
                history_count: 5,
                ..PasswordRules::default()
            },
        );
    if let Some(log) = log {
        identity = identity.with_call_log(log);
    }
    let handle = identity.clone();
    let svc = AuthnService::new(identity, MockFactorStore::new())
        .with_audit_context(AuditContext::default());
    (svc, handle)
}

#[tokio::test]
async fn a_password_refused_for_reuse_keeps_the_link() {
    let (svc, identity) = world(None);
    let user = uid("u1");
    let token = svc
        .begin_password_reset("alice", "default", Duration::from_secs(300))
        .await
        .unwrap()
        .expect("token");
    let reused = "Reused-password-1";
    identity
        .record_password_hash(&user, &axess_factors::generate_password_hash(reused))
        .await
        .unwrap();

    assert!(
        !svc.complete_password_reset(&user, &token, reused)
            .await
            .unwrap()
    );
    // The same link still works for a password that is not a reuse.
    assert!(
        svc.complete_password_reset(&user, &token, "Another-password-2")
            .await
            .unwrap(),
        "the refused attempt spent the single-use token"
    );
    // And it is single-use once it has been spent.
    assert!(
        !svc.complete_password_reset(&user, &token, "Third-password-3")
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn an_unknown_user_id_answers_like_a_bad_token() {
    let (svc, _) = world(None);
    let ghost = uid("nobody");
    let tenant = test_tenant().id;
    assert!(
        !svc.complete_password_reset(&ghost, "t", "New-password-123")
            .await
            .unwrap()
    );
    assert!(
        !svc.complete_password_reset_in_tenant(&ghost, &tenant, "t", "New-password-123")
            .await
            .unwrap()
    );
    // A known user with a bad token gets the same answer.
    assert!(
        !svc.complete_password_reset(&uid("u1"), "wrong", "New-password-123")
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn a_bad_ttl_is_refused_for_known_and_unknown_identifiers() {
    let (svc, _) = world(None);
    for ttl in [
        Duration::from_secs(u64::MAX),
        Duration::from_secs(1_000_000_000_000),
        Duration::from_secs(7 * 24 * 3600 + 1),
        Duration::ZERO,
    ] {
        for who in ["alice", "nobody"] {
            let outcome = svc.begin_password_reset(who, "default", ttl).await;
            assert!(
                matches!(outcome, Err(AuthnError::Internal(_))),
                "{who} with {ttl:?}: got {outcome:?}"
            );
        }
    }
}

#[tokio::test]
async fn an_unknown_identifier_makes_the_same_store_calls_as_a_known_one() {
    let counted = [
        "find_tenant",
        "find_user",
        "store_reset_token",
        "record_event",
    ];
    let mut per_identifier = Vec::new();
    for (who, tenant) in [
        ("alice", "default"),
        ("nobody", "default"),
        ("alice", "no-such-tenant"),
    ] {
        let log = CallLog::new();
        let (svc, _) = world(Some(&log));
        svc.begin_password_reset(who, tenant, Duration::from_secs(300))
            .await
            .unwrap();
        let calls = log.calls();
        per_identifier.push(
            counted
                .iter()
                .map(|name| calls.iter().filter(|c| *c == name).count())
                .collect::<Vec<_>>(),
        );
    }
    assert_eq!(per_identifier[0], vec![1, 1, 1, 1], "the known path");
    assert_eq!(per_identifier[1], per_identifier[0], "unknown user");
    assert_eq!(per_identifier[2], per_identifier[0], "unknown tenant");
}

#[tokio::test]
async fn the_dummy_token_of_an_unknown_identifier_cannot_be_redeemed() {
    let (svc, identity) = world(None);
    svc.begin_password_reset("nobody", "default", Duration::from_secs(300))
        .await
        .unwrap();
    let sentinel = axess_core::authn::ids::UserId::system();
    use axess_core::authn::store::IdentityPasswordReset;
    // Whatever hash was stored, it is already expired at the next instant.
    assert!(
        !identity
            .check_reset_token(
                &sentinel,
                "any",
                chrono::Utc::now() + chrono::Duration::seconds(1)
            )
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn seven_days_is_the_longest_ttl() {
    let (svc, _) = world(None);
    let token = svc
        .begin_password_reset("alice", "default", Duration::from_secs(7 * 24 * 3600))
        .await
        .unwrap();
    assert!(token.is_some());
}

#[tokio::test]
async fn a_token_issued_before_the_tenant_was_suspended_resets_nothing_and_is_kept() {
    use axess_core::authn::types::{EntityState, StatusDetail};
    let (svc, identity) = world(None);
    let user = uid("u1");
    let token = svc
        .begin_password_reset("alice", "default", Duration::from_secs(300))
        .await
        .unwrap()
        .expect("token");

    let mut tenant = test_tenant();
    tenant.status = EntityState::Suspended(StatusDetail {
        reason: "test".into(),
        since: chrono::Utc::now(),
        until: None,
    });
    let active = test_tenant();
    let _ = identity.clone().with_tenant(tenant.clone());

    assert!(
        !svc.complete_password_reset(&user, &token, "New-password-123")
            .await
            .unwrap()
    );
    assert!(
        !svc.complete_password_reset_in_tenant(&user, &tenant.id, &token, "New-password-123")
            .await
            .unwrap()
    );

    // Reactivated, the same token still works: it was never spent.
    let _ = identity.clone().with_tenant(active);
    assert!(
        svc.complete_password_reset(&user, &token, "New-password-123")
            .await
            .unwrap()
    );
}
