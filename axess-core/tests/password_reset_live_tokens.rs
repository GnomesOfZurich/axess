#![cfg(feature = "testing")]
//! A new reset request never invalidates a live link: an account holds up to
//! a named number of live tokens, a request beyond that is refused as
//! throttled and audited, and using any one token consumes them all.

mod common;

use axess_core::authn::event::{AuthEventStatus, AuthEventType};
use axess_core::authn::service::DEFAULT_MAX_LIVE_RESET_TOKENS;
use axess_core::authn::{AuditContext, RequestAuthnService};
use axess_core::authn::{service::AuthnService, types::User};
use axess_core::testing::mock_authn::{MockFactorStore, MockIdentityStore};
use common::{test_tenant, test_user, uid};
use std::time::Duration;

const TTL: Duration = Duration::from_secs(3600);
const NEW_PASSWORD: &str = "A-Fresh-Passw0rd!x";

type Svc = RequestAuthnService<MockIdentityStore, MockFactorStore>;

fn world(max: Option<usize>) -> (Svc, MockIdentityStore) {
    let user: User = test_user("u1", "alice");
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(user);
    let mut builder = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .without_password_reset_cooldown();
    if let Some(max) = max {
        builder = builder.with_max_live_reset_tokens(max);
    }
    (
        builder.build().with_audit_context(AuditContext::default()),
        identity,
    )
}

async fn ask(svc: &Svc) -> Option<String> {
    svc.begin_password_reset("alice", "default", TTL)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_second_request_does_not_kill_the_first_link() {
    let (svc, _) = world(None);
    let first = ask(&svc).await.expect("first token");
    let second = ask(&svc).await.expect("second token");

    assert_ne!(first, second);
    assert!(
        svc.complete_password_reset(&uid("u1"), &first, NEW_PASSWORD)
            .await
            .unwrap(),
        "the first link was killed by the second request"
    );
}

#[tokio::test]
async fn using_any_one_token_consumes_all_of_them() {
    let (svc, _) = world(None);
    let first = ask(&svc).await.unwrap();
    let second = ask(&svc).await.unwrap();

    assert!(
        svc.complete_password_reset(&uid("u1"), &second, NEW_PASSWORD)
            .await
            .unwrap()
    );
    assert!(
        !svc.complete_password_reset(&uid("u1"), &first, "Another-Passw0rd!y")
            .await
            .unwrap(),
        "an earlier link still works after the reset"
    );
}

#[tokio::test]
async fn a_request_beyond_the_limit_is_refused_audited_and_leaves_the_links_alone() {
    let (svc, identity) = world(None);
    let mut tokens = Vec::new();
    for _ in 0..DEFAULT_MAX_LIVE_RESET_TOKENS {
        tokens.push(ask(&svc).await.expect("within the limit"));
    }

    let beyond = ask(&svc).await;

    assert!(beyond.is_none(), "{beyond:?}");
    let refused = identity
        .events()
        .into_iter()
        .filter(|e| {
            e.event_type == AuthEventType::PasswordResetRequested
                && e.event_status == AuthEventStatus::Failure
                && e.error.as_ref().map(|r| r.as_str()) == Some("live_tokens_full")
        })
        .count();
    assert_eq!(refused, 1, "the refusal is audited as live_tokens_full");
    for token in &tokens {
        assert!(
            svc.complete_password_reset_in_tenant(&uid("u1"), &test_tenant().id, token, "short")
                .await
                .is_ok(),
            "peeking a held link failed"
        );
    }
    assert!(
        svc.complete_password_reset(&uid("u1"), &tokens[0], NEW_PASSWORD)
            .await
            .unwrap(),
        "the oldest link died when the limit refused a request"
    );
}

#[tokio::test]
async fn the_limit_is_the_builders() {
    let (svc, _) = world(Some(1));
    assert!(ask(&svc).await.is_some());
    assert!(ask(&svc).await.is_none());
}

#[tokio::test]
async fn an_expired_token_frees_its_slot() {
    use axess_clock::testing::MockClock;
    let clock = MockClock::now();
    let user: User = test_user("u1", "alice");
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(user);
    let svc = AuthnService::builder(identity, MockFactorStore::new())
        .with_clock(clock.clone())
        .without_password_reset_cooldown()
        .with_max_live_reset_tokens(1)
        .build()
        .with_audit_context(AuditContext::default());
    assert!(ask(&svc).await.is_some());
    assert!(ask(&svc).await.is_none());

    clock.advance(chrono::Duration::seconds(3601));

    assert!(ask(&svc).await.is_some(), "an expired token held its slot");
}
