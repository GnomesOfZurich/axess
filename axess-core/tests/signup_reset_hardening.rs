#![cfg(feature = "testing")]
//! Signup and password reset hardening: a taken signup identifier can be
//! answered like a free one, a resumed signup is audited, a refusal names its
//! reason, and a password reset request has a per-identifier cooldown.

use axess_core::testing::fixtures as common;

use axess_clock::testing::MockClock;
use axess_core::authn::AuditContext;
use axess_core::authn::event::{AuthEventStatus, AuthEventType};
use axess_core::authn::service::{AuthnService, RequestAuthnService, SignupOutcome};
use axess_core::authn::store::IdentityLookup;
use axess_core::authn::types::EntityState;
use axess_core::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use common::{test_tenant, test_user, uid};
use std::time::Duration;

// ── Hidden signup conflicts ──────────────────────────────────────────────────

fn signup_service(
    reveal: bool,
) -> (
    RequestAuthnService<MockIdentityStore, MockFactorStore>,
    MockIdentityStore,
) {
    let clock = common::test_clock();
    let mut existing = test_user("u1", "alice@example.com");
    existing.status = EntityState::Active;
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(existing);
    let mut builder =
        AuthnService::builder(identity.clone(), MockFactorStore::new()).with_clock(clock.clone());
    if reveal {
        builder = builder.with_signup_conflicts_revealed();
    }
    let svc = builder.build().with_audit_context(AuditContext::default());
    (svc, identity)
}

fn newcomer() -> axess_core::authn::types::User {
    let mut user = test_user("u2", "alice@example.com");
    user.status = EntityState::Candidate;
    user
}

#[tokio::test]
async fn a_taken_identifier_answers_as_a_free_one_by_default() {
    let (svc, identity) = signup_service(false);
    let taken = test_session();
    let outcome = svc
        .begin_signup(newcomer(), "default", &taken)
        .await
        .unwrap();
    assert!(
        matches!(outcome, SignupOutcome::Started(None)),
        "{outcome:?}"
    );
    // The caller sees `Started`; the session is pending a signup as a free
    // identifier's is, under a user id that names no stored account, so no
    // later call tells the two apart.
    let pending_for = match taken.auth_state().await {
        axess_core::session::data::AuthState::PendingWorkflow { user_id, .. } => user_id,
        other => panic!("pending a signup as a free identifier is, got {other:?}"),
    };
    assert!(identity.get_user(&pending_for).await.unwrap().is_none());
    // So the session's pending user is set here as on the free path, and a
    // handler reads the taken identifier from the outcome's empty payload.
    assert_eq!(taken.pending_user_id().await, Some(pending_for));
    // Nothing was created.
    assert!(identity.get_user(&uid("u2")).await.unwrap().is_none());
    assert!(
        identity.events().iter().any(|e| {
            e.event_type == AuthEventType::SignupStarted
                && e.event_status == AuthEventStatus::Failure
                && e.error.as_ref().map(ToString::to_string).as_deref() == Some("already_exists")
        }),
        "the refusal is audited with its reason"
    );

    let mut free = newcomer();
    free.identifier = "bob@example.com".into();
    let fresh = test_session();
    let outcome = svc.begin_signup(free, "default", &fresh).await.unwrap();
    assert!(
        matches!(outcome, SignupOutcome::Started(Some(_))),
        "{outcome:?}"
    );
    assert!(
        fresh.pending_user_id().await.is_some(),
        "a free identifier is created and the signup is pending for it"
    );
}

#[tokio::test]
async fn a_taken_identifier_is_reported_only_when_revealed() {
    let (svc, _) = signup_service(true);
    let outcome = svc
        .begin_signup(newcomer(), "default", &test_session())
        .await
        .unwrap();
    assert!(
        matches!(outcome, SignupOutcome::AlreadyExists),
        "{outcome:?}"
    );
}

/// The session already pending signup for a user may submit again; the
/// resumption leaves a row saying so.
#[tokio::test]
async fn resuming_ones_own_signup_is_audited() {
    let clock = common::test_clock();
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant());
    let svc = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_clock(clock.clone())
        .allow_plaintext_factor_secrets()
        .build()
        .with_audit_context(AuditContext::default());
    let session = test_session();
    let mut user = newcomer();
    user.identifier = "dave@example.com".into();
    let first = svc
        .begin_signup(user.clone(), "default", &session)
        .await
        .unwrap();
    assert!(matches!(first, SignupOutcome::Started(_)), "{first:?}");
    let again = svc.begin_signup(user, "default", &session).await.unwrap();
    assert!(matches!(again, SignupOutcome::Started(_)), "{again:?}");

    let rows: Vec<_> = identity
        .events()
        .into_iter()
        .filter(|e| {
            matches!(
                e.event_type,
                AuthEventType::SignupStarted | AuthEventType::SignupResumed
            )
        })
        .collect();
    assert_eq!(rows.len(), 2, "one row per submit: {rows:?}");
    assert_eq!(rows[0].event_type, AuthEventType::SignupStarted);
    assert_eq!(rows[1].event_type, AuthEventType::SignupResumed);
    assert_eq!(rows[1].event_status, AuthEventStatus::Success);
    assert_eq!(rows[1].user_id, Some(uid("u2")));
    assert_eq!(
        rows[1].error, None,
        "a success row carries no failure reason"
    );
}

// ── Password reset cooldown ──────────────────────────────────────────────────

fn reset_service(
    cooldown: Option<Duration>,
) -> (
    RequestAuthnService<MockIdentityStore, MockFactorStore>,
    MockClock,
) {
    let clock = common::test_clock();
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let builder = AuthnService::builder(identity, MockFactorStore::new()).with_clock(clock.clone());
    let builder = match cooldown {
        Some(cooldown) => builder.with_password_reset_cooldown(cooldown),
        None => builder.without_password_reset_cooldown(),
    };
    (
        builder.build().with_audit_context(AuditContext::default()),
        clock,
    )
}

const TTL: Duration = Duration::from_secs(300);

#[tokio::test]
async fn a_second_reset_request_inside_the_cooldown_is_refused() {
    let (svc, clock) = reset_service(Some(Duration::from_secs(60)));
    assert!(
        svc.begin_password_reset("alice", "default", TTL)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        svc.begin_password_reset("alice", "default", TTL)
            .await
            .unwrap()
            .is_none(),
        "inside the cooldown"
    );
    clock.advance(axess_clock::SignedDuration::seconds(61));
    assert!(
        svc.begin_password_reset("alice", "default", TTL)
            .await
            .unwrap()
            .is_some(),
        "after the cooldown"
    );
}

#[tokio::test]
async fn the_cooldown_treats_an_unknown_identifier_like_a_known_one() {
    let (svc, clock) = reset_service(Some(Duration::from_secs(60)));
    // An unknown identifier answers None before and during the cooldown, so
    // the cooldown tells a caller nothing about which identifiers exist.
    for _ in 0..2 {
        assert!(
            svc.begin_password_reset("nobody", "default", TTL)
                .await
                .unwrap()
                .is_none()
        );
    }
    clock.advance(axess_clock::SignedDuration::seconds(61));
    assert!(
        svc.begin_password_reset("nobody", "default", TTL)
            .await
            .unwrap()
            .is_none()
    );
    // Another identifier is not held up by the first one's cooldown.
    assert!(
        svc.begin_password_reset("alice", "default", TTL)
            .await
            .unwrap()
            .is_some()
    );
}

/// The cooldown keys on the identifier as a person reads it: case folded,
/// invisible format characters dropped, surrounding whitespace trimmed.
#[tokio::test]
async fn the_cooldown_keys_on_the_normalised_identifier() {
    use axess_core::testing::mock_authn::CallLog;
    let log = CallLog::new();
    let clock = common::test_clock();
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice@x.com"))
        .with_call_log(&log);
    let svc = AuthnService::builder(identity, MockFactorStore::new())
        .with_clock(clock.clone())
        .with_password_reset_cooldown(Duration::from_secs(60))
        .allow_plaintext_factor_secrets()
        .build()
        .with_audit_context(AuditContext::default());

    assert!(
        svc.begin_password_reset("alice@x.com", "default", TTL)
            .await
            .unwrap()
            .is_some()
    );
    for variant in ["ALICE@x.com\u{200B}", " alice@X.COM ", "Alice@x.com"] {
        assert!(
            svc.begin_password_reset(variant, "default", TTL)
                .await
                .unwrap()
                .is_none(),
            "{variant:?} is the same identifier inside the cooldown"
        );
    }
    assert_eq!(
        log.calls()
            .iter()
            .filter(|c| **c == "store_reset_token")
            .count(),
        1,
        "exactly one token was written: {:?}",
        log.calls()
    );
}

/// A builder nobody configured holds a minute's cooldown.
#[tokio::test]
async fn a_new_builder_has_a_minute_of_cooldown() {
    let clock = common::test_clock();
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let svc = AuthnService::builder(identity, MockFactorStore::new())
        .with_clock(clock.clone())
        .allow_plaintext_factor_secrets()
        .build()
        .with_audit_context(AuditContext::default());
    assert!(
        svc.begin_password_reset("alice", "default", TTL)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        svc.begin_password_reset("alice", "default", TTL)
            .await
            .unwrap()
            .is_none(),
        "a second request inside the default cooldown"
    );
    clock.advance(axess_clock::SignedDuration::seconds(61));
    assert!(
        svc.begin_password_reset("alice", "default", TTL)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn without_a_cooldown_repeated_requests_each_get_a_token() {
    let (svc, _) = reset_service(None);
    for _ in 0..3 {
        assert!(
            svc.begin_password_reset("alice", "default", TTL)
                .await
                .unwrap()
                .is_some()
        );
    }
}

/// A refusal whose reason is one of the tags axess names is recorded as that
/// tag, not as `Other` carrying the same text: a dashboard that groups by
/// reason, and a row read back from the store, must agree on what it was.
#[tokio::test]
async fn a_signup_into_an_unknown_tenant_is_audited_as_the_named_reason() {
    let (svc, identity) = signup_service(false);
    let session = test_session();
    svc.begin_signup(newcomer(), "no-such-tenant", &session)
        .await
        .unwrap();
    let reasons: Vec<_> = identity
        .events()
        .iter()
        .filter(|e| e.event_type == AuthEventType::SignupStarted)
        .filter_map(|e| e.error.clone())
        .collect();
    assert_eq!(
        reasons,
        vec![axess_core::authn::event::AuthFailureReason::UnknownTenant]
    );
}
