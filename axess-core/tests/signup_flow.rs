//! Integration tests for the signup, activation, and suspension flows.

#![cfg(feature = "testing")]

mod common;

use axess_core::authn::Actor;
use axess_core::authn::{AuditContext, RequestAuthnService};
use axess_core::{
    authn::{
        error::AuthnError,
        event::AuthEventType,
        ids::UserId,
        service::{AuthnService, SignupOutcome},
        store::IdentityLookup,
        types::{EntityState, StatusDetail, User},
    },
    session::data::AuthState,
    testing::{
        mock_authn::{MockFactorStore, MockIdentityStore},
        test_session,
    },
};
use chrono::Utc;
use common::{test_tenant, tid, uid};

/// Candidate-status variant of [`common::test_user`]; signup flow tests need
/// a user in `EntityState::Candidate` before activation.
fn candidate_user(id: &str, identifier: &str) -> User {
    let now = Utc::now();
    User {
        id: uid(id),
        tenant_id: tid("t1"),
        identifier: identifier.into(),
        display_name: identifier.into(),
        status: EntityState::Candidate,
        webauthn_id: None,
        created_by: UserId::system(),
        created_at: now,
        updated_by: UserId::system(),
        updated_at: now,
    }
}

fn make_service() -> RequestAuthnService<MockIdentityStore, MockFactorStore> {
    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let factors = MockFactorStore::new();
    AuthnService::new(identity, factors).with_audit_context(AuditContext::default())
}

/// Begin a signup and return the verification secret it minted.
async fn begin(
    service: &RequestAuthnService<MockIdentityStore, MockFactorStore>,
    session: &axess_core::session::extractor::AuthSession,
    user: User,
) -> String {
    match service
        .begin_signup(user, "default", session)
        .await
        .unwrap()
    {
        SignupOutcome::Started(Some(verification)) => verification.secret().to_owned(),
        other => panic!("expected a verification secret, got {other:?}"),
    }
}

// ── Signup flow tests ────────────────────────────────────────────────────────

/// A session id the visitor arrived with may have been planted: the pending
/// signup lives under a fresh one.
#[tokio::test]
async fn begin_signup_moves_the_session_to_a_fresh_id() {
    let service = make_service();
    let session = test_session();
    let before = session.session_id().await;

    let user = candidate_user("u1", "alice@example.com");
    let outcome = service
        .begin_signup(user, "default", &session)
        .await
        .unwrap();

    assert!(matches!(outcome, SignupOutcome::Started(_)));
    assert_ne!(session.session_id().await, before);
}

#[tokio::test]
async fn begin_signup_creates_user_and_sets_pending_workflow() {
    let service = make_service();
    let session = test_session();

    let user = candidate_user("u1", "alice@example.com");
    let outcome = service
        .begin_signup(user, "default", &session)
        .await
        .unwrap();

    assert!(matches!(outcome, SignupOutcome::Started(_)));

    // Session should be in PendingWorkflow(Signup).
    let state = session.auth_state().await;
    assert!(matches!(
        state,
        AuthState::PendingWorkflow { ref workflow, .. }
        if workflow.kind == axess_core::session::data::WorkflowKind::Signup
    ));

    // User ID should be set on the session.
    assert_eq!(
        session.pending_user_id().await,
        Some(axess_core::authn::ids::testing::user("u1"))
    );
}

#[tokio::test]
async fn begin_signup_stores_the_user_in_the_tenant_it_validated() {
    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let service = AuthnService::new(identity.clone(), MockFactorStore::new())
        .with_audit_context(AuditContext::default());
    let session = test_session();

    // The record names some other tenant; the slug names `default`.
    let mut user = candidate_user("u1", "alice@example.com");
    user.tenant_id = tid("some-other-tenant");
    service
        .begin_signup(user, "default", &session)
        .await
        .unwrap();

    let stored = identity
        .find_user("alice@example.com", &test_tenant().id)
        .await
        .unwrap()
        .expect("the user lands in the tenant the slug resolved to");
    assert_eq!(stored.tenant_id, test_tenant().id);
    assert_eq!(session.pending_tenant_id().await, Some(test_tenant().id));
}

#[tokio::test]
async fn begin_signup_active_user_returns_already_exists() {
    // An *active* user cannot be overwritten by a fresh signup.
    // Only orphan Candidates resume; Active accounts must reject.
    let mut active_user = candidate_user("u1", "alice@example.com");
    active_user.status = EntityState::Active;
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(active_user);
    let factors = MockFactorStore::new();
    let service = AuthnService::builder(identity, factors)
        .with_signup_conflicts_revealed()
        .build()
        .with_audit_context(AuditContext::default());
    let session = test_session();

    let user = candidate_user("u2", "alice@example.com");
    let outcome = service
        .begin_signup(user, "default", &session)
        .await
        .unwrap();

    assert!(matches!(outcome, SignupOutcome::AlreadyExists));
    assert!(session.auth_state().await.is_guest());
}

/// A duplicate `begin_signup` against an existing *Candidate* row is not
/// resumed for a different session: whoever types an identifier would
/// otherwise be handed the half-created account of the person it belongs
/// to. Only the session already pending signup for that user gets `Started`
/// again (an idempotent resubmit).
#[tokio::test]
async fn begin_signup_orphan_candidate_is_not_handed_to_a_stranger() {
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(candidate_user("u1", "alice@example.com"));
    let factors = MockFactorStore::new();
    let service = AuthnService::builder(identity, factors)
        .with_signup_conflicts_revealed()
        .build()
        .with_audit_context(AuditContext::default());
    let session = test_session();

    let user = candidate_user("u2", "alice@example.com");
    let outcome = service
        .begin_signup(user, "default", &session)
        .await
        .unwrap();

    assert!(
        matches!(outcome, SignupOutcome::AlreadyExists),
        "{outcome:?}"
    );
    assert_eq!(
        session.user_id().await,
        None,
        "nothing of the existing Candidate is attached to the caller"
    );
}

/// The session that began a signup can submit it again: that is the same
/// session, already bound to the user, and gets `Started` once more.
#[tokio::test]
async fn begin_signup_resubmit_from_the_pending_session_is_idempotent() {
    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let service = AuthnService::new(identity, MockFactorStore::new())
        .with_audit_context(AuditContext::default());
    let session = test_session();
    let user = candidate_user("u1", "alice@example.com");
    let first = service
        .begin_signup(user.clone(), "default", &session)
        .await
        .unwrap();
    assert!(matches!(first, SignupOutcome::Started(_)));
    let again = service
        .begin_signup(user, "default", &session)
        .await
        .unwrap();
    assert!(matches!(again, SignupOutcome::Started(_)), "{again:?}");
}

#[tokio::test]
async fn begin_signup_bad_tenant_returns_tenant_not_active() {
    // No tenants registered.
    let identity = MockIdentityStore::new();
    let factors = MockFactorStore::new();
    let service = AuthnService::new(identity, factors).with_audit_context(AuditContext::default());
    let session = test_session();

    let user = candidate_user("u1", "alice@example.com");
    let outcome = service
        .begin_signup(user, "default", &session)
        .await
        .unwrap();

    assert!(matches!(outcome, SignupOutcome::TenantNotActive));
}

#[tokio::test]
async fn complete_signup_activates_user_and_authenticates() {
    let service = make_service();
    let session = test_session();

    // Begin signup.
    let user = candidate_user("u1", "alice@example.com");
    let secret = begin(&service, &session, user).await;

    // Complete signup; should activate user and authenticate session.
    service.complete_signup(&session, &secret).await.unwrap();

    assert!(session.is_authenticated().await);
    assert_eq!(
        session.user_id().await,
        Some(axess_core::authn::ids::testing::user("u1"))
    );
}

#[tokio::test]
async fn complete_signup_without_pending_workflow_returns_no_flow() {
    let service = make_service();
    let session = test_session();

    // Session is Guest; no PendingWorkflow.
    let result = service.complete_signup(&session, "anything").await;
    assert!(matches!(result, Err(AuthnError::NoFlow)), "{result:?}");
}

#[tokio::test]
async fn signup_records_audit_events() {
    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let factors = MockFactorStore::new();
    let service =
        AuthnService::new(identity.clone(), factors).with_audit_context(AuditContext::default());
    let session = test_session();

    let user = candidate_user("u1", "alice@example.com");
    let secret = begin(&service, &session, user).await;
    service.complete_signup(&session, &secret).await.unwrap();

    let events = identity.events();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].event_type, AuthEventType::SignupStarted);
    assert_eq!(events[1].event_type, AuthEventType::SignupCompleted);
}

// ── Suspend / activate tests ─────────────────────────────────────────────────

#[tokio::test]
async fn suspend_user_changes_status() {
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user({
            let now = Utc::now();
            User {
                id: uid("u1"),
                tenant_id: tid("t1"),
                identifier: "alice".into(),
                display_name: "Alice".into(),
                status: EntityState::Active,
                webauthn_id: None,
                created_by: UserId::system(),
                created_at: now,
                updated_by: UserId::system(),
                updated_at: now,
            }
        });
    let factors = MockFactorStore::new();
    let service =
        AuthnService::new(identity.clone(), factors).with_audit_context(AuditContext::default());

    let detail = StatusDetail::administrative("policy violation", Utc::now());
    service
        .suspend_user_across_tenants(Actor::System, &uid("u1"), detail)
        .await
        .unwrap();

    // User should now be suspended.
    let status = identity.account_status(&uid("u1")).await.unwrap();
    assert!(status.is_suspended());

    // Audit event should be recorded.
    let events = identity.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, AuthEventType::AccountSuspended);
}

#[tokio::test]
async fn activate_user_changes_status() {
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user({
            let now = Utc::now();
            User {
                id: uid("u1"),
                tenant_id: tid("t1"),
                identifier: "alice".into(),
                display_name: "Alice".into(),
                status: EntityState::Candidate,
                webauthn_id: None,
                created_by: UserId::system(),
                created_at: now,
                updated_by: UserId::system(),
                updated_at: now,
            }
        });
    let factors = MockFactorStore::new();
    let service =
        AuthnService::new(identity.clone(), factors).with_audit_context(AuditContext::default());

    service
        .activate_user_across_tenants(Actor::System, &uid("u1"))
        .await
        .unwrap();

    let status = identity.account_status(&uid("u1")).await.unwrap();
    assert!(status.is_active());

    let events = identity.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, AuthEventType::AccountActivated);
}

#[tokio::test]
async fn suspend_then_reactivate() {
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user({
            let now = Utc::now();
            User {
                id: uid("u1"),
                tenant_id: tid("t1"),
                identifier: "alice".into(),
                display_name: "Alice".into(),
                status: EntityState::Active,
                webauthn_id: None,
                created_by: UserId::system(),
                created_at: now,
                updated_by: UserId::system(),
                updated_at: now,
            }
        });
    let factors = MockFactorStore::new();
    let service =
        AuthnService::new(identity.clone(), factors).with_audit_context(AuditContext::default());

    // Suspend.
    let detail = StatusDetail::administrative("investigation", Utc::now());
    service
        .suspend_user_across_tenants(Actor::System, &uid("u1"), detail)
        .await
        .unwrap();
    assert!(
        identity
            .account_status(&uid("u1"))
            .await
            .unwrap()
            .is_suspended()
    );

    // Reactivate.
    service
        .activate_user_across_tenants(Actor::System, &uid("u1"))
        .await
        .unwrap();
    assert!(
        identity
            .account_status(&uid("u1"))
            .await
            .unwrap()
            .is_active()
    );
}

// ── Input validation tests ───────────────────────────────────────────────────

#[tokio::test]
async fn signup_rejects_oversized_identifier() {
    let service = make_service();
    let session = test_session();

    let now = Utc::now();
    let user = User {
        id: uid("u1"),
        tenant_id: tid("t1"),
        identifier: "a".repeat(300).into(), // > MAX_IDENTIFIER_BYTES (256)
        display_name: "Alice".into(),
        status: EntityState::Candidate,
        webauthn_id: None,
        created_by: UserId::system(),
        created_at: now,
        updated_by: UserId::system(),
        updated_at: now,
    };
    let result = service.begin_signup(user, "default", &session).await;
    assert!(matches!(result, Err(AuthnError::InvalidAssertion)));
}

#[tokio::test]
async fn signup_rejects_control_chars_in_display_name() {
    let service = make_service();
    let session = test_session();

    let now = Utc::now();
    let user = User {
        id: uid("u1"),
        tenant_id: tid("t1"),
        identifier: "alice@example.com".into(),
        display_name: "Alice\x00Evil".into(), // null byte
        status: EntityState::Candidate,
        webauthn_id: None,
        created_by: UserId::system(),
        created_at: now,
        updated_by: UserId::system(),
        updated_at: now,
    };
    let result = service.begin_signup(user, "default", &session).await;
    assert!(matches!(result, Err(AuthnError::InvalidAssertion)));
}

/// A timed suspension of the tenant that has lapsed by `complete_signup` no
/// longer blocks the activation: the status is read as of the clock, as a
/// login reads it.
#[tokio::test]
async fn complete_signup_admits_a_tenant_whose_timed_suspension_has_lapsed() {
    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let service = AuthnService::new(identity.clone(), MockFactorStore::new())
        .with_audit_context(AuditContext::default());
    let session = test_session();
    let secret = begin(
        &service,
        &session,
        candidate_user("u1", "alice@example.com"),
    )
    .await;

    let mut lapsed = test_tenant();
    lapsed.status = EntityState::Suspended(
        StatusDetail::administrative("hold", Utc::now() - chrono::Duration::hours(2))
            .with_until(Some(Utc::now() - chrono::Duration::hours(1))),
    );
    let _ = identity.clone().with_tenant(lapsed);

    let result = service.complete_signup(&session, &secret).await;

    assert!(result.is_ok(), "{result:?}");
    assert!(session.is_authenticated().await);
}

/// A tenant suspended between `begin_signup` and `complete_signup` refuses the
/// activation: the tenant's status is read again, not taken from the begin.
#[tokio::test]
async fn complete_signup_refuses_a_tenant_suspended_since_the_begin() {
    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let service = AuthnService::new(identity.clone(), MockFactorStore::new())
        .with_audit_context(AuditContext::default());
    let session = test_session();
    let secret = begin(
        &service,
        &session,
        candidate_user("u1", "alice@example.com"),
    )
    .await;

    let mut suspended = test_tenant();
    suspended.status = EntityState::Suspended(StatusDetail::administrative("hold", Utc::now()));
    let _ = identity.clone().with_tenant(suspended);

    let result = service.complete_signup(&session, &secret).await;

    assert!(result.is_err(), "{result:?}");
    assert!(
        !session.is_authenticated().await,
        "a suspended tenant's signup must not authenticate"
    );
}

// ── The verification secret ──────────────────────────────────────────────────

/// The secret `begin_signup` mints is what completes the signup: a session
/// that began one cannot activate itself with anything else.
#[tokio::test]
async fn complete_signup_refuses_a_wrong_secret() {
    let service = make_service();
    let session = test_session();
    let secret = begin(&service, &session, candidate_user("u1", "a@example.com")).await;

    for wrong in ["", "nope", &format!("{secret}x"), &secret[1..]] {
        let result = service.complete_signup(&session, wrong).await;
        assert!(
            matches!(result, Err(AuthnError::InvalidAssertion)),
            "{wrong:?}: {result:?}"
        );
        assert!(!session.is_authenticated().await);
    }
    service.complete_signup(&session, &secret).await.unwrap();
    assert!(session.is_authenticated().await);
}

/// The session holds a digest of the secret, never the secret.
#[tokio::test]
async fn the_pending_signup_holds_a_digest_not_the_secret() {
    let service = make_service();
    let session = test_session();
    let secret = begin(&service, &session, candidate_user("u1", "a@example.com")).await;

    let AuthState::PendingWorkflow { workflow, .. } = session.auth_state().await else {
        panic!("pending signup expected");
    };
    let digest = workflow.verification_digest.expect("a digest is stored");
    assert!(!digest.contains(&secret));
    assert_ne!(digest, secret);
    assert!(workflow.verification_expires_at.is_some());
}

/// A secret older than the verification lifetime completes nothing; the
/// session that submits the signup again gets a new one, and the old one
/// stops working.
#[tokio::test]
async fn an_expired_or_replaced_secret_completes_nothing() {
    use axess_clock::testing::MockClock;
    let clock = MockClock::at(Utc::now());
    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let service = AuthnService::builder(identity, MockFactorStore::new())
        .with_clock(clock.clone())
        .with_signup_verification_ttl(std::time::Duration::from_secs(3600))
        .build()
        .with_audit_context(AuditContext::default());
    let session = test_session();
    let user = candidate_user("u1", "a@example.com");
    let first = begin(&service, &session, user.clone()).await;

    clock.advance(chrono::Duration::minutes(61));
    let result = service.complete_signup(&session, &first).await;
    assert!(
        matches!(result, Err(AuthnError::InvalidAssertion)),
        "{result:?}"
    );
    assert!(!session.is_authenticated().await);

    let second = begin(&service, &session, user).await;
    assert_ne!(first, second);
    let result = service.complete_signup(&session, &first).await;
    assert!(
        matches!(result, Err(AuthnError::InvalidAssertion)),
        "{result:?}"
    );
    service.complete_signup(&session, &second).await.unwrap();
    assert!(session.is_authenticated().await);
}

/// The secret is single use: once the signup is complete, the same secret
/// finds no pending signup.
#[tokio::test]
async fn a_completed_signups_secret_cannot_be_used_again() {
    let service = make_service();
    let session = test_session();
    let secret = begin(&service, &session, candidate_user("u1", "a@example.com")).await;
    service.complete_signup(&session, &secret).await.unwrap();
    let result = service.complete_signup(&session, &secret).await;
    assert!(matches!(result, Err(AuthnError::NoFlow)), "{result:?}");
}

/// A signup pending without a stored digest (begun by an older release, or
/// built by hand) cannot be completed with any secret.
#[tokio::test]
async fn a_pending_signup_without_a_digest_cannot_be_completed() {
    let service = make_service();
    let user = candidate_user("u1", "a@example.com");
    service
        .begin_signup(user.clone(), "default", &test_session())
        .await
        .unwrap();
    let session = common::signup_session_for(&user).await;
    let result = service.complete_signup(&session, "anything").await;
    assert!(
        matches!(result, Err(AuthnError::InvalidAssertion)),
        "{result:?}"
    );
}
