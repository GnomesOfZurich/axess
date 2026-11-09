#![cfg(feature = "testing")]
//! The breached-password check at password choice: a password reset and the
//! service's own admission of a chosen password (`check_chosen_password`,
//! `hash_chosen_password`) consult the check the service was built with,
//! refuse a breached password by name, refuse an unscreened one by default
//! and only under the named opt-out let it through, and leave a tenant that
//! turned the check off alone.

mod common;

use axess_core::authn::event::{AuthEventStatus, AuthEventType, AuthFailureReason};
use axess_core::authn::factor::{BreachCheckUnavailable, NewPasswordError, PasswordRules};
use axess_core::authn::service::ChosenPasswordError;
use axess_core::authn::{AuditContext, AuthnService, RequestAuthnService};
use axess_core::authn::{
    factor::BreachedPasswordCheck,
    types::{EntityState, User},
};
use axess_core::testing::mock_authn::{MockFactorStore, MockIdentityStore};
use axess_core::{BreachCheckOutage, BreachedPasswordList};
use axess_testing::mock_tracing::TracingCapture;
use chrono::Utc;
use common::{test_tenant, tid, uid};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A password that meets the default rules and sits on the list.
const BREACHED: &str = "Password123!";
/// A password that meets the default rules and is not on the list.
const CLEAN: &str = "Gnomes2+andmore";

fn alice() -> User {
    let now = Utc::now();
    User {
        id: uid("u1"),
        tenant_id: tid("t1"),
        identifier: "alice".into(),
        display_name: "alice".into(),
        status: EntityState::Active,
        webauthn_id: None,
        created_by: axess_core::authn::ids::UserId::system(),
        created_at: now,
        updated_by: axess_core::authn::ids::UserId::system(),
        updated_at: now,
    }
}

fn identity(rules: Option<PasswordRules>) -> MockIdentityStore {
    let user = alice();
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(user.clone());
    match rules {
        Some(rules) => identity.with_password_rules(&user.tenant_id, rules),
        None => identity,
    }
}

fn request(
    svc: AuthnService<MockIdentityStore, MockFactorStore>,
) -> RequestAuthnService<MockIdentityStore, MockFactorStore> {
    svc.with_audit_context(AuditContext::default())
}

async fn reset_token(svc: &RequestAuthnService<MockIdentityStore, MockFactorStore>) -> String {
    svc.begin_password_reset("alice", "default", std::time::Duration::from_secs(300))
        .await
        .unwrap()
        .expect("token")
}

fn reset_failure_reasons(identity: &MockIdentityStore) -> Vec<String> {
    identity
        .events()
        .into_iter()
        .filter(|e| {
            e.event_type == AuthEventType::PasswordReset
                && e.event_status == AuthEventStatus::Failure
        })
        .map(|e| e.error.map(|r| r.as_str().to_owned()).unwrap_or_default())
        .collect()
}

/// A check that counts how often it was asked, so a test can show that a
/// flow did not consult it.
struct Counting(Arc<AtomicUsize>);

impl BreachedPasswordCheck for Counting {
    fn is_breached<'a>(
        &'a self,
        _password: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<bool, axess_core::authn::factor::BreachCheckError>,
                > + Send
                + 'a,
        >,
    > {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(std::future::ready(Ok(true)))
    }
}

// ── password reset ──────────────────────────────────────────────────────────

#[tokio::test]
async fn a_reset_to_a_breached_password_is_refused_and_the_link_stays_usable() {
    let identity = identity(None);
    let inspector = identity.clone();
    let svc = request(
        AuthnService::builder(identity, MockFactorStore::new())
            .with_breached_password_check(BreachedPasswordList::new([BREACHED]))
            .build(),
    );
    let token = reset_token(&svc).await;

    assert!(
        !svc.complete_password_reset(&uid("u1"), &token, BREACHED)
            .await
            .unwrap(),
        "a breached password must not reset the account"
    );
    assert_eq!(reset_failure_reasons(&inspector), ["password_breached"]);

    assert!(
        svc.complete_password_reset(&uid("u1"), &token, CLEAN)
            .await
            .unwrap(),
        "the refused attempt must not have spent the token"
    );
}

#[tokio::test]
async fn a_reset_while_the_check_is_down_is_refused_by_default() {
    let identity = identity(None);
    let inspector = identity.clone();
    let svc = request(
        AuthnService::builder(identity, MockFactorStore::new())
            .with_breached_password_check(BreachCheckOutage::new("range service timed out"))
            .build(),
    );
    let token = reset_token(&svc).await;

    assert!(
        !svc.complete_password_reset(&uid("u1"), &token, CLEAN)
            .await
            .unwrap()
    );
    assert_eq!(
        reset_failure_reasons(&inspector),
        ["breach_check_unavailable"]
    );
    let row = inspector
        .events()
        .into_iter()
        .find(|e| e.event_type == AuthEventType::PasswordReset)
        .unwrap();
    assert_eq!(
        row.error,
        Some(AuthFailureReason::from("breach_check_unavailable"))
    );
}

#[tokio::test]
async fn a_reset_while_the_check_is_down_passes_under_the_opt_out() {
    let identity = identity(None);
    let inspector = identity.clone();
    let svc = request(
        AuthnService::builder(identity, MockFactorStore::new())
            .with_breached_password_check(BreachCheckOutage::new("range service timed out"))
            .allow_unchecked_when_breach_check_unavailable()
            .build(),
    );
    let token = reset_token(&svc).await;

    assert!(
        svc.complete_password_reset(&uid("u1"), &token, CLEAN)
            .await
            .unwrap()
    );
    assert!(reset_failure_reasons(&inspector).is_empty());
}

#[tokio::test]
async fn an_exempt_tenant_resets_to_a_password_the_check_knows() {
    let identity = identity(Some(PasswordRules {
        breached_check: false,
        ..PasswordRules::default()
    }));
    let svc = request(
        AuthnService::builder(identity, MockFactorStore::new())
            .with_breached_password_check(BreachedPasswordList::new([BREACHED]))
            .build(),
    );
    let token = reset_token(&svc).await;
    assert!(
        svc.complete_password_reset(&uid("u1"), &token, BREACHED)
            .await
            .unwrap(),
        "a tenant with breached_check off is not screened"
    );
}

#[tokio::test]
async fn without_a_check_a_reset_is_not_screened() {
    let svc = request(AuthnService::new(identity(None), MockFactorStore::new()));
    let token = reset_token(&svc).await;
    assert!(
        svc.complete_password_reset(&uid("u1"), &token, BREACHED)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn a_reset_with_a_wrong_token_does_not_consult_the_check() {
    let calls = Arc::new(AtomicUsize::new(0));
    let identity = identity(None);
    let inspector = identity.clone();
    let svc = request(
        AuthnService::builder(identity, MockFactorStore::new())
            .with_breached_password_check(Counting(calls.clone()))
            .build(),
    );
    let _token = reset_token(&svc).await;

    assert!(
        !svc.complete_password_reset(&uid("u1"), "not-the-token", CLEAN)
            .await
            .unwrap()
    );
    assert_eq!(reset_failure_reasons(&inspector), ["token_mismatch"]);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "an unauthenticated caller must not make the server call the check"
    );
}

#[tokio::test]
async fn a_reset_that_fails_the_rules_does_not_consult_the_check() {
    let calls = Arc::new(AtomicUsize::new(0));
    let identity = identity(None);
    let inspector = identity.clone();
    let svc = request(
        AuthnService::builder(identity, MockFactorStore::new())
            .with_breached_password_check(Counting(calls.clone()))
            .build(),
    );
    let token = reset_token(&svc).await;

    assert!(
        !svc.complete_password_reset(&uid("u1"), &token, "short1A")
            .await
            .unwrap()
    );
    assert_eq!(reset_failure_reasons(&inspector), ["password_rules"]);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

// ── the service's own admission of a chosen password ────────────────────────

#[tokio::test]
async fn check_chosen_password_refuses_a_breached_password_by_name() {
    let svc = AuthnService::builder(identity(None), MockFactorStore::new())
        .with_breached_password_check(BreachedPasswordList::new([BREACHED]))
        .build();
    let rules = PasswordRules::default();
    assert_eq!(
        svc.check_chosen_password(BREACHED, &rules).await,
        Err(NewPasswordError::Breached)
    );
    assert_eq!(svc.check_chosen_password(CLEAN, &rules).await, Ok(()));
    assert_eq!(
        svc.check_chosen_password("short1A", &rules).await,
        Err(NewPasswordError::RulesNotMet)
    );
    let long = format!("Aa1{}", "x".repeat(axess_factors::MAX_PASSWORD_BYTES - 2));
    assert_eq!(
        svc.check_chosen_password(&long, &rules).await,
        Err(NewPasswordError::TooLong)
    );
}

#[tokio::test]
async fn check_chosen_password_refuses_an_outage_unless_opted_out() {
    let refusing = AuthnService::builder(identity(None), MockFactorStore::new())
        .with_breached_password_check(BreachCheckOutage::new("down"))
        .build();
    assert_eq!(
        refusing
            .check_chosen_password(CLEAN, &PasswordRules::default())
            .await,
        Err(NewPasswordError::BreachCheckUnavailable)
    );

    let allowing = AuthnService::builder(identity(None), MockFactorStore::new())
        .with_breached_password_check(BreachCheckOutage::new("down"))
        .allow_unchecked_when_breach_check_unavailable()
        .build();
    assert_eq!(
        allowing
            .check_chosen_password(CLEAN, &PasswordRules::default())
            .await,
        Ok(())
    );
}

#[tokio::test]
async fn check_chosen_password_honours_an_exempt_tenant_and_no_check() {
    let svc = AuthnService::builder(identity(None), MockFactorStore::new())
        .with_breached_password_check(BreachedPasswordList::new([BREACHED]))
        .build();
    let exempt = PasswordRules {
        breached_check: false,
        ..PasswordRules::default()
    };
    assert_eq!(svc.check_chosen_password(BREACHED, &exempt).await, Ok(()));

    let unchecked = AuthnService::new(identity(None), MockFactorStore::new());
    assert_eq!(
        unchecked
            .check_chosen_password(BREACHED, &PasswordRules::default())
            .await,
        Ok(())
    );
}

#[tokio::test]
async fn hash_chosen_password_hashes_an_admitted_password_and_refuses_the_rest() {
    let svc = AuthnService::builder(identity(None), MockFactorStore::new())
        .with_breached_password_check(BreachedPasswordList::new([BREACHED]))
        .build();
    let rules = PasswordRules::default();
    let hash = svc.hash_chosen_password(CLEAN, &rules).await.unwrap();
    assert!(axess_factors::verify_password(CLEAN, &hash).is_ok());
    assert!(!axess_factors::password_needs_rehash(&hash));

    match svc.hash_chosen_password(BREACHED, &rules).await {
        Err(ChosenPasswordError::Refused(NewPasswordError::Breached)) => {}
        other => panic!("expected a breached refusal, got {other:?}"),
    }
}

// ── the builder's warning ───────────────────────────────────────────────────

#[test]
fn building_without_a_check_warns_once_and_with_one_does_not() {
    let capture = TracingCapture::install();
    let _svc = AuthnService::builder(identity(None), MockFactorStore::new()).build();
    assert!(
        capture.contains_at_level(tracing::Level::WARN, "without a breached-password check"),
        "events: {:?}",
        capture.events()
    );
    let before = capture.events().len();

    let _svc = AuthnService::builder(identity(None), MockFactorStore::new())
        .with_breached_password_check(BreachedPasswordList::new([BREACHED]))
        .build();
    let after: Vec<_> = capture.events().into_iter().skip(before).collect();
    assert!(
        !after
            .iter()
            .any(|e| e.message.contains("breached-password check")),
        "a service with a check must not warn about one: {after:?}"
    );
}

#[test]
fn the_unavailable_policy_defaults_to_refuse() {
    assert_eq!(
        BreachCheckUnavailable::default(),
        BreachCheckUnavailable::Refuse
    );
}
