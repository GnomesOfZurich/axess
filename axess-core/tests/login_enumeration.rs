#![cfg(feature = "testing")]
//! What the combined login entry point and the failure pipeline tell a caller
//! who has proved nothing: a lock is never shown by the password form.

mod common;

use axess_clock::testing::MockClock;
use axess_core::authn::AuditContext;
use axess_core::authn::service::{AuthnService, FactorOutcome, RequestAuthnService};
use axess_core::authn::types::LockoutPolicy;
use axess_core::blocking::KdfExecutor;
use axess_core::testing::mock_authn::{MockFactorStore, MockIdentityStore};
use axess_core::testing::test_session;
use chrono::{TimeZone, Utc};
use common::{password_config, password_method, test_tenant, test_user, uid, user_scope};
use std::time::Duration;

type Svc = RequestAuthnService<MockIdentityStore, MockFactorStore>;

fn rig(policy: LockoutPolicy) -> (Svc, MockIdentityStore) {
    let clock = MockClock::at(Utc.timestamp_opt(1_700_000_000, 0).unwrap());
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"))
        .with_lockout_policy(policy)
        .with_clock(clock.clone());
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config("Gnomes2+"))
        .with_method(&uid("u1"), password_method());
    let svc = AuthnService::builder(identity.clone(), factors)
        .with_clock(clock)
        .with_kdf_executor(std::sync::Arc::new(KdfExecutor::inline()))
        .build()
        .with_audit_context(AuditContext::default());
    (svc, identity)
}

#[tokio::test]
async fn the_password_form_answers_the_guess_that_locks_the_account_as_a_wrong_password() {
    let (svc, _) = rig(LockoutPolicy {
        max_attempts: 3,
        duration: Some(Duration::from_secs(900)),
        ..LockoutPolicy::default().without_throttle()
    });
    let mut answers = Vec::new();
    for _ in 0..4 {
        answers.push(
            svc.login_with_password("alice", "default", "wrong", &test_session())
                .await,
        );
    }
    for answer in &answers {
        assert!(
            matches!(answer, Ok(FactorOutcome::InvalidCredential)),
            "an existing account must answer as an unknown one does: {answers:?}"
        );
    }
}
