#![cfg(feature = "testing")]
//! A signup verification TTL an operator set to an extreme value never
//! panics the signup that reads it.

mod common;

use axess_core::authn::AuditContext;
use axess_core::authn::service::{AuthnService, SignupOutcome};
use axess_core::authn::types::EntityState;
use axess_core::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use axess_testing::durations::extreme_durations;
use common::{test_tenant, test_user};

#[tokio::test]
async fn an_extreme_verification_ttl_never_panics_a_signup() {
    for extreme in extreme_durations() {
        let identity = MockIdentityStore::new().with_tenant(test_tenant());
        let svc = AuthnService::builder(identity, MockFactorStore::new())
            .with_signup_verification_ttl(extreme.value)
            .build()
            .with_audit_context(AuditContext::default());
        let mut user = test_user("u2", "bob@example.com");
        user.status = EntityState::Candidate;

        let outcome = svc
            .begin_signup(user, "default", &test_session())
            .await
            .unwrap_or_else(|e| panic!("signup with a ttl of {}: {e:?}", extreme.name));

        assert!(
            matches!(outcome, SignupOutcome::Started(Some(_))),
            "ttl of {}: {outcome:?}",
            extreme.name
        );
    }
}
