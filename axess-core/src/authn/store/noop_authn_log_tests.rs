use super::*;
use crate::authn::event::{AuthEventBuilder, AuthEventType};
use crate::testing::mock_authn::MockIdentityStore;

#[tokio::test]
async fn lookup_delegates_to_inner() {
    let inner = MockIdentityStore::new();
    let wrapped = NoopAuthnLog(inner.clone());
    let inner_user = inner.find_user("nobody", &TenantId::system()).await;
    let wrapped_user = wrapped.find_user("nobody", &TenantId::system()).await;
    assert_eq!(
        inner_user.is_ok(),
        wrapped_user.is_ok(),
        "NoopAuthnLog must pass through IdentityLookup methods unchanged"
    );
}

#[tokio::test]
async fn record_event_silently_drops() {
    let wrapped = NoopAuthnLog(MockIdentityStore::new());
    let event = AuthEventBuilder::success(AuthEventType::FactorVerified).build();
    assert!(wrapped.record_event(event).await.is_ok());
}

#[tokio::test]
async fn record_failed_attempt_always_returns_one() {
    let wrapped = NoopAuthnLog(MockIdentityStore::new());
    let uid = axess_identity::testing::user("noop-victim");
    for _ in 0..50 {
        let count = wrapped.record_failed_attempt(&uid).await.unwrap();
        assert_eq!(
            count, 1,
            "NoopAuthnLog must always report 1 so the lockout pipeline \
             never crosses any max_attempts threshold"
        );
    }
}

#[tokio::test]
async fn reset_failed_attempts_is_noop() {
    let wrapped = NoopAuthnLog(MockIdentityStore::new());
    let uid = axess_identity::testing::user("noop-victim");
    assert!(wrapped.reset_failed_attempts(&uid).await.is_ok());
}

#[tokio::test]
async fn lockout_policy_delegates_to_inner_not_trait_default() {
    // Kills `NoopAuthnLog::lockout_policy -> Default::default()`. The
    // default is max_attempts=5; we configure the inner store with a
    // distinct value so the delegated and the mutated result diverge.
    let custom = LockoutPolicy {
        max_attempts: 13,
        duration: Some(std::time::Duration::from_secs(99)),
        attempt_window: std::time::Duration::from_secs(7),
    };
    let inner = MockIdentityStore::new().with_lockout_policy(custom);
    let wrapped = NoopAuthnLog(inner);
    let got = wrapped.lockout_policy();
    assert_eq!(
        got.max_attempts, 13,
        "NoopAuthnLog::lockout_policy must delegate to inner, \
         not return LockoutPolicy::default() (max_attempts=5)"
    );
}

#[tokio::test]
async fn lockout_policy_for_tenant_delegates_to_inner_not_trait_default() {
    // Kills `NoopAuthnLog::lockout_policy_for_tenant -> Default::default()`.
    // MockIdentityStore's `lockout_policy_for_tenant` falls through to
    // `lockout_policy`; configuring the inner store with a custom global
    // policy is enough to distinguish delegated vs. mutated returns.
    let custom = LockoutPolicy {
        max_attempts: 17,
        duration: None,
        attempt_window: std::time::Duration::from_secs(11),
    };
    let inner = MockIdentityStore::new().with_lockout_policy(custom);
    let wrapped = NoopAuthnLog(inner);
    let got = wrapped.lockout_policy_for_tenant(&TenantId::system());
    assert_eq!(
        got.max_attempts, 17,
        "NoopAuthnLog::lockout_policy_for_tenant must delegate to inner, \
         not return LockoutPolicy::default() (max_attempts=5)"
    );
}

// Three `NoopAuthnLog<L>` impls (`record_event`, `record_failed_attempt`,
// `reset_failed_attempts`) carry only `tracing::trace!` side effects; their
// return values match the body-replacement mutants byte-for-byte
// (`Ok(())`, `Ok(1)`, `Ok(())`). The trace emit is the only observable.
// `TracingCapture::install()` is thread-local, and under heavy parallel
// `cargo test` load the per-callsite interest cache can be primed to
// "no interest" before the per-thread subscriber is in place, racing the
// observation. Those three mutants are therefore treated as equivalent
// (same observable API contract; tracing is diagnostic, not load-bearing).
