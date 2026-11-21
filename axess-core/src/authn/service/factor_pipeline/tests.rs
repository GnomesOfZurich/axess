//! Isolated unit tests for the factor-pipeline helpers.
//!
//! Each helper of the pipeline is testable on its own, and these tests
//! do that: each `enforce_account_status`, `persist_fail_with_update`,
//! `record_factor_failure`, and `persist_pass_with_update` branch is
//! exercised directly rather than only through a full `verify_factor`
//! integration test. A regression in any single branch surfaces here
//! with a much smaller blast radius than chasing it through the full
//! login flow.
//!
//! `AuthSession::authenticating_state` is a method of the session and
//! is tested here all the same, because it pairs with the rest of the
//! pipeline: its 3 branches (Authenticating / Guest / Authenticated)
//! are pinned in `tests/authenticating_state.rs`.
//!
//! This file holds the fixtures every topic shares; the tests sit by topic
//! in the files under `tests/`.

use super::AccountStatusEnforcement;
use super::GuessSlot;
use crate::authn::AuditContext;
use crate::authn::{
    event::{AuthEvent, AuthEventStatus, AuthEventType},
    factor::{EmailOtpConfig, FactorConfig, FactorKind, HotpConfig, ZeroizedString},
    ids::{TenantId, UserId},
    service::{AuthnService, FactorOutcome},
    store::FactorStore,
    types::{
        AuthnScope, CounterUnavailable, EntityState, LockoutPolicy, StatusDetail, Tenant, User,
    },
};
use crate::session::extractor::AuthSession;
use crate::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use axess_clock::Timestamp;
use axess_clock::testing::MockClock;
use axess_clock::testing::Shift;
use std::sync::Arc;

// Fixture helpers, shared by every topic. They compose differently than the
// `tests/common/` set, so they are kept here.

fn uid(v: &str) -> UserId {
    axess_identity::testing::user(v)
}

fn tid(v: &str) -> TenantId {
    axess_identity::testing::tenant(v)
}

/// The instant every service and fixture of these tests stands at: the
/// services read a `MockClock` frozen there, so a time a test writes and the
/// time the service compares it with are the same clock's.
fn start() -> Timestamp {
    Timestamp::from_utc(2026, 1, 1, 0, 0, 0).expect("a valid instant")
}

/// A service over `identity` and `factors` on a clock frozen at [`start`].
fn service_over<F>(identity: MockIdentityStore, factors: F) -> AuthnService<MockIdentityStore, F>
where
    F: crate::authn::store::FactorStore<Error = crate::testing::mock_authn::MockStoreError>,
{
    AuthnService::builder(identity, factors)
        .with_clock(MockClock::at(start()))
        .build()
}

fn user_with_status(status: EntityState) -> User {
    let now = start();
    User {
        id: uid("u1"),
        tenant_id: tid("t1"),
        identifier: "alice".into(),
        display_name: "alice".into(),
        status,
        webauthn_id: None,
        created_by: UserId::system(),
        created_at: now,
        updated_by: UserId::system(),
        updated_at: now,
    }
}

fn fixture_tenant() -> Tenant {
    let now = start();
    Tenant {
        id: tid("t1"),
        identifier: "default".into(),
        display_name: "Test Tenant".into(),
        status: EntityState::Active,
        created_by: UserId::system(),
        created_at: now,
        updated_by: UserId::system(),
        updated_at: now,
    }
}

fn fixture_scope() -> AuthnScope {
    AuthnScope::User {
        tenant_id: tid("t1"),
        user_id: uid("u1"),
    }
}

fn email_otp_config(attempt_count: u8, max_attempts: u8) -> FactorConfig {
    FactorConfig::EmailOtp(EmailOtpConfig {
        email: "alice@example.com".into(),
        pending_hash: Some(ZeroizedString::new("hash".to_string())),
        pending_until: Some(axess_clock::Until::At(
            start().plus(axess_clock::SignedDuration::minutes(5)),
        )),
        code_length: 6,
        ttl: std::time::Duration::from_secs(300),
        max_attempts,
        attempt_count,
    })
}

fn hotp_config(counter: u64) -> FactorConfig {
    hotp_config_with_attempts(counter, 0)
}

fn hotp_config_with_attempts(counter: u64, attempt_count: u8) -> FactorConfig {
    FactorConfig::Hotp(HotpConfig {
        secret: ZeroizedString::new("JBSWY3DPEHPK3PXP".to_string()).into(),
        counter,
        attempt_count,
        ..HotpConfig::default()
    })
}

/// Build an `AuthnService` wired against the mock stores with the
/// supplied user and tenant, on a clock frozen at [`start`] so timestamps
/// are deterministic and audit-row matching is sharp.
fn build_service_with_user(
    user: User,
) -> (
    super::RequestAuthnService<MockIdentityStore, MockFactorStore>,
    MockIdentityStore,
) {
    let identity = MockIdentityStore::new()
        .with_tenant(fixture_tenant())
        .with_user(user)
        .with_lockout_policy(LockoutPolicy {
            max_attempts: 3,
            ..LockoutPolicy::default()
        });
    // We need a second handle to inspect events/counters after the
    // service runs; `MockIdentityStore` is `Clone` and shares the
    // underlying maps via `Arc`.
    let inspector = identity.clone();
    let service =
        service_over(identity, MockFactorStore::new()).with_audit_context(AuditContext::default());
    (service, inspector)
}

/// Same as [`build_service_with_user`] but lets the caller supply a
/// pre-populated [`MockFactorStore`] so factor-config tests can prime
/// the store before exercising the helper.
fn build_service_with_factors(
    user: User,
    factors: MockFactorStore,
) -> (
    super::RequestAuthnService<MockIdentityStore, MockFactorStore>,
    MockIdentityStore,
    MockFactorStore,
) {
    let identity = MockIdentityStore::new()
        .with_tenant(fixture_tenant())
        .with_user(user)
        .with_lockout_policy(LockoutPolicy {
            max_attempts: 3,
            ..LockoutPolicy::default()
        });
    let inspector = identity.clone();
    let factor_inspector = factors.clone();
    let service = service_over(identity, factors).with_audit_context(AuditContext::default());
    (service, inspector, factor_inspector)
}

async fn authenticating_session(remaining: Vec<FactorKind>) -> AuthSession {
    let session = test_session();
    session
        .begin_authenticating(
            uid("u1"),
            tid("t1"),
            Arc::from("test-method"),
            remaining
                .into_iter()
                .map(crate::authn::factor::FactorStep::Required)
                .collect(),
        )
        .await;
    session
}

/// Rows a locked account produces: `Locked` on the status, not `Failure`
/// with the word in `error`. The status is the field a SOC query can filter
/// on and the store enforces; the tag was a string nothing checked, and it
/// left [`AuthEventStatus::Locked`] unreachable.
fn locked_events(events: &[AuthEvent]) -> Vec<&AuthEvent> {
    events
        .iter()
        .filter(|e| {
            matches!(e.event_type, AuthEventType::FactorVerified)
                && matches!(e.event_status, AuthEventStatus::Locked)
        })
        .collect()
}

fn hotp_counter(c: &FactorConfig) -> u64 {
    let FactorConfig::Hotp(h) = c else {
        panic!("expected Hotp")
    };
    h.counter
}

mod account_status;
mod authenticating_state;
mod concurrent_use;
mod persist_fail;
mod persist_pass;
mod record_failure;
