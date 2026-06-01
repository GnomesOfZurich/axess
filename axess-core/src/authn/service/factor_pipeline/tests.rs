//! Isolated unit tests for the factor-pipeline helpers.
//!
//! The pipeline split promised that each extracted helper would be
//! "independently testable." These tests deliver on that: each
//! `enforce_account_status`, `persist_fail_with_update`,
//! `record_factor_failure`, and `persist_pass_with_update` branch is
//! exercised directly rather than only through a full `verify_factor`
//! integration test. A regression in any single branch surfaces here
//! with a much smaller blast radius than chasing it through the full
//! login flow.
//!
//! `extract_authenticating_state` now lives at
//! `AuthSession::authenticating_state`; its 3 branches
//! (Authenticating / Guest / Authenticated) are pinned at the bottom
//! of this file because the function pairs naturally with the rest of
//! the pipeline even though it now lives on the session.

use super::AccountStatusEnforcement;
use crate::authn::{
    event::{AuthEvent, AuthEventStatus, AuthEventType},
    factor::{EmailOtpConfig, FactorConfig, FactorKind, HotpConfig, ZeroizedString},
    ids::{TenantId, UserId},
    service::{AuthnService, FactorOutcome},
    store::FactorStore,
    types::{AuthnScope, EntityState, LockoutPolicy, StatusDetail, Tenant, User},
};
use crate::session::extractor::AuthSession;
use crate::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use chrono::{TimeZone, Utc};
use std::sync::Arc;

// ── Fixture helpers (local; these compose differently than the
// `tests/common/` set, so they're kept inline) ──────────────────────────

fn uid(v: &str) -> UserId {
    axess_identity::testing::user(v)
}

fn tid(v: &str) -> TenantId {
    axess_identity::testing::tenant(v)
}

fn user_with_status(status: EntityState) -> User {
    let now = Utc::now();
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
    let now = Utc::now();
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
        pending_until: Some(Utc::now() + chrono::Duration::minutes(5)),
        code_length: 6,
        ttl_secs: 300,
        max_attempts,
        attempt_count,
    })
}

fn hotp_config(counter: u64) -> FactorConfig {
    hotp_config_with_attempts(counter, 0)
}

fn hotp_config_with_attempts(counter: u64, attempt_count: u8) -> FactorConfig {
    FactorConfig::Hotp(HotpConfig {
        secret: ZeroizedString::new("JBSWY3DPEHPK3PXP".to_string()),
        counter,
        attempt_count,
        ..HotpConfig::default()
    })
}

/// Build an `AuthnService` wired against the mock stores with the
/// supplied user and tenant. `MockClock::now()` keeps timestamps
/// deterministic so audit-row matching is sharp.
fn build_service_with_user(
    user: User,
) -> (
    AuthnService<MockIdentityStore, MockFactorStore>,
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
    // underlying `DashMap`s via `Arc`.
    let inspector = identity.clone();
    let service = AuthnService::new(identity, MockFactorStore::new());
    (service, inspector)
}

/// Same as [`build_service_with_user`] but lets the caller supply a
/// pre-populated [`MockFactorStore`] so factor-config tests can prime
/// the store before exercising the helper.
fn build_service_with_factors(
    user: User,
    factors: MockFactorStore,
) -> (
    AuthnService<MockIdentityStore, MockFactorStore>,
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
    let service = AuthnService::new(identity, factors);
    (service, inspector, factor_inspector)
}

async fn authenticating_session(remaining: Vec<FactorKind>) -> AuthSession {
    let session = test_session();
    session
        .begin_authenticating(uid("u1"), tid("t1"), Arc::from("test-method"), remaining)
        .await;
    session
}

fn locked_failure_events(events: &[AuthEvent]) -> Vec<&AuthEvent> {
    events
        .iter()
        .filter(|e| {
            matches!(e.event_type, AuthEventType::FactorVerified)
                && matches!(e.event_status, AuthEventStatus::Failure)
                && e.error.as_deref() == Some("locked")
        })
        .collect()
}

// ── enforce_account_status ──────────────────────────────────────────────

#[tokio::test]
async fn enforce_account_status_returns_ok_for_active() {
    let user = user_with_status(EntityState::Active);
    let (service, inspector) = build_service_with_user(user);
    let session = authenticating_session(vec![FactorKind::Password]).await;

    let result = service
        .enforce_account_status(&uid("u1"), &tid("t1"), Some(FactorKind::Password), &session)
        .await
        .unwrap();

    assert!(matches!(result, AccountStatusEnforcement::Ok));
    // No audit row for an Active account.
    assert!(
        locked_failure_events(&inspector.events()).is_empty(),
        "Active account must not trigger a `locked` audit row"
    );
}

#[tokio::test]
async fn enforce_account_status_locked_with_until_passes_through_until_and_emits_audit() {
    let until = Utc.with_ymd_and_hms(2026, 5, 1, 12, 0, 0).unwrap();
    let detail = StatusDetail {
        reason: "policy".into(),
        since: Utc::now(),
        until: Some(until),
    };
    let user = user_with_status(EntityState::Suspended(detail));
    let (service, inspector) = build_service_with_user(user);
    let session = authenticating_session(vec![FactorKind::Totp]).await;

    let result = service
        .enforce_account_status(&uid("u1"), &tid("t1"), Some(FactorKind::Totp), &session)
        .await
        .unwrap();

    match result {
        AccountStatusEnforcement::Locked { until: got_until } => {
            assert_eq!(got_until, Some(until));
        }
        other => panic!("expected Locked, got {other:?}"),
    }

    // Exactly one Failure row with `error = "locked"` and the
    // next factor kind on it.
    let all_events = inspector.events();
    let locked_events = locked_failure_events(&all_events);
    assert_eq!(
        locked_events.len(),
        1,
        "locked-account attempt must emit exactly one Failure audit row"
    );
    let event = locked_events[0];
    assert_eq!(event.factor_kind.as_ref(), Some(&FactorKind::Totp));
    assert_eq!(event.user_id.as_ref(), Some(&uid("u1")));
}

#[tokio::test]
async fn enforce_account_status_locked_indefinite_returns_until_none() {
    let detail = StatusDetail {
        reason: "indefinite".into(),
        since: Utc::now(),
        until: None,
    };
    let user = user_with_status(EntityState::Suspended(detail));
    let (service, inspector) = build_service_with_user(user);
    let session = authenticating_session(vec![FactorKind::Password]).await;

    let result = service
        .enforce_account_status(&uid("u1"), &tid("t1"), Some(FactorKind::Password), &session)
        .await
        .unwrap();

    match result {
        AccountStatusEnforcement::Locked { until, .. } => {
            assert_eq!(until, None, "indefinite suspension must surface as None")
        }
        other => panic!("expected Locked, got {other:?}"),
    }
    assert_eq!(locked_failure_events(&inspector.events()).len(), 1);
}

#[tokio::test]
async fn enforce_account_status_pending_returns_not_active_without_audit() {
    let detail = StatusDetail {
        reason: "pending email verification".into(),
        since: Utc::now(),
        until: None,
    };
    let user = user_with_status(EntityState::Pending(detail));
    let (service, inspector) = build_service_with_user(user);
    let session = authenticating_session(vec![FactorKind::Password]).await;

    let result = service
        .enforce_account_status(&uid("u1"), &tid("t1"), Some(FactorKind::Password), &session)
        .await
        .unwrap();

    assert!(matches!(result, AccountStatusEnforcement::NotActive(_)));
    // The locked-attempt audit fires only on `Locked` (Suspended).
    // Pending / Terminated / Archived must not emit one; the SOC
    // signal is specific to brute-force-after-lockout, not "any
    // non-active attempt."
    assert!(
        locked_failure_events(&inspector.events()).is_empty(),
        "Pending account must not trigger the `locked` audit"
    );
}

#[tokio::test]
async fn enforce_account_status_no_next_kind_still_emits_audit_without_factor_field() {
    let detail = StatusDetail {
        reason: "policy".into(),
        since: Utc::now(),
        until: None,
    };
    let user = user_with_status(EntityState::Suspended(detail));
    let (service, inspector) = build_service_with_user(user);
    let session = authenticating_session(vec![]).await;

    // `next_kind = None` mirrors `verify_factor`'s behaviour when
    // `remaining.first()` yields nothing (factor list exhausted but
    // session somehow still in Authenticating). The audit row still
    // fires, just without a `factor_kind` attribution.
    service
        .enforce_account_status(&uid("u1"), &tid("t1"), None, &session)
        .await
        .unwrap();

    let all_events = inspector.events();
    let events = locked_failure_events(&all_events);
    assert_eq!(events.len(), 1);
    assert!(
        events[0].factor_kind.is_none(),
        "no next-kind ⇒ no `with_factor` on the audit row"
    );
}

// ── persist_fail_with_update ────────────────────────────────────────────

#[tokio::test]
async fn persist_fail_with_update_initial_empty_does_plain_insert() {
    // No user-scope row exists. `persist_fail_with_update` must save
    // the supplied `updated_config` directly; there's nothing to race
    // with, so no CAS is attempted (path: `applied = true` after the
    // initial save).
    let user = user_with_status(EntityState::Active);
    let updated = email_otp_config(1, 5);
    let (service, _, factors) = build_service_with_factors(user, MockFactorStore::new());

    service
        .persist_fail_with_update(&fixture_scope(), FactorKind::EmailOtp, &updated)
        .await
        .unwrap();

    let stored = factors
        .load_factor(&fixture_scope(), FactorKind::EmailOtp)
        .await
        .unwrap()
        .expect("factor must be persisted");
    let FactorConfig::EmailOtp(cfg) = stored else {
        panic!("expected EmailOtp")
    };
    assert_eq!(cfg.attempt_count, 1);
}

#[tokio::test]
async fn persist_fail_with_update_existing_row_uses_cas_and_recomputes() {
    // A user-scope row already exists. The helper recomputes the
    // failure update against the *live* value (not the inherited
    // template) and CAS-saves it. Verifies the invariant that
    // we don't blindly trust the caller's `updated_config`.
    let user = user_with_status(EntityState::Active);
    let factors = MockFactorStore::new().with_factor(fixture_scope(), email_otp_config(2, 5));
    let (service, _, factors_inspector) = build_service_with_factors(user, factors);

    // Caller's `updated_config` has failed_attempts=1, but the live
    // row has failed_attempts=2. The helper must recompute against
    // the live row → result should be 3, not 2.
    let stale_updated = email_otp_config(1, 5);

    service
        .persist_fail_with_update(&fixture_scope(), FactorKind::EmailOtp, &stale_updated)
        .await
        .unwrap();

    let stored = factors_inspector
        .load_factor(&fixture_scope(), FactorKind::EmailOtp)
        .await
        .unwrap()
        .expect("factor still present");
    let FactorConfig::EmailOtp(cfg) = stored else {
        panic!("expected EmailOtp")
    };
    assert_eq!(
        cfg.attempt_count, 3,
        "must recompute increment from live (2) → 3, not blindly use caller's updated (1)"
    );
}

#[tokio::test]
async fn persist_fail_with_update_hotp_branch_recomputes_via_apply_hotp_failure() {
    // Same recompute invariant for HOTP; independent code path in
    // the helper's match. Without a dedicated test, a regression that
    // dropped the HOTP arm would only surface through full HOTP
    // flow tests.
    let user = user_with_status(EntityState::Active);
    // Live store: counter=7, attempt_count=2.
    let factors =
        MockFactorStore::new().with_factor(fixture_scope(), hotp_config_with_attempts(7, 2));
    let (service, _, factors_inspector) = build_service_with_factors(user, factors);

    // Stale HOTP config the caller computed; attempt_count=0; the
    // helper must IGNORE this and recompute from the live (2) → 3.
    let stale_updated = hotp_config_with_attempts(7, 0);

    service
        .persist_fail_with_update(&fixture_scope(), FactorKind::Hotp, &stale_updated)
        .await
        .unwrap();

    let stored = factors_inspector
        .load_factor(&fixture_scope(), FactorKind::Hotp)
        .await
        .unwrap()
        .expect("hotp factor persisted");
    let FactorConfig::Hotp(cfg) = stored else {
        panic!("expected Hotp")
    };
    // apply_hotp_failure below max_attempts: attempt_count += 1.
    // Live had 2 → must end at 3, NOT 1 (which is what blindly using
    // the stale `attempt_count=0 → 0+1=1` would yield).
    assert_eq!(
        cfg.attempt_count, 3,
        "HOTP arm: must recompute from live (attempt_count=2 → 3), not blindly use caller's stale (0 → 1)"
    );
    // Counter unchanged below max_attempts.
    assert_eq!(cfg.counter, 7);
}

#[tokio::test]
async fn persist_fail_with_update_email_otp_retry_recomputes_after_cas_loss() {
    // CAS-loss-then-retry path for EmailOtp. The first
    // `compare_and_save_factor` call is forced to return `Ok(false)`
    // via `arm_cas_failures(1)`; the helper must then reload the
    // user-scope row, hit the EmailOtp arm in the retry match
    // (factor_pipeline.rs:253), recompute `apply_email_otp_failure`,
    // and CAS-succeed on the second attempt. Kills the "delete match
    // arm EmailOtp(otp)" mutation: under the mutation the inner
    // match falls through to `_ => break`, the loop exits with
    // `applied = false`, and the stored attempt_count never reaches 3.
    let user = user_with_status(EntityState::Active);
    let factors = MockFactorStore::new().with_factor(fixture_scope(), email_otp_config(2, 5));
    let (service, _, factors_inspector) = build_service_with_factors(user, factors);

    // Force one CAS-loss before the function makes any real CAS attempt.
    factors_inspector.arm_cas_failures(1);

    let stale_updated = email_otp_config(1, 5);
    service
        .persist_fail_with_update(&fixture_scope(), FactorKind::EmailOtp, &stale_updated)
        .await
        .unwrap();

    let stored = factors_inspector
        .load_factor(&fixture_scope(), FactorKind::EmailOtp)
        .await
        .unwrap()
        .expect("email otp present after retry");
    let FactorConfig::EmailOtp(cfg) = stored else {
        panic!("expected EmailOtp")
    };
    assert_eq!(
        cfg.attempt_count, 3,
        "retry path must recompute the EmailOtp increment from the reloaded live row (2) → 3"
    );
}

#[tokio::test]
async fn persist_fail_with_update_hotp_retry_recomputes_after_cas_loss() {
    // CAS-loss-then-retry path for HOTP. Same shape as the EmailOtp
    // test; kills the "delete match arm Hotp(otp)" mutation at
    // factor_pipeline.rs:257. Without the arm, the retry loop's inner
    // match drops through to `_ => break`, `applied` stays false, and
    // the stored attempt_count never advances.
    let user = user_with_status(EntityState::Active);
    let factors =
        MockFactorStore::new().with_factor(fixture_scope(), hotp_config_with_attempts(7, 2));
    let (service, _, factors_inspector) = build_service_with_factors(user, factors);

    factors_inspector.arm_cas_failures(1);

    let stale_updated = hotp_config_with_attempts(7, 0);
    service
        .persist_fail_with_update(&fixture_scope(), FactorKind::Hotp, &stale_updated)
        .await
        .unwrap();

    let stored = factors_inspector
        .load_factor(&fixture_scope(), FactorKind::Hotp)
        .await
        .unwrap()
        .expect("hotp present after retry");
    let FactorConfig::Hotp(cfg) = stored else {
        panic!("expected Hotp")
    };
    assert_eq!(
        cfg.attempt_count, 3,
        "retry path must recompute the HOTP increment from the reloaded live row (2) → 3"
    );
    assert_eq!(cfg.counter, 7);
}

#[tokio::test]
async fn persist_fail_with_update_logs_warning_when_retries_exhausted() {
    // Force every CAS attempt (initial + 8 retries) to lose. The
    // helper must end with `applied = false` and emit the
    // "failed to atomically increment failure counter after retries"
    // warning. Kills the `delete !` mutation on `if !applied { warn!() }`
    // at factor_pipeline.rs:269; under the mutation the warning is
    // emitted ONLY on the success path, never on this exhaustion path.
    use crate::testing::mock_tracing::TracingCapture;

    let capture = TracingCapture::install();

    let user = user_with_status(EntityState::Active);
    let factors = MockFactorStore::new().with_factor(fixture_scope(), email_otp_config(2, 5));
    let (service, _, factors_inspector) = build_service_with_factors(user, factors);

    // 9 CAS losses = 1 initial + 8 retries = full exhaustion.
    factors_inspector.arm_cas_failures(9);

    let stale_updated = email_otp_config(1, 5);
    service
        .persist_fail_with_update(&fixture_scope(), FactorKind::EmailOtp, &stale_updated)
        .await
        .unwrap();

    let saw_exhaustion_warning = capture.events().iter().any(|ev| {
        ev.message
            .contains("failed to atomically increment failure counter after retries")
    });
    assert!(
        saw_exhaustion_warning,
        "exhausted-retry path must emit the \
         'failed to atomically increment failure counter after retries' warning"
    );
}

// ── record_factor_failure ───────────────────────────────────────────────

#[tokio::test]
async fn record_factor_failure_below_threshold_returns_invalid_credential() {
    let user = user_with_status(EntityState::Active);
    let (service, inspector) = build_service_with_user(user);
    let session = authenticating_session(vec![FactorKind::Password]).await;

    let outcome = service
        .record_factor_failure(&uid("u1"), &tid("t1"), &FactorKind::Password, &session)
        .await
        .unwrap();
    assert!(matches!(outcome, FactorOutcome::InvalidCredential));

    // Counter incremented by exactly one.
    assert_eq!(inspector.failed_attempts_for("u1"), 1);

    // A `FactorVerified Failure` row with the kind attached.
    let event = inspector
        .events()
        .into_iter()
        .find(|e| {
            matches!(e.event_type, AuthEventType::FactorVerified)
                && matches!(e.event_status, AuthEventStatus::Failure)
        })
        .expect("failure audit row must be emitted");
    assert_eq!(event.factor_kind.as_ref(), Some(&FactorKind::Password));
}

#[tokio::test]
async fn record_factor_failure_at_threshold_returns_locked() {
    let user = user_with_status(EntityState::Active);
    let (service, inspector) = build_service_with_user(user);
    let session = authenticating_session(vec![FactorKind::Password]).await;

    // Lockout policy in `build_service_with_user` is max_attempts=3.
    // First two attempts: InvalidCredential. Third: Locked.
    for _ in 0..2 {
        let outcome = service
            .record_factor_failure(&uid("u1"), &tid("t1"), &FactorKind::Password, &session)
            .await
            .unwrap();
        assert!(matches!(outcome, FactorOutcome::InvalidCredential));
    }
    let third = service
        .record_factor_failure(&uid("u1"), &tid("t1"), &FactorKind::Password, &session)
        .await
        .unwrap();
    // At the lockout threshold the helper returns Locked, not
    // InvalidCredential.
    // The verdict that *creates* the lockout now carries the
    // lockout window (`now + policy.duration`); earlier code dropped
    // the duration even when the policy carried it. The default mock
    // policy has `duration: Some(15 min)`, so `until` is `Some(_)`.
    let FactorOutcome::Locked { until } = third else {
        panic!("expected Locked at threshold, got {third:?}");
    };
    let until =
        until.expect("Locked must carry policy.duration as `until` when the policy has one");
    // `until` must be in the FUTURE relative to the call site.
    // Default LockoutPolicy duration is 15 min, so `until` ≈ now + 15min.
    // The `replace + with -` mutation on `clock.now() + d` would put
    // `until` 15 min in the *past*; silently leaving the verdict
    // "locked but expired immediately". Pin the direction.
    let before = chrono::Utc::now();
    assert!(
        until > before,
        "Locked.until must be in the future (kills `+ → -` on \
         `clock.now() + policy.duration`); until={until} before={before}"
    );
    assert_eq!(inspector.failed_attempts_for("u1"), 3);
}

#[tokio::test]
async fn record_factor_failure_counter_store_error_mutes_to_invalid_credential() {
    // If `record_failed_attempt` errors, the helper must NOT
    // propagate `Err(AuthnError::Store)`; that would leak a
    // distinct timing/error signature. It must return
    // `Ok(InvalidCredential)` and log a warning.
    let user = user_with_status(EntityState::Active);
    let (service, inspector) = build_service_with_user(user);
    let session = authenticating_session(vec![FactorKind::Password]).await;

    inspector.arm_record_failed_attempt_failure();

    let outcome = service
        .record_factor_failure(&uid("u1"), &tid("t1"), &FactorKind::Password, &session)
        .await
        .expect("store errors must not propagate as Err");
    assert!(
        matches!(outcome, FactorOutcome::InvalidCredential),
        "counter-store outage must surface as InvalidCredential, not Locked or Err"
    );

    // Counter did not advance (the store rejected the increment),
    // but the audit row should still be there (audit
    // BEFORE counter increment).
    assert_eq!(inspector.failed_attempts_for("u1"), 0);
    let has_failure_audit = inspector.events().iter().any(|e| {
        matches!(e.event_type, AuthEventType::FactorVerified)
            && matches!(e.event_status, AuthEventStatus::Failure)
    });
    assert!(
        has_failure_audit,
        "audit row must be emitted BEFORE the counter increment, so a counter-store outage doesn't suppress the SOC signal"
    );
}

// ── persist_pass_with_update ────────────────────────────────────────────

#[tokio::test]
async fn persist_pass_with_update_inserts_when_no_user_scope_row() {
    // First successful verification under an inherited (tenant or
    // global) template; no user-scope row to CAS against, so the
    // helper does a plain insert and returns `true`.
    let user = user_with_status(EntityState::Active);
    let (service, _, factors) = build_service_with_factors(user, MockFactorStore::new());

    let updated = hotp_config(8); // post-verification counter advance
    let saved = service
        .persist_pass_with_update(&fixture_scope(), FactorKind::Hotp, updated)
        .await
        .unwrap();

    assert!(saved, "no prior row ⇒ must save and return true");
    let stored = factors
        .load_factor(&fixture_scope(), FactorKind::Hotp)
        .await
        .unwrap()
        .expect("hotp must be saved to user scope");
    let FactorConfig::Hotp(cfg) = stored else {
        panic!("expected Hotp")
    };
    assert_eq!(cfg.counter, 8);
}

#[tokio::test]
async fn persist_pass_with_update_cas_succeeds_when_prior_matches() {
    // User-scope row already exists and matches what the caller saw
    // when verifying; CAS swaps cleanly and returns true.
    let user = user_with_status(EntityState::Active);
    let factors = MockFactorStore::new().with_factor(fixture_scope(), hotp_config(5));
    let (service, _, factors_inspector) = build_service_with_factors(user, factors);

    let saved = service
        .persist_pass_with_update(&fixture_scope(), FactorKind::Hotp, hotp_config(6))
        .await
        .unwrap();
    assert!(saved);

    let stored = factors_inspector
        .load_factor(&fixture_scope(), FactorKind::Hotp)
        .await
        .unwrap()
        .expect("present");
    let FactorConfig::Hotp(cfg) = stored else {
        panic!("expected Hotp")
    };
    assert_eq!(cfg.counter, 6);
}

#[tokio::test]
async fn persist_pass_with_update_cas_loss_returns_false_as_replay_signal() {
    // CAS-loss path for `persist_pass_with_update`. With
    // `arm_cas_failures(1)` the first (and only) CAS attempt loses,
    // so the helper must return `Ok(false)`; the caller in
    // `verify_factor` reads that as "another writer spent the same
    // step/counter already" and treats it as a replay.
    let user = user_with_status(EntityState::Active);
    let factors = MockFactorStore::new().with_factor(fixture_scope(), hotp_config(5));
    let (service, _, factors_inspector) = build_service_with_factors(user, factors);

    factors_inspector.arm_cas_failures(1);

    let saved = service
        .persist_pass_with_update(&fixture_scope(), FactorKind::Hotp, hotp_config(6))
        .await
        .unwrap();
    assert!(
        !saved,
        "CAS loss must surface as Ok(false) so the caller can flag a replay"
    );
}

// ── AuthSession::authenticating_state ──────────────────────────

#[tokio::test]
async fn authenticating_state_destructures_authenticating_session() {
    let session = authenticating_session(vec![FactorKind::Password, FactorKind::Totp]).await;
    let (user_id, tenant_id, remaining) = session
        .authenticating_state()
        .await
        .expect("Authenticating session must produce a triple");
    assert_eq!(user_id, uid("u1"));
    assert_eq!(tenant_id, tid("t1"));
    assert_eq!(remaining, vec![FactorKind::Password, FactorKind::Totp]);
}

#[tokio::test]
async fn authenticating_state_returns_none_for_guest_session() {
    let session = test_session(); // Guest by default
    assert!(
        session.authenticating_state().await.is_none(),
        "Guest sessions must not surface a triple; callers map None to AuthnError::NoFlow"
    );
}

#[tokio::test]
async fn authenticating_state_returns_none_for_authenticated_session() {
    let session = authenticating_session(vec![FactorKind::Password]).await;
    // Advance through the only remaining factor to flip to Authenticated.
    session
        .advance_factor(&FactorKind::Password, Utc::now())
        .await;
    assert!(session.is_authenticated().await);
    assert!(
        session.authenticating_state().await.is_none(),
        "Authenticated sessions are no longer mid-flow; must yield None"
    );
}
