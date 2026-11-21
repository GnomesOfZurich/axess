//! `persist_fail_with_update`: the first failure inserts, a later one
//! compares and saves with the counter recomputed, and a lost or vanished
//! row is read again before the retry writes.

use super::*;

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
    // user-scope row, hit the EmailOtp arm in the retry match,
    // recompute `apply_email_otp_failure`,
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
    // test, for the `Hotp(otp)` arm of the retry match. Without the
    // arm, the retry loop's inner
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
    // warning. Pins the `!` in `if !applied { warn!() }`: without it
    // the warning is emitted ONLY on the success path, never on this
    // exhaustion path.
    use axess_testing::mock_tracing::TracingCapture;

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

/// A factor store that loses one compare-and-save, then reports the row as
/// absent on the next read while a freshly enrolled config lands in the
/// store: an admin delete and re-enrolment between two reads.
#[derive(Clone)]
struct VanishingRowFactors {
    inner: MockFactorStore,
    lose_next_cas: Arc<std::sync::atomic::AtomicBool>,
    hide_next_load: Arc<std::sync::atomic::AtomicBool>,
    enrolled: Arc<std::sync::Mutex<Option<FactorConfig>>>,
    /// Compare-and-saves the wrapped store answered with a loss: writes
    /// attempted against a prior that was no longer stored.
    lost_to_the_store: Arc<std::sync::atomic::AtomicUsize>,
}

impl FactorStore for VanishingRowFactors {
    type Error = crate::testing::mock_authn::MockStoreError;

    async fn resolve_factor(
        &self,
        scope: &AuthnScope,
        kind: FactorKind,
    ) -> Result<Option<crate::authn::store::ResolvedFactor>, Self::Error> {
        self.inner.resolve_factor(scope, kind).await
    }
    async fn load_factor(
        &self,
        scope: &AuthnScope,
        kind: FactorKind,
    ) -> Result<Option<FactorConfig>, Self::Error> {
        use std::sync::atomic::Ordering;
        if self.hide_next_load.swap(false, Ordering::SeqCst) {
            let enrolled = self.enrolled.lock().unwrap().take();
            if let Some(config) = enrolled {
                self.inner.save_factor(scope, config).await?;
            }
            return Ok(None);
        }
        self.inner.load_factor(scope, kind).await
    }
    async fn save_factor(&self, scope: &AuthnScope, c: FactorConfig) -> Result<(), Self::Error> {
        self.inner.save_factor(scope, c).await
    }
    async fn compare_and_save_factor(
        &self,
        scope: &AuthnScope,
        prior: &FactorConfig,
        updated: FactorConfig,
    ) -> Result<bool, Self::Error> {
        use std::sync::atomic::Ordering;
        if self.lose_next_cas.swap(false, Ordering::SeqCst) {
            self.hide_next_load.store(true, Ordering::SeqCst);
            return Ok(false);
        }
        let swapped = self
            .inner
            .compare_and_save_factor(scope, prior, updated)
            .await?;
        if !swapped {
            self.lost_to_the_store.fetch_add(1, Ordering::SeqCst);
        }
        Ok(swapped)
    }
    async fn insert_factor_if_absent(
        &self,
        scope: &AuthnScope,
        config: FactorConfig,
    ) -> Result<bool, Self::Error> {
        self.inner.insert_factor_if_absent(scope, config).await
    }
    async fn available_methods(
        &self,
        u: &UserId,
        t: &TenantId,
    ) -> Result<Vec<crate::authn::store::AuthMethod>, Self::Error> {
        self.inner.available_methods(u, t).await
    }
    async fn save_method(
        &self,
        s: &AuthnScope,
        m: crate::authn::store::AuthMethod,
    ) -> Result<(), Self::Error> {
        self.inner.save_method(s, m).await
    }
    async fn remove_method(&self, s: &AuthnScope, n: &str) -> Result<(), Self::Error> {
        self.inner.remove_method(s, n).await
    }
    async fn set_method_enabled(
        &self,
        s: &AuthnScope,
        n: &str,
        e: bool,
    ) -> Result<bool, Self::Error> {
        self.inner.set_method_enabled(s, n, e).await
    }
    async fn claim_fido2_credential(
        &self,
        t: &TenantId,
        u: &UserId,
        id: &[u8],
    ) -> Result<crate::authn::store::Fido2CredentialClaim, Self::Error> {
        self.inner.claim_fido2_credential(t, u, id).await
    }
    async fn release_fido2_credential(
        &self,
        t: &TenantId,
        u: &UserId,
        id: &[u8],
    ) -> Result<(), Self::Error> {
        self.inner.release_fido2_credential(t, u, id).await
    }
}

#[tokio::test]
async fn persist_fail_with_update_keeps_a_factor_enrolled_after_the_row_vanished() {
    let inner = MockFactorStore::new().with_factor(fixture_scope(), hotp_config(5));
    let factors = VanishingRowFactors {
        inner: inner.clone(),
        lose_next_cas: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        hide_next_load: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        enrolled: Arc::new(std::sync::Mutex::new(Some(hotp_config(77)))),
        lost_to_the_store: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
    };
    let identity = MockIdentityStore::new()
        .with_tenant(fixture_tenant())
        .with_user(user_with_status(EntityState::Active));
    let service = service_over(identity, factors).with_audit_context(AuditContext::default());

    service
        .persist_fail_with_update(
            &fixture_scope(),
            FactorKind::Hotp,
            &hotp_config_with_attempts(5, 1),
        )
        .await
        .unwrap();

    let stored = inner
        .load_factor(&fixture_scope(), FactorKind::Hotp)
        .await
        .unwrap()
        .expect("hotp present");
    assert_eq!(
        hotp_counter(&stored),
        77,
        "the newly enrolled factor must not be overwritten by the stale failure record"
    );
}

/// After the row vanished and a factor was enrolled meanwhile, the retry
/// reloads it before writing: a compare-and-save against the prior it knew
/// was gone would only lose and spend an attempt.
#[tokio::test]
async fn a_failure_record_reloads_before_writing_after_the_row_vanished() {
    let inner = MockFactorStore::new().with_factor(fixture_scope(), hotp_config(5));
    let lost = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let factors = VanishingRowFactors {
        inner: inner.clone(),
        lose_next_cas: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        hide_next_load: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        enrolled: Arc::new(std::sync::Mutex::new(Some(hotp_config(77)))),
        lost_to_the_store: lost.clone(),
    };
    let identity = MockIdentityStore::new()
        .with_tenant(fixture_tenant())
        .with_user(user_with_status(EntityState::Active));
    let service = service_over(identity, factors).with_audit_context(AuditContext::default());

    service
        .persist_fail_with_update(
            &fixture_scope(),
            FactorKind::Hotp,
            &hotp_config_with_attempts(5, 1),
        )
        .await
        .unwrap();

    assert_eq!(
        lost.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "no write may be attempted against a prior known to be stale"
    );
}
