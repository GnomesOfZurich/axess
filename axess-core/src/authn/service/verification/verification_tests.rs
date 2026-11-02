//! `verification_tests`: extracted from `verification.rs` per the
//! 200-LoC inline-test rule in AGENTS.md.

use super::*;
use crate::authn::factor::{
    EmailOtpConfig, HotpConfig, OtpAlgorithm, PasswordConfig, ZeroizedString,
};
use crate::validation::MAX_PASSWORD_BYTES;
use chrono::Utc;
use std::sync::Arc;

/// RFC 4226 Appendix D shared test secret in base32 form
/// (ASCII "12345678901234567890"). Combined with counter=0 it
/// produces the canonical HOTP code "755224".
const RFC_4226_SECRET_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

// ── apply_hotp_failure ───────────────────────────────────────────

#[test]
fn apply_hotp_failure_zero_max_attempts_applies_default_limit() {
    let now = Utc::now();
    let prior = HotpConfig {
        counter: 7,
        attempt_count: 4,
        max_attempts: 0,
        lookahead_window: 4,
        ..Default::default()
    };
    let next = apply_hotp_failure(&prior, now);
    assert_eq!(next.counter, 7, "the counter never moves on a failure");
    assert!(
        next.is_locked_at(now),
        "zero must lock at the default limit"
    );
    assert_eq!(next.attempt_count, 0);
}

#[test]
fn apply_hotp_failure_below_max_increments_without_locking() {
    let now = Utc::now();
    let prior = HotpConfig {
        counter: 7,
        attempt_count: 2,
        max_attempts: 5,
        ..Default::default()
    };
    let next = apply_hotp_failure(&prior, now);
    assert_eq!(next.counter, 7);
    assert_eq!(next.attempt_count, 3);
    assert_eq!(next.locked_until(), None);
}

#[test]
fn apply_hotp_failure_at_max_locks_with_doubling_backoff_and_keeps_the_counter() {
    let t0 = Utc::now();
    let prior = HotpConfig {
        counter: 100,
        attempt_count: 4,
        max_attempts: 5,
        lookahead_window: 4,
        ..Default::default()
    };
    let first = apply_hotp_failure(&prior, t0);
    assert_eq!(first.counter, 100);
    assert_eq!(first.attempt_count, 0);
    assert_eq!(first.lockouts(), 1);
    assert_eq!(
        first.locked_until(),
        Some(t0 + chrono::Duration::from_std(HotpConfig::lock_duration_after(0)).unwrap())
    );
    // A guess while locked changes nothing.
    assert_eq!(
        apply_hotp_failure(&first, t0 + chrono::Duration::seconds(1)).locked_until(),
        first.locked_until()
    );
    // After the lock, another run of wrong codes earns twice the lock.
    let after = first.locked_until().unwrap();
    let mut cfg = first;
    for _ in 0..5 {
        cfg = apply_hotp_failure(&cfg, after);
    }
    assert_eq!(cfg.lockouts(), 2);
    assert_eq!(
        cfg.locked_until(),
        Some(after + chrono::Duration::from_std(HotpConfig::lock_duration_after(1)).unwrap())
    );
    assert_eq!(cfg.counter, 100);
}

// ── apply_email_otp_failure ──────────────────────────────────────

#[test]
fn apply_email_otp_failure_zero_max_attempts_applies_default_limit() {
    let prior = EmailOtpConfig {
        email: "test@example.com".into(),
        pending_hash: Some(ZeroizedString::new("hash")),
        pending_until: Some(Utc::now()),
        attempt_count: 5,
        max_attempts: 0,
        ..Default::default()
    };
    let next = apply_email_otp_failure(&prior);
    assert!(next.pending_hash.is_none(), "zero must burn at the default");
    assert_eq!(next.attempt_count, 0);
}

// ── verify_credential: HOTP attempt-limit lock ───────────────────

#[test]
fn hotp_attempt_limit_locks_without_moving_the_counter() {
    // A row at the limit with no lock yet (written before the lock
    // existed) is locked on its next use rather than checked.
    let now = Utc::now();
    let cfg = FactorConfig::Hotp(HotpConfig {
        secret: ZeroizedString::new(RFC_4226_SECRET_B32).into(),
        counter: 100,
        attempt_count: 5,
        max_attempts: 5,
        lookahead_window: 4,
        ..Default::default()
    });
    let cred = FactorCredential::OtpCode(Arc::from("123456"));
    let outcome = verify_credential(
        &cred,
        &cfg,
        &FactorKind::Hotp,
        now,
        &RecoveryPeppers::default(),
    );
    match outcome {
        VerifyOutcome::FailWithUpdate(FactorConfig::Hotp(updated)) => {
            assert_eq!(updated.counter, 100);
            assert_eq!(updated.attempt_count, 0);
            assert!(updated.is_locked_at(now));
        }
        _ => panic!("expected FailWithUpdate lock"),
    }
}

#[test]
fn hotp_zero_max_attempts_locks_at_default_limit_and_refuses_while_locked() {
    let now = Utc::now();
    let cfg = FactorConfig::Hotp(HotpConfig {
        secret: ZeroizedString::new(RFC_4226_SECRET_B32).into(),
        counter: 0,
        attempt_count: 5,
        max_attempts: 0,
        lookahead_window: 0,
        ..Default::default()
    });
    // "755224" is the correct code for counter 0; at the default limit it
    // is not checked, and while the lock holds nothing is checked or
    // changed.
    let cred = FactorCredential::OtpCode(Arc::from("755224"));
    let locked = match verify_credential(
        &cred,
        &cfg,
        &FactorKind::Hotp,
        now,
        &RecoveryPeppers::default(),
    ) {
        VerifyOutcome::FailWithUpdate(FactorConfig::Hotp(updated)) => {
            assert_eq!(updated.counter, 0);
            assert!(updated.is_locked_at(now));
            updated
        }
        _ => panic!("expected the factor to lock"),
    };
    let cfg = FactorConfig::Hotp(locked.clone());
    assert!(
        matches!(
            verify_credential(
                &cred,
                &cfg,
                &FactorKind::Hotp,
                now,
                &RecoveryPeppers::default()
            ),
            VerifyOutcome::Fail
        ),
        "a locked factor refuses the right code without an update"
    );
    // Once the lock has run out the same code, at the same counter, passes
    // and the throttle state is forgotten.
    let later = locked.locked_until().unwrap();
    match verify_credential(
        &cred,
        &cfg,
        &FactorKind::Hotp,
        later,
        &RecoveryPeppers::default(),
    ) {
        VerifyOutcome::PassWithUpdate(FactorConfig::Hotp(updated)) => {
            assert_eq!(updated.counter, 1);
            assert_eq!((updated.locked_until(), updated.lockouts()), (None, 0));
        }
        _ => panic!("expected the token's code to pass after the lock"),
    }
}

// ── verify_credential: HOTP success advances counter by exactly 1 ─

#[test]
fn hotp_success_advances_counter_by_one() {
    let cfg = FactorConfig::Hotp(HotpConfig {
        secret: ZeroizedString::new(RFC_4226_SECRET_B32).into(),
        digits: 6,
        algorithm: OtpAlgorithm::Sha1,
        counter: 0,
        lookahead_window: 0,
        attempt_count: 0,
        max_attempts: 5,
        throttle: Default::default(),
    });
    let cred = FactorCredential::OtpCode(Arc::from("755224"));
    let outcome = verify_credential(
        &cred,
        &cfg,
        &FactorKind::Hotp,
        Utc::now(),
        &RecoveryPeppers::default(),
    );
    match outcome {
        VerifyOutcome::PassWithUpdate(FactorConfig::Hotp(updated)) => {
            assert_eq!(updated.counter, 1);
            assert_eq!(updated.attempt_count, 0);
        }
        _ => panic!("expected PassWithUpdate"),
    }
}

// ── verify_credential: Email OTP attempt-limit boundary ──────────

#[test]
fn email_otp_zero_max_attempts_burns_at_default_limit() {
    let hash = axess_factors::generate_password_hash("12345678");
    let future = Utc::now() + chrono::Duration::seconds(300);
    let cfg = FactorConfig::EmailOtp(EmailOtpConfig {
        email: "test@example.com".into(),
        pending_hash: Some(ZeroizedString::new(&hash)),
        pending_until: Some(future),
        attempt_count: 5,
        max_attempts: 0,
        ..Default::default()
    });
    let cred = FactorCredential::OtpCode(Arc::from("12345678"));
    match verify_credential(
        &cred,
        &cfg,
        &FactorKind::EmailOtp,
        Utc::now(),
        &RecoveryPeppers::default(),
    ) {
        VerifyOutcome::FailWithUpdate(FactorConfig::EmailOtp(updated)) => {
            assert!(updated.pending_hash.is_none());
        }
        _ => panic!("expected the code to burn"),
    }
}

#[test]
fn email_otp_without_expiry_is_rejected() {
    let code = "12345678";
    let hash = axess_factors::generate_password_hash(code);
    let cfg = FactorConfig::EmailOtp(EmailOtpConfig {
        email: "test@example.com".into(),
        pending_hash: Some(ZeroizedString::new(&hash)),
        pending_until: None,
        ..Default::default()
    });
    let cred = FactorCredential::OtpCode(Arc::from(code));
    let outcome = verify_credential(
        &cred,
        &cfg,
        &FactorKind::EmailOtp,
        Utc::now(),
        &RecoveryPeppers::default(),
    );
    assert!(matches!(outcome, VerifyOutcome::Fail));
}

#[test]
fn generate_otp_code_handles_long_lengths() {
    for len in [19usize, 20, 25, 40] {
        let code = generate_otp_code(&crate::testing::mock_random::MockRng::new(7), len);
        assert_eq!(code.len(), len);
        assert!(code.bytes().all(|b| b.is_ascii_digit()));
    }
}

// ── verify_credential: Email OTP expiry boundary ─────────────────

#[test]
fn email_otp_at_expiry_boundary_still_valid() {
    let code = "12345678";
    let hash = axess_factors::generate_password_hash(code);
    let now = Utc::now();
    let cfg = FactorConfig::EmailOtp(EmailOtpConfig {
        email: "test@example.com".into(),
        pending_hash: Some(ZeroizedString::new(&hash)),
        pending_until: Some(now),
        attempt_count: 0,
        max_attempts: 5,
        ..Default::default()
    });
    let cred = FactorCredential::OtpCode(Arc::from(code));
    let outcome = verify_credential(
        &cred,
        &cfg,
        &FactorKind::EmailOtp,
        now,
        &RecoveryPeppers::default(),
    );
    assert!(matches!(outcome, VerifyOutcome::PassWithUpdate(_)));
}

// ── verify_credential: password length boundary ──────────────────

#[test]
fn password_at_max_length_succeeds() {
    let max_password = "a".repeat(MAX_PASSWORD_BYTES);
    let hash = axess_factors::generate_password_hash(&max_password);
    let cfg = FactorConfig::Password(PasswordConfig {
        hash: ZeroizedString::new(&hash),
        rules: Default::default(),
        password_id: None,
    });
    let cred = FactorCredential::Password(ZeroizedString::new(&max_password));
    let outcome = verify_credential(
        &cred,
        &cfg,
        &FactorKind::Password,
        Utc::now(),
        &RecoveryPeppers::default(),
    );
    assert!(matches!(outcome, VerifyOutcome::Pass));
}

// ── verify_credential: TOTP success path ─────────────────────────

/// RFC 6238 Appendix B vector: at Unix timestamp t=59 with 30s period
/// and the standard ASCII secret "12345678901234567890", the
/// 8-digit SHA-1 TOTP is "94287082" and the step index is 59/30=1.
///
/// Kills line 95 delete-match-arm (TOTP arm returns PassWithUpdate,
/// fallthrough would return Fail) and line 123 `<= → >` (with
/// cfg.last_step=Some(0), step(1) <= 0 is false so we proceed;
/// mutation makes step(1) > 0 true and rejects valid code).
#[test]
fn totp_success_passes_replay_guard_and_returns_update() {
    use crate::authn::factor::TotpConfig;
    use chrono::TimeZone;

    let cfg = FactorConfig::Totp(TotpConfig {
        secret: ZeroizedString::new(RFC_4226_SECRET_B32).into(),
        digits: 8,
        period_secs: 30,
        algorithm: OtpAlgorithm::Sha1,
        past_window: 0,
        future_window: 0,
        last_step: Some(0),
    });
    let cred = FactorCredential::OtpCode(Arc::from("94287082"));
    let now = Utc.timestamp_opt(59, 0).unwrap();
    let outcome = verify_credential(
        &cred,
        &cfg,
        &FactorKind::Totp,
        now,
        &RecoveryPeppers::default(),
    );
    match outcome {
        VerifyOutcome::PassWithUpdate(FactorConfig::Totp(updated)) => {
            assert_eq!(updated.last_step, Some(1));
        }
        _ => panic!("expected TOTP PassWithUpdate at RFC 6238 vector"),
    }
}

// ── verify_credential: HOTP code-length boundary ─────────────────

/// Kills line 134 `> → ==/>=` on HOTP code-length guard. A code at
/// exactly MAX_OTP_CODE_BYTES bytes must NOT take the early-Fail
/// path; it continues to verify_hotp, which rejects (returning
/// `None`) and yields FailWithUpdate(attempt_count+1). The early
/// `return Fail` of the mutations skips the update entirely.
#[test]
fn hotp_code_at_max_length_continues_to_verify_with_update() {
    use crate::validation::MAX_OTP_CODE_BYTES;
    let cfg = FactorConfig::Hotp(HotpConfig {
        secret: ZeroizedString::new(RFC_4226_SECRET_B32).into(),
        counter: 100,
        attempt_count: 0,
        max_attempts: 5,
        ..Default::default()
    });
    let at_max = "1".repeat(MAX_OTP_CODE_BYTES);
    let cred = FactorCredential::OtpCode(Arc::from(at_max.as_str()));
    let outcome = verify_credential(
        &cred,
        &cfg,
        &FactorKind::Hotp,
        Utc::now(),
        &RecoveryPeppers::default(),
    );
    match outcome {
        VerifyOutcome::FailWithUpdate(FactorConfig::Hotp(updated)) => {
            assert_eq!(updated.attempt_count, 1);
        }
        _ => panic!("expected FailWithUpdate when continuing through length guard"),
    }
}

// ── verify_credential: Email OTP code-length boundary ────────────

// Kills line 182 `> → ==/>=` on Email OTP code-length guard. At
// exactly MAX_OTP_CODE_BYTES bytes the continuing path runs Argon2
// verify, fails, and yields FailWithUpdate(increment). The
// mutations short-circuit to Fail with no state update.

// ── generate_otp_code: rejection sampling bounds ─────────────────

/// Test-only `SecureRng` that returns a hand-crafted sequence of u64
/// values. Lets us probe the rejection-sampling bounds in
/// `generate_otp_code` directly: with a real RNG these mutations land
/// in microscopically narrow value bands that no realistic seed hits.
struct FixedBytesRng {
    sequence: Vec<u64>,
    idx: std::sync::Mutex<usize>,
}

impl axess_rng::SecureRng for FixedBytesRng {
    fn fill_bytes(&self, dest: &mut [u8]) {
        let mut idx = self.idx.lock().expect("FixedBytesRng mutex poisoned");
        let value = self.sequence[*idx];
        *idx += 1;
        let bytes = value.to_le_bytes();
        let len = dest.len().min(8);
        dest[..len].copy_from_slice(&bytes[..len]);
    }
}

/// Kills line 249 `- → /` and `% → /` on `max_fair` computation.
///
/// For length=6, modulus = 10^6 and:
///   - max_fair_original = u64::MAX - (u64::MAX % 10^6) ≈ 1.844674e19
///   - max_fair (mutated `% → /`)  ≈ 1.844673e19  (slightly smaller)
///   - max_fair (mutated `- → /`)  ≈ 3.0e16        (much smaller)
///
/// `V1 = 18_446_730 * 10^12` sits BELOW the original bound (accepted)
/// but ABOVE both mutated bounds (rejected → next sample). Picking
/// `V2 = 1` produces a distinguishable output:
/// original "000000" (V1 % 10^6 = 0), mutation "000001".
#[test]
fn generate_otp_code_accepts_value_just_under_original_max_fair() {
    let v1: u64 = 18_446_730_000_000_000_000;
    let rng = FixedBytesRng {
        sequence: vec![v1, 1],
        idx: std::sync::Mutex::new(0),
    };
    let code = generate_otp_code(&rng, 6);
    assert_eq!(code, "000000");
}

/// Kills line 254 `<` → `<=` on the rejection-sampling guard.
///
/// At `V == max_fair`, the original strict `<` rejects (loops); the
/// mutated `<=` accepts. Crafting V1 = max_fair gives outputs that
/// differ:
/// original "000000" (loops, takes V2=0), mutation "551001" (V1 % 10^6).
#[test]
fn generate_otp_code_rejects_value_equal_to_max_fair() {
    let modulus: u64 = 1_000_000;
    let max_fair: u64 = u64::MAX - (u64::MAX % modulus);
    let rng = FixedBytesRng {
        sequence: vec![max_fair, 0],
        idx: std::sync::Mutex::new(0),
    };
    let code = generate_otp_code(&rng, 6);
    assert_eq!(code, "000000");
}

#[test]
fn email_otp_code_at_max_length_continues_to_verify_with_update() {
    use crate::validation::MAX_OTP_CODE_BYTES;
    let hash = axess_factors::generate_password_hash("12345678");
    let future = Utc::now() + chrono::Duration::seconds(300);
    let cfg = FactorConfig::EmailOtp(EmailOtpConfig {
        email: "test@example.com".into(),
        pending_hash: Some(ZeroizedString::new(&hash)),
        pending_until: Some(future),
        attempt_count: 0,
        max_attempts: 5,
        ..Default::default()
    });
    let at_max = "1".repeat(MAX_OTP_CODE_BYTES);
    let cred = FactorCredential::OtpCode(Arc::from(at_max.as_str()));
    let outcome = verify_credential(
        &cred,
        &cfg,
        &FactorKind::EmailOtp,
        Utc::now(),
        &RecoveryPeppers::default(),
    );
    match outcome {
        VerifyOutcome::FailWithUpdate(FactorConfig::EmailOtp(updated)) => {
            assert_eq!(updated.attempt_count, 1);
            assert!(updated.pending_hash.is_some());
        }
        _ => panic!("expected FailWithUpdate when continuing through length guard"),
    }
}

// ── email OTP burn keeps the cooldown ────────────────────────────

#[test]
fn email_otp_burn_clears_the_code_but_keeps_pending_until() {
    let until = Utc::now() + chrono::Duration::minutes(5);
    let prior = EmailOtpConfig {
        pending_hash: Some(ZeroizedString::new("hash")),
        pending_until: Some(until),
        attempt_count: 5,
        max_attempts: 5,
        ..Default::default()
    };
    let next = apply_email_otp_failure(&prior);
    assert!(next.pending_hash.is_none());
    assert_eq!(next.attempt_count, 0);
    assert_eq!(
        next.pending_until,
        Some(until),
        "the cooldown survives the burn"
    );
}

// ── verify_credential: the HOTP throttle must not desync the token ──

/// Feed `code` through `verify_credential` and return the config the
/// outcome leaves behind (the input one when nothing changed).
fn hotp_after(
    cfg: HotpConfig,
    code: &str,
    now: chrono::DateTime<Utc>,
) -> (VerifyOutcome, HotpConfig) {
    let cred = FactorCredential::OtpCode(Arc::from(code));
    let outcome = verify_credential(
        &cred,
        &FactorConfig::Hotp(cfg.clone()),
        &FactorKind::Hotp,
        now,
        &RecoveryPeppers::default(),
    );
    let next = match &outcome {
        VerifyOutcome::FailWithUpdate(FactorConfig::Hotp(c))
        | VerifyOutcome::PassWithUpdate(FactorConfig::Hotp(c)) => c.clone(),
        _ => cfg,
    };
    (outcome, next)
}

#[test]
fn the_legitimate_code_still_verifies_after_the_attempt_limit_and_its_lock() {
    // Anyone who knows the password could otherwise lock the user out of
    // their own token: reaching the limit used to advance the counter past
    // the lookahead window, so the token's next code never matched again.
    let t0 = Utc::now();
    let mut cfg = HotpConfig {
        secret: ZeroizedString::new(RFC_4226_SECRET_B32).into(),
        counter: 0,
        lookahead_window: 4,
        max_attempts: 3,
        ..Default::default()
    };
    for _ in 0..4 {
        let (outcome, next) = hotp_after(cfg, "000000", t0);
        assert!(
            matches!(
                outcome,
                VerifyOutcome::Fail | VerifyOutcome::FailWithUpdate(_)
            ),
            "a wrong code fails"
        );
        cfg = next;
    }
    assert_eq!(cfg.counter, 0, "the counter must not move on failures");
    // Well past any throttle: the token's next code is the one at counter 0.
    let later = t0 + chrono::Duration::hours(2);
    let (outcome, next) = hotp_after(cfg, "755224", later);
    assert!(
        matches!(outcome, VerifyOutcome::PassWithUpdate(_)),
        "the code the token shows next must verify once the throttle has run out"
    );
    assert_eq!(next.counter, 1);
    assert_eq!(next.attempt_count, 0);
}

// ── verify_credential: recovery codes across a pepper rotation ───

mod recovery_pepper_rotation {
    //! A set generated under pepper A must still log in after the service
    //! moved to pepper B, as long as A is kept as the previous pepper, and
    //! the match must be reported so the set can be regenerated.

    use super::*;
    use crate::authn::factor::RecoveryCodesConfig;
    use crate::testing::mock_random::MockRng;
    use axess_factors::{RecoveryCodePepper, generate_recovery_codes_peppered};

    fn pepper(fill: u8) -> Arc<RecoveryCodePepper> {
        Arc::new(RecoveryCodePepper::new(vec![fill; 32]).expect("long enough"))
    }

    fn peppers(
        current: Option<Arc<RecoveryCodePepper>>,
        previous: Option<Arc<RecoveryCodePepper>>,
    ) -> RecoveryPeppers {
        RecoveryPeppers { current, previous }
    }

    /// A one-code set under pepper A and the code as the user types it.
    fn set_under_a() -> (RecoveryCodesConfig, String) {
        let made = generate_recovery_codes_peppered(&MockRng::new(3), 1, &pepper(0xA));
        let code: &str = made.display[0].as_ref();
        (made.config, code.to_owned())
    }

    fn check(cfg: &RecoveryCodesConfig, code: &str, peppers: &RecoveryPeppers) -> VerifyOutcome {
        verify_credential(
            &FactorCredential::RecoveryCode(Arc::from(code)),
            &FactorConfig::RecoveryCodes(cfg.clone()),
            &FactorKind::RecoveryCode,
            Utc::now(),
            peppers,
        )
    }

    #[test]
    fn a_code_under_the_previous_pepper_logs_in_and_marks_the_set() {
        let (cfg, code) = set_under_a();
        let rotated = peppers(Some(pepper(0xB)), Some(pepper(0xA)));
        match check(&cfg, &code, &rotated) {
            VerifyOutcome::PassWithUpdate(FactorConfig::RecoveryCodes(after)) => {
                assert_eq!(after.remaining(), 0, "the code is spent");
                assert!(
                    after.under_previous_pepper,
                    "a match under the previous pepper must be reported"
                );
            }
            _ => panic!("a code made under the previous pepper must still verify"),
        }
    }

    #[test]
    fn a_code_under_the_current_pepper_is_not_marked() {
        let (cfg, code) = set_under_a();
        let same = peppers(Some(pepper(0xA)), Some(pepper(0x9)));
        match check(&cfg, &code, &same) {
            VerifyOutcome::PassWithUpdate(FactorConfig::RecoveryCodes(after)) => {
                assert!(!after.under_previous_pepper);
            }
            _ => panic!("a code under the current pepper verifies"),
        }
    }

    #[test]
    fn without_the_previous_pepper_the_old_set_fails_closed() {
        let (cfg, code) = set_under_a();
        let only_b = peppers(Some(pepper(0xB)), None);
        assert!(matches!(check(&cfg, &code, &only_b), VerifyOutcome::Fail));
    }

    #[test]
    fn the_builder_keeps_both_peppers() {
        use crate::authn::service::AuthnService;
        use crate::testing::mock_authn::{MockFactorStore, MockIdentityStore};
        let svc = AuthnService::builder(MockIdentityStore::new(), MockFactorStore::new())
            .with_recovery_code_pepper(RecoveryCodePepper::new(vec![0xB; 32]).unwrap())
            .with_previous_recovery_code_pepper(RecoveryCodePepper::new(vec![0xA; 32]).unwrap())
            .build();
        let peppers = &svc.inner.recovery_peppers;
        assert!(peppers.current.is_some() && peppers.previous.is_some());
    }
}

// ── verify_credential_blocking: a saturated executor is Busy, not Internal ─

/// One permit, no queue, one job in flight: the next password check is
/// refused as `Busy`, and the error the service surfaces for it is
/// `AuthnError::Busy` with a retry delay, never `Internal`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_verify_on_a_saturated_executor_is_busy() {
    use crate::authn::error::AuthnError;
    use crate::authn::factor::PasswordRules;

    #[derive(Debug, thiserror::Error)]
    #[error("test")]
    struct TestStoreError;

    let kdf = Arc::new(KdfExecutor::pool_with_permits(1).with_max_queue(0));
    let release = Arc::new(std::sync::Barrier::new(2));
    let holder = {
        let (kdf, release) = (kdf.clone(), release.clone());
        tokio::spawn(async move {
            kdf.run(move || {
                release.wait();
            })
            .await
        })
    };
    while kdf.jobs_started() == 0 {
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    let config = FactorConfig::Password(PasswordConfig {
        hash: ZeroizedString::new(axess_factors::generate_password_hash("Gnomes2+")),
        rules: PasswordRules::default(),
        password_id: None,
    });
    let refused = verify_credential_blocking(
        &kdf,
        &FactorCredential::Password(ZeroizedString::new("Gnomes2+")),
        &config,
        &FactorKind::Password,
        Utc::now(),
        &RecoveryPeppers::default(),
    )
    .await;
    let Err(e) = refused else {
        panic!("the job must be refused while the only permit is held");
    };
    assert!(matches!(e, KdfError::Busy), "{e:?}");
    let mapped: AuthnError<TestStoreError> = e.into();
    assert!(
        matches!(mapped, AuthnError::Busy { retry_after } if retry_after > std::time::Duration::ZERO),
        "{mapped:?}"
    );
    release.wait();
    holder.await.unwrap().unwrap();
}
