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
fn apply_hotp_failure_zero_max_attempts_increments_without_burn() {
    let prior = HotpConfig {
        counter: 7,
        attempt_count: 100,
        max_attempts: 0,
        ..Default::default()
    };
    let next = apply_hotp_failure(&prior);
    assert_eq!(next.counter, 7);
    assert_eq!(next.attempt_count, 101);
}

#[test]
fn apply_hotp_failure_below_max_increments_without_burn() {
    let prior = HotpConfig {
        counter: 7,
        attempt_count: 2,
        max_attempts: 5,
        ..Default::default()
    };
    let next = apply_hotp_failure(&prior);
    assert_eq!(next.counter, 7);
    assert_eq!(next.attempt_count, 3);
}

#[test]
fn apply_hotp_failure_burn_advances_counter_by_lookahead_plus_one() {
    let prior = HotpConfig {
        counter: 100,
        attempt_count: 5,
        max_attempts: 5,
        lookahead_window: 4,
        ..Default::default()
    };
    let next = apply_hotp_failure(&prior);
    assert_eq!(next.counter, 105);
    assert_eq!(next.attempt_count, 0);
}

// ── apply_email_otp_failure ──────────────────────────────────────

#[test]
fn apply_email_otp_failure_zero_max_attempts_increments_without_burn() {
    let prior = EmailOtpConfig {
        email: "test@example.com".into(),
        pending_hash: Some(ZeroizedString::new("hash")),
        pending_until: Some(Utc::now()),
        attempt_count: 100,
        max_attempts: 0,
        ..Default::default()
    };
    let next = apply_email_otp_failure(&prior);
    assert!(next.pending_hash.is_some());
    assert_eq!(next.attempt_count, 101);
}

// ── verify_credential: HOTP attempt-limit burn ───────────────────

#[test]
fn hotp_attempt_limit_burns_lookahead_window() {
    let cfg = FactorConfig::Hotp(HotpConfig {
        secret: ZeroizedString::new(RFC_4226_SECRET_B32),
        counter: 100,
        attempt_count: 5,
        max_attempts: 5,
        lookahead_window: 4,
        ..Default::default()
    });
    let cred = FactorCredential::OtpCode(Arc::from("123456"));
    let outcome = verify_credential(&cred, &cfg, &FactorKind::Hotp, Utc::now());
    match outcome {
        VerifyOutcome::FailWithUpdate(FactorConfig::Hotp(updated)) => {
            assert_eq!(updated.counter, 105);
            assert_eq!(updated.attempt_count, 0);
        }
        _ => panic!("expected FailWithUpdate burn"),
    }
}

#[test]
fn hotp_zero_max_attempts_does_not_burn() {
    let cfg = FactorConfig::Hotp(HotpConfig {
        secret: ZeroizedString::new(RFC_4226_SECRET_B32),
        counter: 100,
        attempt_count: 0,
        max_attempts: 0,
        lookahead_window: 4,
        ..Default::default()
    });
    let cred = FactorCredential::OtpCode(Arc::from("999999"));
    let outcome = verify_credential(&cred, &cfg, &FactorKind::Hotp, Utc::now());
    match outcome {
        VerifyOutcome::FailWithUpdate(FactorConfig::Hotp(updated)) => {
            assert_eq!(updated.counter, 100);
            assert_eq!(updated.attempt_count, 1);
        }
        other => panic!(
            "expected FailWithUpdate without burn, got {:?}",
            match other {
                VerifyOutcome::Fail => "Fail",
                VerifyOutcome::Pass => "Pass",
                VerifyOutcome::PassWithUpdate(_) => "PassWithUpdate",
                _ => "other",
            }
        ),
    }
}

// ── verify_credential: HOTP success advances counter by exactly 1 ─

#[test]
fn hotp_success_advances_counter_by_one() {
    let cfg = FactorConfig::Hotp(HotpConfig {
        secret: ZeroizedString::new(RFC_4226_SECRET_B32),
        digits: 6,
        algorithm: OtpAlgorithm::Sha1,
        counter: 0,
        lookahead_window: 0,
        attempt_count: 0,
        max_attempts: 5,
    });
    let cred = FactorCredential::OtpCode(Arc::from("755224"));
    let outcome = verify_credential(&cred, &cfg, &FactorKind::Hotp, Utc::now());
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
fn email_otp_zero_max_attempts_does_not_burn() {
    let hash = axess_factors::generate_password_hash("12345678");
    let future = Utc::now() + chrono::Duration::seconds(300);
    let cfg = FactorConfig::EmailOtp(EmailOtpConfig {
        email: "test@example.com".into(),
        pending_hash: Some(ZeroizedString::new(&hash)),
        pending_until: Some(future),
        attempt_count: 0,
        max_attempts: 0,
        ..Default::default()
    });
    let cred = FactorCredential::OtpCode(Arc::from("00000000"));
    let outcome = verify_credential(&cred, &cfg, &FactorKind::EmailOtp, Utc::now());
    match outcome {
        VerifyOutcome::FailWithUpdate(FactorConfig::EmailOtp(updated)) => {
            assert!(updated.pending_hash.is_some());
            assert_eq!(updated.attempt_count, 1);
        }
        _ => panic!("expected FailWithUpdate without burn"),
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
    let outcome = verify_credential(&cred, &cfg, &FactorKind::EmailOtp, now);
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
    });
    let cred = FactorCredential::Password(ZeroizedString::new(&max_password));
    let outcome = verify_credential(&cred, &cfg, &FactorKind::Password, Utc::now());
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
        secret: ZeroizedString::new(RFC_4226_SECRET_B32),
        digits: 8,
        period_secs: 30,
        algorithm: OtpAlgorithm::Sha1,
        past_window: 0,
        future_window: 0,
        last_step: Some(0),
    });
    let cred = FactorCredential::OtpCode(Arc::from("94287082"));
    let now = Utc.timestamp_opt(59, 0).unwrap();
    let outcome = verify_credential(&cred, &cfg, &FactorKind::Totp, now);
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
        secret: ZeroizedString::new(RFC_4226_SECRET_B32),
        counter: 100,
        attempt_count: 0,
        max_attempts: 5,
        ..Default::default()
    });
    let at_max = "1".repeat(MAX_OTP_CODE_BYTES);
    let cred = FactorCredential::OtpCode(Arc::from(at_max.as_str()));
    let outcome = verify_credential(&cred, &cfg, &FactorKind::Hotp, Utc::now());
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
    let outcome = verify_credential(&cred, &cfg, &FactorKind::EmailOtp, Utc::now());
    match outcome {
        VerifyOutcome::FailWithUpdate(FactorConfig::EmailOtp(updated)) => {
            assert_eq!(updated.attempt_count, 1);
            assert!(updated.pending_hash.is_some());
        }
        _ => panic!("expected FailWithUpdate when continuing through length guard"),
    }
}
