//! `tests`: the unit tests of `verification.rs`, kept beside it per the
//! 200-line inline-test rule in AGENTS.md.

use super::*;
use crate::authn::factor::{EmailOtpConfig, PasswordConfig, ZeroizedString};
use crate::testing::mock_random::MockRng;
use chrono::Utc;
use std::sync::Arc;

// ── Password ─────────────────────────────────────────────────────

#[test]
fn password_correct() {
    let hash = axess_factors::generate_password_hash("Gnomes2+");
    let cfg = FactorConfig::Password(PasswordConfig {
        hash: ZeroizedString::new(&hash),
        rules: Default::default(),
        password_id: None,
    });
    let cred = FactorCredential::Password(ZeroizedString::new("Gnomes2+"));
    let outcome = verify_credential(
        &cred,
        &cfg,
        &FactorKind::Password,
        Utc::now(),
        &RecoveryPeppers::default(),
    );
    assert!(matches!(outcome, VerifyOutcome::Pass));
}

#[test]
fn password_wrong() {
    let hash = axess_factors::generate_password_hash("Gnomes2+");
    let cfg = FactorConfig::Password(PasswordConfig {
        hash: ZeroizedString::new(&hash),
        rules: Default::default(),
        password_id: None,
    });
    let cred = FactorCredential::Password(ZeroizedString::new("wrong"));
    let outcome = verify_credential(
        &cred,
        &cfg,
        &FactorKind::Password,
        Utc::now(),
        &RecoveryPeppers::default(),
    );
    assert!(matches!(outcome, VerifyOutcome::Fail));
}

#[test]
fn password_oversized_rejected() {
    let hash = axess_factors::generate_password_hash("x");
    let cfg = FactorConfig::Password(PasswordConfig {
        hash: ZeroizedString::new(&hash),
        rules: Default::default(),
        password_id: None,
    });
    let oversized = "x".repeat(crate::validation::MAX_PASSWORD_BYTES + 1);
    let cred = FactorCredential::Password(ZeroizedString::new(&oversized));
    let outcome = verify_credential(
        &cred,
        &cfg,
        &FactorKind::Password,
        Utc::now(),
        &RecoveryPeppers::default(),
    );
    assert!(matches!(outcome, VerifyOutcome::Fail));
}

// ── Email OTP ────────────────────────────────────────────────────

#[test]
fn email_otp_expired_rejected() {
    let code = "12345678";
    let hash = axess_factors::generate_password_hash(code);
    let expired = Utc::now() - chrono::Duration::seconds(10);
    let cfg = FactorConfig::EmailOtp(EmailOtpConfig {
        email: "test@example.com".into(),
        pending_hash: Some(ZeroizedString::new(&hash)),
        pending_until: Some(expired),
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
fn email_otp_no_pending_hash_rejected() {
    let cfg = FactorConfig::EmailOtp(EmailOtpConfig {
        email: "test@example.com".into(),
        pending_hash: None,
        pending_until: None,
        ..Default::default()
    });
    let cred = FactorCredential::OtpCode(Arc::from("12345678"));
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
fn email_otp_attempt_limit_burns_code() {
    let code = "12345678";
    let hash = axess_factors::generate_password_hash(code);
    let future = Utc::now() + chrono::Duration::seconds(300);
    let cfg = FactorConfig::EmailOtp(EmailOtpConfig {
        email: "test@example.com".into(),
        pending_hash: Some(ZeroizedString::new(&hash)),
        pending_until: Some(future),
        attempt_count: 5,
        max_attempts: 5,
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
    match outcome {
        VerifyOutcome::FailWithUpdate(FactorConfig::EmailOtp(updated)) => {
            assert!(updated.pending_hash.is_none());
            assert_eq!(updated.attempt_count, 0);
        }
        _ => panic!("expected FailWithUpdate with burned code"),
    }
}

#[test]
fn apply_email_otp_failure_increments_below_limit() {
    let prior = EmailOtpConfig {
        email: "test@example.com".into(),
        pending_hash: Some(ZeroizedString::new("hash")),
        pending_until: Some(Utc::now()),
        attempt_count: 2,
        max_attempts: 5,
        ..Default::default()
    };
    let next = apply_email_otp_failure(&prior);
    assert_eq!(next.attempt_count, 3);
    assert!(next.pending_hash.is_some());
}

#[test]
fn apply_email_otp_failure_burns_at_limit() {
    let prior = EmailOtpConfig {
        email: "test@example.com".into(),
        pending_hash: Some(ZeroizedString::new("hash")),
        pending_until: Some(Utc::now()),
        attempt_count: 5,
        max_attempts: 5,
        ..Default::default()
    };
    let next = apply_email_otp_failure(&prior);
    assert!(next.pending_hash.is_none());
    assert!(next.pending_until.is_some(), "the cooldown survives a burn");
    assert_eq!(next.attempt_count, 0);
}

#[test]
fn email_otp_wrong_code_increments_counter() {
    let hash = axess_factors::generate_password_hash("12345678");
    let future = Utc::now() + chrono::Duration::seconds(300);
    let cfg = FactorConfig::EmailOtp(EmailOtpConfig {
        email: "test@example.com".into(),
        pending_hash: Some(ZeroizedString::new(&hash)),
        pending_until: Some(future),
        attempt_count: 2,
        max_attempts: 5,
        ..Default::default()
    });
    let cred = FactorCredential::OtpCode(Arc::from("00000000"));
    let outcome = verify_credential(
        &cred,
        &cfg,
        &FactorKind::EmailOtp,
        Utc::now(),
        &RecoveryPeppers::default(),
    );
    match outcome {
        VerifyOutcome::FailWithUpdate(FactorConfig::EmailOtp(updated)) => {
            assert_eq!(updated.attempt_count, 3);
            assert!(updated.pending_hash.is_some());
        }
        _ => panic!("expected FailWithUpdate with incremented counter"),
    }
}

// ── Mismatched credential/config ────────────────────────────────

#[test]
fn mismatched_credential_config_rejected() {
    let cfg = FactorConfig::Password(PasswordConfig {
        hash: ZeroizedString::new("$argon2id$v=19$m=19456,t=2,p=1$fake$fake"),
        rules: Default::default(),
        password_id: None,
    });
    let cred = FactorCredential::OtpCode(Arc::from("123456"));
    let outcome = verify_credential(
        &cred,
        &cfg,
        &FactorKind::Totp,
        Utc::now(),
        &RecoveryPeppers::default(),
    );
    assert!(matches!(outcome, VerifyOutcome::Fail));
}

// ── generate_otp_code ────────────────────────────────────────────

#[test]
fn otp_code_correct_length() {
    let rng = MockRng::new(42);
    let code = generate_otp_code(&rng, 8);
    assert_eq!(code.len(), 8);
    assert!(code.chars().all(|c| c.is_ascii_digit()));
}

#[test]
fn otp_code_deterministic_with_same_seed() {
    let code1 = generate_otp_code(&MockRng::new(99), 6);
    let code2 = generate_otp_code(&MockRng::new(99), 6);
    assert_eq!(code1, code2);
}

#[test]
fn otp_code_different_seeds_differ() {
    let code1 = generate_otp_code(&MockRng::new(1), 6);
    let code2 = generate_otp_code(&MockRng::new(2), 6);
    assert_ne!(code1, code2);
}
