//! Factor credential verification and OTP code generation.

use crate::authn::factor::{
    EmailOtpConfig, FactorConfig, FactorCredential, FactorKind, OtpAlgorithm,
};
use axess_rng::SecureRng;

/// Compute the next HOTP config state after a failed verification.
///
/// Mirror of [`apply_email_otp_failure`] for HOTP. If the prior
/// config has reached `max_attempts`, advance `counter` past the
/// lookahead window (burning the current window) and reset
/// `attempt_count`. Otherwise increment `attempt_count`.
pub(crate) fn apply_hotp_failure(
    prior: &crate::authn::factor::HotpConfig,
) -> crate::authn::factor::HotpConfig {
    let mut next = prior.clone();
    if prior.max_attempts > 0 && prior.attempt_count >= prior.max_attempts {
        next.counter = prior
            .counter
            .saturating_add(prior.lookahead_window as u64 + 1);
        next.attempt_count = 0;
    } else {
        next.attempt_count = prior.attempt_count.saturating_add(1);
    }
    next
}

/// Compute the next Email OTP config state after a failed verification.
///
/// If the prior config has already reached `max_attempts`, burns the pending
/// code (clears `pending_hash`, `pending_until`, resets `attempt_count`).
/// Otherwise increments `attempt_count`.
///
/// Exposed so callers performing compare-and-swap retries can recompute the
/// next state from the latest persisted prior config without duplicating the
/// burn/increment policy.
pub(crate) fn apply_email_otp_failure(prior: &EmailOtpConfig) -> EmailOtpConfig {
    let mut next = prior.clone();
    if prior.max_attempts > 0 && prior.attempt_count >= prior.max_attempts {
        next.pending_hash = None;
        next.pending_until = None;
        next.attempt_count = 0;
    } else {
        next.attempt_count = prior.attempt_count.saturating_add(1);
    }
    next
}

/// Result of verifying a single factor credential.
pub(crate) enum VerifyOutcome {
    /// Verification failed: wrong credential or replay detected.
    Fail,
    /// Verification failed, but the factor config must be persisted
    /// (e.g. to record the failed attempt count for Email OTP).
    FailWithUpdate(FactorConfig),
    /// Verification succeeded: no factor state needs persisting.
    Pass,
    /// Verification succeeded: caller must persist this updated config.
    ///
    /// Used for TOTP (update `last_step` for replay prevention) and
    /// HOTP (advance `counter` to prevent reuse).
    PassWithUpdate(FactorConfig),
}

/// Verify a credential against a factor config.
///
/// `now` is supplied by the caller (from an injectable [`Clock`]) rather than
/// reading `Utc::now()` directly, keeping the function deterministically
/// testable under DST. Converted to `SystemTime` only for the TOTP path
/// which requires it.
pub(crate) fn verify_credential(
    credential: &FactorCredential,
    config: &FactorConfig,
    kind: &FactorKind,
    now: chrono::DateTime<chrono::Utc>,
) -> VerifyOutcome {
    use crate::validation::{MAX_OTP_CODE_BYTES, MAX_PASSWORD_BYTES};

    match (credential, config, kind) {
        (FactorCredential::Password(pwd), FactorConfig::Password(cfg), FactorKind::Password) => {
            let pwd_str: &str = pwd.as_ref();
            // Reject oversized passwords before Argon2; prevents CPU DoS.
            if pwd_str.len() > MAX_PASSWORD_BYTES {
                return VerifyOutcome::Fail;
            }
            let hash_str: &str = cfg.hash.as_ref();
            if axess_factors::verify_password(pwd_str, hash_str).is_ok() {
                VerifyOutcome::Pass
            } else {
                VerifyOutcome::Fail
            }
        }

        (FactorCredential::OtpCode(code), FactorConfig::Totp(cfg), FactorKind::Totp) => {
            if code.as_ref().len() > MAX_OTP_CODE_BYTES {
                return VerifyOutcome::Fail;
            }
            let algorithm = match cfg.algorithm {
                OtpAlgorithm::Sha1 => axess_factors::TotpAlgorithm::SHA1,
                OtpAlgorithm::Sha256 => axess_factors::TotpAlgorithm::SHA256,
                OtpAlgorithm::Sha512 => axess_factors::TotpAlgorithm::SHA512,
            };
            let matched = axess_factors::verify_totp(
                cfg.secret.as_ref(),
                code.as_ref(),
                now,
                axess_factors::TotpVerifyParams {
                    length: Some(cfg.digits as usize),
                    period: Some(cfg.period_secs as u64),
                    past_window: Some(cfg.past_window as u64),
                    future_window: Some(cfg.future_window as u64),
                    algorithm,
                },
            );
            match matched {
                None => VerifyOutcome::Fail,
                Some(step) => {
                    // Reject replays: the matched step must be strictly greater than
                    // the last accepted step. Equality means the same code is being
                    // reused within the same time window.
                    if cfg.last_step.is_some_and(|ls| step <= ls) {
                        return VerifyOutcome::Fail;
                    }
                    let mut updated = cfg.clone();
                    updated.last_step = Some(step);
                    VerifyOutcome::PassWithUpdate(FactorConfig::Totp(updated))
                }
            }
        }

        (FactorCredential::OtpCode(code), FactorConfig::Hotp(cfg), FactorKind::Hotp) => {
            if code.as_ref().len() > MAX_OTP_CODE_BYTES {
                return VerifyOutcome::Fail;
            }
            // RFC 4226 §7.4: enforce per-counter throttling. If
            // attempts have already maxed out, burn the lookahead window
            // (advance the counter past it) and fail. The user must
            // re-sync their token (typically by pressing it once and
            // re-enrolling, or by an admin counter reset).
            if cfg.max_attempts > 0 && cfg.attempt_count >= cfg.max_attempts {
                let mut burned = cfg.clone();
                burned.counter = cfg.counter.saturating_add(cfg.lookahead_window as u64 + 1);
                burned.attempt_count = 0;
                tracing::warn!("HOTP attempt limit reached; burning lookahead window");
                return VerifyOutcome::FailWithUpdate(FactorConfig::Hotp(burned));
            }
            let hotp_algo = match cfg.algorithm {
                OtpAlgorithm::Sha1 => axess_factors::HotpAlgorithm::Sha1,
                OtpAlgorithm::Sha256 => axess_factors::HotpAlgorithm::Sha256,
                OtpAlgorithm::Sha512 => axess_factors::HotpAlgorithm::Sha512,
            };
            let matched = axess_factors::verify_hotp(
                cfg.secret.as_ref(),
                code.as_ref(),
                cfg.counter,
                cfg.digits as usize,
                cfg.lookahead_window as u64,
                hotp_algo,
            );
            match matched {
                None => {
                    // Increment per-counter attempt count on failure.
                    let mut failed = cfg.clone();
                    failed.attempt_count = cfg.attempt_count.saturating_add(1);
                    VerifyOutcome::FailWithUpdate(FactorConfig::Hotp(failed))
                }
                Some(counter) => {
                    // Advance counter past the matched value to prevent reuse.
                    // Reset attempt_count for the new counter window.
                    // `saturating_add` matches the failure path above; a
                    // counter at `u64::MAX` (18e18 verifications) sticks
                    // rather than wraps back to zero, keeping the
                    // never-decreases invariant that anti-reuse relies on.
                    let mut updated = cfg.clone();
                    updated.counter = counter.saturating_add(1);
                    updated.attempt_count = 0;
                    VerifyOutcome::PassWithUpdate(FactorConfig::Hotp(updated))
                }
            }
        }

        (FactorCredential::OtpCode(code), FactorConfig::EmailOtp(cfg), FactorKind::EmailOtp) => {
            // Reject oversized codes before Argon2; prevents CPU DoS.
            if code.as_ref().len() > MAX_OTP_CODE_BYTES {
                return VerifyOutcome::Fail;
            }
            // Charset pre-check. Email OTP codes are ASCII digits
            // by construction (`generate_otp_code` only emits 0-9). Any
            // non-digit input is structurally impossible for a valid code,
            // so we can reject before paying ~10ms of Argon2id verification
            // cost; meaningful at brute-force load. The check is on the
            // raw input (no allocation) to keep the cost negligible on the
            // happy path.
            if !code.as_ref().bytes().all(|b| b.is_ascii_digit()) {
                return VerifyOutcome::Fail;
            }
            // Verify: pending hash must exist and code must not have expired.
            let hash = match &cfg.pending_hash {
                Some(h) => h,
                None => return VerifyOutcome::Fail,
            };

            // Check expiry using the injected clock time.
            if cfg.pending_until.is_some_and(|until| now > until) {
                return VerifyOutcome::Fail;
            }

            // Enforce per-code attempt limit; burn the code after max_attempts
            // failed verifications to prevent brute-force within the TTL window.
            if cfg.max_attempts > 0 && cfg.attempt_count >= cfg.max_attempts {
                tracing::warn!("email OTP attempt limit exceeded, burning code");
                let mut burned = cfg.clone();
                burned.pending_hash = None;
                burned.pending_until = None;
                burned.attempt_count = 0;
                return VerifyOutcome::FailWithUpdate(FactorConfig::EmailOtp(burned));
            }

            // Constant-time hash comparison via Argon2id verify.
            if axess_factors::verify_password(code.as_ref(), hash.as_ref()).is_err() {
                // Increment attempt counter and persist.
                let mut failed = cfg.clone();
                failed.attempt_count = cfg.attempt_count.saturating_add(1);
                return VerifyOutcome::FailWithUpdate(FactorConfig::EmailOtp(failed));
            }

            // Clear the pending state to prevent reuse.
            let mut updated = cfg.clone();
            updated.pending_hash = None;
            updated.pending_until = None;
            updated.attempt_count = 0;
            VerifyOutcome::PassWithUpdate(FactorConfig::EmailOtp(updated))
        }

        (FactorCredential::Fido2Assertion(_), FactorConfig::Fido2(_), FactorKind::Fido2) => {
            // Defensive fail-closed for `#[cfg(not(feature = "fido2"))]` builds.
            //
            // With the `fido2` feature ON, this arm is unreachable in normal
            // flows: `service::login::verify_factor` short-circuits
            // `FactorKind::Fido2` to `verify_fido2_factor` BEFORE ever calling
            // `verify_credential`. See `service/login.rs`: the
            // `#[cfg(feature = "fido2")]` branch dispatches to
            // `Fido2Service::verify_fido2_factor` and returns.
            //
            // With the feature OFF, that short-circuit is compiled out, but
            // `FactorKind::Fido2` / `FactorConfig::Fido2` /
            // `FactorCredential::Fido2Assertion` variants still exist (they
            // are not feature-gated on the enum surface). A caller who
            // constructs one and dispatches through `verify_credential`
            // reaches this arm; `Fail` is the correct answer because no
            // WebAuthn verifier is available in the build.
            VerifyOutcome::Fail
        }

        _ => VerifyOutcome::Fail,
    }
}

/// Generate a random numeric OTP code of the given length using the injectable RNG.
///
/// Returns a zero-padded decimal string (e.g. `"042817"` for length 6).
pub(crate) fn generate_otp_code(rng: &impl SecureRng, length: usize) -> String {
    let modulus = 10u64.pow(length as u32);
    // Rejection sampling to eliminate modulo bias: discard values from the
    // partial final bucket that would skew the distribution.
    let max_fair = u64::MAX - (u64::MAX % modulus);
    loop {
        let mut bytes = [0u8; 8];
        rng.fill_bytes(&mut bytes);
        let value = u64::from_le_bytes(bytes);
        if value < max_fair {
            return format!("{:0>width$}", value % modulus, width = length);
        }
        // Extremely rare (~5.4e-14 probability per iteration for 6-digit codes).
    }
}

#[cfg(test)]
mod tests {
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
        });
        let cred = FactorCredential::Password(ZeroizedString::new("Gnomes2+"));
        let outcome = verify_credential(&cred, &cfg, &FactorKind::Password, Utc::now());
        assert!(matches!(outcome, VerifyOutcome::Pass));
    }

    #[test]
    fn password_wrong() {
        let hash = axess_factors::generate_password_hash("Gnomes2+");
        let cfg = FactorConfig::Password(PasswordConfig {
            hash: ZeroizedString::new(&hash),
            rules: Default::default(),
        });
        let cred = FactorCredential::Password(ZeroizedString::new("wrong"));
        let outcome = verify_credential(&cred, &cfg, &FactorKind::Password, Utc::now());
        assert!(matches!(outcome, VerifyOutcome::Fail));
    }

    #[test]
    fn password_oversized_rejected() {
        let hash = axess_factors::generate_password_hash("x");
        let cfg = FactorConfig::Password(PasswordConfig {
            hash: ZeroizedString::new(&hash),
            rules: Default::default(),
        });
        let oversized = "x".repeat(crate::validation::MAX_PASSWORD_BYTES + 1);
        let cred = FactorCredential::Password(ZeroizedString::new(&oversized));
        let outcome = verify_credential(&cred, &cfg, &FactorKind::Password, Utc::now());
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
        let outcome = verify_credential(&cred, &cfg, &FactorKind::EmailOtp, Utc::now());
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
        let outcome = verify_credential(&cred, &cfg, &FactorKind::EmailOtp, Utc::now());
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
        let outcome = verify_credential(&cred, &cfg, &FactorKind::EmailOtp, Utc::now());
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
        assert!(next.pending_until.is_none());
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
        let outcome = verify_credential(&cred, &cfg, &FactorKind::EmailOtp, Utc::now());
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
        });
        let cred = FactorCredential::OtpCode(Arc::from("123456"));
        let outcome = verify_credential(&cred, &cfg, &FactorKind::Totp, Utc::now());
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
}

#[cfg(test)]
mod verification_tests;
