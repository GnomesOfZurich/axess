//! Factor credential verification and OTP code generation.

use crate::authn::factor::{
    EmailOtpConfig, FactorConfig, FactorCredential, FactorKind, HotpConfig, OtpAlgorithm,
    PasswordConfig, RecoveryCodesConfig, TotpConfig,
};
use crate::blocking::{KdfError, KdfExecutor};
use crate::validation::{MAX_OTP_CODE_BYTES, MAX_PASSWORD_BYTES};
use axess_rng::SecureRng;
use std::sync::Arc;

/// Attempt limit applied when a config carries `max_attempts = 0`.
///
/// Zero used to switch the limit off. A zero reaches a config through a
/// missing field in stored JSON, a partial migration or a careless admin
/// form, and "no limit" is the worst thing any of those should silently
/// mean, so zero now means the default.
pub(crate) const DEFAULT_MAX_OTP_ATTEMPTS: u8 = 5;

/// The attempt limit in force for a configured `max_attempts`.
pub(crate) fn effective_max_attempts(configured: u8) -> u8 {
    if configured == 0 {
        DEFAULT_MAX_OTP_ATTEMPTS
    } else {
        configured
    }
}

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
    if prior.attempt_count >= effective_max_attempts(prior.max_attempts) {
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
    if prior.attempt_count >= effective_max_attempts(prior.max_attempts) {
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
    /// Used for TOTP (update `last_step` for replay prevention), HOTP
    /// (advance `counter` to prevent reuse) and recovery codes (spend the
    /// matched code).
    PassWithUpdate(FactorConfig),
}

/// Verify a credential against a factor config.
///
/// `now` is supplied by the caller (from an injectable [`Clock`]) rather than
/// reading `Utc::now()` directly, keeping the function deterministically
/// testable under DST. Converted to `SystemTime` only for the TOTP path
/// which requires it.
///
/// `pepper` is the secret keyed recovery codes are checked under; without it
/// a keyed row cannot match. Password, email-OTP and (for Argon2id rows)
/// recovery-code checks run Argon2id: reach them through
/// [`verify_credential_blocking`] from async code.
pub(crate) fn verify_credential(
    credential: &FactorCredential,
    config: &FactorConfig,
    kind: &FactorKind,
    now: chrono::DateTime<chrono::Utc>,
    pepper: Option<&axess_factors::RecoveryCodePepper>,
) -> VerifyOutcome {
    match (credential, config, kind) {
        (FactorCredential::Password(pwd), FactorConfig::Password(cfg), FactorKind::Password) => {
            verify_password_factor(pwd.as_ref(), cfg)
        }
        (FactorCredential::OtpCode(code), FactorConfig::Totp(cfg), FactorKind::Totp) => {
            verify_totp_factor(code.as_ref(), cfg, now)
        }
        (FactorCredential::OtpCode(code), FactorConfig::Hotp(cfg), FactorKind::Hotp) => {
            verify_hotp_factor(code.as_ref(), cfg)
        }
        (FactorCredential::OtpCode(code), FactorConfig::EmailOtp(cfg), FactorKind::EmailOtp) => {
            verify_email_otp_factor(code.as_ref(), cfg, now)
        }
        (
            FactorCredential::RecoveryCode(code),
            FactorConfig::RecoveryCodes(cfg),
            FactorKind::RecoveryCode,
        ) => verify_recovery_code_factor(code.as_ref(), cfg, now, pepper),
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

/// Check a password against its stored Argon2id hash.
///
/// Oversized passwords are refused before Argon2 runs, so the cost of one
/// attempt is bounded.
fn verify_password_factor(pwd_str: &str, cfg: &PasswordConfig) -> VerifyOutcome {
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

/// Check a TOTP code, refusing a step at or before the last accepted one.
fn verify_totp_factor(
    code: &str,
    cfg: &TotpConfig,
    now: chrono::DateTime<chrono::Utc>,
) -> VerifyOutcome {
    if code.len() > MAX_OTP_CODE_BYTES {
        return VerifyOutcome::Fail;
    }
    let algorithm = match cfg.algorithm {
        OtpAlgorithm::Sha1 => axess_factors::TotpAlgorithm::SHA1,
        OtpAlgorithm::Sha256 => axess_factors::TotpAlgorithm::SHA256,
        OtpAlgorithm::Sha512 => axess_factors::TotpAlgorithm::SHA512,
    };
    let matched = axess_factors::verify_totp(
        cfg.secret.as_ref(),
        code,
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

/// Check an HOTP code inside the lookahead window, throttled per counter.
fn verify_hotp_factor(code: &str, cfg: &HotpConfig) -> VerifyOutcome {
    if code.len() > MAX_OTP_CODE_BYTES {
        return VerifyOutcome::Fail;
    }
    // RFC 4226 §7.4: enforce per-counter throttling. If
    // attempts have already maxed out, burn the lookahead window
    // (advance the counter past it) and fail. The user must
    // re-sync their token (typically by pressing it once and
    // re-enrolling, or by an admin counter reset).
    if cfg.attempt_count >= effective_max_attempts(cfg.max_attempts) {
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
        code,
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

/// Check an emailed one-time code against its pending Argon2id hash.
///
/// A code is single-use, expires, and is burned after the attempt limit.
fn verify_email_otp_factor(
    code: &str,
    cfg: &EmailOtpConfig,
    now: chrono::DateTime<chrono::Utc>,
) -> VerifyOutcome {
    // Reject oversized codes before Argon2; prevents CPU DoS.
    if code.len() > MAX_OTP_CODE_BYTES {
        return VerifyOutcome::Fail;
    }
    // Charset pre-check. Email OTP codes are ASCII digits
    // by construction (`generate_otp_code` only emits 0-9). Any
    // non-digit input is structurally impossible for a valid code,
    // so we can reject before paying ~10ms of Argon2id verification
    // cost; meaningful at brute-force load. The check is on the
    // raw input (no allocation) to keep the cost negligible on the
    // happy path.
    if !code.bytes().all(|b| b.is_ascii_digit()) {
        return VerifyOutcome::Fail;
    }
    // Verify: pending hash must exist and code must not have expired.
    let hash = match &cfg.pending_hash {
        Some(h) => h,
        None => return VerifyOutcome::Fail,
    };

    // Check expiry using the injected clock time.
    // A code with no expiry is never valid: refuse rather than
    // accept a code that would live forever.
    match cfg.pending_until {
        Some(until) if now <= until => {}
        _ => return VerifyOutcome::Fail,
    }

    // Enforce per-code attempt limit; burn the code after max_attempts
    // failed verifications to prevent brute-force within the TTL window.
    if cfg.attempt_count >= effective_max_attempts(cfg.max_attempts) {
        tracing::warn!("email OTP attempt limit exceeded, burning code");
        let mut burned = cfg.clone();
        burned.pending_hash = None;
        burned.pending_until = None;
        burned.attempt_count = 0;
        return VerifyOutcome::FailWithUpdate(FactorConfig::EmailOtp(burned));
    }

    // Constant-time hash comparison via Argon2id verify.
    if axess_factors::verify_password(code, hash.as_ref()).is_err() {
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

/// Check a recovery code and return the set with that code spent.
fn verify_recovery_code_factor(
    code: &str,
    cfg: &RecoveryCodesConfig,
    now: chrono::DateTime<chrono::Utc>,
    pepper: Option<&axess_factors::RecoveryCodePepper>,
) -> VerifyOutcome {
    if code.len() > MAX_OTP_CODE_BYTES {
        return VerifyOutcome::Fail;
    }
    // A match returns the set with that code spent; persisting it by
    // compare-and-swap is what makes the code single-use: a second
    // login racing on the same code loses the swap and is rejected
    // as a replay.
    match axess_factors::verify_recovery_code(cfg, code, now, pepper) {
        Some(updated) => VerifyOutcome::PassWithUpdate(FactorConfig::RecoveryCodes(updated)),
        None => VerifyOutcome::Fail,
    }
}

/// Whether checking `credential` against `config` runs Argon2id.
fn runs_kdf(credential: &FactorCredential, config: &FactorConfig) -> bool {
    match (credential, config) {
        (FactorCredential::Password(_), FactorConfig::Password(_))
        | (FactorCredential::OtpCode(_), FactorConfig::EmailOtp(_)) => true,
        (FactorCredential::RecoveryCode(_), FactorConfig::RecoveryCodes(cfg)) => {
            cfg.needs_slow_verification()
        }
        _ => false,
    }
}

/// [`verify_credential`] for async callers: a check that runs Argon2id is
/// moved onto `kdf` with owned copies of its inputs, so it never holds a
/// runtime worker; any other check runs inline, being microseconds.
pub(crate) async fn verify_credential_blocking(
    kdf: &KdfExecutor,
    credential: &FactorCredential,
    config: &FactorConfig,
    kind: &FactorKind,
    now: chrono::DateTime<chrono::Utc>,
    pepper: Option<&Arc<axess_factors::RecoveryCodePepper>>,
) -> Result<VerifyOutcome, KdfError> {
    if !runs_kdf(credential, config) {
        return Ok(verify_credential(
            credential,
            config,
            kind,
            now,
            pepper.map(|p| &**p),
        ));
    }
    let (credential, config, kind, pepper) = (
        credential.clone(),
        config.clone(),
        kind.clone(),
        pepper.cloned(),
    );
    kdf.run(move || verify_credential(&credential, &config, &kind, now, pepper.as_deref()))
        .await
}

/// Generate a random numeric OTP code of the given length using the injectable RNG.
///
/// Returns a zero-padded decimal string (e.g. `"042817"` for length 6).
pub(crate) fn generate_otp_code(rng: &impl SecureRng, length: usize) -> String {
    // A u64 holds at most 19 decimal digits, so longer codes are built from
    // chunks of up to 18; each chunk is drawn uniformly on its own.
    const CHUNK: usize = 18;
    let mut code = String::with_capacity(length);
    let mut remaining = length;
    while remaining > 0 {
        let width = remaining.min(CHUNK);
        code.push_str(&random_digits(rng, width));
        remaining -= width;
    }
    code
}

/// `width` (1..=18) uniformly random decimal digits, zero padded.
fn random_digits(rng: &impl SecureRng, width: usize) -> String {
    let modulus = 10u64.pow(width as u32);
    // Rejection sampling to eliminate modulo bias: discard values from the
    // partial final bucket that would skew the distribution.
    let max_fair = u64::MAX - (u64::MAX % modulus);
    loop {
        let mut bytes = [0u8; 8];
        rng.fill_bytes(&mut bytes);
        let value = u64::from_le_bytes(bytes);
        if value < max_fair {
            return format!("{:0>width$}", value % modulus, width = width);
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
        let outcome = verify_credential(&cred, &cfg, &FactorKind::Password, Utc::now(), None);
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
        let outcome = verify_credential(&cred, &cfg, &FactorKind::Password, Utc::now(), None);
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
        let outcome = verify_credential(&cred, &cfg, &FactorKind::Password, Utc::now(), None);
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
        let outcome = verify_credential(&cred, &cfg, &FactorKind::EmailOtp, Utc::now(), None);
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
        let outcome = verify_credential(&cred, &cfg, &FactorKind::EmailOtp, Utc::now(), None);
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
        let outcome = verify_credential(&cred, &cfg, &FactorKind::EmailOtp, Utc::now(), None);
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
        let outcome = verify_credential(&cred, &cfg, &FactorKind::EmailOtp, Utc::now(), None);
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
        let outcome = verify_credential(&cred, &cfg, &FactorKind::Totp, Utc::now(), None);
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
