//! Email OTP factor configuration: server-issued one-time codes
//! delivered out-of-band by email.
//!
//! Unlike TOTP and HOTP, there is no shared-secret HMAC: the server
//! generates a numeric code at challenge time, hashes it for storage,
//! sends the plaintext via email, and matches it against the stored
//! hash on submission. The verifier itself ships in axess-core's
//! `service/login.rs` today; this module owns just the typed config
//! the orchestrator persists with the pending challenge.

use crate::secret::ZeroizedString;
use axess_clock::Until;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

/// The shortest life an email code may be given: one minute, the time a
/// mail takes to arrive and be read. A shorter code is refused by the login
/// service when it is about to be issued.
pub const MIN_EMAIL_OTP_TTL: Duration = Duration::from_secs(60);

/// The longest life an email code may be given: thirty minutes. A code that
/// lives longer sits in an inbox for a guesser to find; the login service
/// refuses to issue one.
pub const MAX_EMAIL_OTP_TTL: Duration = Duration::from_secs(1800);

/// Email OTP factor configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailOtpConfig {
    /// Destination email address for code delivery.
    pub email: Arc<str>,
    /// Length of the generated numeric code (typically 6 to 8 digits).
    pub code_length: u8,
    /// Time-to-live for an issued code: a whole number of seconds, at least
    /// [`MIN_EMAIL_OTP_TTL`] and at most [`MAX_EMAIL_OTP_TTL`], outside which
    /// the login service refuses to issue a code. Stored as a count of
    /// seconds under `ttl_secs`, as before.
    #[serde(rename = "ttl_secs", with = "crate::whole_seconds::u32_seconds")]
    pub ttl: Duration,
    /// SHA-256 hash of the currently pending code, or `None` when no code is outstanding.
    pub pending_hash: Option<ZeroizedString>,
    /// When the pending code ends: it is considered expired after this.
    /// Computed from the time of issue and a lifetime, so it is an
    /// [`Until`]; it is stored as the same RFC 3339 text as before.
    pub pending_until: Option<Until>,
    /// Number of verification attempts made against the current pending code.
    /// Incremented on each failed verification. When `attempt_count >= max_attempts`,
    /// the pending code is invalidated and a new one must be issued.
    #[serde(default)]
    pub attempt_count: u8,
    /// Maximum failed verification attempts before the pending code is burned.
    /// Default: 5. A value of 0 is treated as
    /// the default, never as "no limit".
    #[serde(default = "default_max_email_otp_attempts")]
    pub max_attempts: u8,
}

fn default_max_email_otp_attempts() -> u8 {
    5
}

impl Default for EmailOtpConfig {
    fn default() -> Self {
        Self {
            email: "".into(),
            // 8 digits (10^8 = 100 M possibilities) makes brute-force
            // infeasible within the 5-minute TTL when combined with the
            // max_attempts limit (default 5 tries before code is burned).
            code_length: 8,
            ttl: Duration::from_secs(300),
            pending_hash: None,
            pending_until: None,
            attempt_count: 0,
            max_attempts: 5,
        }
    }
}

// Pins the documented `max_attempts` default of five. A default of 0 would
// lock the user out at once or never count a failure, depending on how the
// verify path reads it.
#[cfg(test)]
mod tests {
    use super::{EmailOtpConfig, default_max_email_otp_attempts};

    #[test]
    fn email_otp_default_max_attempts_is_five() {
        assert_eq!(default_max_email_otp_attempts(), 5);
        assert_eq!(EmailOtpConfig::default().max_attempts, 5);
    }
}
