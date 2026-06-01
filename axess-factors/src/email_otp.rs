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
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Email OTP factor configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailOtpConfig {
    /// Destination email address for code delivery.
    pub email: Arc<str>,
    /// Length of the generated numeric code (typically 6 to 8 digits).
    pub code_length: u8,
    /// Time-to-live for an issued code, in seconds.
    pub ttl_secs: u32,
    /// SHA-256 hash of the currently pending code, or `None` when no code is outstanding.
    pub pending_hash: Option<ZeroizedString>,
    /// Wall-clock instant after which the pending code is considered expired.
    pub pending_until: Option<DateTime<Utc>>,
    /// Number of verification attempts made against the current pending code.
    /// Incremented on each failed verification. When `attempt_count >= max_attempts`,
    /// the pending code is invalidated and a new one must be issued.
    #[serde(default)]
    pub attempt_count: u8,
    /// Maximum failed verification attempts before the pending code is burned.
    /// Default: 5. Set to 0 to disable (not recommended).
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
            ttl_secs: 300,
            pending_hash: None,
            pending_until: None,
            attempt_count: 0,
            max_attempts: 5,
        }
    }
}

// mutation-testing follow-up: pin the documented `max_attempts` default. A value
// of 0 would either lock the user out instantly or never expire the
// counter. Mutation testing found the previous suite didn't
// assert this default.
#[cfg(test)]
mod tests {
    use super::{EmailOtpConfig, default_max_email_otp_attempts};

    #[test]
    fn email_otp_default_max_attempts_is_five() {
        assert_eq!(default_max_email_otp_attempts(), 5);
        assert_eq!(EmailOtpConfig::default().max_attempts, 5);
    }
}
