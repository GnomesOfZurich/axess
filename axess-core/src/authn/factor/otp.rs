//! OTP factor configurations: TOTP, HOTP, and Email OTP.

use super::password::ZeroizedString;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// ── OtpAlgorithm ─────────────────────────────────────────────────────────────

/// The HMAC algorithm used for OTP generation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum OtpAlgorithm {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

// ── TotpConfig ───────────────────────────────────────────────────────────────

/// TOTP factor configuration (RFC 6238).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpConfig {
    pub secret: ZeroizedString,
    pub digits: u8,
    pub period_secs: u32,
    pub algorithm: OtpAlgorithm,
    pub past_window: u32,
    pub future_window: u32,
    /// The last validated step counter — prevents code replay.
    pub last_step: Option<u64>,
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self {
            secret: ZeroizedString::new(""),
            digits: 6,
            period_secs: 30,
            algorithm: OtpAlgorithm::Sha1,
            past_window: 1,
            future_window: 0,
            last_step: None,
        }
    }
}

// ── HotpConfig ───────────────────────────────────────────────────────────────

/// HOTP factor configuration (RFC 4226).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotpConfig {
    pub secret: ZeroizedString,
    pub digits: u8,
    pub algorithm: OtpAlgorithm,
    pub counter: u64,
    pub lookahead_window: u32,
}

impl Default for HotpConfig {
    fn default() -> Self {
        Self {
            secret: ZeroizedString::new(""),
            digits: 6,
            algorithm: OtpAlgorithm::Sha1,
            counter: 0,
            lookahead_window: 10,
        }
    }
}

// ── EmailOtpConfig ───────────────────────────────────────────────────────────

/// Email OTP factor configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailOtpConfig {
    pub email: Arc<str>,
    pub code_length: u8,
    pub ttl_secs: u32,
    pub pending_hash: Option<ZeroizedString>,
    pub pending_until: Option<DateTime<Utc>>,
}

impl Default for EmailOtpConfig {
    fn default() -> Self {
        Self {
            email: "".into(),
            code_length: 6,
            ttl_secs: 300,
            pending_hash: None,
            pending_until: None,
        }
    }
}
