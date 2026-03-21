//! Factor kinds, typed configurations, and the `ZeroizedString` secret wrapper.
//!
//! Replaces the old `HashMap<String, JsonValue>` approach with typed structs
//! for each supported factor kind.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{fmt, ops::Deref, sync::Arc};
use zeroize::Zeroize;

// ── FactorKind ─────────────────────────────────────────────────────────────────

/// The kind of authentication factor.
///
/// Used to identify and route factor verification within an authentication flow.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FactorKind {
    /// Standard password-based authentication.
    Password,
    /// Time-based one-time password (RFC 6238).
    Totp,
    /// HMAC-based one-time password (RFC 4226).
    Hotp,
    /// One-time code sent via email.
    EmailOtp,
    /// FIDO2 / WebAuthn credential.
    Fido2,
    /// Federated identity via an external provider.
    Federated(FederatedProvider),
}

impl FactorKind {
    /// Return a stable lowercase string representation.
    pub fn as_str(&self) -> &str {
        match self {
            FactorKind::Password => "password",
            FactorKind::Totp => "totp",
            FactorKind::Hotp => "hotp",
            FactorKind::EmailOtp => "email_otp",
            FactorKind::Fido2 => "fido2",
            FactorKind::Federated(p) => p.as_str(),
        }
    }
}

impl fmt::Display for FactorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ── FederatedProvider ─────────────────────────────────────────────────────────

/// A federated identity provider for OAuth2/OIDC-based authentication.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FederatedProvider {
    Github,
    Google,
    Microsoft,
    /// Any custom/unlisted provider, identified by name.
    Custom(Arc<str>),
}

impl FederatedProvider {
    /// Return a stable lowercase string representation.
    pub fn as_str(&self) -> &str {
        match self {
            FederatedProvider::Github => "github",
            FederatedProvider::Google => "google",
            FederatedProvider::Microsoft => "microsoft",
            FederatedProvider::Custom(s) => s.as_ref(),
        }
    }
}

// ── ZeroizedString ─────────────────────────────────────────────────────────────

/// A `String` that is zeroed in memory on drop.
///
/// Used for secrets at rest in memory (password hashes, OTP secrets) to reduce
/// the window during which sensitive data is recoverable from a process dump.
#[derive(Clone, Serialize, Deserialize)]
pub struct ZeroizedString(String);

impl ZeroizedString {
    /// Wrap a string value, taking ownership.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

impl Drop for ZeroizedString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Zeroize for ZeroizedString {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Deref for ZeroizedString {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Debug for ZeroizedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ZeroizedString(***)")
    }
}

impl From<String> for ZeroizedString {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for ZeroizedString {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

// ── OtpAlgorithm ─────────────────────────────────────────────────────────────

/// The HMAC algorithm used for OTP generation.
///
/// Most implementations use SHA-1 (RFC default); SHA-256/512 are supported by
/// some apps for increased security.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum OtpAlgorithm {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

// ── PasswordRules ─────────────────────────────────────────────────────────────

/// Complexity requirements for passwords.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordRules {
    /// Minimum number of characters.
    pub min_length: usize,
    /// At least one uppercase ASCII letter required.
    pub require_uppercase: bool,
    /// At least one lowercase ASCII letter required.
    pub require_lowercase: bool,
    /// At least one ASCII digit required.
    pub require_digit: bool,
    /// At least one special character required.
    pub require_special: bool,
}

impl Default for PasswordRules {
    fn default() -> Self {
        Self {
            min_length: 12,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: false,
        }
    }
}

// ── Per-factor Config structs ─────────────────────────────────────────────────

/// Password factor configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordConfig {
    /// Argon2id PHC hash string, zeroized on drop.
    pub hash: ZeroizedString,
    /// Strength rules applied when setting a new password.
    pub rules: PasswordRules,
}

/// TOTP factor configuration (RFC 6238).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpConfig {
    /// Base32-encoded shared secret, zeroized on drop.
    pub secret: ZeroizedString,
    /// Number of digits in the OTP (default: 6).
    pub digits: u8,
    /// Step period in seconds (default: 30).
    pub period_secs: u32,
    /// HMAC algorithm (default: SHA-1).
    pub algorithm: OtpAlgorithm,
    /// How many past steps to accept for clock drift (default: 1).
    pub past_window: u32,
    /// How many future steps to accept (default: 0).
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

/// HOTP factor configuration (RFC 4226).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotpConfig {
    /// Base32-encoded shared secret, zeroized on drop.
    pub secret: ZeroizedString,
    /// Number of digits in the OTP (default: 6).
    pub digits: u8,
    /// HMAC algorithm (default: SHA-1).
    pub algorithm: OtpAlgorithm,
    /// Current counter value. Must be atomically incremented before returning a result.
    pub counter: u64,
    /// How many future counter values to accept (default: 10).
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

/// Email OTP factor configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailOtpConfig {
    /// Email address to send the OTP to.
    pub email: Arc<str>,
    /// Number of digits in the OTP (default: 6).
    pub code_length: u8,
    /// How long the OTP is valid for in seconds (default: 300).
    pub ttl_secs: u32,
    /// Argon2id hash of the pending OTP code. `None` if no code is pending.
    pub pending_hash: Option<ZeroizedString>,
    /// When the pending code expires.
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

/// FIDO2/WebAuthn factor configuration.
///
/// Placeholder — full FIDO2 support is planned for a future release.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Fido2Config {
    /// Registered FIDO2 credentials (opaque blobs until FIDO2 is implemented).
    pub credentials: Vec<serde_json::Value>,
}

// ── FactorConfig ──────────────────────────────────────────────────────────────

/// Typed factor configuration — one variant per factor kind.
///
/// Replaces the old `HashMap<String, serde_json::Value>` config map.
/// Stored per-factor in the [`FactorStore`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FactorConfig {
    Password(PasswordConfig),
    Totp(TotpConfig),
    Hotp(HotpConfig),
    EmailOtp(EmailOtpConfig),
    Fido2(Fido2Config),
}

impl FactorConfig {
    /// Return the [`FactorKind`] for this config variant.
    pub fn kind(&self) -> FactorKind {
        match self {
            FactorConfig::Password(_) => FactorKind::Password,
            FactorConfig::Totp(_) => FactorKind::Totp,
            FactorConfig::Hotp(_) => FactorKind::Hotp,
            FactorConfig::EmailOtp(_) => FactorKind::EmailOtp,
            FactorConfig::Fido2(_) => FactorKind::Fido2,
        }
    }
}

// ── FactorCredential ──────────────────────────────────────────────────────────

/// A credential presented for factor verification.
///
/// Passed to [`AuthnService::verify_factor`].
#[derive(Debug)]
pub enum FactorCredential {
    /// A plaintext password (zeroized on drop).
    Password(ZeroizedString),
    /// A numeric OTP code — used for TOTP, HOTP, and EmailOtp.
    OtpCode(Arc<str>),
    /// A FIDO2/WebAuthn assertion (placeholder until FIDO2 is implemented).
    Fido2Assertion(serde_json::Value),
}
