//! Factor policy utilities for the authentication subsystem.
//!
//! This module groups the reusable pieces that describe how factors should be
//! validated and stored:
//! - [`PasswordRules`] / [`PasswordRulesBuilder`] define password complexity
//!   requirements enforced when capturing credentials.
//! - [`OtpRules`] / [`OtpRulesBuilder`] describe acceptable OTP lengths, charsets,
//!   and window tolerances used during HOTP/TOTP verification.
//! - [`FactorConfig`] wraps the serialized configuration persisted alongside each
//!   factor instance so callers can read fields without touching raw JSON maps.
//! - [`FactorConfigBuilder`] provides ergonomic constructors for common factor
//!   configs (password hashes, HOTP, TOTP) and ad-hoc overrides when provisioning
//!   factors through [`AuthSession`](../session/auth_session.rs) or custom backends.
//!
//! Higher-level components (forms, session flows, examples) should rely on these
//! helpers to keep validation logic and stored configurations aligned.

use std::{collections::HashMap, str::FromStr};

use crate::tracing::debug;

use lazy_regex::regex;
use serde::{Deserialize, Serialize};
use serde_json::{Number as JsonNumber, Value as JsonValue};

/// Defines password complexity requirements for authentication factors.
///
/// `PasswordRules` is used to validate user-supplied passwords during signup, password change,
/// and credential verification flows. It supports configurable minimum and maximum length,
/// and requirements for uppercase, lowercase, numeric, and special characters.
///
/// # Fields
/// - `min`: Minimum password length (if set).
/// - `max`: Maximum password length (if set).
/// - `require_uppercase`: Require at least one uppercase letter.
/// - `require_lowercase`: Require at least one lowercase letter.
/// - `require_number`: Require at least one digit.
/// - `require_special`: Require at least one special symbol.
///
/// # Usage
/// Use [`PasswordRules::validate`] to check if a password meets the configured requirements.
/// Use [`PasswordRules::builder`] for ergonomic construction of custom rules.
///
/// # Example
/// ```rust
/// use axess_core::authn::methods::policy::PasswordRules;
///
/// let rules = PasswordRules::builder()
///     .with_min(Some(8))
///     .with_max(Some(64))
///     .require_uppercase(true)
///     .require_lowercase(true)
///     .require_number(true)
///     .require_special(true)
///     .build();
///
/// assert!(rules.validate("Valid123!"));
/// assert!(!rules.validate("short"));
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasswordRules {
    /// Minimum password length (if set).
    pub min: Option<usize>,
    /// Maximum password length (if set).
    pub max: Option<usize>,
    /// Require at least one uppercase letter.
    pub require_uppercase: bool,
    /// Require at least one lowercase letter.
    pub require_lowercase: bool,
    /// Require at least one digit.
    pub require_number: bool,
    /// Require at least one special symbol.
    pub require_special: bool,
}

impl PasswordRules {
    /// Returns a builder for ergonomic construction of custom password rules.
    pub fn builder() -> PasswordRulesBuilder {
        PasswordRulesBuilder::default()
    }

    /// Validates a password against these rules.
    ///
    /// Returns `true` if the password meets all requirements, `false` otherwise.
    pub fn validate(&self, password: &str) -> bool {
        if let Some(min) = self.min
            && password.len() < min
        {
            debug!(
                "Password validation error: Min password length: {} symbols",
                min
            );
            return false;
        }
        if let Some(max) = self.max
            && password.len() > max
        {
            debug!(
                "Password validation error: Max password length: {} symbols",
                max
            );
            return false;
        }

        let has_uppercase = regex!(r#"\p{Lu}"#);
        let has_lowercase = regex!(r#"\p{Ll}"#);
        let has_number = regex!(r#"\d"#);
        let has_special = regex!(r#"[!@#\$%\^&_\*\.\[\]\{\}\(\)\|\+\-~,:;!?'¤<>€£¥₹$/\\]"#);

        if self.require_uppercase && !has_uppercase.is_match(password) {
            debug!("Invalid Password: At least 1 uppercase letter");
            false
        } else if self.require_lowercase && !has_lowercase.is_match(password) {
            debug!("Invalid Password: At least 1 lowercase letter");
            false
        } else if self.require_number && !has_number.is_match(password) {
            debug!("Invalid Password: At least 1 number");
            false
        } else if self.require_special && !has_special.is_match(password) {
            debug!("Invalid Password: At least 1 special symbol");
            false
        } else {
            true
        }
    }
}

impl Default for PasswordRules {
    /// Returns a modern, secure default set of password rules:
    /// - Minimum length: 12
    /// - Maximum length: 512
    /// - Requires at least one uppercase letter
    /// - Requires at least one lowercase letter
    /// - Requires at least one digit
    /// - Requires at least one special symbol
    fn default() -> Self {
        Self {
            min: Some(12),
            max: Some(512),
            require_uppercase: true,
            require_lowercase: true,
            require_number: true,
            require_special: true,
        }
    }
}

/// Builder for [`PasswordRules`] to enable ergonomic configuration.
///
/// # Example
/// ```rust
/// use axess_core::authn::methods::policy::PasswordRules;
///
/// let rules = PasswordRules::builder()
///     .with_min(Some(8))
///     .with_max(Some(64))
///     .require_uppercase(true)
///     .require_lowercase(true)
///     .require_number(true)
///     .require_special(true)
///     .build();
/// ```
#[derive(Default)]
pub struct PasswordRulesBuilder {
    min: Option<usize>,
    max: Option<usize>,
    require_uppercase: bool,
    require_lowercase: bool,
    require_number: bool,
    require_special: bool,
}

impl PasswordRulesBuilder {
    /// Sets the minimum password length.
    pub fn with_min(mut self, value: Option<usize>) -> Self {
        self.min = value;
        self
    }

    /// Sets the maximum password length.
    pub fn with_max(mut self, value: Option<usize>) -> Self {
        self.max = value;
        self
    }

    /// Requires at least one uppercase letter.
    pub fn require_uppercase(mut self, value: bool) -> Self {
        self.require_uppercase = value;
        self
    }

    /// Requires at least one lowercase letter.
    pub fn require_lowercase(mut self, value: bool) -> Self {
        self.require_lowercase = value;
        self
    }

    /// Requires at least one digit.
    pub fn require_number(mut self, value: bool) -> Self {
        self.require_number = value;
        self
    }

    /// Requires at least one special symbol.
    pub fn require_special(mut self, value: bool) -> Self {
        self.require_special = value;
        self
    }

    /// Builds and returns a [`PasswordRules`] instance.
    pub fn build(self) -> PasswordRules {
        PasswordRules {
            min: self.min,
            max: self.max,
            require_uppercase: self.require_uppercase,
            require_lowercase: self.require_lowercase,
            require_number: self.require_number,
            require_special: self.require_special,
        }
    }
}

/// Character set used for validating and generating OTP codes.
///
/// `TokenCharset` determines which characters are allowed in a one-time password (OTP) code.
/// This is used for both TOTP (time-based) and HOTP (counter-based) authentication factors,
/// and ensures that codes are validated according to the expected format.
///
/// # Variants
/// - `Numeric`: Only ASCII digits (`0-9`) are allowed.
/// - `Hex`: Only ASCII hexadecimal characters (`0-9`, `a-f`, `A-F`) are allowed.
/// - `Alphanumeric`: Only ASCII alphanumeric characters (`0-9`, `a-z`, `A-Z`) are allowed.
///
/// # Usage
/// Use `TokenCharset` in [`OtpRules`] to specify the allowed code format for a factor.
/// The charset is checked during code validation and can be configured for custom OTP flows.
///
/// # Example
/// ```rust
/// use axess_core::authn::methods::policy::TokenCharset;
///
/// assert_eq!(TokenCharset::Numeric.as_str(), "numeric");
/// assert_eq!(TokenCharset::Hex.as_str(), "hex");
/// assert_eq!(TokenCharset::Alphanumeric.as_str(), "alphanumeric");
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenCharset {
    /// Only ASCII digits (`0-9`) are allowed.
    Numeric,
    /// Only ASCII hexadecimal characters (`0-9`, `a-f`, `A-F`) are allowed.
    Hex,
    /// Only ASCII alphanumeric characters (`0-9`, `a-z`, `A-Z`) are allowed.
    Alphanumeric,
}

impl TokenCharset {
    /// Returns the canonical string representation of the charset.
    ///
    /// This is used for serialization, logging, and config storage.
    pub fn as_str(&self) -> &'static str {
        match self {
            TokenCharset::Numeric => "numeric",
            TokenCharset::Hex => "hex",
            TokenCharset::Alphanumeric => "alphanumeric",
        }
    }
}

impl FromStr for TokenCharset {
    type Err = ();

    /// Parses a string into an `TokenCharset`.
    ///
    /// Accepts `"numeric"`, `"hex"`, or `"alphanumeric"` (case-insensitive).
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "numeric" => Ok(TokenCharset::Numeric),
            "hex" => Ok(TokenCharset::Hex),
            "alphanumeric" => Ok(TokenCharset::Alphanumeric),
            _ => Err(()),
        }
    }
}

/// Defines validation rules for One-Time Password (OTP) authentication factors.
///
/// `OtpRules` describes the expected code length, character set, time period, and window tolerances
/// for HOTP (counter-based) and TOTP (time-based) factors. These rules are used to validate user-supplied
/// OTP codes during authentication and to configure factor provisioning flows.
///
/// # Fields
/// - `length`: Number of digits or characters in the OTP code.
/// - `charset`: Allowed character set for the code (numeric, hex, alphanumeric).
/// - `past_window`: Number of previous time steps/counters to accept (for clock drift or sync).
/// - `future_window`: Number of future time steps/counters to accept.
/// - `period`: Time period in seconds for TOTP codes (ignored for HOTP).
///
/// # Usage
/// Use [`OtpRules::validate_code`] to check if a code matches the expected length and charset.
/// Use [`OtpRulesBuilder`] for ergonomic construction of custom rules.
///
/// # Example
/// ```rust
/// use axess_core::authn::methods::policy::{OtpRules, TokenCharset};
///
/// let rules = OtpRules {
///     length: 6,
///     charset: TokenCharset::Numeric,
///     past_window: 1,
///     future_window: 0,
///     period: 30,
/// };
///
/// assert!(rules.validate_code("123456"));
/// assert!(!rules.validate_code("abcdef")); // not numeric
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OtpRules {
    /// Number of digits or characters in the OTP code.
    pub length: usize,
    /// Allowed character set for the code (numeric, hex, alphanumeric).
    pub charset: TokenCharset,
    /// Number of previous time steps/counters to accept (for clock drift or sync).
    pub past_window: u64,
    /// Number of future time steps/counters to accept.
    pub future_window: u64,
    /// Time period in seconds for TOTP codes (ignored for HOTP).
    pub period: u64,
}

impl Default for OtpRules {
    /// Returns default TOTP rules: 6 digits, numeric, 30s period, 1 past window, 0 future window.
    fn default() -> Self {
        Self {
            length: 6,
            charset: TokenCharset::Numeric,
            past_window: 1,
            future_window: 0,
            period: 30,
        }
    }
}

impl OtpRules {
    /// Returns a builder for ergonomic construction of custom OTP rules.
    pub fn builder() -> OtpRulesBuilder {
        OtpRulesBuilder::default()
    }

    /// Returns default TOTP rules.
    pub fn totp_defaults() -> Self {
        Self::default()
    }

    /// Returns default HOTP rules: 6 digits, numeric, 0 past window, 10 future window, no period.
    pub fn hotp_defaults() -> Self {
        Self {
            length: 6,
            charset: TokenCharset::Numeric,
            past_window: 0,
            future_window: 10,
            period: 0,
        }
    }

    /// Validates an OTP code against these rules.
    ///
    /// Returns `true` if the code matches the expected length and charset, `false` otherwise.
    pub fn validate_code(&self, code: &str) -> bool {
        if code.len() != self.length {
            return false;
        }
        match self.charset {
            TokenCharset::Numeric => code.chars().all(|c| c.is_ascii_digit()),
            TokenCharset::Hex => code.chars().all(|c| c.is_ascii_hexdigit()),
            TokenCharset::Alphanumeric => code.chars().all(|c| c.is_ascii_alphanumeric()),
        }
    }
}

/// Builder for [`OtpRules`] to enable ergonomic configuration of OTP validation policies.
///
/// This builder allows you to specify code length, character set, time period, and window tolerances
/// for HOTP (counter-based) and TOTP (time-based) authentication factors. Use it to construct custom
/// OTP rules for your authentication flows.
///
/// # Example
/// ```rust
/// use axess_core::authn::methods::policy::{OtpRules, OtpRulesBuilder, TokenCharset};
///
/// let rules = OtpRulesBuilder::default()
///     .with_length(8)
///     .with_charset(TokenCharset::Alphanumeric)
///     .with_period(60)
///     .with_past_window(2)
///     .with_future_window(1)
///     .build();
///
/// assert_eq!(rules.length, 8);
/// assert_eq!(rules.charset, TokenCharset::Alphanumeric);
/// assert_eq!(rules.period, 60);
/// assert_eq!(rules.past_window, 2);
/// assert_eq!(rules.future_window, 1);
/// ```
#[derive(Default)]
pub struct OtpRulesBuilder {
    length: Option<usize>,
    charset: Option<TokenCharset>,
    past_window: Option<u64>,
    future_window: Option<u64>,
    period: Option<u64>,
}

impl OtpRulesBuilder {
    /// Sets the OTP code length (number of digits or characters).
    pub fn with_length(mut self, value: usize) -> Self {
        self.length = Some(value);
        self
    }

    /// Sets the allowed character set for the OTP code.
    pub fn with_charset(mut self, value: TokenCharset) -> Self {
        self.charset = Some(value);
        self
    }

    /// Sets the number of previous time steps/counters to accept (for clock drift or sync).
    pub fn with_past_window(mut self, value: u64) -> Self {
        self.past_window = Some(value);
        self
    }

    /// Sets the number of future time steps/counters to accept.
    pub fn with_future_window(mut self, value: u64) -> Self {
        self.future_window = Some(value);
        self
    }

    /// Sets the time period in seconds for TOTP codes (ignored for HOTP).
    pub fn with_period(mut self, value: u64) -> Self {
        self.period = Some(value);
        self
    }

    /// Builds and returns an [`OtpRules`] instance with the configured values.
    /// Unspecified fields fall back to the defaults: 6 digits, numeric charset, 30s period, 1 past window, 0 future window.
    pub fn build(self) -> OtpRules {
        OtpRules {
            length: self.length.unwrap_or(6),
            charset: self.charset.unwrap_or(TokenCharset::Numeric),
            past_window: self.past_window.unwrap_or(1),
            future_window: self.future_window.unwrap_or(0),
            period: self.period.unwrap_or(30),
        }
    }
}

/// Wrapper for configuration fields associated with an authentication factor.
///
/// `FactorConfig` provides a type-safe interface for reading and mutating the
/// configuration map stored alongside each factor instance. This map typically
/// contains settings such as password hashes, OTP secrets, code length, period,
/// and other factor-specific parameters.
///
/// Use this struct to avoid working directly with raw JSON maps and to access
/// ergonomic helpers for common config patterns.
///
/// # Usage
/// - Construct with [`FactorConfig::new`] or [`FactorConfig::from_map`].
/// - Access fields with [`get_string`], [`get_u64`], [`get_usize`], etc.
/// - Convert to a builder for ergonomic mutation with [`to_builder`].
///
/// # Example
/// ```rust
/// use axess_core::authn::methods::policy::{FactorConfig, FactorConfigBuilder};
///
/// let config = FactorConfigBuilder::totp("SECRET")
///     .with_length(8)
///     .with_period(60)
///     .build();
///
/// assert_eq!(config.get_string("secret"), Some("SECRET"));
/// assert_eq!(config.get_usize("length"), Some(8));
/// assert_eq!(config.get_u64("period"), Some(60));
/// ```
#[derive(Clone, Debug, Default)]
pub struct FactorConfig {
    inner: HashMap<String, JsonValue>,
}

impl FactorConfig {
    /// Creates a new, empty `FactorConfig`.
    ///
    /// Use this when you want to start with no configuration fields and add them incrementally.
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    /// Constructs a `FactorConfig` from an existing map.
    ///
    /// This is useful when deserializing or converting from a builder.
    pub fn from_map(map: HashMap<String, JsonValue>) -> Self {
        Self { inner: map }
    }

    /// Consumes the `FactorConfig` and returns the inner `HashMap` containing all configuration fields.
    ///
    /// Use this when you need ownership of the config map for mutation or serialization.
    pub fn into_inner(self) -> HashMap<String, JsonValue> {
        self.inner
    }

    /// Returns a reference to the inner `HashMap` containing all configuration fields.
    ///
    /// Use this to read or inspect the config without taking ownership.
    pub fn as_map(&self) -> &HashMap<String, JsonValue> {
        &self.inner
    }

    /// Returns `true` if the configuration contains no fields.
    ///
    /// Useful for checking if a factor has been provisioned with any settings.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns a reference to the JsonValue for the given key, if present.
    ///
    /// Use this to access raw configuration JsonValues, such as secrets or hashes.
    pub fn get_value(&self, key: &str) -> Option<&JsonValue> {
        self.inner.get(key)
    }

    /// Returns the value for the given key as a string, if present and of the correct type.
    ///
    /// This is a convenience method for accessing string-based config fields.
    pub fn get_string(&self, key: &str) -> Option<&str> {
        self.get_value(key).and_then(JsonValue::as_str)
    }

    /// Returns the value for the given key as a `u64`, if present and of the correct type.
    ///
    /// Useful for numeric config fields such as OTP length or period.
    pub fn get_u64(&self, key: &str) -> Option<u64> {
        self.get_value(key).and_then(JsonValue::as_u64)
    }

    /// Returns the value for the given key as a `usize`, if present and convertible.
    ///
    /// This is a convenience for fields that are stored as `u64` but used as `usize`.
    pub fn get_usize(&self, key: &str) -> Option<usize> {
        self.get_u64(key).map(|v| v as usize)
    }

    /// Converts this config into a `FactorConfigBuilder` for ergonomic mutation.
    ///
    /// Use this to start with an existing config and add or update fields.
    pub fn to_builder(&self) -> FactorConfigBuilder {
        FactorConfigBuilder::from_map(self.inner.clone())
    }
}

/// Builder for constructing [`FactorConfig`] instances ergonomically.
///
/// This builder provides fluent methods for assembling configuration maps for authentication factors,
/// including password, TOTP, and HOTP. It is used throughout Axess to ensure factor configs are
/// constructed consistently and with all required fields.
///
/// # Examples
///
/// ```rust
/// use axess_core::authn::methods::policy::FactorConfigBuilder;
///
/// // Build a password config
/// let config = FactorConfigBuilder::password("hashed_pw").build();
///
/// // Build a TOTP config with custom period
/// let config = FactorConfigBuilder::totp("BASE32SECRET")
///     .with_length(8)
///     .with_period(60)
///     .build();
/// ```
#[derive(Clone, Debug, Default)]
pub struct FactorConfigBuilder {
    inner: HashMap<String, JsonValue>,
}

impl FactorConfigBuilder {
    /// Creates a new, empty builder.
    ///
    /// Use this to start building a custom factor config from scratch.
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    /// Creates a builder from an existing config map.
    ///
    /// Useful for mutating or extending a config.
    pub fn from_map(map: HashMap<String, JsonValue>) -> Self {
        Self { inner: map }
    }

    /// Creates a builder from an existing [`FactorConfig`].
    ///
    /// This allows ergonomic mutation of an existing config.
    pub fn from_config(config: FactorConfig) -> Self {
        Self {
            inner: config.into_inner(),
        }
    }

    /// Creates a password factor config builder with the given hash.
    ///
    /// Sets the `"password_hash"` field.
    pub fn password(hash: impl Into<String>) -> Self {
        Self::new()
            .with_field("kind", JsonValue::String("password".into()))
            .with_field("password_hash", JsonValue::String(hash.into()))
    }

    /// Creates a TOTP factor config builder with the given secret.
    ///
    /// Sets `"kind"`, `"secret"`, `"length"`, `"period"`, `"past_window"`, `"future_window"`, and `"last_totp_step"`.
    pub fn totp(secret: impl Into<String>) -> Self {
        Self::new()
            .with_field("kind", JsonValue::String("totp".into()))
            .with_secret(secret)
            .with_length(6)
            .with_period(30)
            .with_windows(1, 0)
            .with_last_totp_step(0)
    }

    /// Creates a HOTP factor config builder with the given secret.
    ///
    /// Sets `"kind"`, `"secret"`, `"length"`, `"counter"`, and `"window"`.
    pub fn hotp(secret: impl Into<String>) -> Self {
        Self::new()
            .with_field("kind", JsonValue::String("hotp".into()))
            .with_secret(secret)
            .with_length(6)
            .with_field("counter", JsonValue::Number(JsonNumber::from(0u64)))
            .with_field("window", JsonValue::Number(JsonNumber::from(10u64)))
    }

    /// Creates a One-Time Confirmation factor config builder with the given email.
    ///
    /// Sets `"kind"`, `"email"`, `"length"`, `"counter"`, and `"window"`.
    pub fn email(email: impl Into<String>) -> Self {
        Self::new()
            .with_field("kind", JsonValue::String("email_otp".into()))
            .with_field("email", JsonValue::String(email.into()))
            .with_field("token", JsonValue::String("".into()))
            .with_length(6)
    }

    /// Inserts or updates a field in the config.
    ///
    /// Use this for custom or additional fields.
    pub fn with_field(mut self, key: impl Into<String>, value: JsonValue) -> Self {
        self.inner.insert(key.into(), value);
        self
    }

    /// Sets the `"secret"` field.
    pub fn with_secret(self, secret: impl Into<String>) -> Self {
        self.with_field("secret", JsonValue::String(secret.into()))
    }

    /// Sets the `"length"` field (number of digits).
    pub fn with_length(self, length: usize) -> Self {
        self.with_field("length", JsonValue::Number(JsonNumber::from(length as u64)))
    }

    /// Sets the `"period"` field (TOTP time period in seconds).
    pub fn with_period(self, period: u64) -> Self {
        self.with_field("period", JsonValue::Number(JsonNumber::from(period)))
    }

    /// Sets the `"past_window"` and `"future_window"` fields for OTP tolerance.
    pub fn with_windows(self, past: u64, future: u64) -> Self {
        self.with_field("past_window", JsonValue::Number(JsonNumber::from(past)))
            .with_field("future_window", JsonValue::Number(JsonNumber::from(future)))
    }

    /// Sets the `"last_totp_step"` field (used for replay protection).
    pub fn with_last_totp_step(self, step: u64) -> Self {
        self.with_field("last_totp_step", JsonValue::Number(JsonNumber::from(step)))
    }

    /// Consumes the builder and returns a [`FactorConfig`] with all fields set.
    pub fn build(self) -> FactorConfig {
        FactorConfig::from_map(self.inner)
    }
}

impl From<FactorConfigBuilder> for HashMap<String, JsonValue> {
    fn from(builder: FactorConfigBuilder) -> Self {
        builder.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// Checks that password validation enforces all configured rules.
    fn password_rules_validation() {
        let rules = PasswordRules::builder()
            .with_min(Some(8))
            .with_max(Some(64))
            .require_uppercase(true)
            .require_lowercase(true)
            .require_number(true)
            .require_special(true)
            .build();

        assert!(rules.validate("Valid123!"));
        assert!(!rules.validate("short"));
        assert!(!rules.validate("NOLOWERCASE123!"));
        assert!(!rules.validate("nouppercase123!"));
        assert!(!rules.validate("NoNumber!"));
        assert!(!rules.validate("NoSpecialChar1"));
    }

    #[test]
    /// Verifies that TOTP config builder sets correct defaults and values.
    fn config_builder_totp_defaults() {
        let config = FactorConfigBuilder::totp("SECRET").build();

        assert_eq!(config.get_string("kind"), Some("totp"));
        assert_eq!(config.get_string("secret"), Some("SECRET"));
        assert_eq!(config.get_u64("length"), Some(6));
        assert_eq!(config.get_u64("period"), Some(30));
        assert_eq!(config.get_u64("past_window"), Some(1));
        assert_eq!(config.get_u64("future_window"), Some(0));
        assert_eq!(config.get_u64("last_totp_step"), Some(0));
    }

    #[test]
    /// Verifies that HOTP config builder sets correct defaults and allows overrides.
    fn config_builder_hotp_defaults() {
        let config = FactorConfigBuilder::hotp("HOTSECRET")
            .with_field("counter", JsonValue::Number(JsonNumber::from(7u64)))
            .with_field("window", JsonValue::Number(JsonNumber::from(5u64)))
            .build();

        assert_eq!(config.get_string("kind"), Some("hotp"));
        assert_eq!(config.get_string("secret"), Some("HOTSECRET"));
        assert_eq!(config.get_u64("length"), Some(6));
        assert_eq!(config.get_u64("counter"), Some(7));
        assert_eq!(config.get_u64("window"), Some(5));
        assert!(config.get_u64("period").is_none());
    }
}
