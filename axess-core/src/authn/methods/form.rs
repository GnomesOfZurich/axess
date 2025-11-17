//! Factor form definitions, validation, and verification glue.
//!
//! This module exposes the [`FactorForm`] trait plus ready-made implementations for
//! the default credential flows used throughout Axess (password, HOTP/TOTP, OAuth,
//! signup/reset helpers, etc.). Each form:
//! - performs local validation using utilities from `crate::utils::validation` and
//!   policy types such as [`PasswordRules`] and [`OtpRules`];
//! - surfaces the primary credential via [`FactorForm::credential`] so session and
//!   backend logic can authenticate consistently;
//! - serializes typed field maps consumed by provisioning flows or templates; and
//! - verifies user-supplied values against persisted factor configuration produced
//!   by [`FactorConfigBuilder`](super::policy::FactorConfigBuilder).
//!
//! Higher-level components (e.g. [`AuthSession`](crate::authn::session::auth_session))
//! rely on these forms to drive setup and verification without duplicating parsing
//! or validation rules.

use crate::{
    authn::{
        errors::FormError,
        methods::{
            factor::AuthFactorKind,
            policy::{OtpCharset, OtpRules, OtpType, PasswordRules},
        },
    },
    tracing::{error, warn},
    utils::validation::{
        is_valid_country_code, is_valid_email, is_valid_language_code, is_valid_name,
        is_valid_otp_code, is_valid_password, is_valid_url_format,
    },
};
use axess_factors::{TOTP_LENGTH, TOTP_PERIOD, verify_hotp, verify_password, verify_totp};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, collections::HashMap, fmt::Debug, time::SystemTime};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FactorFormKind {
    Setup,
    Verify,
}

/// Type-safe field identifiers for factor forms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FormField {
    Username,
    Password,
    Tenant,
    Next,
    OtpCode,
    OtpSecret,
    OauthProvider,
    Email,
    Language,
    Domicile,
    Fullname,
    /// Custom field defined by users
    Custom(&'static str),
}

impl FormField {
    pub const fn as_str(&self) -> &'static str {
        match self {
            FormField::Username => "username",
            FormField::Password => "password",
            FormField::Tenant => "tenant",
            FormField::Next => "next",
            FormField::OtpCode => "otp_code",
            FormField::OtpSecret => "otp_secret",
            FormField::OauthProvider => "provider",
            FormField::Email => "email",
            FormField::Language => "language",
            FormField::Domicile => "domicile",
            FormField::Fullname => "fullname",
            FormField::Custom(s) => s,
        }
    }
}

/// Field value that can be string, binary, or JSON
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FormFieldValue {
    /// String value (most common)
    String(Cow<'static, str>),
    /// Binary data (e.g., fingerprints, WebAuthn credentials)
    Binary(Vec<u8>),
    /// Structured JSON data (e.g., OAuth tokens with metadata)
    Json(serde_json::Value),
}

impl FormFieldValue {
    /// Convert to string if possible
    pub fn as_str(&self) -> Option<&str> {
        match self {
            FormFieldValue::String(s) => Some(s.as_ref()),
            _ => None,
        }
    }
}

impl From<String> for FormFieldValue {
    fn from(s: String) -> Self {
        FormFieldValue::String(Cow::Owned(s))
    }
}

impl From<&'static str> for FormFieldValue {
    fn from(s: &'static str) -> Self {
        FormFieldValue::String(Cow::Borrowed(s))
    }
}

impl From<Vec<u8>> for FormFieldValue {
    fn from(data: Vec<u8>) -> Self {
        FormFieldValue::Binary(data)
    }
}

impl From<serde_json::Value> for FormFieldValue {
    fn from(value: serde_json::Value) -> Self {
        FormFieldValue::Json(value)
    }
}

pub trait FactorForm: Send + Sync + Debug + for<'de> Deserialize<'de> {
    /// Which factor is this form for?
    fn factor_kind(&self) -> AuthFactorKind;
    /// Is this a setup or verification form?
    fn form_kind(&self) -> FactorFormKind;
    /// Validate the form before backend processing
    fn validate_form(&self) -> Result<&Self, FormError>;
    /// Get the authentication credential from the form, if applicable (password, TOTP code, OAuth provider, etc.)
    fn credential(&self) -> Option<&str>;
    /// Verify credentials against the factor's stored configuration (e.g., password or TOTP secret)
    fn verify_against_config(&self, config: &serde_json::Value) -> Result<&Self, FormError>;

    /// Returns form fields with type-safe keys and flexible values
    ///
    /// This method supports string, binary, and JSON field values.
    /// The default built-in forms use string values for simplicity,
    /// but custom forms can use any type.
    fn fields(&self) -> HashMap<FormField, FormFieldValue>;
}

/// Extension trait for ergonomic field access
///
/// These accessors return owned values to avoid returning references into a
/// temporary HashMap produced by `fields()`.
pub trait FactorFormExt: FactorForm {
    /// Get a string field value (owned)
    fn get_string_field(&self, field: FormField) -> Option<String> {
        match self.fields().get(&field)? {
            FormFieldValue::String(s) => Some(s.clone().into_owned()),
            _ => None,
        }
    }

    /// Get a binary field value (owned)
    fn get_binary_field(&self, field: FormField) -> Option<Vec<u8>> {
        match self.fields().get(&field)? {
            FormFieldValue::Binary(data) => Some(data.clone()),
            _ => None,
        }
    }

    /// Get a JSON field value (owned)
    fn get_json_field(&self, field: FormField) -> Option<serde_json::Value> {
        match self.fields().get(&field)? {
            FormFieldValue::Json(value) => Some(value.clone()),
            _ => None,
        }
    }

    /// Require a string field, returning an error if missing or wrong type
    fn require_string_field(&self, field: FormField) -> Result<String, FormError> {
        self.get_string_field(field)
            .ok_or_else(|| FormError::MissingField(field.as_str().to_string()))
    }
}

impl<T: FactorForm> FactorFormExt for T {}

/// Default form for requesting an authentication factor reset.
/// This could be used to implement both self-service, admin-initiated resets or intermediary flows,
/// such e.g. involving required approvals by a helpdesk or admin users.
#[derive(Debug, Clone, Deserialize)]
pub struct FactorResetRequestForm {
    /// Tenant identifier for multi-tenant systems
    pub tenant: String,
    /// Username or email of the user requesting the reset
    pub username: String,
    /// The specific factor kind to reset (Password, Otp, etc.)
    pub factor_kind: AuthFactorKind,
    /// Optional specific factor ID (if user has multiple factors of same kind)
    pub factor_id: Option<String>,
    /// Reason for the reset (strongly recommended for audit trail)
    pub reason: Option<String>,
    /// Optional ticket/case ID for compliance tracking
    pub ticket_id: Option<String>,
}

impl FactorForm for FactorResetRequestForm {
    fn factor_kind(&self) -> AuthFactorKind {
        AuthFactorKind::Password
    }

    fn form_kind(&self) -> FactorFormKind {
        FactorFormKind::Setup
    }

    fn validate_form(&self) -> Result<&Self, FormError> {
        // 1. Validate tenant
        if !is_valid_name(&self.tenant) {
            return Err(FormError::ValidationFailed(
                "Invalid tenant identifier".to_string(),
            ));
        }

        // 2. Validate username (email or name)
        if !is_valid_email(&self.username) && !is_valid_name(&self.username) {
            return Err(FormError::ValidationFailed(
                "Invalid username or email".to_string(),
            ));
        }

        // 3. Validate factor_id format if present
        if let Some(id) = &self.factor_id
            && !(id.is_empty() || id.len() > 128)
        {
            return Err(FormError::ValidationFailed(
                "Invalid factor ID format".to_string(),
            ));
        }

        // 4. Validate reason length if present
        if let Some(reason) = &self.reason {
            let len = reason.trim().len();
            if !(10..=500).contains(&len) {
                return Err(FormError::ValidationFailed(
                    "Unexpected length for reset reason".to_string(),
                ));
            }
        }

        // 5. Validate ticket_id if present
        if let Some(ticket) = &self.ticket_id
            && (ticket.is_empty() || ticket.len() > 64)
        {
            return Err(FormError::ValidationFailed(
                "Invalid ticket ID format".to_string(),
            ));
        }

        Ok(self)
    }

    fn credential(&self) -> Option<&str> {
        None
    }

    fn verify_against_config(&self, _config: &serde_json::Value) -> Result<&Self, FormError> {
        self.validate_form()
    }

    fn fields(&self) -> HashMap<FormField, FormFieldValue> {
        let mut map = HashMap::new();
        if let Some(reason) = &self.reason {
            map.insert(
                FormField::Custom("reason"),
                FormFieldValue::String(Cow::Owned(reason.clone())),
            );
        }
        if let Some(old) = &self.factor_id {
            map.insert(
                FormField::Custom("factor_id"),
                FormFieldValue::String(Cow::Owned(old.clone())),
            );
        }
        if let Some(token) = &self.ticket_id {
            map.insert(
                FormField::Custom("ticket_id"),
                FormFieldValue::String(Cow::Owned(token.clone())),
            );
        }
        // tenant is a required String on FactorResetRequestForm; include if non-empty
        if !self.tenant.is_empty() {
            map.insert(
                FormField::Tenant,
                FormFieldValue::String(Cow::Owned(self.tenant.clone())),
            );
        }
        map
    }
}

/// Default form for setting a new password (useful when changing a password)
#[derive(Debug, Clone, Deserialize)]
pub struct PasswordSetupForm {
    /// The new password to set.
    pub new_password: String,
    /// Optionally, the old password (for authenticated change).
    pub old_password: Option<String>,
    /// Optionally, a reset token (for password reminders).
    pub reset_token: Option<String>,
    pub tenant: Option<String>,
    pub next: Option<String>,
}

impl FactorForm for PasswordSetupForm {
    fn factor_kind(&self) -> AuthFactorKind {
        AuthFactorKind::Password
    }

    fn form_kind(&self) -> FactorFormKind {
        FactorFormKind::Setup
    }

    fn validate_form(&self) -> Result<&Self, FormError> {
        if self.new_password.len() < 8 || self.new_password.len() > 512 {
            return Err(FormError::ValidationFailed(
                "New password must be between 8 and 512 characters.".to_string(),
            ));
        }
        // Optionally require old_password for authenticated change
        Ok(self)
    }

    fn credential(&self) -> Option<&str> {
        Some(&self.new_password)
    }

    fn verify_against_config(&self, _config: &serde_json::Value) -> Result<&Self, FormError> {
        self.validate_form()
    }

    fn fields(&self) -> HashMap<FormField, FormFieldValue> {
        let mut map = HashMap::new();
        map.insert(
            FormField::Password,
            FormFieldValue::String(Cow::Owned(self.new_password.clone())),
        );
        if let Some(old) = &self.old_password {
            map.insert(
                FormField::Custom("old_password"),
                FormFieldValue::String(Cow::Owned(old.clone())),
            );
        }
        if let Some(token) = &self.reset_token {
            map.insert(
                FormField::Custom("reset_token"),
                FormFieldValue::String(Cow::Owned(token.clone())),
            );
        }
        if let Some(tenant) = &self.tenant {
            map.insert(
                FormField::Tenant,
                FormFieldValue::String(Cow::Owned(tenant.clone())),
            );
        }
        if let Some(next) = &self.next {
            map.insert(
                FormField::Next,
                FormFieldValue::String(Cow::Owned(next.clone())),
            );
        }
        map
    }
}

/// Default form for verifying password during login
///
/// This form captures the username and password, along with optional tenant and next URL.
/// It includes validation to ensure the username is a valid email or name,
/// and that the password meets some basic security requirements.
#[derive(Debug, Clone, Deserialize)]
pub struct PasswordForm {
    pub username: String,
    pub password: String,
    pub tenant: Option<String>,
    pub next: Option<String>,
}
impl FactorForm for PasswordForm {
    fn factor_kind(&self) -> AuthFactorKind {
        AuthFactorKind::Password
    }

    fn form_kind(&self) -> FactorFormKind {
        FactorFormKind::Verify
    }

    fn validate_form(&self) -> Result<&Self, FormError> {
        if self.username.is_empty() {
            warn!("Username field is empty.");
            return Err(FormError::InvalidFormData);
        }
        // Only accept if username is a valid email OR a valid name
        if !is_valid_email(&self.username) && !is_valid_name(&self.username) {
            warn!("Username is not a valid email or name.");
            return Err(FormError::InvalidFormData);
        }
        if !is_valid_password(&self.password, &PasswordRules::default()) {
            return Err(FormError::ValidationFailed(
                "Data in submitted \"password\" field is invalid".to_string(),
            ));
        } else if self.tenant.is_some() && !is_valid_name(self.tenant.as_ref().unwrap()) {
            warn!("Data in submitted \"Tenant\" field is invalid.");
            return Err(FormError::InvalidFormData);
        }
        if let Some(next) = &self.next
            && !is_valid_url_format(next)
        {
            warn!("PasswordForm submitted with invalid next URL");
            return Err(FormError::InvalidFormData);
        }
        Ok(self)
    }

    fn credential(&self) -> Option<&str> {
        if self.password.is_empty() {
            None
        } else {
            Some(&self.password)
        }
    }

    fn fields(&self) -> HashMap<FormField, FormFieldValue> {
        let capacity = 2 + self.tenant.is_some() as usize + self.next.is_some() as usize;
        let mut map = HashMap::with_capacity(capacity);

        map.insert(
            FormField::Username,
            FormFieldValue::String(Cow::Owned(self.username.clone())),
        );
        map.insert(
            FormField::Password,
            FormFieldValue::String(Cow::Owned(self.password.clone())),
        );

        if let Some(tenant) = &self.tenant {
            map.insert(
                FormField::Tenant,
                FormFieldValue::String(Cow::Owned(tenant.clone())),
            );
        }
        if let Some(next) = &self.next {
            map.insert(
                FormField::Next,
                FormFieldValue::String(Cow::Owned(next.clone())),
            );
        }

        map
    }

    fn verify_against_config(&self, config: &serde_json::Value) -> Result<&Self, FormError> {
        let credential = self.credential().ok_or_else(|| {
            FormError::ValidationFailed("Missing password credential.".to_string())
        })?;

        let password_hash = config
            .get("password_hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FormError::AuthConfigError(AuthFactorKind::Password.to_string()))?;

        match verify_password(credential, password_hash) {
            Ok(()) => Ok(self),
            Err(_) => {
                error!("Password verification failed for {:?}", self.username);
                Err(FormError::ValidationFailed(
                    "Invalid username or password.".to_string(),
                ))
            }
        }
    }
}

/// Form for setting up a TOTP factor (default implementation of an OTP factor).
///
/// This is used when the user is registering a new TOTP factor.
/// It includes the TOTP secret and an optional redirect URL after setup.
/// The secret is typically generated by the server and displayed to the user.
/// The user will then use this secret to configure their TOTP app.
///
/// By default, this follows the TOTP standard (RFC 6238), but can be configured for other OTP types.
///
/// # References
/// - [RFC 6238: TOTP: Time-Based One-Time Password Algorithm](https://datatracker.ietf.org/doc/html/rfc6238)
#[derive(Clone, Deserialize)]
pub struct TotpSetupForm {
    pub otp_secret: String,
    pub tenant: Option<String>,
    pub next: Option<String>,
}

impl Debug for TotpSetupForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpSetupForm")
            .field("otp_secret", &"***REDACTED***")
            .field("tenant", &self.tenant)
            .field("next", &self.next)
            .finish()
    }
}

impl FactorForm for TotpSetupForm {
    fn factor_kind(&self) -> AuthFactorKind {
        AuthFactorKind::Otp
    }

    fn form_kind(&self) -> FactorFormKind {
        FactorFormKind::Setup
    }

    fn validate_form(&self) -> Result<&Self, FormError> {
        if self.otp_secret.is_empty() {
            Err(FormError::ValidationFailed(
                "TOTP secret cannot be empty.".to_string(),
            ))
        } else if self.otp_secret.len() < 4 {
            Err(FormError::ValidationFailed(
                "TOTP secret must be at least 4 characters long.".to_string(),
            ))
        } else if self.tenant.is_some() && !is_valid_name(self.tenant.as_ref().unwrap()) {
            warn!("Data in submitted \"Tenant\" field is invalid.");
            Err(FormError::InvalidFormData)
        } else if let Some(next) = &self.next {
            if !is_valid_url_format(next) {
                warn!("PasswordForm submitted with invalid next URL");
                Err(FormError::InvalidFormData)
            } else {
                Ok(self)
            }
        } else {
            Ok(self)
        }
    }

    fn credential(&self) -> Option<&str> {
        Some(&self.otp_secret)
    }

    fn fields(&self) -> HashMap<FormField, FormFieldValue> {
        let capacity = 1 + self.tenant.is_some() as usize + self.next.is_some() as usize;
        let mut map = HashMap::with_capacity(capacity);

        map.insert(
            FormField::OtpSecret,
            FormFieldValue::String(Cow::Owned(self.otp_secret.clone())),
        );

        if let Some(tenant) = &self.tenant {
            map.insert(
                FormField::Tenant,
                FormFieldValue::String(Cow::Owned(tenant.clone())),
            );
        }
        if let Some(next) = &self.next {
            map.insert(
                FormField::Next,
                FormFieldValue::String(Cow::Owned(next.clone())),
            );
        }

        map
    }

    fn verify_against_config(&self, _config: &serde_json::Value) -> Result<&Self, FormError> {
        // For factor setup, verification against existing credentials is not meaningful.
        // Instead, just validate the form and allow setup to proceed.
        self.validate_form()
    }
}

/// Form for verifying a TOTP code.
/// Now supports configurable charset for numeric, hex, or alphanumeric codes.
#[derive(Clone, Deserialize)]
pub struct TotpForm {
    pub otp_code: String,
    pub tenant: Option<String>,
    pub next: Option<String>,
}

impl Debug for TotpForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpVerifyForm")
            .field("otp_code", &"***REDACTED***")
            .field("tenant", &self.tenant)
            .field("next", &self.next)
            .finish()
    }
}

impl FactorForm for TotpForm {
    fn factor_kind(&self) -> AuthFactorKind {
        AuthFactorKind::Otp
    }

    fn form_kind(&self) -> FactorFormKind {
        FactorFormKind::Verify
    }

    fn validate_form(&self) -> Result<&Self, FormError> {
        let config = OtpRules::default();
        if !is_valid_otp_code(&self.otp_code, &config) {
            return Err(FormError::ValidationFailed(format!(
                "TOTP code must be exactly {} {}.",
                TOTP_LENGTH,
                match config.charset {
                    OtpCharset::Numeric => "digits",
                    OtpCharset::Hex => "hex characters",
                    OtpCharset::Alphanumeric => "alphanumeric characters",
                }
            )));
        }
        if self.tenant.is_some() && !is_valid_name(self.tenant.as_ref().unwrap()) {
            warn!("Data in submitted \"Tenant\" field is invalid.");
            return Err(FormError::InvalidFormData);
        }
        if let Some(next) = &self.next
            && !is_valid_url_format(next)
        {
            warn!("PasswordForm submitted with invalid next URL");
            return Err(FormError::InvalidFormData);
        }
        Ok(self)
    }

    fn credential(&self) -> Option<&str> {
        Some(&self.otp_code)
    }

    fn fields(&self) -> HashMap<FormField, FormFieldValue> {
        let capacity = 1 + self.tenant.is_some() as usize + self.next.is_some() as usize;
        let mut map = HashMap::with_capacity(capacity);

        map.insert(
            FormField::OtpCode,
            FormFieldValue::String(Cow::Owned(self.otp_code.clone())),
        );

        if let Some(tenant) = &self.tenant {
            map.insert(
                FormField::Tenant,
                FormFieldValue::String(Cow::Owned(tenant.clone())),
            );
        }
        if let Some(next) = &self.next {
            map.insert(
                FormField::Next,
                FormFieldValue::String(Cow::Owned(next.clone())),
            );
        }

        map
    }

    fn verify_against_config(&self, config: &serde_json::Value) -> Result<&Self, FormError> {
        let secret = config
            .get("otp_secret")
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                FormError::AuthConfigError("Missing otp_secret in factor configuration".into())
            })?;

        let length = config
            .get("length")
            .and_then(|value| value.as_u64())
            .map(|value| value as usize)
            .unwrap_or(TOTP_LENGTH);

        let period = config
            .get("period")
            .and_then(|value| value.as_u64())
            .unwrap_or(TOTP_PERIOD);

        let past_window = config
            .get("past_window")
            .and_then(|value| value.as_u64())
            .unwrap_or(1);

        let future_window = config
            .get("future_window")
            .and_then(|value| value.as_u64())
            .unwrap_or(0);

        if verify_totp(
            secret,
            &self.otp_code,
            SystemTime::now(),
            Some(length),
            Some(period),
            Some(past_window),
            Some(future_window),
        )
        .is_none()
        {
            return Err(FormError::ValidationFailed(
                "Invalid TOTP code.".to_string(),
            ));
        }

        Ok(self)
    }
}

/// Form for setting up an HOTP factor (HMAC-based One-Time Password).
///
/// This is used when the user is registering a new HOTP factor.
/// It includes the HOTP secret and an optional redirect URL after setup.
/// The secret is typically generated by the server and displayed to the user.
/// The user will then use this secret to configure their HOTP app.
///
/// By default, this follows the HOTP standard ([RFC 4226: HOTP: An HMAC-Based One-Time Password Algorithm](https://datatracker.ietf.org/doc/html/rfc4226)).
#[derive(Debug, Clone, Deserialize)]
pub struct HotpSetupForm {
    /// The new HOTP secret to set up.
    pub otp_secret: String,
    /// Optional tenant for multi-tenancy.
    pub tenant: Option<String>,
    /// Optional redirect URL after setup.
    pub next: Option<String>,
}

impl FactorForm for HotpSetupForm {
    fn factor_kind(&self) -> AuthFactorKind {
        AuthFactorKind::Otp
    }

    fn form_kind(&self) -> FactorFormKind {
        FactorFormKind::Setup
    }

    fn validate_form(&self) -> Result<&Self, FormError> {
        if self.otp_secret.is_empty() {
            return Err(FormError::ValidationFailed(
                "HOTP secret cannot be empty.".to_string(),
            ));
        }
        if self.otp_secret.len() < 4 {
            return Err(FormError::ValidationFailed(
                "HOTP secret must be at least 4 characters long.".to_string(),
            ));
        }
        if let Some(tenant) = &self.tenant
            && !is_valid_name(tenant)
        {
            warn!("Data in submitted \"Tenant\" field is invalid.");
            return Err(FormError::InvalidFormData);
        }
        if let Some(next) = &self.next
            && !is_valid_url_format(next)
        {
            warn!("HotpSetupForm submitted with invalid next URL");
            return Err(FormError::InvalidFormData);
        }
        Ok(self)
    }

    fn credential(&self) -> Option<&str> {
        Some(&self.otp_secret)
    }

    fn fields(&self) -> HashMap<FormField, FormFieldValue> {
        let capacity = 1 + self.tenant.is_some() as usize + self.next.is_some() as usize;
        let mut map = HashMap::with_capacity(capacity);

        map.insert(
            FormField::OtpSecret,
            FormFieldValue::String(Cow::Owned(self.otp_secret.clone())),
        );
        if let Some(tenant) = &self.tenant {
            map.insert(
                FormField::Tenant,
                FormFieldValue::String(Cow::Owned(tenant.clone())),
            );
        }
        if let Some(next) = &self.next {
            map.insert(
                FormField::Next,
                FormFieldValue::String(Cow::Owned(next.clone())),
            );
        }
        map
    }

    fn verify_against_config(&self, _config: &serde_json::Value) -> Result<&Self, FormError> {
        // For HOTP setup, just validate the form.
        self.validate_form()
    }
}

/// Form for verifying a HOTP code.
#[derive(Debug, Clone, Deserialize)]
pub struct HotpForm {
    pub otp_code: String,
    pub counter: u64,
    pub tenant: Option<String>,
    pub next: Option<String>,
}

impl FactorForm for HotpForm {
    fn factor_kind(&self) -> AuthFactorKind {
        AuthFactorKind::Otp
    }

    fn form_kind(&self) -> FactorFormKind {
        FactorFormKind::Verify
    }

    fn validate_form(&self) -> Result<&Self, FormError> {
        let config = OtpRules::default();
        if !is_valid_otp_code(&self.otp_code, &config) {
            return Err(FormError::ValidationFailed(format!(
                "HOTP code must be exactly {} {}.",
                config.length,
                match config.charset {
                    OtpCharset::Numeric => "digits",
                    OtpCharset::Hex => "hex characters",
                    OtpCharset::Alphanumeric => "alphanumeric characters",
                }
            )));
        }
        if self.tenant.is_some() && !is_valid_name(self.tenant.as_ref().unwrap()) {
            warn!("Data in submitted \"Tenant\" field is invalid.");
            return Err(FormError::InvalidFormData);
        }
        if let Some(next) = &self.next
            && !is_valid_url_format(next)
        {
            warn!("HotpForm submitted with invalid next URL");
            return Err(FormError::InvalidFormData);
        }
        Ok(self)
    }

    fn credential(&self) -> Option<&str> {
        Some(&self.otp_code)
    }

    fn fields(&self) -> HashMap<FormField, FormFieldValue> {
        let mut map = HashMap::with_capacity(4);
        map.insert(
            FormField::OtpCode,
            FormFieldValue::String(Cow::Owned(self.otp_code.clone())),
        );
        map.insert(
            FormField::Custom("counter"),
            FormFieldValue::Json(serde_json::json!(self.counter)),
        );
        if let Some(tenant) = &self.tenant {
            map.insert(
                FormField::Tenant,
                FormFieldValue::String(Cow::Owned(tenant.clone())),
            );
        }
        if let Some(next) = &self.next {
            map.insert(
                FormField::Next,
                FormFieldValue::String(Cow::Owned(next.clone())),
            );
        }
        map
    }

    fn verify_against_config(&self, config: &serde_json::Value) -> Result<&Self, FormError> {
        // ✅ Use credential() for the OTP code (primary auth value)
        let code = self
            .credential()
            .ok_or_else(|| FormError::ValidationFailed("Missing HOTP code".to_string()))?;

        let secret = config
            .get("otp_secret")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FormError::AuthConfigError(AuthFactorKind::Otp.to_string()))?;

        let stored_counter = config
            .get("counter")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| FormError::AuthConfigError("Missing HOTP counter".to_string()))?;

        // ✅ Verify OTP type matches expectation
        let otp_type: OtpType = config
            .get("otp_type")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or(OtpType::Totp);

        if otp_type != OtpType::Hotp {
            return Err(FormError::ValidationFailed(format!(
                "Expected HOTP factor, found {}",
                otp_type.as_str()
            )));
        }

        // ✅ Use OtpRules for consistent length handling
        let otp_config = OtpRules::default();
        let window = 5u64;

        // ✅ Access form-specific field directly (counter is HOTP-specific, not a general credential)
        // Note: For HOTP, the form's counter field can be used for client-side sync hints,
        // but verification always uses the stored counter from config
        match verify_hotp(secret, code, stored_counter, otp_config.length, window) {
            Some(_used_counter) => {
                // Note: Counter increment happens in AuthSession::verify_factor, not here
                Ok(self)
            }
            None => {
                error!("HOTP verification failed for counter {}", stored_counter);
                Err(FormError::ValidationFailed("Invalid HOTP code".to_string()))
            }
        }
    }
}

/// Form for verifying email address during signup or email change
///
/// This form captures the email, tenant, verification token, and optional next URL.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EmailVerificationForm {
    pub email: String,
    pub tenant: String, // Name of tenant
    pub token: String,  // The email verification token
    pub next: Option<String>,
}

impl FactorForm for EmailVerificationForm {
    fn factor_kind(&self) -> AuthFactorKind {
        todo!()
    }

    fn form_kind(&self) -> FactorFormKind {
        todo!()
    }

    fn validate_form(&self) -> Result<&Self, FormError> {
        todo!()
    }
    fn credential(&self) -> Option<&str> {
        Some(&self.token)
    }

    fn fields(&self) -> HashMap<FormField, FormFieldValue> {
        todo!()
    }

    fn verify_against_config(&self, _config: &serde_json::Value) -> Result<&Self, FormError> {
        self.validate_form()
    }
}

/// Default form for setting up a new user account during signup
///
/// This form captures a basic set of user details needed for account creation.
/// It also includes validation ensuring that all fields are properly formatted.
#[derive(Clone, Serialize, Deserialize)]
pub struct UserSetupForm {
    pub tenant: String,
    pub username: String,
    pub fullname: String,
    pub email: String,
    pub language: String, // language code
    pub domicile: String, // country code
    pub password: String,
    pub next: Option<String>,
}

impl Debug for UserSetupForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserSetupForm")
            .field("tenant", &self.tenant)
            .field("username", &self.username)
            .field("fullname", &self.fullname)
            .field("email", &self.email)
            .field("language", &self.language)
            .field("domicile", &self.domicile)
            .field("password", &"***REDACTED***")
            .field("next", &self.next)
            .finish()
    }
}

impl FactorForm for UserSetupForm {
    fn factor_kind(&self) -> AuthFactorKind {
        AuthFactorKind::Custom("signup".to_owned())
    }

    fn form_kind(&self) -> FactorFormKind {
        FactorFormKind::Setup
    }

    fn validate_form(&self) -> Result<&Self, FormError> {
        if self.tenant.len() < 3 || self.tenant.len() > 64 || !is_valid_name(&self.tenant) {
            Err(FormError::ValidationFailed(
                "Submitted \"tenant\" field is empty or invalid".to_string(),
            ))
        } else if self.fullname.len() < 3
            || self.fullname.len() > 128
            || !is_valid_name(&self.fullname)
        {
            Err(FormError::ValidationFailed(
                "Data in submitted \"fullname\" field is invalid".to_string(),
            ))
        } else if !is_valid_language_code(&self.language) {
            Err(FormError::ValidationFailed(
                "Data in submitted \"lang\" field is invalid".to_string(),
            ))
        } else if !is_valid_email(&self.email) {
            Err(FormError::ValidationFailed(
                "Data in submitted \"email\" field is invalid".to_string(),
            ))
        } else if !is_valid_password(&self.password, &PasswordRules::default()) {
            Err(FormError::ValidationFailed(
                "Data in submitted \"Password\" field is invalid".to_string(),
            ))
        } else if self.domicile.len() != 2 || !is_valid_country_code(&self.domicile) {
            Err(FormError::ValidationFailed(
                "Data in submitted \"Domicile\" field is invalid".to_string(),
            ))
        } else if self.username.is_empty()
            || self.username.len() > 64
            || !is_valid_name(&self.username)
        {
            Err(FormError::ValidationFailed(
                "Data in submitted \"Username\" field is invalid".to_string(),
            ))
        } else if self.fullname.is_empty()
            || self.fullname.len() > 128
            || !is_valid_name(&self.fullname)
        {
            Err(FormError::ValidationFailed(
                "Data in submitted \"Fullname\" field is invalid".to_string(),
            ))
        } else if let Some(next) = &self.next {
            if !is_valid_url_format(next) {
                warn!("PasswordForm submitted with invalid next URL");
                Err(FormError::InvalidFormData)
            } else {
                Ok(self)
            }
        } else {
            Ok(self)
        }
    }

    fn credential(&self) -> Option<&str> {
        Some(&self.password)
    }

    fn verify_against_config(&self, _config: &serde_json::Value) -> Result<&Self, FormError> {
        self.validate_form()
    }

    fn fields(&self) -> HashMap<FormField, FormFieldValue> {
        let mut map = HashMap::new();
        map.insert(
            FormField::Tenant,
            FormFieldValue::String(Cow::Owned(self.tenant.clone())),
        );
        map.insert(
            FormField::Username,
            FormFieldValue::String(Cow::Owned(self.username.clone())),
        );
        map.insert(
            FormField::Fullname,
            FormFieldValue::String(Cow::Owned(self.fullname.clone())),
        );
        map.insert(
            FormField::Email,
            FormFieldValue::String(Cow::Owned(self.email.clone())),
        );
        map.insert(
            FormField::Language,
            FormFieldValue::String(Cow::Owned(self.language.clone())),
        );
        map.insert(
            FormField::Domicile,
            FormFieldValue::String(Cow::Owned(self.domicile.clone())),
        );
        map.insert(
            FormField::Password,
            FormFieldValue::String(Cow::Owned(self.password.clone())),
        );
        if let Some(next) = &self.next {
            map.insert(
                FormField::Next,
                FormFieldValue::String(Cow::Owned(next.clone())),
            );
        }
        map
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axess_factors::generate_password_hash;

    // ========================================================================
    // FormField Tests
    // ========================================================================

    #[test]
    fn test_form_field_as_str() {
        assert_eq!(FormField::Username.as_str(), "username");
        assert_eq!(FormField::Password.as_str(), "password");
        assert_eq!(FormField::Tenant.as_str(), "tenant");
        assert_eq!(FormField::Next.as_str(), "next");
        assert_eq!(FormField::OtpCode.as_str(), "otp_code");
        assert_eq!(FormField::OtpSecret.as_str(), "otp_secret");
        assert_eq!(FormField::OauthProvider.as_str(), "provider");
        assert_eq!(FormField::Email.as_str(), "email");
        assert_eq!(FormField::Language.as_str(), "language");
        assert_eq!(FormField::Domicile.as_str(), "domicile");
        assert_eq!(FormField::Fullname.as_str(), "fullname");
        assert_eq!(FormField::Custom("custom_field").as_str(), "custom_field");
    }

    // ========================================================================
    // FormFieldValue Tests
    // ========================================================================

    #[test]
    fn test_form_field_value_from_string() {
        let value = FormFieldValue::from("test".to_string());
        match value {
            FormFieldValue::String(s) => assert_eq!(s, "test"),
            _ => panic!("Expected String variant"),
        }
    }

    #[test]
    fn test_form_field_value_from_static_str() {
        let value = FormFieldValue::from("static");
        match value {
            FormFieldValue::String(s) => assert_eq!(s, "static"),
            _ => panic!("Expected String variant"),
        }
    }

    #[test]
    fn test_form_field_value_from_binary() {
        let data = vec![1, 2, 3, 4];
        let value = FormFieldValue::from(data.clone());
        match value {
            FormFieldValue::Binary(d) => assert_eq!(d, data),
            _ => panic!("Expected Binary variant"),
        }
    }

    #[test]
    fn test_form_field_value_from_json() {
        let json = serde_json::json!({"key": "value"});
        let value = FormFieldValue::from(json.clone());
        match value {
            FormFieldValue::Json(v) => assert_eq!(v, json),
            _ => panic!("Expected Json variant"),
        }
    }

    // ========================================================================
    // PasswordForm Tests
    // ========================================================================

    #[test]
    fn test_password_form_validation() {
        let valid = PasswordForm {
            username: "alice@example.com".to_string(),
            password: "Verysecurepassword1!".to_string(),
            tenant: None,
            next: None,
        };
        assert!(valid.validate_form().is_ok());

        let empty_username = PasswordForm {
            username: "".to_string(),
            password: "Verysecurepassword1!".to_string(),
            tenant: None,
            next: None,
        };
        assert!(empty_username.validate_form().is_err());

        let short_password = PasswordForm {
            username: "alice@example.com".to_string(),
            password: "short".to_string(),
            tenant: None,
            next: None,
        };
        assert!(short_password.validate_form().is_err());

        let long_password = PasswordForm {
            username: "alice@example.com".to_string(),
            password: "A".repeat(513),
            tenant: None,
            next: None,
        };
        assert!(long_password.validate_form().is_err());
    }

    #[test]
    fn test_password_form_invalid_username() {
        let form = PasswordForm {
            username: "!!!".to_string(),
            password: "Validpass1!".to_string(),
            tenant: None,
            next: None,
        };
        assert!(form.validate_form().is_err());
    }

    #[test]
    fn test_password_form_min_max_length() {
        let min_pass = "Aa1!".repeat(2); // 8 chars
        let max_pass = "Aa1!".repeat(128); // 512 chars
        let form_min = PasswordForm {
            username: "user".to_string(),
            password: min_pass.clone(),
            tenant: None,
            next: None,
        };
        let form_max = PasswordForm {
            username: "user".to_string(),
            password: max_pass.clone(),
            tenant: None,
            next: None,
        };
        assert!(form_min.validate_form().is_ok());
        assert!(form_max.validate_form().is_ok());
    }

    #[test]
    fn test_password_form_fields() {
        let form = PasswordForm {
            username: "testuser".to_string(),
            password: "password123".to_string(),
            tenant: Some("tenant1".to_string()),
            next: Some("/dashboard".to_string()),
        };

        let fields = form.fields();
        assert_eq!(fields.len(), 4);

        match fields.get(&FormField::Username) {
            Some(FormFieldValue::String(s)) => assert_eq!(s.as_ref(), "testuser"),
            Some(_) => panic!("Expected FormFieldValue::String for Username"),
            None => panic!("Username field is missing from fields()"),
        }
    }

    #[test]
    fn test_password_form_credential() {
        let form = PasswordForm {
            username: "user".to_string(),
            password: "mypassword".to_string(),
            tenant: None,
            next: None,
        };
        assert_eq!(form.credential(), Some("mypassword"));

        let empty_form = PasswordForm {
            username: "user".to_string(),
            password: "".to_string(),
            tenant: None,
            next: None,
        };
        assert_eq!(empty_form.credential(), None);
    }

    #[test]
    fn test_password_verify_against_config_success() {
        let password = "correctpassword";
        let hash = generate_password_hash(password);

        let form = PasswordForm {
            username: "user".to_string(),
            password: password.to_string(),
            tenant: None,
            next: None,
        };

        let config = serde_json::json!({"password_hash": hash});
        assert!(form.verify_against_config(&config).is_ok());
    }

    #[test]
    fn test_password_verify_against_config_wrong_password() {
        let correct_password = "correctpassword";
        let wrong_password = "wrongpassword";
        let hash = generate_password_hash(correct_password);

        let form = PasswordForm {
            username: "user".to_string(),
            password: wrong_password.to_string(),
            tenant: None,
            next: None,
        };

        let config = serde_json::json!({"password_hash": hash});
        assert!(form.verify_against_config(&config).is_err());
    }

    #[test]
    fn test_password_form_factor_kind() {
        let form = PasswordForm {
            username: "user".to_string(),
            password: "password123".to_string(),
            tenant: None,
            next: None,
        };

        assert_eq!(form.factor_kind(), AuthFactorKind::Password);
        assert_eq!(form.form_kind(), FactorFormKind::Verify);
    }

    // ========================================================================
    // TotpSetupForm Tests
    // ========================================================================

    #[test]
    fn test_totp_setup_form_validation() {
        let valid = TotpSetupForm {
            otp_secret: "abcd".to_string(),
            tenant: None,
            next: None,
        };
        assert!(valid.validate_form().is_ok());

        let empty_secret = TotpSetupForm {
            otp_secret: "".to_string(),
            tenant: None,
            next: None,
        };
        assert!(empty_secret.validate_form().is_err());

        let short_secret = TotpSetupForm {
            otp_secret: "abc".to_string(),
            tenant: None,
            next: None,
        };
        assert!(short_secret.validate_form().is_err());
    }

    #[test]
    fn test_totp_setup_form_kinds() {
        let form = TotpSetupForm {
            otp_secret: "secret123".to_string(),
            tenant: None,
            next: None,
        };

        assert_eq!(form.factor_kind(), AuthFactorKind::Otp);
        assert_eq!(form.form_kind(), FactorFormKind::Setup);
    }

    // ========================================================================
    // TotpForm Tests
    // ========================================================================

    #[test]
    fn test_totp_form_numeric_code() {
        let form = TotpForm {
            otp_code: "123456".to_string(),
            tenant: None,
            next: None,
        };
        assert!(form.validate_form().is_ok());
    }

    #[test]
    fn test_totp_form_invalid_hex_code() {
        // TOTP only supports numeric codes, hex should fail
        let form = TotpForm {
            otp_code: "a1b2c3".to_string(),
            tenant: None,
            next: None,
        };
        assert!(form.validate_form().is_err());
    }

    #[test]
    fn test_totp_form_invalid_alphanumeric_code() {
        // TOTP only supports numeric codes, alphanumeric should fail
        let form = TotpForm {
            otp_code: "A1b2C3".to_string(),
            tenant: None,
            next: None,
        };
        assert!(form.validate_form().is_err());
    }

    #[test]
    fn test_totp_form_default_numeric() {
        // No charset specified, should default to numeric
        let form = TotpForm {
            otp_code: "123456".to_string(),
            tenant: None,
            next: None,
        };
        assert!(form.validate_form().is_ok());

        let invalid = TotpForm {
            otp_code: "12ab56".to_string(),
            tenant: None,
            next: None,
        };
        assert!(invalid.validate_form().is_err());
    }

    #[test]
    fn test_totp_form_too_short() {
        let form = TotpForm {
            otp_code: "12345".to_string(), // 5 digits, should be 6
            tenant: None,
            next: None,
        };
        assert!(form.validate_form().is_err());
    }

    #[test]
    fn test_totp_form_too_long() {
        let form = TotpForm {
            otp_code: "1234567".to_string(), // 7 digits, should be 6
            tenant: None,
            next: None,
        };
        assert!(form.validate_form().is_err());
    }

    #[test]
    fn test_totp_form_invalid_characters() {
        let form = TotpForm {
            otp_code: "12a456".to_string(), // contains a letter, should be digits only by default
            tenant: None,
            next: None,
        };
        assert!(form.validate_form().is_err());
    }

    // ========================================================================
    // Negative tests for is_valid_otp_code helper
    // ========================================================================

    #[test]
    fn test_is_valid_otp_code_numeric_negative() {
        let config = OtpRules {
            length: 6,
            charset: OtpCharset::Numeric,
            past_window: 1u64,
            future_window: 0u64,
            period: 30u64,
        };
        assert!(!is_valid_otp_code("12345", &config)); // too short
        assert!(!is_valid_otp_code("1234567", &config)); // too long
    }

    #[test]
    fn test_is_valid_otp_code_hex_negative() {
        let config = OtpRules {
            length: 6,
            charset: OtpCharset::Hex,
            past_window: 1u64,
            future_window: 0u64,
            period: 30u64,
        };
        assert!(!is_valid_otp_code("a1b2c", &config)); // too short
        assert!(!is_valid_otp_code("a1b2c3d", &config)); // too long
    }

    #[test]
    fn test_is_valid_otp_code_alphanumeric_negative() {
        let config = OtpRules {
            length: 6,
            charset: OtpCharset::Alphanumeric,
            past_window: 1u64,
            future_window: 0u64,
            period: 30u64,
        };
        assert!(!is_valid_otp_code("A1b2C", &config)); // too short
        assert!(!is_valid_otp_code("A1b2C3D", &config)); // too long
        assert!(!is_valid_otp_code("A1b2C!", &config)); // '!' is not alphanumeric
    }
}
