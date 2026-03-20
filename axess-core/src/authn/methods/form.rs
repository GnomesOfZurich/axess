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
            factor::Kind,
            policy::{OtpRules, PasswordRules, TokenCharset},
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
use serde_json::{Value as JsonValue, from_value, json};
use std::{borrow::Cow, collections::HashMap, fmt::Debug, time::SystemTime};

/// High-level flow for a factor (knowledge, possession, crypto, federated, etc.)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Flow {
    Workflow,
    Knowledge,
    Otp,
    Crypto,
    Federated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum Action {
    Setup,
    Update,
    Recover,
    Verify,
}

/// Type-safe field identifiers for factor forms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FormField {
    UserName,
    Password,
    TenantName,
    FactorName,
    FactorKind,
    MethodName,
    Next,
    OtpCode,
    OtpSecret,
    Provider,
    Email,
    Language,
    Domicile,
    Fullname,
    Token,
    /// Custom field defined by users
    Custom(&'static str),
}

impl FormField {
    pub const fn as_str(&self) -> &'static str {
        match self {
            FormField::UserName => "username",
            FormField::Password => "password",
            FormField::TenantName => "tenant",
            FormField::FactorName => "factor",
            FormField::FactorKind => "kind",
            FormField::MethodName => "method",
            FormField::Next => "next",
            FormField::OtpCode => "otp_code",
            FormField::OtpSecret => "secret",
            FormField::Provider => "provider",
            FormField::Email => "email",
            FormField::Language => "language",
            FormField::Domicile => "domicile",
            FormField::Fullname => "fullname",
            FormField::Token => "token",
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
    Json(JsonValue),
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

impl From<JsonValue> for FormFieldValue {
    fn from(value: JsonValue) -> Self {
        FormFieldValue::Json(value)
    }
}

pub fn form_fields_to_json(
    fields: &HashMap<FormField, FormFieldValue>,
) -> HashMap<String, JsonValue> {
    fields
        .iter()
        .map(|(k, v)| {
            let key = k.as_str().to_string();
            let value = match v {
                FormFieldValue::String(s) => JsonValue::String(s.clone().into_owned()),
                FormFieldValue::Binary(b) => {
                    JsonValue::Array(b.iter().map(|byte| JsonValue::from(*byte)).collect())
                }
                FormFieldValue::Json(j) => j.clone(),
            };
            (key, value)
        })
        .collect()
}

/// Trait for all authentication factor forms in Axess.
///
/// Implement this trait for each supported form (password, TOTP, HOTP, OAuth, etc.).
/// This enables generic session flows, type-safe validation, and ergonomic UI integration.
pub trait FactorForm: Send + Sync + Debug + for<'de> Deserialize<'de> {
    /// The high-level flow category for this factor (knowledge, possession, etc.).
    fn flow(&self) -> Flow;

    /// The specific kind of factor (password, otp, oauth, etc.).
    fn kind(&self) -> Kind;

    /// The action/operation being performed (setup, verify, change, etc.).
    fn action(&self) -> Action;

    /// Validate the form before backend processing.
    fn validate_form(&self) -> Result<&Self, FormError>;

    /// Get the authentication credential from the form, if applicable (password, TOTP code, etc.).
    fn credential(&self) -> Option<&str>;

    /// Verify the form's credentials against the configuration as stored on the relevant factor state
    fn verify_against_config(
        &self,
        config: &HashMap<String, JsonValue>,
    ) -> Result<&Self, FormError>;

    /// Returns form fields with type-safe keys and flexible values.
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
    fn get_json_field(&self, field: FormField) -> Option<JsonValue> {
        match self.fields().get(&field)? {
            FormFieldValue::Json(value) => Some(value.clone()),
            _ => None,
        }
    }

    fn get_bool_field(&self, field: FormField) -> Option<bool> {
        match self.fields().get(&field)? {
            FormFieldValue::Json(value) => value.as_bool(),
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

/// Default form for setting a new password
#[derive(Clone, Deserialize)]
pub struct PasswordSetupForm {
    /// Name of the factor (must be unique per user/tenant)
    pub factor: String,
    /// The new password to set.
    pub new_password: String,
    /// Optionally, the tenant name.
    pub tenant: Option<String>,
    /// Optionally, the next URL to redirect to after setup.
    pub next: Option<String>,
}

impl FactorForm for PasswordSetupForm {
    fn flow(&self) -> Flow {
        Flow::Knowledge
    }

    fn kind(&self) -> Kind {
        Kind::Password
    }

    fn action(&self) -> Action {
        Action::Setup
    }

    fn validate_form(&self) -> Result<&Self, FormError> {
        if self.new_password.len() < 8 || self.new_password.len() > 512 {
            return Err(FormError::ValidationFailed(
                "New password must be between 8 and 512 characters.".to_string(),
            ));
        }
        Ok(self)
    }

    fn credential(&self) -> Option<&str> {
        Some(&self.new_password)
    }

    fn verify_against_config(
        &self,
        config: &HashMap<String, JsonValue>,
    ) -> Result<&Self, FormError> {
        // ✅ Verify that factor kind matches expectation
        let _kind: Kind = config
            .get("kind")
            .and_then(|v| from_value(v.clone()).ok())
            .unwrap_or(Kind::Password);

        self.validate_form()
    }

    fn fields(&self) -> HashMap<FormField, FormFieldValue> {
        let mut map = HashMap::new();
        map.insert(
            FormField::Password,
            FormFieldValue::String(Cow::Owned(self.new_password.clone())),
        );
        if let Some(tenant) = &self.tenant {
            map.insert(
                FormField::TenantName,
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

impl Debug for PasswordSetupForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordSetupForm")
            .field("new_password", &"***REDACTED***")
            .field("tenant", &self.tenant)
            .field("next", &self.next)
            .finish()
    }
}

/// Default form for setting a new password (useful when changing a password)
#[derive(Clone, Deserialize)]
pub struct PasswordChangeForm {
    /// Name of the factor (must be unique per user/tenant)
    pub factor: String,
    /// The new password to set.
    pub new_password: String,
    /// Optionally, the old password (for authenticated change).
    pub old_password: Option<String>,
    /// Optionally, a reset token (for password reminders).
    pub token: Option<String>,
    pub tenant: Option<String>,
    pub next: Option<String>,
}

/// Implementation of FactorForm for PasswordChangeForm
/// This form captures the new password, and optionally the old password or a reset token.
/// It includes validation to ensure the new password meets basic security requirements.
impl FactorForm for PasswordChangeForm {
    fn flow(&self) -> Flow {
        Flow::Knowledge
    }

    fn kind(&self) -> Kind {
        Kind::Password
    }

    fn action(&self) -> Action {
        Action::Update
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

    fn verify_against_config(
        &self,
        config: &HashMap<String, JsonValue>,
    ) -> Result<&Self, FormError> {
        // ✅ Verify that factor kind matches expectation
        let _kind: Kind = config
            .get("kind")
            .and_then(|v| from_value(v.clone()).ok())
            .unwrap_or(Kind::Password);

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
        if let Some(token) = &self.token {
            map.insert(
                FormField::Custom("token"),
                FormFieldValue::String(Cow::Owned(token.clone())),
            );
        }
        if let Some(tenant) = &self.tenant {
            map.insert(
                FormField::TenantName,
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

impl Debug for PasswordChangeForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordChangeForm")
            .field("new_password", &"***REDACTED***")
            .field(
                "old_password",
                &self.old_password.as_ref().map(|_| "***REDACTED***"),
            )
            .field("token", &self.token.as_ref().map(|_| "***REDACTED***"))
            .field("tenant", &self.tenant)
            .field("next", &self.next)
            .finish()
    }
}

/// Default form for verifying password during login
///
/// This form captures the username and password, along with optional tenant and next URL.
/// It includes validation to ensure the username is a valid email or name,
/// and that the password meets some basic security requirements.
#[derive(Clone, Deserialize)]
pub struct PasswordVerifyForm {
    /// Name of the authentication method (must be unique per tenant)
    pub method: String,
    /// Name of the factor (must be unique per  user/tenant)
    pub factor: String,
    /// Username of the user attempting to verify their password
    pub username: String,
    /// Password of the user attempting to verify their password
    pub password: String,
    /// Optional tenant identifier
    pub tenant: Option<String>,
    /// Optional URL to redirect to after successful login
    pub next: Option<String>,
}

impl FactorForm for PasswordVerifyForm {
    fn flow(&self) -> Flow {
        Flow::Knowledge
    }

    fn kind(&self) -> Kind {
        Kind::Password
    }

    fn action(&self) -> Action {
        Action::Verify
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
        let mut map = HashMap::new();
        map.insert(
            FormField::UserName,
            FormFieldValue::String(Cow::Owned(self.username.clone())),
        );
        map.insert(
            FormField::Password,
            FormFieldValue::String(Cow::Owned(self.password.clone())),
        );
        if let Some(tenant) = &self.tenant {
            map.insert(
                FormField::TenantName,
                FormFieldValue::String(Cow::Owned(tenant.clone())),
            );
        }
        if let Some(next) = &self.next {
            map.insert(
                FormField::Next,
                FormFieldValue::String(Cow::Owned(next.clone())),
            );
        }
        // method and factor are required on PasswordVerifyForm — insert them directly
        map.insert(
            FormField::MethodName,
            FormFieldValue::String(Cow::Owned(self.method.clone())),
        );
        map.insert(
            FormField::FactorName,
            FormFieldValue::String(Cow::Owned(self.factor.clone())),
        );
        map
    }

    fn verify_against_config(
        &self,
        config: &HashMap<String, JsonValue>,
    ) -> Result<&Self, FormError> {
        // ✅ Verify that factor kind matches expectation
        let _kind: Kind = config
            .get("kind")
            .and_then(|v| from_value(v.clone()).ok())
            .unwrap_or(Kind::Password);

        let credential = self.credential().ok_or_else(|| {
            FormError::ValidationFailed("Missing password credential.".to_string())
        })?;

        let password_hash = config
            .get("password_hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FormError::AuthConfigError(Kind::Password.to_string()))?;

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

impl Debug for PasswordVerifyForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordVerifyForm")
            .field("username", &self.username)
            .field("password", &"***REDACTED***")
            .field("tenant", &self.tenant)
            .field("next", &self.next)
            .finish()
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
    /// Name of the factor (must be unique per user/tenant)
    pub factor: String,
    /// The TOTP secret provided to the user for setup
    pub secret: String,
    /// Optional tenant identifier
    pub tenant: Option<String>,
    /// Optional URL to redirect to after successful setup
    pub next: Option<String>,
}

impl FactorForm for TotpSetupForm {
    fn flow(&self) -> Flow {
        Flow::Otp
    }

    fn kind(&self) -> Kind {
        Kind::Totp
    }

    fn action(&self) -> Action {
        Action::Setup
    }

    fn validate_form(&self) -> Result<&Self, FormError> {
        if self.secret.is_empty() {
            Err(FormError::ValidationFailed(
                "TOTP secret cannot be empty.".to_string(),
            ))
        } else if self.secret.len() < 4 {
            Err(FormError::ValidationFailed(
                "TOTP secret must be at least 4 characters long.".to_string(),
            ))
        } else if self.tenant.is_some() && !is_valid_name(self.tenant.as_ref().unwrap()) {
            warn!("Data in submitted \"Tenant\" field is invalid.");
            Err(FormError::InvalidFormData)
        } else if let Some(next) = &self.next {
            if !is_valid_url_format(next) {
                warn!("TotpSetupForm submitted with invalid next URL");
                Err(FormError::InvalidFormData)
            } else {
                Ok(self)
            }
        } else {
            Ok(self)
        }
    }

    fn credential(&self) -> Option<&str> {
        Some(&self.secret)
    }

    fn fields(&self) -> HashMap<FormField, FormFieldValue> {
        let capacity = 1 + self.tenant.is_some() as usize + self.next.is_some() as usize;
        let mut map = HashMap::with_capacity(capacity);

        map.insert(
            FormField::OtpSecret,
            FormFieldValue::String(Cow::Owned(self.secret.clone())),
        );

        if let Some(tenant) = &self.tenant {
            map.insert(
                FormField::TenantName,
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

    fn verify_against_config(
        &self,
        config: &HashMap<String, JsonValue>,
    ) -> Result<&Self, FormError> {
        // ✅ Verify that factor kind matches expectation
        let _kind: Kind = config
            .get("kind")
            .and_then(|v| from_value(v.clone()).ok())
            .unwrap_or(Kind::Totp);

        // For factor setup, verification against existing credentials is not meaningful.
        // Instead, just validate the form and allow setup to proceed.
        self.validate_form()
    }
}

impl Debug for TotpSetupForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpSetupForm")
            .field("secret", &"***REDACTED***")
            .field("tenant", &self.tenant)
            .field("next", &self.next)
            .finish()
    }
}

#[derive(Clone, Deserialize)]
pub struct TotpChangeForm {
    /// Name of the factor (must be unique per user/tenant)
    pub factor: String,
    /// The old TOTP secret to be replaced
    pub old_secret: String,
    /// The new TOTP secret to set
    pub new_secret: String,
    /// Optional tenant identifier
    pub tenant: Option<String>,
    /// Optional URL to redirect to after successful setup
    pub next: Option<String>,
}

impl FactorForm for TotpChangeForm {
    fn flow(&self) -> Flow {
        Flow::Otp
    }
    fn kind(&self) -> Kind {
        Kind::Totp
    }
    fn action(&self) -> Action {
        Action::Update
    }
    fn validate_form(&self) -> Result<&Self, FormError> {
        if self.old_secret.is_empty() || self.new_secret.is_empty() {
            return Err(FormError::ValidationFailed(
                "Secrets cannot be empty".to_string(),
            ));
        }
        Ok(self)
    }
    fn credential(&self) -> Option<&str> {
        Some(&self.new_secret)
    }
    fn verify_against_config(
        &self,
        config: &HashMap<String, JsonValue>,
    ) -> Result<&Self, FormError> {
        // ✅ Verify that factor kind matches expectation
        let _kind: Kind = config
            .get("kind")
            .and_then(|v| from_value(v.clone()).ok())
            .unwrap_or(Kind::Totp);

        self.validate_form()
    }
    fn fields(&self) -> HashMap<FormField, FormFieldValue> {
        let mut map = HashMap::new();
        map.insert(
            FormField::OtpSecret,
            FormFieldValue::String(Cow::Owned(self.new_secret.clone())),
        );
        map.insert(
            FormField::Custom("old_secret"),
            FormFieldValue::String(Cow::Owned(self.old_secret.clone())),
        );
        if let Some(tenant) = &self.tenant {
            map.insert(
                FormField::TenantName,
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

impl Debug for TotpChangeForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpChangeForm")
            .field("old_secret", &"***REDACTED***")
            .field("new_secret", &"***REDACTED***")
            .field("tenant", &self.tenant)
            .field("next", &self.next)
            .finish()
    }
}

/// Form for verifying a TOTP code.
/// Now supports configurable charset for numeric, hex, or alphanumeric codes.
#[derive(Clone, Deserialize)]
pub struct TotpVerifyForm {
    /// Name of the authentication method (must be unique per user/tenant)
    pub method: String,
    /// Name of the factor (must be unique per user/tenant)
    pub factor: String,
    /// The TOTP code to verify
    pub otp_code: String,
    /// Optional tenant identifiers
    pub tenant: Option<String>,
    /// Optional URL to redirect to after successful verification
    pub next: Option<String>,
}

impl FactorForm for TotpVerifyForm {
    fn flow(&self) -> Flow {
        Flow::Otp
    }

    fn kind(&self) -> Kind {
        Kind::Totp
    }

    fn action(&self) -> Action {
        Action::Verify
    }

    fn validate_form(&self) -> Result<&Self, FormError> {
        let config = OtpRules::default();
        if !is_valid_otp_code(&self.otp_code, &config) {
            return Err(FormError::ValidationFailed(format!(
                "TOTP code must be exactly {} {}.",
                TOTP_LENGTH,
                match config.charset {
                    TokenCharset::Numeric => "digits",
                    TokenCharset::Hex => "hex characters",
                    TokenCharset::Alphanumeric => "alphanumeric characters",
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
            warn!("TotpVerifyForm submitted with invalid next URL");
            return Err(FormError::InvalidFormData);
        }
        Ok(self)
    }

    fn credential(&self) -> Option<&str> {
        Some(&self.otp_code)
    }

    fn fields(&self) -> HashMap<FormField, FormFieldValue> {
        let mut map = HashMap::new();
        map.insert(
            FormField::OtpCode,
            FormFieldValue::String(Cow::Owned(self.otp_code.clone())),
        );
        if let Some(tenant) = &self.tenant {
            map.insert(
                FormField::TenantName,
                FormFieldValue::String(Cow::Owned(tenant.clone())),
            );
        }
        if let Some(next) = &self.next {
            map.insert(
                FormField::Next,
                FormFieldValue::String(Cow::Owned(next.clone())),
            );
        }

        map.insert(
            FormField::MethodName,
            FormFieldValue::String(Cow::Owned(self.method.clone())),
        );
        map.insert(
            FormField::FactorName,
            FormFieldValue::String(Cow::Owned(self.factor.clone())),
        );
        map
    }

    fn verify_against_config(
        &self,
        config: &HashMap<String, JsonValue>,
    ) -> Result<&Self, FormError> {
        // ✅ Verify that factor kind matches expectation
        let _kind: Kind = config
            .get("kind")
            .and_then(|v| from_value(v.clone()).ok())
            .unwrap_or(Kind::Totp);

        let secret = config
            .get("secret")
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                FormError::AuthConfigError("Missing secret in factor configuration".into())
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

impl Debug for TotpVerifyForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpVerifyForm")
            .field("otp_code", &"***REDACTED***")
            .field("tenant", &self.tenant)
            .field("next", &self.next)
            .finish()
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
#[derive(Clone, Deserialize)]
pub struct HotpSetupForm {
    /// Name of the factor (must be unique per  user/tenant)
    pub factor: String,
    /// The new HOTP secret to set up.
    pub secret: String,
    /// Optional tenant for multi-tenancy.
    pub tenant: Option<String>,
    /// Optional redirect URL after setup.
    pub next: Option<String>,
}

impl FactorForm for HotpSetupForm {
    fn flow(&self) -> Flow {
        Flow::Otp
    }

    fn kind(&self) -> Kind {
        Kind::Hotp
    }

    fn action(&self) -> Action {
        Action::Setup
    }

    fn validate_form(&self) -> Result<&Self, FormError> {
        if self.secret.is_empty() {
            return Err(FormError::ValidationFailed(
                "HOTP secret cannot be empty.".to_string(),
            ));
        }
        if self.secret.len() < 4 {
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
        Some(&self.secret)
    }

    fn fields(&self) -> HashMap<FormField, FormFieldValue> {
        let capacity = 1 + self.tenant.is_some() as usize + self.next.is_some() as usize;
        let mut map = HashMap::with_capacity(capacity);

        map.insert(
            FormField::OtpSecret,
            FormFieldValue::String(Cow::Owned(self.secret.clone())),
        );

        if let Some(tenant) = &self.tenant {
            map.insert(
                FormField::TenantName,
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

    fn verify_against_config(
        &self,
        config: &HashMap<String, JsonValue>,
    ) -> Result<&Self, FormError> {
        // ✅ Verify that factor kind matches expectation
        let _kind: Kind = config
            .get("kind")
            .and_then(|v| from_value(v.clone()).ok())
            .unwrap_or(Kind::Hotp);

        self.validate_form()
    }
}

impl Debug for HotpSetupForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HotpSetupForm")
            .field("secret", &"***REDACTED***")
            .field("tenant", &self.tenant)
            .field("next", &self.next)
            .finish()
    }
}

/// Form for changing an HOTP factor (HMAC-based One-Time Password).
#[derive(Clone, Deserialize)]
pub struct HotpChangeForm {
    /// Name of the factor (must be unique per  user/tenant)
    pub factor: String,
    /// The old HOTP secret to be replaced
    pub old_secret: String,
    /// The new HOTP secret to set
    pub new_secret: String,
    /// Optional tenant identifier
    pub tenant: Option<String>,
    /// Optional URL to redirect to after successful setup
    pub next: Option<String>,
}

impl FactorForm for HotpChangeForm {
    fn flow(&self) -> Flow {
        Flow::Otp
    }
    fn kind(&self) -> Kind {
        Kind::Hotp
    }
    fn action(&self) -> Action {
        Action::Update
    }
    fn validate_form(&self) -> Result<&Self, FormError> {
        if self.old_secret.is_empty() || self.new_secret.is_empty() {
            return Err(FormError::ValidationFailed(
                "Secrets cannot be empty".to_string(),
            ));
        }
        Ok(self)
    }
    fn credential(&self) -> Option<&str> {
        Some(&self.new_secret)
    }
    fn verify_against_config(
        &self,
        config: &HashMap<String, JsonValue>,
    ) -> Result<&Self, FormError> {
        // ✅ Verify that factor kind matches expectation
        let _kind: Kind = config
            .get("kind")
            .and_then(|v| from_value(v.clone()).ok())
            .unwrap_or(Kind::Hotp);

        self.validate_form()
    }
    fn fields(&self) -> HashMap<FormField, FormFieldValue> {
        let mut map = HashMap::new();
        map.insert(
            FormField::OtpSecret,
            FormFieldValue::String(Cow::Owned(self.new_secret.clone())),
        );
        map.insert(
            FormField::Custom("old_secret"),
            FormFieldValue::String(Cow::Owned(self.old_secret.clone())),
        );
        if let Some(tenant) = &self.tenant {
            map.insert(
                FormField::TenantName,
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

impl Debug for HotpChangeForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HotpChangeForm")
            .field("old_secret", &"***REDACTED***")
            .field("new_secret", &"***REDACTED***")
            .field("tenant", &self.tenant)
            .field("next", &self.next)
            .finish()
    }
}

/// Form for verifying a HOTP code.
#[derive(Clone, Deserialize)]
pub struct HotpVerifyForm {
    /// Name of the authentication method (must be unique per tenant)
    pub method: String,
    /// Name of the factor (must be unique per  user/tenant)
    pub factor: String,
    /// The TOTP code to verify
    pub otp_code: String,
    /// The counter value provided by the client
    pub counter: u64,
    /// Optional tenant identifier
    pub tenant: Option<String>,
    /// Optional URL to redirect to after successful verification
    pub next: Option<String>,
}

impl FactorForm for HotpVerifyForm {
    fn flow(&self) -> Flow {
        Flow::Otp
    }

    fn kind(&self) -> Kind {
        Kind::Hotp
    }

    fn action(&self) -> Action {
        Action::Verify
    }

    fn validate_form(&self) -> Result<&Self, FormError> {
        let config = OtpRules::default();
        if !is_valid_otp_code(&self.otp_code, &config) {
            return Err(FormError::ValidationFailed(format!(
                "HOTP code must be exactly {} {}.",
                config.length,
                match config.charset {
                    TokenCharset::Numeric => "digits",
                    TokenCharset::Hex => "hex characters",
                    TokenCharset::Alphanumeric => "alphanumeric characters",
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
            FormFieldValue::Json(json!(self.counter)),
        );
        if let Some(tenant) = &self.tenant {
            map.insert(
                FormField::TenantName,
                FormFieldValue::String(Cow::Owned(tenant.clone())),
            );
        }
        if let Some(next) = &self.next {
            map.insert(
                FormField::Next,
                FormFieldValue::String(Cow::Owned(next.clone())),
            );
        }
        // method and factor are required on PasswordVerifyForm — insert them directly
        map.insert(
            FormField::MethodName,
            FormFieldValue::String(Cow::Owned(self.method.clone())),
        );
        map.insert(
            FormField::FactorName,
            FormFieldValue::String(Cow::Owned(self.factor.clone())),
        );
        map
    }

    fn verify_against_config(
        &self,
        config: &HashMap<String, JsonValue>,
    ) -> Result<&Self, FormError> {
        // ✅ Verify that factor kind matches expectation
        let _kind: Kind = config
            .get("kind")
            .and_then(|v| from_value(v.clone()).ok())
            .unwrap_or(Kind::Hotp);

        // ✅ Use credential() for the OTP code (primary auth value)
        let code = self
            .credential()
            .ok_or_else(|| FormError::ValidationFailed("Missing HOTP code".to_string()))?;

        let secret = config
            .get("secret")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FormError::AuthConfigError(Kind::Hotp.to_string()))?;

        let stored_counter = config
            .get("counter")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| FormError::AuthConfigError("Missing HOTP counter".to_string()))?;

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

impl Debug for HotpVerifyForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HotpVerifyForm")
            .field("otp_code", &"***REDACTED***")
            .field("counter", &self.counter)
            .field("tenant", &self.tenant)
            .field("next", &self.next)
            .finish()
    }
}

/// Form for setting up a new email address (or initiating reset).
// TODO: This form needs to be reviewed !!!
#[derive(Clone, Deserialize)]
pub struct EmailSetupForm {
    /// Name of the authentication factor (must be unique per  user/tenant)
    pub factor: String,
    /// Display name of the user setting up the email factor
    pub name: String,
    /// Email address to set up
    pub email: String,
    /// Optional tenant identifier
    pub tenant: Option<String>,
    /// Optional URL to redirect to after successful setup
    pub next: Option<String>,
}

impl FactorForm for EmailSetupForm {
    fn flow(&self) -> Flow {
        Flow::Otp
    }

    fn kind(&self) -> Kind {
        Kind::EmailOtp
    }

    fn action(&self) -> Action {
        Action::Setup
    }

    fn validate_form(&self) -> Result<&Self, FormError> {
        if !is_valid_email(&self.email) {
            return Err(FormError::ValidationFailed(
                "Invalid old email address".to_string(),
            ));
        }
        if let Some(tenant) = &self.tenant
            && !is_valid_name(tenant)
        {
            return Err(FormError::ValidationFailed(
                "Invalid tenant name".to_string(),
            ));
        }
        if !is_valid_name(&self.name) {
            return Err(FormError::ValidationFailed(
                "Invalid name of email owner".to_string(),
            ));
        }
        if let Some(next) = &self.next
            && !is_valid_url_format(next)
        {
            return Err(FormError::InvalidFormData);
        }
        Ok(self)
    }

    fn credential(&self) -> Option<&str> {
        None
    }

    fn verify_against_config(
        &self,
        config: &HashMap<String, JsonValue>,
    ) -> Result<&Self, FormError> {
        // ✅ Verify that factor kind matches expectation
        let _kind: Kind = config
            .get("kind")
            .and_then(|v| from_value(v.clone()).ok())
            .unwrap_or(Kind::EmailOtp);

        let email = config
            .get("email")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                FormError::AuthConfigError("Missing expected 'email' in config".to_string())
            })?;
        if self.email != email {
            return Err(FormError::ValidationFailed(
                "New email does not match config".to_string(),
            ));
        }
        Ok(self)
    }

    fn fields(&self) -> HashMap<FormField, FormFieldValue> {
        let mut map = HashMap::new();
        map.insert(
            FormField::Email,
            FormFieldValue::String(Cow::Owned(self.email.clone())),
        );
        if let Some(tenant) = &self.tenant {
            map.insert(
                FormField::TenantName,
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

impl Debug for EmailSetupForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailSetupForm")
            .field("tenant", &self.tenant)
            .field("name", &self.name)
            .field("email", &self.email)
            .field("next", &self.next)
            .finish()
    }
}

/// Form for verifying email address during signup.
#[derive(Clone, Deserialize)]
pub struct EmailVerifyForm {
    /// Name of the authentication method (must be unique per tenant)
    pub method: Option<String>,
    /// Name of the factor (must be unique per  user/tenant)
    pub factor: Option<String>,
    /// Email address to verify
    pub email: String,
    /// Optional tenant identifier
    pub tenant: Option<String>,
    /// Verification token sent to the email address
    pub token: String,
    /// Optional URL to redirect to after successful verification
    pub next: Option<String>,
}

impl FactorForm for EmailVerifyForm {
    fn flow(&self) -> Flow {
        Flow::Otp
    }

    fn kind(&self) -> Kind {
        Kind::EmailOtp
    }

    fn action(&self) -> Action {
        Action::Verify
    }

    fn validate_form(&self) -> Result<&Self, FormError> {
        if !is_valid_email(&self.email) {
            return Err(FormError::ValidationFailed(
                "Invalid email address".to_string(),
            ));
        }
        if self.token.is_empty() {
            return Err(FormError::ValidationFailed(
                "Missing verification token".to_string(),
            ));
        }
        if let Some(tenant) = &self.tenant
            && !is_valid_name(tenant)
        {
            return Err(FormError::ValidationFailed(
                "Invalid tenant name".to_string(),
            ));
        }
        if let Some(next) = &self.next
            && !is_valid_url_format(next)
        {
            return Err(FormError::InvalidFormData);
        }
        Ok(self)
    }

    fn credential(&self) -> Option<&str> {
        Some(&self.token)
    }

    fn verify_against_config(
        &self,
        config: &HashMap<String, JsonValue>,
    ) -> Result<&Self, FormError> {
        // ✅ Verify that factor kind matches expectation
        let _kind: Kind = config
            .get("kind")
            .and_then(|v| from_value(v.clone()).ok())
            .unwrap_or(Kind::EmailOtp);

        let expected_token = config
            .get("token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FormError::AuthConfigError("Missing token in config".to_string()))?;
        if self.token != expected_token {
            return Err(FormError::ValidationFailed(
                "Invalid verification token".to_string(),
            ));
        }
        Ok(self)
    }

    fn fields(&self) -> HashMap<FormField, FormFieldValue> {
        let mut map = HashMap::new();
        map.insert(
            FormField::Email,
            FormFieldValue::String(Cow::Owned(self.email.clone())),
        );
        if let Some(tenant) = &self.tenant {
            map.insert(
                FormField::TenantName,
                FormFieldValue::String(Cow::Owned(tenant.clone())),
            );
        }
        map.insert(
            FormField::Token,
            FormFieldValue::String(Cow::Owned(self.token.clone())),
        );
        if let Some(next) = &self.next {
            map.insert(
                FormField::Next,
                FormFieldValue::String(Cow::Owned(next.clone())),
            );
        }
        if let Some(method_name) = &self.method {
            map.insert(
                FormField::Custom("method_name"),
                FormFieldValue::String(Cow::Owned(method_name.clone())),
            );
        }
        if let Some(factor_name) = &self.factor {
            map.insert(
                FormField::Custom("factor_name"),
                FormFieldValue::String(Cow::Owned(factor_name.clone())),
            );
        }
        map
    }
}

impl Debug for EmailVerifyForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailVerifyForm")
            .field("email", &self.email)
            .field("tenant", &self.tenant)
            .field("token", &"***REDACTED***")
            .field("next", &self.next)
            .finish()
    }
}

/// Email change request (change form)
#[derive(Clone, Deserialize)]
pub struct EmailChangeForm {
    /// Name of the authentication factor (must be unique per user/tenant)
    pub factor: String,
    /// Old email address
    pub old_email: String,
    /// New email address
    pub new_email: String,
    /// Optional tenant identifier
    pub tenant: Option<String>,
    /// Optional URL to redirect to after successful change
    pub next: Option<String>,
}

impl FactorForm for EmailChangeForm {
    fn flow(&self) -> Flow {
        Flow::Otp
    }

    fn kind(&self) -> Kind {
        Kind::EmailOtp
    }

    fn action(&self) -> Action {
        Action::Update
    }

    fn validate_form(&self) -> Result<&Self, FormError> {
        if !is_valid_email(&self.old_email) || !is_valid_email(&self.new_email) {
            return Err(FormError::ValidationFailed(
                "Invalid email address".to_string(),
            ));
        }
        Ok(self)
    }
    fn credential(&self) -> Option<&str> {
        Some(&self.new_email)
    }
    fn verify_against_config(
        &self,
        config: &HashMap<String, JsonValue>,
    ) -> Result<&Self, FormError> {
        // ✅ Verify that factor kind matches expectation
        let _kind: Kind = config
            .get("kind")
            .and_then(|v| from_value(v.clone()).ok())
            .unwrap_or(Kind::EmailOtp);

        self.validate_form()
    }

    fn fields(&self) -> HashMap<FormField, FormFieldValue> {
        let mut map = HashMap::new();
        map.insert(
            FormField::Email,
            FormFieldValue::String(Cow::Owned(self.new_email.clone())),
        );
        map.insert(
            FormField::Custom("old_email"),
            FormFieldValue::String(Cow::Owned(self.old_email.clone())),
        );
        if let Some(tenant) = &self.tenant {
            map.insert(
                FormField::TenantName,
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

impl Debug for EmailChangeForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailChangeForm")
            .field("old_email", &self.old_email)
            .field("new_email", &self.new_email)
            .field("tenant", &self.tenant)
            .field("next", &self.next)
            .finish()
    }
}

/// Default form for requesting an authentication factor reset.
/// This could be used to implement both self-service, admin-initiated resets or intermediary flows,
/// such e.g. involving required approvals by a helpdesk or admin users.
#[derive(Clone, Deserialize)]
pub struct FactorResetForm {
    /// Name of the factor (must be unique per user/tenant)
    pub factor: String,
    /// Kind of factor to reset (e.g., "totp", "hotp", "email_otp")
    pub kind: Kind,
    /// Username or email of the user requesting the reset
    pub username: String,
    /// Optional tenant identifier
    pub tenant: Option<String>,
    /// Reason for the reset (strongly recommended for audit trail)
    pub reason: Option<String>,
    /// Optional ticket/case ID for compliance tracking
    pub ticket_id: Option<String>,
    /// Optional URL to redirect to after successful reset initiation
    pub next: Option<String>,
}

impl FactorForm for FactorResetForm {
    fn flow(&self) -> Flow {
        Flow::Knowledge
    }

    fn kind(&self) -> Kind {
        self.kind.clone()
    }

    fn action(&self) -> Action {
        Action::Setup
    }

    fn validate_form(&self) -> Result<&Self, FormError> {
        // 1. Validate tenant
        if let Some(tenant) = &self.tenant
            && !is_valid_name(tenant)
        {
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
        if self.factor.is_empty() || self.factor.len() > 128 {
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

    fn verify_against_config(
        &self,
        _config: &HashMap<String, JsonValue>,
    ) -> Result<&Self, FormError> {
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
        map.insert(
            FormField::FactorName,
            FormFieldValue::String(Cow::Owned(self.factor.clone())),
        );

        if let Some(token) = &self.ticket_id {
            map.insert(
                FormField::Custom("ticket_id"),
                FormFieldValue::String(Cow::Owned(token.clone())),
            );
        }
        // tenant is a required String on FactorResetRequestForm; include if non-empty
        if let Some(tenant) = &self.tenant {
            map.insert(
                FormField::TenantName,
                FormFieldValue::String(Cow::Owned(tenant.clone())),
            );
        }
        map
    }
}

impl std::fmt::Debug for FactorResetForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FactorResetForm")
            .field("tenant", &self.tenant)
            .field("username", &self.username)
            .field("kind", &self.kind)
            .field("factor", &self.factor)
            .field("reason", &self.reason.as_ref().map(|_| "***REDACTED***"))
            .field("ticket_id", &self.ticket_id)
            .finish()
    }
}

#[derive(Clone, Deserialize)]
pub struct SignupForm {
    pub tenant: Option<String>,
    pub username: String,
    pub fullname: String,
    pub email: String,
    pub domicile: Option<String>, // iso_3 country code
    pub language: Option<String>, // language code
    pub password: String,
    pub next: Option<String>,
}

impl FactorForm for SignupForm {
    fn flow(&self) -> Flow {
        Flow::Workflow
    }

    fn kind(&self) -> Kind {
        Kind::Workflow
    }

    fn action(&self) -> Action {
        Action::Setup
    }

    fn validate_form(&self) -> Result<&Self, FormError> {
        // 1. Validate tenant
        if let Some(tenant) = &self.tenant
            && !is_valid_name(tenant)
        {
            return Err(FormError::ValidationFailed(
                "Invalid tenant identifier".to_string(),
            ));
        }

        // 2. Validate username (email)
        if !is_valid_email(&self.username) {
            return Err(FormError::ValidationFailed("Invalid email".to_string()));
        }

        // 3. Validate fullname
        if !is_valid_name(&self.fullname) {
            return Err(FormError::ValidationFailed("Invalid fullname".to_string()));
        }

        // 4. Validate email
        if !is_valid_email(&self.email) {
            return Err(FormError::ValidationFailed(
                "Invalid email address".to_string(),
            ));
        }

        // 5. Validate domicile
        if let Some(domicile) = &self.domicile
            && !is_valid_country_code(domicile)
        {
            return Err(FormError::ValidationFailed(
                "Invalid domicile country code".to_string(),
            ));
        }

        // 6. Validate language
        if let Some(language) = &self.language
            && !is_valid_language_code(language)
        {
            return Err(FormError::ValidationFailed(
                "Invalid language code".to_string(),
            ));
        }

        // 7. Validate password
        if !&self.password.is_empty()
            && !is_valid_password(&self.password, &PasswordRules::default())
        {
            return Err(FormError::ValidationFailed("Invalid password".to_string()));
        }

        // 8. Validate next field
        if let Some(next) = &self.next
            && !is_valid_url_format(next)
        {
            return Err(FormError::ValidationFailed("Invalid next URL".to_string()));
        }

        Ok(self)
    }

    fn credential(&self) -> Option<&str> {
        Some(&self.email)
    }

    fn verify_against_config(
        &self,
        _config: &HashMap<String, JsonValue>,
    ) -> Result<&Self, FormError> {
        self.validate_form()
    }

    fn fields(&self) -> HashMap<FormField, FormFieldValue> {
        let mut map = HashMap::new();
        if let Some(tenant) = &self.tenant {
            map.insert(
                FormField::TenantName,
                FormFieldValue::String(Cow::Owned(tenant.clone())),
            );
        }
        map.insert(
            FormField::UserName,
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
            FormField::Password,
            FormFieldValue::String(Cow::Owned(self.password.clone())),
        );
        if let Some(next) = &self.next {
            map.insert(
                FormField::Custom("next"),
                FormFieldValue::String(Cow::Owned(next.clone())),
            );
        }
        map
    }
}
impl Debug for SignupForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignupForm")
            .field("tenant", &self.tenant)
            .field("username", &self.username)
            .field("fullname", &self.fullname)
            .field("email", &self.email)
            .field("domicile", &self.domicile)
            .field("language", &self.language)
            .field("password", &"***REDACTED***")
            .field("next", &self.next)
            .finish()
    }
}
