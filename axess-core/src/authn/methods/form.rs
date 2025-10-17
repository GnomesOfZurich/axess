use crate::{
    authn::{errors::FormError, methods::factor::AuthFactorKind},
    tracing::error,
};
use password_auth;
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, collections::HashMap, fmt::Debug};

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
    TotpCode,
    TotpSecret,
    OauthProvider,
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
            FormField::TotpCode => "code",
            FormField::TotpSecret => "secret",
            FormField::OauthProvider => "provider",
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
        if self.username.is_empty()
            || self.username.len() > 64
            || self.password.len() < 8
            || self.password.len() > 512
        {
            Err(FormError::ValidationFailed(
                "Username must be between 1 and 64 characters, password must be between 8 and 512 characters.".to_string(),
            ))
        } else {
            Ok(self)
        }
    }

    fn credential(&self) -> Option<&str> {
        if self.password.is_empty() {
            None
        } else {
            Some(&self.password)
        }
    }

    // ✅ Updated to use FormField enum and FormFieldValue
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
        // Expect the stored password hash under "password_hash"
        let credential = self.credential().ok_or_else(|| {
            FormError::ValidationFailed("Missing password credential.".to_string())
        })?;

        let password_hash = config
            .get("password_hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FormError::AuthConfigError(AuthFactorKind::Password.to_string()))?;

        match password_auth::verify_password(credential, password_hash) {
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

/// Form for setting up a TOTP factor.
/// This is used when the user is registering a new TOTP factor.
/// It includes the TOTP secret and an optional redirect URL after setup.
/// The secret is typically generated by the server and displayed to the user.
/// The user will then use this secret to configure their TOTP app.
#[derive(Debug, Clone, Deserialize)]
pub struct TotpSetupForm {
    pub secret: String,
    pub tenant: Option<String>,
    pub next: Option<String>,
}

impl FactorForm for TotpSetupForm {
    fn factor_kind(&self) -> AuthFactorKind {
        AuthFactorKind::Totp
    }

    fn form_kind(&self) -> FactorFormKind {
        FactorFormKind::Setup
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
            FormField::TotpSecret,
            FormFieldValue::String(Cow::Owned(self.secret.clone())),
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
/// This is used when the user is entering a TOTP code to complete authentication.
/// It includes the TOTP code and an optional redirect URL after verification.
/// The code is typically generated by the user's TOTP app and must match the expected value.
#[derive(Debug, Clone, Deserialize)]
pub struct TotpVerifyForm {
    pub code: String,
    pub tenant: Option<String>,
    pub next: Option<String>,
}

impl FactorForm for TotpVerifyForm {
    fn factor_kind(&self) -> AuthFactorKind {
        AuthFactorKind::Totp
    }

    fn form_kind(&self) -> FactorFormKind {
        FactorFormKind::Verify
    }

    fn validate_form(&self) -> Result<&Self, FormError> {
        if self.code.len() != 6 {
            Err(FormError::ValidationFailed(
                "TOTP code must be exactly 6 characters.".to_string(),
            ))
        } else {
            Ok(self)
        }
    }

    fn credential(&self) -> Option<&str> {
        Some(&self.code)
    }

    fn fields(&self) -> HashMap<FormField, FormFieldValue> {
        let capacity = 1 + self.tenant.is_some() as usize + self.next.is_some() as usize;
        let mut map = HashMap::with_capacity(capacity);

        map.insert(
            FormField::TotpCode,
            FormFieldValue::String(Cow::Owned(self.code.clone())),
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
            FormError::ValidationFailed("Missing TOTP code credential.".to_string())
        })?;

        if let Some(stored_code) = config.get("code").and_then(|v| v.as_str()) {
            if stored_code == credential {
                Ok(self)
            } else {
                error!("Failed to verify TOTP code versus stored auth config.");
                Err(FormError::ValidationFailed(
                    "Invalid TOTP code.".to_string(),
                ))
            }
        } else {
            Err(FormError::AuthConfigError(AuthFactorKind::Totp.to_string()))
        }
    }
}

/// Form for verifying an OAuth factor.
/// This is used when the user is authenticating via an OAuth provider.
/// It includes the OAuth provider name and an optional redirect URL after verification.
/// The provider is here represented as a string identifier for the OAuth service (e.g., "github", "google", etc.).
/// The actual OAuth flow would typically involve redirecting the user to the provider's login page.
#[derive(Debug, Clone, Deserialize)]
pub struct OauthForm {
    pub provider: String,
    pub tenant: Option<String>,
    pub next: Option<String>,
}

impl FactorForm for OauthForm {
    fn factor_kind(&self) -> AuthFactorKind {
        AuthFactorKind::Oauth
    }

    fn form_kind(&self) -> FactorFormKind {
        FactorFormKind::Verify
    }

    fn validate_form(&self) -> Result<&Self, FormError> {
        if self.provider.is_empty() {
            Err(FormError::ValidationFailed(
                "OAuth provider cannot be empty.".to_string(),
            ))
        } else if self.provider.len() > 64 {
            Err(FormError::ValidationFailed(
                "OAuth provider name must be between 1 and 64 characters.".to_string(),
            ))
        } else {
            Ok(self)
        }
    }

    fn credential(&self) -> Option<&str> {
        Some(&self.provider)
    }

    fn fields(&self) -> HashMap<FormField, FormFieldValue> {
        let capacity = 1 + self.tenant.is_some() as usize + self.next.is_some() as usize;
        let mut map = HashMap::with_capacity(capacity);

        map.insert(
            FormField::OauthProvider,
            FormFieldValue::String(Cow::Owned(self.provider.clone())),
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
        if let Some(stored_provider) = config.get("provider").and_then(|v| v.as_str()) {
            if stored_provider == self.provider {
                Ok(self)
            } else {
                error!("Failed to verify OAuth provider versus stored auth config.");
                Err(FormError::ValidationFailed(
                    "Invalid OAuth provider.".to_string(),
                ))
            }
        } else {
            Err(FormError::AuthConfigError(
                AuthFactorKind::Oauth.to_string(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use password_auth::generate_hash;

    // ========================================================================
    // FormField Tests
    // ========================================================================

    #[test]
    fn test_form_field_as_str() {
        assert_eq!(FormField::Username.as_str(), "username");
        assert_eq!(FormField::Password.as_str(), "password");
        assert_eq!(FormField::Tenant.as_str(), "tenant");
        assert_eq!(FormField::Next.as_str(), "next");
        assert_eq!(FormField::TotpCode.as_str(), "code");
        assert_eq!(FormField::TotpSecret.as_str(), "secret");
        assert_eq!(FormField::OauthProvider.as_str(), "provider");
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
            username: "SomeValidUser".to_string(),
            password: "verysecurepassword".to_string(),
            tenant: None,
            next: None,
        };
        assert!(valid.validate_form().is_ok());

        let empty_username = PasswordForm {
            username: "".to_string(),
            password: "verysecurepassword".to_string(),
            tenant: None,
            next: None,
        };
        assert!(empty_username.validate_form().is_err());

        let short_password = PasswordForm {
            username: "user".to_string(),
            password: "short".to_string(),
            tenant: None,
            next: None,
        };
        assert!(short_password.validate_form().is_err());

        let long_password = PasswordForm {
            username: "user".to_string(),
            password: "a".repeat(513),
            tenant: None,
            next: None,
        };
        assert!(long_password.validate_form().is_err());
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

        match fields.get(&FormField::Username).unwrap() {
            FormFieldValue::String(s) => assert_eq!(s.as_ref(), "testuser"),
            _ => panic!("Expected String"),
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
        let hash = generate_hash(password);

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
        let hash = generate_hash(correct_password);

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
            secret: "abcd".to_string(),
            tenant: None,
            next: None,
        };
        assert!(valid.validate_form().is_ok());

        let empty_secret = TotpSetupForm {
            secret: "".to_string(),
            tenant: None,
            next: None,
        };
        assert!(empty_secret.validate_form().is_err());

        let short_secret = TotpSetupForm {
            secret: "abc".to_string(),
            tenant: None,
            next: None,
        };
        assert!(short_secret.validate_form().is_err());
    }

    #[test]
    fn test_totp_setup_form_kinds() {
        let form = TotpSetupForm {
            secret: "secret123".to_string(),
            tenant: None,
            next: None,
        };

        assert_eq!(form.factor_kind(), AuthFactorKind::Totp);
        assert_eq!(form.form_kind(), FactorFormKind::Setup);
    }

    // ========================================================================
    // TotpVerifyForm Tests
    // ========================================================================

    #[test]
    fn test_totp_verify_form_validation() {
        let valid = TotpVerifyForm {
            code: "123456".to_string(),
            tenant: None,
            next: None,
        };
        assert!(valid.validate_form().is_ok());

        let short_code = TotpVerifyForm {
            code: "12345".to_string(),
            tenant: None,
            next: None,
        };
        assert!(short_code.validate_form().is_err());

        let long_code = TotpVerifyForm {
            code: "1234567".to_string(),
            tenant: None,
            next: None,
        };
        assert!(long_code.validate_form().is_err());
    }

    #[test]
    fn test_totp_verify_against_config_success() {
        let form = TotpVerifyForm {
            code: "123456".to_string(),
            tenant: None,
            next: None,
        };

        let config = serde_json::json!({"code": "123456"});
        assert!(form.verify_against_config(&config).is_ok());
    }

    // ========================================================================
    // OAuthForm Tests
    // ========================================================================

    #[test]
    fn test_oauth_form_validation() {
        let valid = OauthForm {
            provider: "github".to_string(),
            tenant: None,
            next: None,
        };
        assert!(valid.validate_form().is_ok());

        let empty_provider = OauthForm {
            provider: "".to_string(),
            tenant: None,
            next: None,
        };
        assert!(empty_provider.validate_form().is_err());

        let long_provider = OauthForm {
            provider: "a".repeat(65),
            tenant: None,
            next: None,
        };
        assert!(long_provider.validate_form().is_err());
    }

    #[test]
    fn test_oauth_verify_against_config_success() {
        let form = OauthForm {
            provider: "github".to_string(),
            tenant: None,
            next: None,
        };

        let config = serde_json::json!({"provider": "github"});
        assert!(form.verify_against_config(&config).is_ok());
    }

    // ========================================================================
    // FactorFormExt Tests
    // ========================================================================

    #[test]
    fn test_get_string_field() {
        let form = PasswordForm {
            username: "alice".to_string(),
            password: "secret123".to_string(),
            tenant: None,
            next: None,
        };

        assert_eq!(
            form.get_string_field(FormField::Username),
            Some("alice".to_string())
        );
        assert_eq!(form.get_string_field(FormField::Tenant), None);
    }

    #[test]
    fn test_require_string_field_success() {
        let form = PasswordForm {
            username: "bob".to_string(),
            password: "password123".to_string(),
            tenant: Some("default".to_string()),
            next: None,
        };

        assert!(form.require_string_field(FormField::Username).is_ok());
        assert_eq!(
            form.require_string_field(FormField::Tenant).unwrap(),
            "default"
        );
    }

    #[test]
    fn test_require_string_field_missing() {
        let form = PasswordForm {
            username: "charlie".to_string(),
            password: "password123".to_string(),
            tenant: None,
            next: None,
        };

        let result = form.require_string_field(FormField::Tenant);
        assert!(result.is_err());

        match result.unwrap_err() {
            FormError::MissingField(field) => assert_eq!(field, "tenant"),
            _ => panic!("Expected MissingField error"),
        }
    }
}
