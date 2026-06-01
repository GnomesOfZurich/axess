//! Factor kinds, typed configurations, and credentials.
//!
//! Each factor kind has its own submodule with config types. This module
//! re-exports everything for a flat import surface:
//! `use crate::authn::factor::{FactorKind, PasswordConfig, TotpConfig, ...}`
//!
//! # Factor kind summary
//!
//! | `FactorKind` | `FactorConfig` variant | Stateful? | `FactorCredential` type | Notes |
//! |---|---|---|---|---|
//! | `Password` | `FactorConfig::Password(PasswordConfig)` | Yes (stored hash) | `FactorCredential::Password(ZeroizedString)` | Argon2id; constant-time comparison |
//! | `Totp` | `FactorConfig::Totp(TotpConfig)` | Yes (shared secret) | `FactorCredential::OtpCode(Arc<str>)` | RFC 6238; secret is zeroized on drop |
//! | `Hotp` | `FactorConfig::Hotp(HotpConfig)` | Yes (shared secret + counter) | `FactorCredential::OtpCode(Arc<str>)` | RFC 4226; counter increments on success |
//! | `EmailOtp` | `FactorConfig::EmailOtp(EmailOtpConfig)` | No (code is transient) | `FactorCredential::OtpCode(Arc<str>)` | Server-generated code sent out-of-band |
//! | `Fido2` | `FactorConfig::Fido2(Fido2Config)` | Yes (credential public key) | `FactorCredential::Fido2Assertion(Value)` | WebAuthn; requires `fido2` feature |
//! | `LdapBind` | `FactorConfig::LdapBind(LdapBindFactorConfig)` | No (directory-side) | `FactorCredential::Password(ZeroizedString)` | Bind DN from config or provider template |
//! | `Federated(_)` | N/A (OAuth flow) | No (IdP-side) | N/A (token exchange) | OAuth2/OIDC; handled by `OAuthService` |

mod template;

// ── Re-exports (flat surface) ────────────────────────────────────────────────
//
// The factor *configs* (PasswordConfig / PasswordRules / TotpConfig /
// HotpConfig / EmailOtpConfig / OtpAlgorithm / ZeroizedString) live in
// `axess-factors`; colocated with the verifiers
// they pair 1:1 with. The flat `crate::authn::factor::{...}` import
// surface is preserved via these re-exports so adopters and internal
// call sites stay source-compatible. `Fido2Config` / `FactorTemplate` /
// `default_catalog` still live in axess-core.

pub use axess_factors::Fido2Config;
pub use axess_factors::{
    EmailOtpConfig, HotpConfig, OtpAlgorithm, PasswordConfig, PasswordRules, TotpConfig,
    ZeroizedString,
};
pub use template::{FactorTemplate, default_catalog};

#[cfg(feature = "fido2")]
pub use axess_factors::{
    AuthenticationResult, AuthenticatorAttachment, CredentialID, Fido2Credential, Fido2Options,
};

use serde::{Deserialize, Serialize};
use std::{fmt, sync::Arc};

// ── FactorKind ───────────────────────────────────────────────────────────────

/// The kind of authentication factor.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub enum FactorKind {
    /// Argon2id-hashed password verified locally.
    Password,
    /// Time-based one-time password (RFC 6238).
    Totp,
    /// HMAC-based one-time password with a counter (RFC 4226).
    Hotp,
    /// One-time code delivered out-of-band over email.
    EmailOtp,
    /// FIDO2/WebAuthn passkey assertion.
    Fido2,
    /// LDAP simple bind: password verified against an LDAP directory.
    LdapBind,
    /// OAuth 2.0 / OIDC federated login through an external identity provider.
    Federated(FederatedProvider),
}

impl FactorKind {
    /// Stable lower-case string tag used in audit logs and metrics.
    pub fn as_str(&self) -> &str {
        match self {
            FactorKind::Password => "password",
            FactorKind::Totp => "totp",
            FactorKind::Hotp => "hotp",
            FactorKind::EmailOtp => "email_otp",
            FactorKind::Fido2 => "fido2",
            FactorKind::LdapBind => "ldap_bind",
            FactorKind::Federated(p) => p.as_str(),
        }
    }
}

impl fmt::Display for FactorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ── FactorStep ──────────────────────────────────────────────────────────────

/// A step in an authentication method: either a required factor or a choice.
///
/// # Examples
///
/// Sequential MFA (password then TOTP):
/// ```text
/// vec![FactorStep::Required(Password), FactorStep::Required(Totp)]
/// ```
///
/// Factor choice (FIDO2 or password+TOTP):
/// ```text
/// vec![FactorStep::AnyOf(vec![Fido2, Password]), FactorStep::Required(Totp)]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FactorStep {
    /// Exactly this factor must be verified.
    Required(FactorKind),
    /// The user may choose any one of these factors.
    AnyOf(Vec<FactorKind>),
}

impl FactorStep {
    /// Return the factor kind if this is a `Required` step, or `None` for `AnyOf`.
    pub fn as_required(&self) -> Option<&FactorKind> {
        match self {
            FactorStep::Required(k) => Some(k),
            FactorStep::AnyOf(_) => None,
        }
    }

    /// Return `true` if the given kind satisfies this step.
    pub fn accepts(&self, kind: &FactorKind) -> bool {
        match self {
            FactorStep::Required(k) => k == kind,
            FactorStep::AnyOf(choices) => choices.contains(kind),
        }
    }
}

impl From<FactorKind> for FactorStep {
    fn from(kind: FactorKind) -> Self {
        FactorStep::Required(kind)
    }
}

// ── FederatedProvider ────────────────────────────────────────────────────────

/// A federated identity provider for OAuth2/OIDC-based authentication.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub enum FederatedProvider {
    /// GitHub OAuth 2.0 (`https://github.com`).
    Github,
    /// Google OIDC (`https://accounts.google.com`).
    Google,
    /// Microsoft Entra ID / Azure AD OIDC.
    Microsoft,
    /// Custom OIDC/OAuth provider identified by a stable tag.
    Custom(String),
}

impl FederatedProvider {
    /// Stable lower-case tag used as the provider key in storage and logs.
    pub fn as_str(&self) -> &str {
        match self {
            FederatedProvider::Github => "github",
            FederatedProvider::Google => "google",
            FederatedProvider::Microsoft => "microsoft",
            FederatedProvider::Custom(s) => s.as_ref(),
        }
    }
}

// ── FactorConfig ─────────────────────────────────────────────────────────────

/// Typed factor configuration: one variant per factor kind.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FactorConfig {
    /// Argon2id password configuration (rules + stored hash).
    Password(PasswordConfig),
    /// TOTP configuration (RFC 6238): shared secret, period, digits.
    Totp(TotpConfig),
    /// HOTP configuration (RFC 4226): shared secret, counter, digits.
    Hotp(HotpConfig),
    /// Email OTP configuration: target address, code length, TTL, pending challenge.
    EmailOtp(EmailOtpConfig),
    /// FIDO2/WebAuthn passkey configuration with registered credentials.
    Fido2(Fido2Config),
    /// LDAP bind factor. Per-user config is optional; if absent, the bind DN
    /// is constructed from the provider's template and the user's identifier.
    LdapBind(LdapBindFactorConfig),
}

impl FactorConfig {
    /// Return the [`FactorKind`] associated with this configuration variant.
    pub fn kind(&self) -> FactorKind {
        match self {
            FactorConfig::Password(_) => FactorKind::Password,
            FactorConfig::Totp(_) => FactorKind::Totp,
            FactorConfig::Hotp(_) => FactorKind::Hotp,
            FactorConfig::EmailOtp(_) => FactorKind::EmailOtp,
            FactorConfig::Fido2(_) => FactorKind::Fido2,
            FactorConfig::LdapBind(_) => FactorKind::LdapBind,
        }
    }
}

// ── LdapBindFactorConfig ────────────────────────────────────────────────────

/// Per-user configuration for LDAP bind authentication.
///
/// If `bind_dn` is `None`, the bind DN is constructed from the provider's
/// template and the user's login identifier. Set `bind_dn` explicitly when
/// a user's directory DN differs from the template pattern.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LdapBindFactorConfig {
    /// Explicit bind DN for this user. Overrides the provider template.
    pub bind_dn: Option<String>,
}

// ── FactorCredential ─────────────────────────────────────────────────────────

/// A credential presented for factor verification.
///
/// The enum shape is stable regardless of feature flags. FIDO2 assertions
/// are stored as `serde_json::Value` and deserialized on demand when the
/// `fido2` feature is enabled.
#[derive(Debug)]
pub enum FactorCredential {
    /// Plaintext password, zeroized on drop. Compared against a stored Argon2id hash.
    Password(ZeroizedString),
    /// One-time code as entered by the user (TOTP, HOTP, or email OTP).
    OtpCode(Arc<str>),
    /// FIDO2/WebAuthn authentication assertion (JSON-serialized `PublicKeyCredential`).
    ///
    /// Use [`FactorCredential::fido2_assertion`] to construct, and
    /// [`FactorCredential::as_public_key_credential`] (requires `fido2` feature)
    /// to deserialize.
    Fido2Assertion(serde_json::Value),
}

impl FactorCredential {
    /// Construct a `Fido2Assertion` from a `PublicKeyCredential`.
    #[cfg(feature = "fido2")]
    pub fn fido2_assertion(
        cred: &webauthn_rs::prelude::PublicKeyCredential,
    ) -> Result<Self, serde_json::Error> {
        serde_json::to_value(cred).map(Self::Fido2Assertion)
    }

    /// Deserialize the stored JSON into a `PublicKeyCredential`.
    ///
    /// Returns `None` if this is not a `Fido2Assertion` or deserialization fails.
    #[cfg(feature = "fido2")]
    pub fn as_public_key_credential(&self) -> Option<webauthn_rs::prelude::PublicKeyCredential> {
        match self {
            Self::Fido2Assertion(v) => serde_json::from_value(v.clone()).ok(),
            _ => None,
        }
    }
}

#[cfg(test)]
mod factor_tests {
    //! Pin pure-function bodies on `FactorKind`,
    //! `FactorStep`, `FederatedProvider`, and `FactorCredential`.
    use super::*;

    /// Kills line 78 `FactorKind::fmt -> Ok(Default::default())`:
    /// Display must emit the canonical `as_str()` tag, not an empty
    /// formatter write.
    #[test]
    fn factor_kind_display_matches_as_str() {
        assert_eq!(FactorKind::Password.to_string(), "password");
        assert_eq!(FactorKind::Totp.to_string(), "totp");
        assert_eq!(FactorKind::EmailOtp.to_string(), "email_otp");
        // Display interpolates Federated tag through as_str.
        assert_eq!(
            FactorKind::Federated(FederatedProvider::Github).to_string(),
            "github"
        );
    }

    /// Kills line 108 `FactorStep::as_required -> None`: a Required
    /// step must return `Some(&kind)`.
    #[test]
    fn factor_step_as_required_returns_some_for_required_variant() {
        let step = FactorStep::Required(FactorKind::Totp);
        assert_eq!(step.as_required(), Some(&FactorKind::Totp));
    }

    /// AnyOf must still return None: pins the match arm against
    /// being swapped.
    #[test]
    fn factor_step_as_required_returns_none_for_anyof_variant() {
        let step = FactorStep::AnyOf(vec![FactorKind::Password, FactorKind::Totp]);
        assert!(step.as_required().is_none());
    }

    /// Kills line 116 `accepts -> true/false` and line 117 `== → !=`:
    /// `accepts` must be true ONLY for the matching `Required` kind
    /// or membership in an `AnyOf` choice list.
    #[test]
    fn factor_step_accepts_required_only_for_matching_kind() {
        let step = FactorStep::Required(FactorKind::Totp);
        assert!(step.accepts(&FactorKind::Totp));
        assert!(!step.accepts(&FactorKind::Password));
    }

    /// AnyOf accepts any listed kind, rejects non-listed.
    #[test]
    fn factor_step_accepts_anyof_member_only() {
        let step = FactorStep::AnyOf(vec![FactorKind::Password, FactorKind::Totp]);
        assert!(step.accepts(&FactorKind::Password));
        assert!(step.accepts(&FactorKind::Totp));
        assert!(!step.accepts(&FactorKind::EmailOtp));
    }

    /// Kills line 147 `FederatedProvider::as_str -> ""` and
    /// `-> "xyzzy"`: must return the canonical lower-case tag per
    /// variant. Includes the Custom arm to defend the match against
    /// arm reordering.
    #[test]
    fn federated_provider_as_str_per_variant() {
        assert_eq!(FederatedProvider::Github.as_str(), "github");
        assert_eq!(FederatedProvider::Google.as_str(), "google");
        assert_eq!(FederatedProvider::Microsoft.as_str(), "microsoft");
        assert_eq!(
            FederatedProvider::Custom("okta-prod".to_string()).as_str(),
            "okta-prod"
        );
        // Different Custom values must yield different tags; pins
        // against `as_str() → constant` mutations that ignore the
        // variant data.
        assert_ne!(
            FederatedProvider::Custom("a".to_string()).as_str(),
            FederatedProvider::Custom("b".to_string()).as_str()
        );
    }

    /// Pin `FactorCredential::as_public_key_credential` against the
    /// `-> None` body replacement and against deleting the
    /// `Self::Fido2Assertion(v)` match arm. A Fido2Assertion carrying a
    /// valid PublicKeyCredential JSON must round-trip back to `Some`;
    /// non-FIDO2 variants must yield `None`.
    #[cfg(feature = "fido2")]
    #[test]
    fn as_public_key_credential_yields_some_for_fido2_assertion() {
        let pkc_json = serde_json::json!({
            "id": "AAAA",
            "rawId": "AAAA",
            "type": "public-key",
            "response": {
                "authenticatorData": "AAAA",
                "clientDataJSON": "AAAA",
                "signature": "AAAA",
                "userHandle": null,
            },
            "extensions": {},
        });
        let cred = FactorCredential::Fido2Assertion(pkc_json);
        assert!(
            cred.as_public_key_credential().is_some(),
            "Fido2Assertion with a valid PublicKeyCredential JSON must yield Some"
        );

        let non_fido2 = FactorCredential::OtpCode(Arc::from("123456"));
        assert!(
            non_fido2.as_public_key_credential().is_none(),
            "non-Fido2 variants must yield None"
        );
    }
}
