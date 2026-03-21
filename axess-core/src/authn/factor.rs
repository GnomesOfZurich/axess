//! Factor kinds, typed configurations, and credentials.
//!
//! Each factor kind has its own submodule with config types. This module
//! re-exports everything for a flat import surface:
//! `use crate::authn::factor::{FactorKind, PasswordConfig, TotpConfig, ...}`

mod otp;
mod password;

mod fido2_factor;

// ── Re-exports (flat surface) ────────────────────────────────────────────────

pub use fido2_factor::Fido2Config;
pub use otp::{EmailOtpConfig, HotpConfig, OtpAlgorithm, TotpConfig};
pub use password::{PasswordConfig, PasswordRules, ZeroizedString};

#[cfg(feature = "fido2")]
pub use fido2_factor::{
    AuthenticationResult, AuthenticatorAttachment, CredentialID, Fido2Credential, Fido2Options,
};

use serde::{Deserialize, Serialize};
use std::{fmt, sync::Arc};

// ── FactorKind ───────────────────────────────────────────────────────────────

/// The kind of authentication factor.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FactorKind {
    Password,
    Totp,
    Hotp,
    EmailOtp,
    Fido2,
    Federated(FederatedProvider),
}

impl FactorKind {
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

// ── FederatedProvider ────────────────────────────────────────────────────────

/// A federated identity provider for OAuth2/OIDC-based authentication.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FederatedProvider {
    Github,
    Google,
    Microsoft,
    Custom(Arc<str>),
}

impl FederatedProvider {
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

/// Typed factor configuration — one variant per factor kind.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FactorConfig {
    Password(PasswordConfig),
    Totp(TotpConfig),
    Hotp(HotpConfig),
    EmailOtp(EmailOtpConfig),
    Fido2(Fido2Config),
}

impl FactorConfig {
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

// ── FactorCredential ─────────────────────────────────────────────────────────

/// A credential presented for factor verification.
#[derive(Debug)]
pub enum FactorCredential {
    Password(ZeroizedString),
    OtpCode(Arc<str>),
    #[cfg(feature = "fido2")]
    Fido2Assertion(webauthn_rs::prelude::PublicKeyCredential),
    #[cfg(not(feature = "fido2"))]
    Fido2Assertion(serde_json::Value),
}
