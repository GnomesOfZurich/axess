//! [`StepUp`]: the step-up a refusal names and
//! `RequestAuthnService::begin_step_up_for` begins.

use super::FactorAssurance;
use crate::authn::factor::{FactorKind, Fido2Ceremony, SecurityKeyVerification};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// A step-up: the factor to verify again and, for FIDO2, the typed ceremony
/// that verifies it.
///
/// Named in a Cedar policy's `@step_up("<name>")` annotation and in the
/// `step_up_required` refusal, and parsed back from the client to begin it.
/// The names are `totp`, `hotp`, `email_otp`, `recovery_code`, `password`,
/// `ldap_bind` and a [`Fido2Ceremony`] name (`passkey`,
/// `security_key:preferred`, `security_key:discouraged`,
/// `attested_passkey:<trust anchor>`). The order is the order a gate tries
/// them in: possession codes, then knowledge factors, then the FIDO2
/// ceremonies from the one that asks the least.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub enum StepUp {
    /// A TOTP code.
    Totp,
    /// An HOTP code.
    Hotp,
    /// An email one-time code.
    EmailOtp,
    /// A recovery code.
    RecoveryCode,
    /// The password.
    Password,
    /// An LDAP bind.
    LdapBind,
    /// A FIDO2 assertion through the named ceremony.
    Fido2(Fido2Ceremony),
}

impl StepUp {
    /// The factor the step-up verifies.
    pub fn factor_kind(&self) -> FactorKind {
        match self {
            Self::Totp => FactorKind::Totp,
            Self::Hotp => FactorKind::Hotp,
            Self::EmailOtp => FactorKind::EmailOtp,
            Self::RecoveryCode => FactorKind::RecoveryCode,
            Self::Password => FactorKind::Password,
            Self::LdapBind => FactorKind::LdapBind,
            Self::Fido2(_) => FactorKind::Fido2,
        }
    }

    /// The FIDO2 ceremony a FIDO2 step-up runs.
    pub fn fido2_ceremony(&self) -> Option<&Fido2Ceremony> {
        match self {
            Self::Fido2(ceremony) => Some(ceremony),
            _ => None,
        }
    }

    /// The best proof this step-up can yield, verified at `at`: what a gate
    /// assumes when it asks whether the step-up would satisfy a policy. A
    /// passkey may come back synced; its best is device-bound. A
    /// UV-discouraged security key asks the authenticator not to verify, so
    /// its best is not user-verified.
    pub fn best_proof(&self, at: DateTime<Utc>) -> FactorAssurance {
        match self {
            Self::Fido2(ceremony) => {
                let (user_verified, trust_anchor) = match ceremony {
                    Fido2Ceremony::SecurityKey(SecurityKeyVerification::Discouraged) => {
                        (false, None)
                    }
                    Fido2Ceremony::SecurityKey(SecurityKeyVerification::Preferred)
                    | Fido2Ceremony::Passkey => (true, None),
                    Fido2Ceremony::AttestedPasskey { trust_anchor } => {
                        (true, Some(Arc::from(trust_anchor.as_str())))
                    }
                };
                FactorAssurance::fido2(user_verified, false, false, trust_anchor, at)
            }
            other => FactorAssurance::for_kind(other.factor_kind(), at),
        }
    }
}

/// A string that names no [`StepUp`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "unknown step-up {value:?}: expected totp, hotp, email_otp, recovery_code, password, \
     ldap_bind or a FIDO2 ceremony (passkey, security_key:preferred, \
     security_key:discouraged, attested_passkey:<trust anchor>)"
)]
pub struct StepUpParseError {
    /// The string that was refused.
    pub value: String,
}

impl std::fmt::Display for StepUp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Totp => f.write_str("totp"),
            Self::Hotp => f.write_str("hotp"),
            Self::EmailOtp => f.write_str("email_otp"),
            Self::RecoveryCode => f.write_str("recovery_code"),
            Self::Password => f.write_str("password"),
            Self::LdapBind => f.write_str("ldap_bind"),
            Self::Fido2(ceremony) => ceremony.fmt(f),
        }
    }
}

impl std::str::FromStr for StepUp {
    type Err = StepUpParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(match value {
            "totp" => Self::Totp,
            "hotp" => Self::Hotp,
            "email_otp" => Self::EmailOtp,
            "recovery_code" => Self::RecoveryCode,
            "password" => Self::Password,
            "ldap_bind" => Self::LdapBind,
            other => Self::Fido2(other.parse().map_err(|_| StepUpParseError {
                value: value.to_string(),
            })?),
        })
    }
}

impl From<StepUp> for String {
    fn from(step_up: StepUp) -> Self {
        step_up.to_string()
    }
}

impl TryFrom<String> for StepUp {
    type Error = StepUpParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}
