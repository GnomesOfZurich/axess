//! What each verified factor proved: the record a session keeps at login and
//! at every step-up, read by Cedar through
//! [`AssuranceContext`](crate::authz::assurance::AssuranceContext) (feature
//! `authz`).
//!
//! See `docs/authorization/assurance.md` for the design: the per-factor
//! table of what `user_verified` and `credential` mean, where the record
//! lives, and why a session from before the record existed satisfies no
//! assurance policy.

use crate::authn::factor::FactorKind;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Whether the credential a factor used is bound to one device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialBinding {
    /// A FIDO2 credential whose authenticator reported neither backup
    /// eligibility nor backup state: its key cannot leave the device.
    DeviceBound,
    /// A FIDO2 credential that is backed up, or eligible to be: it may be
    /// present on other devices of the same account.
    Synced,
    /// The factor has no credential that could be bound to a device (a
    /// password, a one-time code, a federated login).
    NotApplicable,
}

impl CredentialBinding {
    /// The string a Cedar policy compares against: `"device_bound"`,
    /// `"synced"` or `"not_applicable"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DeviceBound => "device_bound",
            Self::Synced => "synced",
            Self::NotApplicable => "not_applicable",
        }
    }

    /// The binding a FIDO2 authenticator reports through its backup flags:
    /// device-bound only when it is neither backed up nor eligible to be.
    pub fn from_backup_flags(backup_eligible: bool, backup_state: bool) -> Self {
        if backup_eligible || backup_state {
            Self::Synced
        } else {
            Self::DeviceBound
        }
    }
}

/// What one verified factor proved, and when.
///
/// Recorded only by the code path that verified the factor, from the
/// verifier's own result, and kept on the authenticated state
/// ([`AuthState::assurance`](crate::session::data::AuthState::assurance)).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactorAssurance {
    /// The factor that was verified.
    pub kind: FactorKind,
    /// When it was verified, from the service's injected clock.
    pub at: DateTime<Utc>,
    /// Whether the factor proved the person and not only a device or a
    /// channel: the UV flag of a FIDO2 assertion; `true` for a password or
    /// an LDAP bind (a memorized secret); `false` for one-time codes,
    /// recovery codes and federated logins.
    pub user_verified: bool,
    /// The trust anchor an attested ceremony verified the authenticator
    /// against, by the name the provider holds it under; `None` unless an
    /// attested ceremony ran and the attestation still verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_anchor: Option<Arc<str>>,
    /// Whether the credential is synced or bound to one device.
    pub credential: CredentialBinding,
}

impl FactorAssurance {
    /// What a factor of `kind` proves by its kind alone, verified at `at`.
    ///
    /// The table on the design page: a password and an LDAP bind are
    /// user-verified, one-time codes, recovery codes and federated logins
    /// are not, and none of them has a device-bound credential. A FIDO2
    /// factor recorded this way, without its assertion's flags, claims the
    /// least: not user-verified and synced. The FIDO2 verifier records
    /// [`fido2`](Self::fido2) instead.
    pub fn for_kind(kind: FactorKind, at: DateTime<Utc>) -> Self {
        let (user_verified, credential) = match kind {
            FactorKind::Password | FactorKind::LdapBind => (true, CredentialBinding::NotApplicable),
            FactorKind::Totp
            | FactorKind::Hotp
            | FactorKind::EmailOtp
            | FactorKind::RecoveryCode
            | FactorKind::Federated(_) => (false, CredentialBinding::NotApplicable),
            FactorKind::Fido2 => (false, CredentialBinding::Synced),
        };
        Self {
            kind,
            at,
            user_verified,
            trust_anchor: None,
            credential,
        }
    }

    /// What a FIDO2 assertion proved: its UV flag, its backup flags and the
    /// trust anchor an attested ceremony verified, at `at`.
    pub fn fido2(
        user_verified: bool,
        backup_eligible: bool,
        backup_state: bool,
        trust_anchor: Option<Arc<str>>,
        at: DateTime<Utc>,
    ) -> Self {
        Self {
            kind: FactorKind::Fido2,
            at,
            user_verified,
            trust_anchor,
            credential: CredentialBinding::from_backup_flags(backup_eligible, backup_state),
        }
    }

    /// [`fido2`](Self::fido2) read from a `webauthn-rs` authentication result.
    #[cfg(feature = "fido2")]
    pub fn from_fido2_result(
        result: &webauthn_rs::prelude::AuthenticationResult,
        trust_anchor: Option<Arc<str>>,
        at: DateTime<Utc>,
    ) -> Self {
        Self::fido2(
            result.user_verified(),
            result.backup_eligible(),
            result.backup_state(),
            trust_anchor,
            at,
        )
    }
}

/// Record `proof` in `record`, replacing the earlier proof of the same kind:
/// the record holds the most recent proof of each factor kind.
pub(crate) fn record_proof(record: &mut Vec<FactorAssurance>, proof: FactorAssurance) {
    record.retain(|earlier| earlier.kind != proof.kind);
    record.push(proof);
}

mod step_up;
pub use step_up::{StepUp, StepUpParseError};

#[cfg(test)]
mod assurance_tests;
#[cfg(test)]
mod step_up_tests;
