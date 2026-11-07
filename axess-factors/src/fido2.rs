//! FIDO2/WebAuthn factor data types: config, credential metadata,
//! options, the ceremony vocabulary, and re-exports of the `webauthn-rs`
//! primitives the orchestrator persists alongside them.
//!
//! [`Fido2Config`], [`Fido2Ceremony`] and [`SecurityKeyVerification`] are
//! plain data and compile without the `fido2` feature, so admin tooling and
//! policy code can name them without `webauthn-rs`. Everything else is
//! gated on `fido2`: the stored credential ([`Fido2Credential`] holding a
//! typed [`Fido2Key`]), the ceremony state ([`Fido2Registration`],
//! [`Fido2Authentication`]), the [`Fido2Provider`] trait and its
//! [`DefaultFido2Provider`].

#[cfg(feature = "fido2")]
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── Fido2Config ──────────────────────────────────────────────────────────────

/// FIDO2/WebAuthn factor configuration.
///
/// When the `fido2` feature is enabled, credentials are stored as typed
/// [`Fido2Credential`] values. Without the feature, they round-trip as
/// opaque `serde_json::Value` so admin tooling that doesn't pull
/// `webauthn-rs` can still read and write factor rows.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Fido2Config {
    /// Registered FIDO2 credentials available to this factor.
    #[cfg(feature = "fido2")]
    pub credentials: Vec<Fido2Credential>,
    /// Opaque JSON-encoded credentials (used when the `fido2` feature is disabled).
    #[cfg(not(feature = "fido2"))]
    pub credentials: Vec<serde_json::Value>,
}

// ── Fido2Ceremony ────────────────────────────────────────────────────────────

/// Which typed WebAuthn ceremony runs for an operation.
///
/// WebAuthn fixes the user verification and attestation it asks for in the
/// challenge, before the ceremony; `webauthn-rs` makes that choice a typed
/// ceremony, and this names the three axess runs. A credential keeps the type
/// of the ceremony that registered it, and a login ceremony offers only the
/// credentials it can authenticate ([`accepts`](Self::accepts), `fido2`
/// feature).
///
/// Written and parsed as a string (its [`Display`](std::fmt::Display) form):
/// `passkey`, `security_key:preferred`, `security_key:discouraged`,
/// `attested_passkey:<trust anchor>`. The order is from the ceremony that
/// asks the least to the one that asks the most.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub enum Fido2Ceremony {
    /// The security-key ceremony (`start_securitykey_*`): a non-discoverable
    /// credential, with user verification preferred or discouraged.
    SecurityKey(SecurityKeyVerification),
    /// The passkey ceremony (`start_passkey_*`): user verification required,
    /// no attestation. What axess ran for every operation before the
    /// ceremony was chosen per operation, and [`DEFAULT_FIDO2_CEREMONY`].
    Passkey,
    /// The attested-passkey ceremony (`start_attested_passkey_*`): user
    /// verification required, the authenticator's attestation verified
    /// against the trust anchor (`AttestationCaList`) the provider holds
    /// under `trust_anchor`, and synced authenticators refused.
    AttestedPasskey {
        /// The name the provider holds the trust anchor under.
        trust_anchor: String,
    },
}

/// The ceremony every FIDO2 operation runs unless the adopter chooses
/// another: [`Fido2Ceremony::Passkey`].
pub const DEFAULT_FIDO2_CEREMONY: Fido2Ceremony = Fido2Ceremony::Passkey;

/// The user verification a security-key ceremony asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityKeyVerification {
    /// Ask the authenticator not to verify the user: presence only. Needs a
    /// `Webauthn` built for presence-only security keys, see
    /// `DefaultFido2Provider::with_presence_only_security_keys`.
    Discouraged,
    /// Ask the authenticator to verify the user when it can.
    Preferred,
}

/// A string that names no [`Fido2Ceremony`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fido2CeremonyParseError {
    /// The string that was refused.
    pub value: String,
}

impl std::fmt::Display for Fido2CeremonyParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "unknown FIDO2 ceremony {:?}: expected passkey, security_key:preferred, \
             security_key:discouraged or attested_passkey:<trust anchor>",
            self.value
        )
    }
}

impl std::error::Error for Fido2CeremonyParseError {}

impl std::fmt::Display for Fido2Ceremony {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Passkey => f.write_str("passkey"),
            Self::SecurityKey(SecurityKeyVerification::Preferred) => {
                f.write_str("security_key:preferred")
            }
            Self::SecurityKey(SecurityKeyVerification::Discouraged) => {
                f.write_str("security_key:discouraged")
            }
            Self::AttestedPasskey { trust_anchor } => write!(f, "attested_passkey:{trust_anchor}"),
        }
    }
}

impl std::str::FromStr for Fido2Ceremony {
    type Err = Fido2CeremonyParseError;

    /// Parse the [`Display`](std::fmt::Display) form. A trust anchor name is
    /// one or more visible ASCII characters (no space, no control
    /// character), because it travels in policy annotations and responses.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let refused = || Fido2CeremonyParseError {
            value: value.to_string(),
        };
        match value {
            "passkey" => Ok(Self::Passkey),
            "security_key:preferred" => Ok(Self::SecurityKey(SecurityKeyVerification::Preferred)),
            "security_key:discouraged" => {
                Ok(Self::SecurityKey(SecurityKeyVerification::Discouraged))
            }
            other => {
                let anchor = other
                    .strip_prefix("attested_passkey:")
                    .ok_or_else(refused)?;
                if anchor.is_empty() || !anchor.bytes().all(|b| b.is_ascii_graphic()) {
                    return Err(refused());
                }
                Ok(Self::AttestedPasskey {
                    trust_anchor: anchor.to_string(),
                })
            }
        }
    }
}

impl From<Fido2Ceremony> for String {
    fn from(ceremony: Fido2Ceremony) -> Self {
        ceremony.to_string()
    }
}

impl TryFrom<String> for Fido2Ceremony {
    type Error = Fido2CeremonyParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

// ── Fido2Credential ──────────────────────────────────────────────────────────

/// A FIDO2 credential with application-level metadata.
///
/// Wraps the typed [`Fido2Key`] the registering ceremony produced with a
/// friendly name, registration timestamp, and last-used timestamp for
/// credential management UIs.
///
/// A passkey is stored in the shape earlier releases wrote (its key under
/// `passkey`), so they still read it; a security key or an attested passkey
/// is stored under `key`. Both shapes read back.
#[cfg(feature = "fido2")]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "credential_wire::Fido2CredentialWire")]
#[serde(into = "credential_wire::Fido2CredentialWire")]
pub struct Fido2Credential {
    /// The credential as the ceremony that registered it typed it.
    pub key: Fido2Key,
    /// User-supplied label shown in credential management UIs.
    pub name: String,
    /// Timestamp at which the credential was registered.
    pub registered_at: DateTime<Utc>,
    /// Timestamp of the most recent successful authentication, if any.
    pub last_used_at: Option<DateTime<Utc>>,
}

#[cfg(feature = "fido2")]
impl Fido2Credential {
    /// Construct a fresh credential record with `last_used_at` cleared. A
    /// `Passkey` converts into a [`Fido2Key`], so a passkey is passed as is.
    pub fn new(
        key: impl Into<Fido2Key>,
        name: impl Into<String>,
        registered_at: DateTime<Utc>,
    ) -> Self {
        Self {
            key: key.into(),
            name: name.into(),
            registered_at,
            last_used_at: None,
        }
    }

    /// Return the WebAuthn credential ID assigned by the authenticator.
    pub fn cred_id(&self) -> &webauthn_rs::prelude::CredentialID {
        self.key.cred_id()
    }

    /// Update the stored counter from a successful authentication and record
    /// the moment it occurred.
    pub fn record_authentication(
        &mut self,
        result: &webauthn_rs::prelude::AuthenticationResult,
        now: DateTime<Utc>,
    ) {
        // `update_credential` answers `None` for a result that belongs to
        // another credential; only the matching one counts as used.
        if self.key.update_credential(result).is_some() {
            self.last_used_at = Some(now);
        }
    }
}

#[cfg(feature = "fido2")]
mod credential_wire;

// ── Re-exports ───────────────────────────────────────────────────────────────

#[cfg(feature = "fido2")]
pub use webauthn_rs::prelude::AuthenticatorAttachment;
#[cfg(feature = "fido2")]
pub use webauthn_rs::prelude::{AttestationCaList, AuthenticationResult, CredentialID};

// ── Fido2Options ─────────────────────────────────────────────────────────────

/// Configuration for FIDO2/WebAuthn ceremony management.
///
/// Controls the ceremony state timeout, the age a session needs for a
/// credential change, and which ceremony registration and login run. A
/// step-up for a named action takes its ceremony from the `@step_up`
/// annotation of the Cedar rule that requires it instead.
#[cfg(feature = "fido2")]
#[derive(Debug, Clone)]
pub struct Fido2Options {
    /// Maximum lifetime of a registration or authentication ceremony before
    /// the in-flight state is discarded.
    pub ceremony_timeout: std::time::Duration,
    /// How recently the session must have authenticated for a credential
    /// change (beginning or finishing a registration, deleting a passkey).
    /// A session whose authentication is older is refused the change and
    /// must step up first, so a session left open on a shared machine
    /// cannot enrol an attacker's passkey hours later. `None`, the
    /// default, applies no age limit; a few minutes is the usual choice.
    pub max_authn_age: Option<std::time::Duration>,
    /// The ceremony a registration runs unless the call names one
    /// (`begin_fido2_registration_with`). Default
    /// [`DEFAULT_FIDO2_CEREMONY`], the passkey ceremony.
    pub registration_ceremony: Fido2Ceremony,
    /// The ceremony the FIDO2 step of a login method runs, and a step-up
    /// begun without a ceremony of its own. Default
    /// [`DEFAULT_FIDO2_CEREMONY`], the passkey ceremony.
    pub login_ceremony: Fido2Ceremony,
}

#[cfg(feature = "fido2")]
impl Default for Fido2Options {
    fn default() -> Self {
        Self {
            ceremony_timeout: std::time::Duration::from_secs(300),
            max_authn_age: None,
            registration_ceremony: DEFAULT_FIDO2_CEREMONY,
            login_ceremony: DEFAULT_FIDO2_CEREMONY,
        }
    }
}

// ── Typed keys, ceremony state, provider ────────────────────────────────────

#[cfg(feature = "fido2")]
mod key;
#[cfg(feature = "fido2")]
pub use key::{Fido2Authentication, Fido2Key, Fido2Registration};

#[cfg(feature = "fido2")]
mod provider;
#[cfg(feature = "fido2")]
pub use provider::{DefaultFido2Provider, Fido2Provider};

#[cfg(all(feature = "fido2", any(test, feature = "testing")))]
mod mock;
#[cfg(all(feature = "fido2", any(test, feature = "testing")))]
pub use mock::MockFido2Provider;

#[cfg(all(test, feature = "fido2"))]
mod ceremony_tests;

#[cfg(all(test, feature = "fido2"))]
mod credential_tests;

#[cfg(all(test, feature = "fido2"))]
mod verifier_tests;
