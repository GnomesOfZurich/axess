//! A stored credential typed by the ceremony that registered it, and the
//! in-flight state of each typed ceremony.

use super::{Fido2Ceremony, SecurityKeyVerification};
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::{
    AttestedPasskey, AttestedPasskeyAuthentication, AttestedPasskeyRegistration,
    AuthenticationResult, CredentialID, Passkey, PasskeyAuthentication, PasskeyRegistration,
    SecurityKey, SecurityKeyAuthentication, SecurityKeyRegistration,
};

/// A registered credential, typed by the ceremony that registered it.
///
/// `webauthn-rs` authenticates each type with its own ceremony and converts
/// only an attested passkey into a passkey, so the type decides which login
/// ceremonies can use the credential ([`Fido2Ceremony::accepts`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Fido2Key {
    /// Registered by the passkey ceremony.
    Passkey(Passkey),
    /// Registered by the security-key ceremony.
    SecurityKey(SecurityKey),
    /// Registered by the attested-passkey ceremony, its attestation verified
    /// against the trust anchor named `trust_anchor` at registration.
    AttestedPasskey {
        /// The attested credential.
        key: AttestedPasskey,
        /// The name of the trust anchor the registration verified against.
        trust_anchor: String,
    },
}

impl Fido2Key {
    /// The WebAuthn credential ID assigned by the authenticator.
    pub fn cred_id(&self) -> &CredentialID {
        match self {
            Self::Passkey(key) => key.cred_id(),
            Self::SecurityKey(key) => key.cred_id(),
            Self::AttestedPasskey { key, .. } => key.cred_id(),
        }
    }

    /// Apply a successful authentication's counter and flags to the
    /// credential; `None` when the result belongs to another credential.
    pub fn update_credential(&mut self, result: &AuthenticationResult) -> Option<bool> {
        match self {
            Self::Passkey(key) => key.update_credential(result),
            Self::SecurityKey(key) => key.update_credential(result),
            Self::AttestedPasskey { key, .. } => key.update_credential(result),
        }
    }

    /// The credential as a passkey, for the passkey and discoverable
    /// ceremonies: a passkey itself, or an attested passkey converted;
    /// `None` for a security key, which `webauthn-rs` does not convert.
    pub fn passkey(&self) -> Option<Passkey> {
        match self {
            Self::Passkey(key) => Some(key.clone()),
            Self::AttestedPasskey { key, .. } => Some(Passkey::from(key)),
            Self::SecurityKey(_) => None,
        }
    }

    /// The trust anchor an attested passkey was registered against.
    pub fn trust_anchor(&self) -> Option<&str> {
        match self {
            Self::AttestedPasskey { trust_anchor, .. } => Some(trust_anchor),
            Self::Passkey(_) | Self::SecurityKey(_) => None,
        }
    }
}

impl From<Passkey> for Fido2Key {
    fn from(key: Passkey) -> Self {
        Self::Passkey(key)
    }
}

impl From<SecurityKey> for Fido2Key {
    fn from(key: SecurityKey) -> Self {
        Self::SecurityKey(key)
    }
}

impl Fido2Ceremony {
    /// Whether a login under this ceremony can authenticate `key`: the
    /// passkey ceremony a passkey or an attested passkey, the security-key
    /// ceremony a security key, the attested-passkey ceremony an attested
    /// passkey registered against the same trust anchor.
    pub fn accepts(&self, key: &Fido2Key) -> bool {
        match (self, key) {
            (Self::Passkey, Fido2Key::Passkey(_) | Fido2Key::AttestedPasskey { .. }) => true,
            (Self::SecurityKey(_), Fido2Key::SecurityKey(_)) => true,
            (
                Self::AttestedPasskey { trust_anchor },
                Fido2Key::AttestedPasskey {
                    trust_anchor: registered,
                    ..
                },
            ) => trust_anchor == registered,
            _ => false,
        }
    }
}

/// The in-flight state of a registration ceremony, typed by the ceremony
/// that began it so a finish cannot complete it as another.
///
/// Keep it server-side: it is the ceremony's trust anchor. An attested
/// registration carries its trust anchor's certificate list, so keep that
/// list to the roots you trust.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Fido2Registration {
    /// A passkey registration.
    Passkey(PasskeyRegistration),
    /// A security-key registration.
    SecurityKey {
        /// The `webauthn-rs` state.
        state: SecurityKeyRegistration,
        /// The user verification the ceremony asked for.
        verification: SecurityKeyVerification,
    },
    /// An attested-passkey registration.
    AttestedPasskey {
        /// The `webauthn-rs` state.
        state: AttestedPasskeyRegistration,
        /// The name of the trust anchor the ceremony verifies against.
        trust_anchor: String,
    },
}

/// The in-flight state of an authentication ceremony, typed by the ceremony
/// that began it so a finish cannot complete it as another.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Fido2Authentication {
    /// A passkey authentication.
    Passkey(PasskeyAuthentication),
    /// A security-key authentication.
    SecurityKey {
        /// The `webauthn-rs` state.
        state: SecurityKeyAuthentication,
        /// The user verification the ceremony asked for.
        verification: SecurityKeyVerification,
    },
    /// An attested-passkey authentication.
    AttestedPasskey {
        /// The `webauthn-rs` state.
        state: AttestedPasskeyAuthentication,
        /// The name of the trust anchor the credentials were registered
        /// against.
        trust_anchor: String,
    },
}

impl Fido2Registration {
    /// The ceremony that began this registration.
    pub fn ceremony(&self) -> Fido2Ceremony {
        match self {
            Self::Passkey(_) => Fido2Ceremony::Passkey,
            Self::SecurityKey { verification, .. } => Fido2Ceremony::SecurityKey(*verification),
            Self::AttestedPasskey { trust_anchor, .. } => Fido2Ceremony::AttestedPasskey {
                trust_anchor: trust_anchor.clone(),
            },
        }
    }
}

impl Fido2Authentication {
    /// The ceremony that began this authentication.
    pub fn ceremony(&self) -> Fido2Ceremony {
        match self {
            Self::Passkey(_) => Fido2Ceremony::Passkey,
            Self::SecurityKey { verification, .. } => Fido2Ceremony::SecurityKey(*verification),
            Self::AttestedPasskey { trust_anchor, .. } => Fido2Ceremony::AttestedPasskey {
                trust_anchor: trust_anchor.clone(),
            },
        }
    }
}
