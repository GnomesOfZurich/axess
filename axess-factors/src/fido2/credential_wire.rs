//! The stored shape of a [`Fido2Credential`]: a passkey under `passkey`, as
//! earlier releases wrote and read it, and any other key under `key`.

use super::{Fido2Credential, Fido2Key};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::Passkey;

/// The stored form. Exactly one of `passkey` and `key` is present.
#[derive(Serialize, Deserialize)]
pub(super) struct Fido2CredentialWire {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    passkey: Option<Passkey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key: Option<Fido2Key>,
    name: String,
    registered_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
}

/// A stored credential that names no key, or two.
#[derive(Debug)]
pub(super) struct Fido2CredentialShapeError(&'static str);

impl std::fmt::Display for Fido2CredentialShapeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl TryFrom<Fido2CredentialWire> for Fido2Credential {
    type Error = Fido2CredentialShapeError;

    fn try_from(wire: Fido2CredentialWire) -> Result<Self, Self::Error> {
        let key = match (wire.passkey, wire.key) {
            (Some(passkey), None) => Fido2Key::Passkey(passkey),
            (None, Some(key)) => key,
            (None, None) => {
                return Err(Fido2CredentialShapeError(
                    "a stored FIDO2 credential names no key",
                ));
            }
            (Some(_), Some(_)) => {
                return Err(Fido2CredentialShapeError(
                    "a stored FIDO2 credential names two keys",
                ));
            }
        };
        Ok(Self {
            key,
            name: wire.name,
            registered_at: wire.registered_at,
            last_used_at: wire.last_used_at,
        })
    }
}

impl From<Fido2Credential> for Fido2CredentialWire {
    fn from(credential: Fido2Credential) -> Self {
        let (passkey, key) = match credential.key {
            Fido2Key::Passkey(passkey) => (Some(passkey), None),
            other => (None, Some(other)),
        };
        Self {
            passkey,
            key,
            name: credential.name,
            registered_at: credential.registered_at,
            last_used_at: credential.last_used_at,
        }
    }
}
