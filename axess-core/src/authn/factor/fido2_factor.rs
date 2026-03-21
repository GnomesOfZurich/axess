//! FIDO2/WebAuthn factor types: config, credential metadata, options, and re-exports.

#[cfg(feature = "fido2")]
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── Fido2Config ──────────────────────────────────────────────────────────────

/// FIDO2/WebAuthn factor configuration.
///
/// When the `fido2` feature is enabled, credentials are stored as typed
/// [`Fido2Credential`] values. Without the feature, they are opaque JSON.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Fido2Config {
    #[cfg(feature = "fido2")]
    pub credentials: Vec<Fido2Credential>,
    #[cfg(not(feature = "fido2"))]
    pub credentials: Vec<serde_json::Value>,
}

// ── Fido2Credential ──────────────────────────────────────────────────────────

/// A FIDO2 credential with application-level metadata.
///
/// Wraps webauthn-rs `Passkey` with a friendly name, registration timestamp,
/// and last-used timestamp for credential management UIs.
#[cfg(feature = "fido2")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fido2Credential {
    pub passkey: webauthn_rs::prelude::Passkey,
    pub name: String,
    pub registered_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[cfg(feature = "fido2")]
impl Fido2Credential {
    pub fn new(
        passkey: webauthn_rs::prelude::Passkey,
        name: impl Into<String>,
        registered_at: DateTime<Utc>,
    ) -> Self {
        Self {
            passkey,
            name: name.into(),
            registered_at,
            last_used_at: None,
        }
    }

    pub fn cred_id(&self) -> &webauthn_rs::prelude::CredentialID {
        self.passkey.cred_id()
    }

    pub fn record_authentication(
        &mut self,
        result: &webauthn_rs::prelude::AuthenticationResult,
        now: DateTime<Utc>,
    ) {
        self.passkey.update_credential(result);
        self.last_used_at = Some(now);
    }
}

// ── Re-exports ───────────────────────────────────────────────────────────────

#[cfg(feature = "fido2")]
pub use webauthn_rs::prelude::AuthenticatorAttachment;
#[cfg(feature = "fido2")]
pub use webauthn_rs::prelude::{AuthenticationResult, CredentialID};

// ── Fido2Options ─────────────────────────────────────────────────────────────

/// Configuration for FIDO2/WebAuthn ceremony management.
///
/// Controls the ceremony state timeout at the service level.
/// UV policy, authenticator attachment, and attestation are configured at
/// `WebauthnBuilder` level.
#[cfg(feature = "fido2")]
#[derive(Debug, Clone)]
pub struct Fido2Options {
    pub ceremony_timeout: std::time::Duration,
}

#[cfg(feature = "fido2")]
impl Default for Fido2Options {
    fn default() -> Self {
        Self {
            ceremony_timeout: std::time::Duration::from_secs(300),
        }
    }
}
