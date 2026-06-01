//! FIDO2/WebAuthn factor data types: config, credential metadata,
//! options, and re-exports of the `webauthn-rs` primitives the
//! orchestrator persists alongside them.
//!
//! Gated on the `fido2` feature. The *verifier* (ceremony logic, the
//! `Fido2Provider` trait, `Fido2Service`) still lives in axess-core
//! until lands; the types here are just the
//! storage shapes the orchestrator's `FactorConfig::Fido2(...)`
//! variant embeds.

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

// ── Fido2Credential ──────────────────────────────────────────────────────────

/// A FIDO2 credential with application-level metadata.
///
/// Wraps webauthn-rs `Passkey` with a friendly name, registration timestamp,
/// and last-used timestamp for credential management UIs.
#[cfg(feature = "fido2")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fido2Credential {
    /// Underlying webauthn-rs `Passkey` (public key + counter + transports).
    pub passkey: webauthn_rs::prelude::Passkey,
    /// User-supplied label shown in credential management UIs.
    pub name: String,
    /// Timestamp at which the credential was registered.
    pub registered_at: DateTime<Utc>,
    /// Timestamp of the most recent successful authentication, if any.
    pub last_used_at: Option<DateTime<Utc>>,
}

#[cfg(feature = "fido2")]
impl Fido2Credential {
    /// Construct a fresh credential record with `last_used_at` cleared.
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

    /// Return the WebAuthn credential ID assigned by the authenticator.
    pub fn cred_id(&self) -> &webauthn_rs::prelude::CredentialID {
        self.passkey.cred_id()
    }

    /// Update the stored counter from a successful authentication and record
    /// the moment it occurred.
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
    /// Maximum lifetime of a registration or authentication ceremony before
    /// the in-flight state is discarded.
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

// ── Fido2Provider trait (verifier abstraction) ───────────────────────────────
//
// Pairs with the orchestrator's FIDO2 service in axess-core
// (`AuthnService` methods are orchestrator-level). The trait + the two
// impl shapes live here next to the credential type.

#[cfg(feature = "fido2")]
use axess_identity::DeviceId;
#[cfg(feature = "fido2")]
use webauthn_rs::prelude::*;

/// Abstraction over WebAuthn ceremony operations.
///
/// Production: [`DefaultFido2Provider`] (wraps `webauthn_rs::Webauthn`).
/// Tests: [`MockFido2Provider`] (configurable outcomes without crypto).
///
/// # Timeouts
///
/// FIDO2 ceremonies are browser-side; the authenticator interaction happens
/// on the client. The server enforces a ceremony timeout: stale ceremony
/// state is rejected if the timestamp exceeds the configured limit (default
/// 5 minutes). No server-side network calls are involved, so no HTTP timeout
/// is needed.
///
/// # Limitations (webauthn-rs 0.6)
///
/// The `Webauthn` struct hardcodes `UserVerificationPolicy::Required` in
/// `start_passkey_authentication`. UV policy, authenticator attachment, and
/// attestation preferences are configured at `WebauthnBuilder` construction
/// time, not per-ceremony. When webauthn-rs exposes per-ceremony configuration,
/// the `Fido2Provider` trait is already designed to support it.
#[cfg(feature = "fido2")]
pub trait Fido2Provider: Send + Sync + 'static {
    /// Start a passkey authentication ceremony.
    fn start_authentication(
        &self,
        credentials: &[Passkey],
    ) -> WebauthnResult<(RequestChallengeResponse, PasskeyAuthentication)>;

    /// Finish a passkey authentication ceremony.
    fn finish_authentication(
        &self,
        assertion: &PublicKeyCredential,
        state: &PasskeyAuthentication,
    ) -> WebauthnResult<AuthenticationResult>;

    /// Start a passkey registration ceremony.
    fn start_registration(
        &self,
        user_id: uuid::Uuid,
        user_name: &str,
        display_name: &str,
        exclude: Option<Vec<CredentialID>>,
    ) -> WebauthnResult<(CreationChallengeResponse, PasskeyRegistration)>;

    /// Finish a passkey registration ceremony.
    fn finish_registration(
        &self,
        response: &RegisterPublicKeyCredential,
        state: &PasskeyRegistration,
    ) -> WebauthnResult<Passkey>;

    /// Start a discoverable (passwordless) authentication ceremony.
    fn start_discoverable_authentication(
        &self,
    ) -> WebauthnResult<(RequestChallengeResponse, DiscoverableAuthentication)>;

    /// Finish a discoverable authentication ceremony.
    fn finish_discoverable_authentication(
        &self,
        assertion: &PublicKeyCredential,
        state: DiscoverableAuthentication,
        keys: &[DiscoverableKey],
    ) -> WebauthnResult<AuthenticationResult>;

    /// Credential-used notification hook.
    ///
    /// Fired by the orchestrator's service layer after a successful
    /// WebAuthn ceremony (registration or assertion) for which the
    /// request resolved to a known device. Adopters that wire the
    /// orchestrator's device subsystem override this method to persist
    /// a `DeviceBinding::WebAuthn` row (or update `last_used_at` on an
    /// existing binding) so the device → credential relation is
    /// auditable and step-up policy can reason about "this device has
    /// presented this credential before."
    ///
    /// # Sync surface, async-friendly
    ///
    /// The default impl is a no-op so the trait stays sync; adopters
    /// that need to write to an async device store spawn a task inside
    /// the override (`tokio::spawn(async move { … })`) or push the
    /// event onto a channel for a background worker. The hook is
    /// informational; failures inside the override must not fail the
    /// surrounding ceremony; the ceremony already succeeded at the
    /// WebAuthn layer when this fires.
    fn on_credential_used(&self, credential_id: &CredentialID, device_id: &DeviceId) {
        tracing::trace!(
            target: "axess::factors::fido2",
            ?credential_id,
            %device_id,
            "Fido2Provider::on_credential_used default impl: no observer wired",
        );
    }
}

// ── DefaultFido2Provider ─────────────────────────────────────────────────────

/// Production FIDO2 provider wrapping `webauthn_rs::Webauthn`.
///
/// Construct with `WebauthnBuilder` to set relying party ID and origin:
///
/// ```rust,ignore
/// use webauthn_rs::prelude::*;
/// use axess_factors::fido2::DefaultFido2Provider;
///
/// let webauthn = WebauthnBuilder::new("example.com", &Url::parse("https://example.com")?)
///     .unwrap()
///     .build()
///     .unwrap();
/// let provider = DefaultFido2Provider::new(webauthn);
/// ```
#[cfg(feature = "fido2")]
pub struct DefaultFido2Provider {
    inner: Webauthn,
}

#[cfg(feature = "fido2")]
impl DefaultFido2Provider {
    /// Wrap an existing `Webauthn` instance.
    pub fn new(webauthn: Webauthn) -> Self {
        Self { inner: webauthn }
    }
}

#[cfg(feature = "fido2")]
impl Fido2Provider for DefaultFido2Provider {
    fn start_authentication(
        &self,
        credentials: &[Passkey],
    ) -> WebauthnResult<(RequestChallengeResponse, PasskeyAuthentication)> {
        self.inner.start_passkey_authentication(credentials)
    }

    fn finish_authentication(
        &self,
        assertion: &PublicKeyCredential,
        state: &PasskeyAuthentication,
    ) -> WebauthnResult<AuthenticationResult> {
        self.inner.finish_passkey_authentication(assertion, state)
    }

    fn start_registration(
        &self,
        user_id: uuid::Uuid,
        user_name: &str,
        display_name: &str,
        exclude: Option<Vec<CredentialID>>,
    ) -> WebauthnResult<(CreationChallengeResponse, PasskeyRegistration)> {
        self.inner
            .start_passkey_registration(user_id, user_name, display_name, exclude)
    }

    fn finish_registration(
        &self,
        response: &RegisterPublicKeyCredential,
        state: &PasskeyRegistration,
    ) -> WebauthnResult<Passkey> {
        self.inner.finish_passkey_registration(response, state)
    }

    fn start_discoverable_authentication(
        &self,
    ) -> WebauthnResult<(RequestChallengeResponse, DiscoverableAuthentication)> {
        self.inner.start_discoverable_authentication()
    }

    fn finish_discoverable_authentication(
        &self,
        assertion: &PublicKeyCredential,
        state: DiscoverableAuthentication,
        keys: &[DiscoverableKey],
    ) -> WebauthnResult<AuthenticationResult> {
        self.inner
            .finish_discoverable_authentication(assertion, state, keys)
    }
}

// ── MockFido2Provider ────────────────────────────────────────────────────────

/// Test double for [`Fido2Provider`]. Fails every ceremony call so the
/// caller can exercise error paths without real WebAuthn crypto; for
/// end-to-end FIDO2 tests, use [`DefaultFido2Provider`] against a
/// `WebauthnBuilder` configured for a test origin.
#[cfg(feature = "fido2")]
pub struct MockFido2Provider;

#[cfg(feature = "fido2")]
impl MockFido2Provider {
    /// Construct a new mock provider that always fails ceremony calls.
    pub fn new() -> Self {
        Self
    }
}

#[cfg(feature = "fido2")]
impl Default for MockFido2Provider {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "fido2")]
impl Fido2Provider for MockFido2Provider {
    fn start_authentication(
        &self,
        credentials: &[Passkey],
    ) -> WebauthnResult<(RequestChallengeResponse, PasskeyAuthentication)> {
        tracing::debug!(
            target: "axess::testing::mock_fido2",
            credential_count = credentials.len(),
            "MockFido2Provider::start_authentication rejected",
        );
        Err(WebauthnError::CredentialNotFound)
    }

    fn finish_authentication(
        &self,
        assertion: &PublicKeyCredential,
        _state: &PasskeyAuthentication,
    ) -> WebauthnResult<AuthenticationResult> {
        tracing::debug!(
            target: "axess::testing::mock_fido2",
            credential_id = ?assertion.id,
            "MockFido2Provider::finish_authentication rejected",
        );
        Err(WebauthnError::CredentialNotFound)
    }

    fn start_registration(
        &self,
        user_id: uuid::Uuid,
        user_name: &str,
        display_name: &str,
        exclude: Option<Vec<CredentialID>>,
    ) -> WebauthnResult<(CreationChallengeResponse, PasskeyRegistration)> {
        tracing::debug!(
            target: "axess::testing::mock_fido2",
            %user_id,
            user_name,
            display_name,
            exclude_count = exclude.as_ref().map(Vec::len).unwrap_or(0),
            "MockFido2Provider::start_registration rejected",
        );
        Err(WebauthnError::CredentialNotFound)
    }

    fn finish_registration(
        &self,
        response: &RegisterPublicKeyCredential,
        _state: &PasskeyRegistration,
    ) -> WebauthnResult<Passkey> {
        tracing::debug!(
            target: "axess::testing::mock_fido2",
            credential_id = ?response.id,
            "MockFido2Provider::finish_registration rejected",
        );
        Err(WebauthnError::CredentialNotFound)
    }

    fn start_discoverable_authentication(
        &self,
    ) -> WebauthnResult<(RequestChallengeResponse, DiscoverableAuthentication)> {
        tracing::debug!(
            target: "axess::testing::mock_fido2",
            "MockFido2Provider::start_discoverable_authentication rejected",
        );
        Err(WebauthnError::CredentialNotFound)
    }

    fn finish_discoverable_authentication(
        &self,
        assertion: &PublicKeyCredential,
        _state: DiscoverableAuthentication,
        keys: &[DiscoverableKey],
    ) -> WebauthnResult<AuthenticationResult> {
        tracing::debug!(
            target: "axess::testing::mock_fido2",
            credential_id = ?assertion.id,
            discoverable_key_count = keys.len(),
            "MockFido2Provider::finish_discoverable_authentication rejected",
        );
        Err(WebauthnError::CredentialNotFound)
    }
}

#[cfg(all(test, feature = "fido2"))]
mod verifier_tests {
    use super::*;
    use std::sync::Mutex;

    /// The default `on_credential_used` is a no-op and must not panic.
    /// Mock providers + adopter impls that don't care about device
    /// binding inherit this default.
    #[test]
    fn default_on_credential_used_is_noop() {
        let provider = MockFido2Provider::new();
        let device_id = axess_identity::testing::device("d-fido2-noop");
        let cred = CredentialID::from(vec![0u8; 16]);
        // No assertion, no panic, no return; just confirms the call
        // path exists and the default impl runs cleanly.
        provider.on_credential_used(&cred, &device_id);
    }

    /// Adopters override the hook to capture `(credential_id,
    /// device_id)` pairs for binding persistence. Verify that an
    /// override is visible to the trait dispatch path.
    #[test]
    fn override_captures_credential_and_device_id() {
        struct CountingProvider {
            inner: MockFido2Provider,
            captured: Mutex<Vec<(Vec<u8>, DeviceId)>>,
        }
        impl Fido2Provider for CountingProvider {
            fn start_authentication(
                &self,
                credentials: &[Passkey],
            ) -> WebauthnResult<(RequestChallengeResponse, PasskeyAuthentication)> {
                self.inner.start_authentication(credentials)
            }
            fn finish_authentication(
                &self,
                assertion: &PublicKeyCredential,
                state: &PasskeyAuthentication,
            ) -> WebauthnResult<AuthenticationResult> {
                self.inner.finish_authentication(assertion, state)
            }
            fn start_registration(
                &self,
                user_id: uuid::Uuid,
                user_name: &str,
                display_name: &str,
                exclude: Option<Vec<CredentialID>>,
            ) -> WebauthnResult<(CreationChallengeResponse, PasskeyRegistration)> {
                self.inner
                    .start_registration(user_id, user_name, display_name, exclude)
            }
            fn finish_registration(
                &self,
                response: &RegisterPublicKeyCredential,
                state: &PasskeyRegistration,
            ) -> WebauthnResult<Passkey> {
                self.inner.finish_registration(response, state)
            }
            fn start_discoverable_authentication(
                &self,
            ) -> WebauthnResult<(RequestChallengeResponse, DiscoverableAuthentication)>
            {
                self.inner.start_discoverable_authentication()
            }
            fn finish_discoverable_authentication(
                &self,
                assertion: &PublicKeyCredential,
                state: DiscoverableAuthentication,
                keys: &[DiscoverableKey],
            ) -> WebauthnResult<AuthenticationResult> {
                self.inner
                    .finish_discoverable_authentication(assertion, state, keys)
            }
            fn on_credential_used(&self, credential_id: &CredentialID, device_id: &DeviceId) {
                let bytes: Vec<u8> = credential_id.as_ref().to_vec();
                self.captured.lock().unwrap().push((bytes, *device_id));
            }
        }

        let provider = CountingProvider {
            inner: MockFido2Provider::new(),
            captured: Mutex::new(Vec::new()),
        };
        let device_id = axess_identity::testing::device("d-fido2-override");
        let cred = CredentialID::from(vec![0xAB, 0xCD, 0xEF]);

        provider.on_credential_used(&cred, &device_id);
        provider.on_credential_used(&cred, &device_id);

        let captured = provider.captured.lock().unwrap();
        assert_eq!(captured.len(), 2, "override must run on every call");
        assert_eq!(captured[0].0, vec![0xAB, 0xCD, 0xEF]);
        assert_eq!(captured[0].1, device_id);
    }
}
