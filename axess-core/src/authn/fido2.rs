//! FIDO2/WebAuthn provider trait and implementations.
//!
//! The [`Fido2Provider`] trait abstracts WebAuthn ceremony operations so that:
//! - Tests can use [`MockFido2Provider`] for deterministic simulation
//! - The library doesn't depend on concrete `Webauthn` in its public API
//!
//! # Limitations (webauthn-rs 0.6)
//!
//! The `Webauthn` struct hardcodes `UserVerificationPolicy::Required` in
//! `start_passkey_authentication`. UV policy, authenticator attachment, and
//! attestation preferences are configured at `WebauthnBuilder` construction
//! time, not per-ceremony. When webauthn-rs exposes per-ceremony configuration,
//! the `Fido2Provider` trait is already designed to support it.

use webauthn_rs::prelude::*;

// ── Fido2Provider trait ──────────────────────────────────────────────────────

/// Abstraction over WebAuthn ceremony operations.
///
/// Production: [`DefaultFido2Provider`] (wraps `webauthn_rs::Webauthn`).
/// Tests: [`MockFido2Provider`] (configurable outcomes without crypto).
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
}

// ── DefaultFido2Provider ─────────────────────────────────────────────────────

/// Production FIDO2 provider wrapping `webauthn_rs::Webauthn`.
///
/// Construct with [`WebauthnBuilder`] to set relying party ID and origin:
///
/// ```rust,ignore
/// use webauthn_rs::prelude::*;
/// use axess::authn::fido2::DefaultFido2Provider;
///
/// let webauthn = WebauthnBuilder::new("example.com", &Url::parse("https://example.com")?)
///     .unwrap()
///     .build()
///     .unwrap();
/// let provider = DefaultFido2Provider::new(webauthn);
/// ```
pub struct DefaultFido2Provider {
    inner: Webauthn,
}

impl DefaultFido2Provider {
    /// Wrap an existing `Webauthn` instance.
    pub fn new(webauthn: Webauthn) -> Self {
        Self { inner: webauthn }
    }
}

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

/// Mock FIDO2 provider for deterministic simulation testing.
///
/// Since WebAuthn ceremonies require real cryptographic operations to produce
/// valid challenges and assertions, the mock cannot produce ceremony objects
/// that pass validation. Instead, it's used to verify that:
/// - The `AuthnService` correctly calls the provider methods
/// - Error paths (no webauthn configured, ceremony timeout) work
/// - The service gracefully handles provider failures
///
/// For full FIDO2 integration tests, use [`DefaultFido2Provider`] with
/// `webauthn_rs::prelude::WebauthnBuilder` configured for a test origin.
pub struct MockFido2Provider {
    _private: (),
}

impl MockFido2Provider {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for MockFido2Provider {
    fn default() -> Self {
        Self::new()
    }
}

impl Fido2Provider for MockFido2Provider {
    fn start_authentication(
        &self,
        _credentials: &[Passkey],
    ) -> WebauthnResult<(RequestChallengeResponse, PasskeyAuthentication)> {
        Err(WebauthnError::CredentialNotFound)
    }

    fn finish_authentication(
        &self,
        _assertion: &PublicKeyCredential,
        _state: &PasskeyAuthentication,
    ) -> WebauthnResult<AuthenticationResult> {
        Err(WebauthnError::CredentialNotFound)
    }

    fn start_registration(
        &self,
        _user_id: uuid::Uuid,
        _user_name: &str,
        _display_name: &str,
        _exclude: Option<Vec<CredentialID>>,
    ) -> WebauthnResult<(CreationChallengeResponse, PasskeyRegistration)> {
        Err(WebauthnError::CredentialNotFound)
    }

    fn finish_registration(
        &self,
        _response: &RegisterPublicKeyCredential,
        _state: &PasskeyRegistration,
    ) -> WebauthnResult<Passkey> {
        Err(WebauthnError::CredentialNotFound)
    }

    fn start_discoverable_authentication(
        &self,
    ) -> WebauthnResult<(RequestChallengeResponse, DiscoverableAuthentication)> {
        Err(WebauthnError::CredentialNotFound)
    }

    fn finish_discoverable_authentication(
        &self,
        _assertion: &PublicKeyCredential,
        _state: DiscoverableAuthentication,
        _keys: &[DiscoverableKey],
    ) -> WebauthnResult<AuthenticationResult> {
        Err(WebauthnError::CredentialNotFound)
    }
}
