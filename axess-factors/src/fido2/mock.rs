//! [`MockFido2Provider`]: a provider that refuses every ceremony.

use super::{Fido2Authentication, Fido2Ceremony, Fido2Key, Fido2Provider, Fido2Registration};
use webauthn_rs::prelude::*;

/// Test double for [`Fido2Provider`]. Fails every ceremony call so the
/// caller can exercise error paths without real WebAuthn crypto; for
/// end-to-end FIDO2 tests, use [`DefaultFido2Provider`](super::DefaultFido2Provider)
/// against a `WebauthnBuilder` configured for a test origin.
pub struct MockFido2Provider {
    rp_id: String,
}

impl MockFido2Provider {
    /// Construct a new mock provider that always fails ceremony calls. Its
    /// relying-party id is `localhost`; change it with
    /// [`with_relying_party_id`](Self::with_relying_party_id).
    pub fn new() -> Self {
        Self {
            rp_id: "localhost".to_string(),
        }
    }

    /// The relying-party id [`Fido2Provider::relying_party_id`] reports.
    #[must_use]
    pub fn with_relying_party_id(mut self, rp_id: impl Into<String>) -> Self {
        self.rp_id = rp_id.into();
        self
    }
}

impl Default for MockFido2Provider {
    fn default() -> Self {
        Self::new()
    }
}

impl Fido2Provider for MockFido2Provider {
    fn relying_party_id(&self) -> &str {
        &self.rp_id
    }

    fn start_authentication(
        &self,
        ceremony: &Fido2Ceremony,
        credentials: &[Fido2Key],
    ) -> WebauthnResult<(RequestChallengeResponse, Fido2Authentication)> {
        tracing::debug!(
            target: "axess::testing::mock_fido2",
            %ceremony,
            credential_count = credentials.len(),
            "MockFido2Provider::start_authentication rejected",
        );
        Err(WebauthnError::CredentialNotFound)
    }

    fn finish_authentication(
        &self,
        assertion: &PublicKeyCredential,
        state: &Fido2Authentication,
    ) -> WebauthnResult<AuthenticationResult> {
        tracing::debug!(
            target: "axess::testing::mock_fido2",
            credential_id = ?assertion.id,
            ceremony = %state.ceremony(),
            "MockFido2Provider::finish_authentication rejected",
        );
        Err(WebauthnError::CredentialNotFound)
    }

    fn start_registration(
        &self,
        ceremony: &Fido2Ceremony,
        user_id: uuid::Uuid,
        user_name: &str,
        display_name: &str,
        exclude: Option<Vec<CredentialID>>,
    ) -> WebauthnResult<(CreationChallengeResponse, Fido2Registration)> {
        tracing::debug!(
            target: "axess::testing::mock_fido2",
            %ceremony,
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
        state: &Fido2Registration,
    ) -> WebauthnResult<Fido2Key> {
        tracing::debug!(
            target: "axess::testing::mock_fido2",
            credential_id = ?response.id,
            ceremony = %state.ceremony(),
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
        _: DiscoverableAuthentication,
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
