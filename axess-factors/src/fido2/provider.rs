//! The [`Fido2Provider`] verifier abstraction and its production
//! implementation over `webauthn_rs::Webauthn`.
//!
//! Pairs with the orchestrator's FIDO2 service in axess-core
//! (`AuthnService` methods are orchestrator-level).

use super::SecurityKeyVerification;
use super::{Fido2Authentication, Fido2Ceremony, Fido2Key, Fido2Registration};
use axess_identity::DeviceId;
use std::collections::BTreeMap;
use webauthn_rs::prelude::*;

/// Abstraction over WebAuthn ceremony operations.
///
/// Production: [`DefaultFido2Provider`] (wraps `webauthn_rs::Webauthn`).
/// Tests: `MockFido2Provider` (`testing` feature; configurable outcomes without crypto).
///
/// # Ceremonies
///
/// A registration or authentication runs the typed ceremony its caller
/// names ([`Fido2Ceremony`]); the state it returns records which, so the
/// finish completes the same ceremony. The discoverable (passwordless)
/// ceremony is its own operation.
///
/// # Timeouts
///
/// FIDO2 ceremonies are browser-side; the authenticator interaction happens
/// on the client. The server enforces a ceremony timeout: stale ceremony
/// state is rejected if the timestamp exceeds the configured limit (default
/// 5 minutes). No server-side network calls are involved, so no HTTP timeout
/// is needed.
///
/// # Declared determinism exception
///
/// [`DefaultFido2Provider`] delegates to `webauthn-rs`, which draws challenge
/// bytes from the thread RNG and checks attestation validity against the
/// system clock; neither can be injected through its API. Everything axess
/// itself decides around a ceremony (its timeout, timestamps, the credential
/// list) uses the service's injected `Clock`. A test
/// that needs a reproducible ceremony substitutes the provider:
/// `MockFido2Provider` returns configured outcomes with no randomness and
/// no clock.
pub trait Fido2Provider: Send + Sync + 'static {
    /// The relying-party id this provider's ceremonies are bound to.
    ///
    /// A passkey is bound to the relying-party id it was registered under, so
    /// changing it orphans every registered credential. A live reload
    /// (`AuthnService::reload_fido2`) compares the id of the provider it
    /// replaces with the candidate's and refuses a change unless the caller
    /// acknowledged it. An implementation that cannot tell returns an empty
    /// string, which equals no real id, so a reload to or from it is refused
    /// until acknowledged.
    fn relying_party_id(&self) -> &str;

    /// Start an authentication ceremony of the typed `ceremony` over
    /// `credentials`, which the caller has narrowed to those the ceremony
    /// accepts ([`Fido2Ceremony::accepts`]).
    fn start_authentication(
        &self,
        ceremony: &Fido2Ceremony,
        credentials: &[Fido2Key],
    ) -> WebauthnResult<(RequestChallengeResponse, Fido2Authentication)>;

    /// Finish the authentication ceremony `state` began.
    fn finish_authentication(
        &self,
        assertion: &PublicKeyCredential,
        state: &Fido2Authentication,
    ) -> WebauthnResult<AuthenticationResult>;

    /// Start a registration ceremony of the typed `ceremony`.
    fn start_registration(
        &self,
        ceremony: &Fido2Ceremony,
        user_id: uuid::Uuid,
        user_name: &str,
        display_name: &str,
        exclude: Option<Vec<CredentialID>>,
    ) -> WebauthnResult<(CreationChallengeResponse, Fido2Registration)>;

    /// Finish the registration ceremony `state` began, returning the
    /// credential typed by that ceremony.
    fn finish_registration(
        &self,
        response: &RegisterPublicKeyCredential,
        state: &Fido2Registration,
    ) -> WebauthnResult<Fido2Key>;

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

    /// The trust anchor `key`'s attestation verifies against now, by name:
    /// for an attested passkey, its registration's trust anchor when the
    /// provider still holds one of that name and the credential's
    /// attestation still verifies against it; `None` otherwise.
    ///
    /// The orchestrator records the answer as what an attested-passkey
    /// login proved. The default answers `None`, so a provider that does not
    /// check attestation never claims it.
    fn attests(&self, key: &Fido2Key) -> Option<String> {
        tracing::trace!(
            target: "axess::factors::fido2",
            credential_id = ?key.cred_id(),
            "Fido2Provider::attests default impl: no attestation is claimed",
        );
        None
    }

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
/// let provider = DefaultFido2Provider::new(webauthn)
///     // The attested-passkey ceremony `attested_passkey:vendor-roots`.
///     .with_trust_anchor("vendor-roots", vendor_roots);
/// ```
pub struct DefaultFido2Provider {
    inner: Webauthn,
    rp_id: String,
    trust_anchors: BTreeMap<String, AttestationCaList>,
    presence_only: Option<Webauthn>,
}

impl DefaultFido2Provider {
    /// Wrap an existing `Webauthn` instance.
    ///
    /// The relying-party id is read from the instance itself (the challenge
    /// a discoverable authentication would send names it), so it cannot
    /// disagree with the ceremonies. If that read fails, which the library
    /// does not do for a built instance, the id is empty and a reload is
    /// refused until acknowledged.
    ///
    /// The provider holds no trust anchor and no presence-only instance:
    /// the attested-passkey ceremony and the UV-discouraged security-key
    /// ceremony are refused until [`with_trust_anchor`](Self::with_trust_anchor)
    /// and [`with_presence_only_security_keys`](Self::with_presence_only_security_keys)
    /// supply them.
    pub fn new(webauthn: Webauthn) -> Self {
        let rp_id = relying_party_of(&webauthn).unwrap_or_default();
        Self {
            inner: webauthn,
            rp_id,
            trust_anchors: BTreeMap::new(),
            presence_only: None,
        }
    }

    /// Hold `list` as the trust anchor named `name`, for the
    /// attested-passkey ceremony `attested_passkey:<name>`. A later call
    /// with the same name replaces the list. The list travels in the
    /// registration state the session holds, so keep it to the roots you
    /// trust.
    #[must_use]
    pub fn with_trust_anchor(mut self, name: impl Into<String>, list: AttestationCaList) -> Self {
        self.trust_anchors.insert(name.into(), list);
        self
    }

    /// Serve the UV-discouraged security-key ceremony with `webauthn`, an
    /// instance built with `webauthn-rs`'s
    /// `danger_set_user_presence_only_security_keys(true)` (its
    /// `danger-user-presence-only-security-keys` feature, which the adopter
    /// enables in their own build) for the same relying party.
    ///
    /// # Errors
    ///
    /// [`WebauthnError::Configuration`] when the instance does not
    /// discourage user verification, or names another relying party.
    pub fn with_presence_only_security_keys(
        mut self,
        webauthn: Webauthn,
    ) -> Result<Self, WebauthnError> {
        let (challenge, _) = webauthn.start_securitykey_registration(
            Uuid::nil(),
            "probe",
            "probe",
            None,
            None,
            None,
        )?;
        // `webauthn-rs` does not export the policy type; its wire name is the
        // one the browser reads.
        let discourages = challenge
            .public_key
            .authenticator_selection
            .as_ref()
            .and_then(|selection| serde_json::to_value(selection).ok())
            .is_some_and(|selection| selection["userVerification"] == "discouraged");
        if !discourages || challenge.public_key.rp.id != self.rp_id {
            tracing::error!(
                discourages,
                "presence-only security-key instance refused: it must discourage user \
                 verification and serve the provider's relying party"
            );
            return Err(WebauthnError::Configuration);
        }
        self.presence_only = Some(webauthn);
        Ok(self)
    }

    fn trust_anchor(&self, name: &str) -> WebauthnResult<&AttestationCaList> {
        self.trust_anchors.get(name).ok_or_else(|| {
            tracing::warn!(
                trust_anchor = name,
                "FIDO2 ceremony names a trust anchor the provider does not hold"
            );
            WebauthnError::MissingAttestationCaList
        })
    }

    fn security_key_instance(
        &self,
        verification: SecurityKeyVerification,
    ) -> WebauthnResult<&Webauthn> {
        match verification {
            SecurityKeyVerification::Preferred => Ok(&self.inner),
            SecurityKeyVerification::Discouraged => self.presence_only.as_ref().ok_or_else(|| {
                tracing::warn!(
                    "UV-discouraged security-key ceremony refused: no presence-only instance"
                );
                WebauthnError::Configuration
            }),
        }
    }
}

/// The credentials a ceremony offers, refused when there are none: an
/// authentication that names no credential is not this operation.
fn offered<T>(keys: Vec<T>) -> WebauthnResult<Vec<T>> {
    if keys.is_empty() {
        tracing::warn!("FIDO2 authentication refused: no credential fits the ceremony");
        return Err(WebauthnError::CredentialNotFound);
    }
    Ok(keys)
}

/// The relying-party id a `Webauthn` instance's ceremonies name.
fn relying_party_of(webauthn: &Webauthn) -> Option<String> {
    webauthn
        .start_discoverable_authentication()
        .ok()
        .map(|(challenge, _)| challenge.public_key.rp_id)
}

impl Fido2Provider for DefaultFido2Provider {
    fn relying_party_id(&self) -> &str {
        &self.rp_id
    }

    fn start_authentication(
        &self,
        ceremony: &Fido2Ceremony,
        credentials: &[Fido2Key],
    ) -> WebauthnResult<(RequestChallengeResponse, Fido2Authentication)> {
        match ceremony {
            Fido2Ceremony::Passkey => {
                let keys: Vec<Passkey> = credentials.iter().filter_map(Fido2Key::passkey).collect();
                let keys = offered(keys)?;
                let (challenge, state) = self.inner.start_passkey_authentication(&keys)?;
                Ok((challenge, Fido2Authentication::Passkey(state)))
            }
            Fido2Ceremony::SecurityKey(verification) => {
                let keys: Vec<SecurityKey> = credentials
                    .iter()
                    .filter_map(|key| match key {
                        Fido2Key::SecurityKey(key) => Some(key.clone()),
                        _ => None,
                    })
                    .collect();
                let keys = offered(keys)?;
                let (challenge, state) = self
                    .security_key_instance(*verification)?
                    .start_securitykey_authentication(&keys)?;
                Ok((
                    challenge,
                    Fido2Authentication::SecurityKey {
                        state,
                        verification: *verification,
                    },
                ))
            }
            Fido2Ceremony::AttestedPasskey { trust_anchor } => {
                self.trust_anchor(trust_anchor)?;
                let keys: Vec<AttestedPasskey> = credentials
                    .iter()
                    .filter_map(|key| match key {
                        Fido2Key::AttestedPasskey {
                            key,
                            trust_anchor: registered,
                        } if registered == trust_anchor => Some(key.clone()),
                        _ => None,
                    })
                    .collect();
                let keys = offered(keys)?;
                let (challenge, state) = self.inner.start_attested_passkey_authentication(&keys)?;
                Ok((
                    challenge,
                    Fido2Authentication::AttestedPasskey {
                        state,
                        trust_anchor: trust_anchor.clone(),
                    },
                ))
            }
        }
    }

    fn finish_authentication(
        &self,
        assertion: &PublicKeyCredential,
        state: &Fido2Authentication,
    ) -> WebauthnResult<AuthenticationResult> {
        match state {
            Fido2Authentication::Passkey(state) => {
                self.inner.finish_passkey_authentication(assertion, state)
            }
            Fido2Authentication::SecurityKey {
                state,
                verification,
            } => self
                .security_key_instance(*verification)?
                .finish_securitykey_authentication(assertion, state),
            Fido2Authentication::AttestedPasskey { state, .. } => self
                .inner
                .finish_attested_passkey_authentication(assertion, state),
        }
    }

    fn start_registration(
        &self,
        ceremony: &Fido2Ceremony,
        user_id: uuid::Uuid,
        user_name: &str,
        display_name: &str,
        exclude: Option<Vec<CredentialID>>,
    ) -> WebauthnResult<(CreationChallengeResponse, Fido2Registration)> {
        match ceremony {
            Fido2Ceremony::Passkey => {
                let (challenge, state) = self.inner.start_passkey_registration(
                    user_id,
                    user_name,
                    display_name,
                    exclude,
                )?;
                Ok((challenge, Fido2Registration::Passkey(state)))
            }
            Fido2Ceremony::SecurityKey(verification) => {
                let (challenge, state) = self
                    .security_key_instance(*verification)?
                    .start_securitykey_registration(
                        user_id,
                        user_name,
                        display_name,
                        exclude,
                        None,
                        None,
                    )?;
                Ok((
                    challenge,
                    Fido2Registration::SecurityKey {
                        state,
                        verification: *verification,
                    },
                ))
            }
            Fido2Ceremony::AttestedPasskey { trust_anchor } => {
                let list = self.trust_anchor(trust_anchor)?.clone();
                let (challenge, state) = self.inner.start_attested_passkey_registration(
                    user_id,
                    user_name,
                    display_name,
                    exclude,
                    list,
                    None,
                )?;
                Ok((
                    challenge,
                    Fido2Registration::AttestedPasskey {
                        state,
                        trust_anchor: trust_anchor.clone(),
                    },
                ))
            }
        }
    }

    fn finish_registration(
        &self,
        response: &RegisterPublicKeyCredential,
        state: &Fido2Registration,
    ) -> WebauthnResult<Fido2Key> {
        match state {
            Fido2Registration::Passkey(state) => self
                .inner
                .finish_passkey_registration(response, state)
                .map(Fido2Key::Passkey),
            Fido2Registration::SecurityKey {
                state,
                verification,
            } => self
                .security_key_instance(*verification)?
                .finish_securitykey_registration(response, state)
                .map(Fido2Key::SecurityKey),
            Fido2Registration::AttestedPasskey {
                state,
                trust_anchor,
            } => self
                .inner
                .finish_attested_passkey_registration(response, state)
                .map(|key| Fido2Key::AttestedPasskey {
                    key,
                    trust_anchor: trust_anchor.clone(),
                }),
        }
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
        // webauthn-rs verifies one credential at a time and answers
        // `CredentialNotFound` for a key whose id is not the assertion's
        // before it checks anything else, so the first key that answers
        // otherwise is the assertion's own and its verdict is final. With
        // no matching key the assertion is refused, as before.
        for key in keys {
            match self
                .inner
                .finish_discoverable_authentication_v2(assertion, state.clone(), key)
            {
                Err(WebauthnError::CredentialNotFound) => {}
                verdict => return verdict,
            }
        }
        Err(WebauthnError::CredentialNotFound)
    }

    fn attests(&self, key: &Fido2Key) -> Option<String> {
        let Fido2Key::AttestedPasskey { key, trust_anchor } = key else {
            return None;
        };
        let list = self.trust_anchors.get(trust_anchor)?;
        match key.verify_attestation(list) {
            Ok(_) => Some(trust_anchor.clone()),
            Err(e) => {
                tracing::warn!(
                    trust_anchor = trust_anchor.as_str(),
                    "attested passkey no longer verifies against its trust anchor: {e:?}"
                );
                None
            }
        }
    }
}
