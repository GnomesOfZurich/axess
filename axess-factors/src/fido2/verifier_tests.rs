//! The typed ceremonies `DefaultFido2Provider` runs, the credentials each one
//! offers, attestation re-verification, the stored credential shapes, and
//! the provider hooks.

use super::*;
use axess_identity::DeviceId;
use chrono::TimeZone;
use serde_json::json;
use std::sync::Mutex;
use url::Url;
use webauthn_rs::prelude::*;

/// URL-safe base64 of `aaaa` and `bbbb`.
const AAAA: &str = "YWFhYQ";
const BBBB: &str = "YmJiYg";

/// The serialised credential every `webauthn-rs` key type wraps.
fn cred(id: &str) -> serde_json::Value {
    let coord = "A".repeat(43);
    json!({
        "cred": {
            "cred_id": id,
            "cred": { "type_": "ES256",
                "key": { "EC_EC2": { "curve": "SECP256R1", "x": coord, "y": coord } } },
            "counter": 1,
            "transports": null,
            "user_verified": true,
            "backup_eligible": false,
            "backup_state": false,
            "registration_policy": "required",
            "extensions": {},
            "attestation": { "data": "None", "metadata": "None" },
            "attestation_format": "none"
        }
    })
}

fn passkey(id: &str) -> Fido2Key {
    Fido2Key::Passkey(serde_json::from_value(cred(id)).expect("passkey fixture"))
}

fn security_key(id: &str) -> Fido2Key {
    Fido2Key::SecurityKey(serde_json::from_value(cred(id)).expect("security key fixture"))
}

fn attested(id: &str, anchor: &str) -> Fido2Key {
    Fido2Key::AttestedPasskey {
        key: serde_json::from_value(cred(id)).expect("attested passkey fixture"),
        trust_anchor: anchor.into(),
    }
}

fn webauthn() -> Webauthn {
    let origin = Url::parse("https://example.com").unwrap();
    WebauthnBuilder::new("example.com", &origin)
        .unwrap()
        .build()
        .unwrap()
}

/// A trust anchor holding one self-signed root.
fn roots() -> AttestationCaList {
    let params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
    let key = rcgen::KeyPair::generate().expect("key");
    let der = params
        .self_signed(&key)
        .expect("self-signed")
        .der()
        .to_vec();
    let mut builder = AttestationCaListBuilder::new();
    builder
        .insert_device_der(&der, Uuid::nil(), "test".into(), Default::default())
        .expect("root");
    builder.build()
}

fn provider() -> DefaultFido2Provider {
    DefaultFido2Provider::new(webauthn()).with_trust_anchor("roots", roots())
}

fn registration_json(
    provider: &DefaultFido2Provider,
    ceremony: &Fido2Ceremony,
) -> serde_json::Value {
    let (challenge, state) = provider
        .start_registration(ceremony, Uuid::nil(), "alice", "Alice", None)
        .expect("registration starts");
    assert_eq!(
        &state.ceremony(),
        ceremony,
        "the state records its ceremony"
    );
    serde_json::to_value(challenge).unwrap()["publicKey"].clone()
}

#[test]
fn each_registration_ceremony_asks_for_its_own_verification_and_attestation() {
    let provider = provider();
    let passkey = registration_json(&provider, &Fido2Ceremony::Passkey);
    assert_eq!(
        passkey["authenticatorSelection"]["userVerification"],
        "required"
    );
    assert_eq!(passkey["attestation"], "none");

    let key = registration_json(
        &provider,
        &Fido2Ceremony::SecurityKey(SecurityKeyVerification::Preferred),
    );
    assert_eq!(
        key["authenticatorSelection"]["userVerification"],
        "preferred"
    );

    let attested = registration_json(
        &provider,
        &Fido2Ceremony::AttestedPasskey {
            trust_anchor: "roots".into(),
        },
    );
    assert_eq!(
        attested["authenticatorSelection"]["userVerification"],
        "required"
    );
    assert_eq!(attested["attestation"], "direct");
}

#[test]
fn a_ceremony_naming_an_absent_trust_anchor_is_refused_at_its_start() {
    let provider = provider();
    let ceremony = Fido2Ceremony::AttestedPasskey {
        trust_anchor: "elsewhere".into(),
    };
    assert!(matches!(
        provider.start_registration(&ceremony, Uuid::nil(), "a", "A", None),
        Err(WebauthnError::MissingAttestationCaList)
    ));
    assert!(matches!(
        provider.start_authentication(&ceremony, &[attested(AAAA, "elsewhere")]),
        Err(WebauthnError::MissingAttestationCaList)
    ));
}

#[test]
fn a_discouraged_security_key_ceremony_needs_a_presence_only_instance() {
    let provider = provider();
    let discouraged = Fido2Ceremony::SecurityKey(SecurityKeyVerification::Discouraged);
    assert!(matches!(
        provider.start_registration(&discouraged, Uuid::nil(), "a", "A", None),
        Err(WebauthnError::Configuration)
    ));
    assert!(matches!(
        provider.start_authentication(&discouraged, &[security_key(AAAA)]),
        Err(WebauthnError::Configuration)
    ));
}

#[test]
fn an_instance_that_verifies_users_is_refused_as_presence_only() {
    assert!(matches!(
        provider().with_presence_only_security_keys(webauthn()),
        Err(WebauthnError::Configuration)
    ));
}

#[test]
fn a_presence_only_instance_serves_the_discouraged_ceremony() {
    let origin = Url::parse("https://example.com").unwrap();
    let presence_only = WebauthnBuilder::new("example.com", &origin)
        .unwrap()
        .danger_set_user_presence_only_security_keys(true)
        .build()
        .unwrap();
    let provider = provider()
        .with_presence_only_security_keys(presence_only)
        .expect("a presence-only instance for the same relying party");
    let discouraged = Fido2Ceremony::SecurityKey(SecurityKeyVerification::Discouraged);
    let json = registration_json(&provider, &discouraged);
    assert_eq!(
        json["authenticatorSelection"]["userVerification"],
        "discouraged"
    );
}

fn offered(provider: &DefaultFido2Provider, ceremony: &Fido2Ceremony, keys: &[Fido2Key]) -> usize {
    let (challenge, state) = provider
        .start_authentication(ceremony, keys)
        .expect("authentication starts");
    assert_eq!(&state.ceremony(), ceremony);
    serde_json::to_value(challenge).unwrap()["publicKey"]["allowCredentials"]
        .as_array()
        .expect("allow list")
        .len()
}

#[test]
fn a_login_ceremony_offers_only_the_credentials_it_can_authenticate() {
    let provider = provider();
    let all = [
        passkey(AAAA),
        security_key(BBBB),
        attested("Y2NjYw", "roots"),
    ];
    assert_eq!(offered(&provider, &Fido2Ceremony::Passkey, &all), 2);
    assert_eq!(
        offered(
            &provider,
            &Fido2Ceremony::SecurityKey(SecurityKeyVerification::Preferred),
            &all
        ),
        1
    );
    let attested_ceremony = Fido2Ceremony::AttestedPasskey {
        trust_anchor: "roots".into(),
    };
    assert_eq!(offered(&provider, &attested_ceremony, &all), 1);
    assert!(
        matches!(
            provider.start_authentication(&attested_ceremony, &[passkey(AAAA)]),
            Err(WebauthnError::CredentialNotFound)
        ),
        "a ceremony no credential fits is refused"
    );
}

#[test]
fn accepts_matches_each_ceremony_to_its_key_types() {
    let attested_roots = Fido2Ceremony::AttestedPasskey {
        trust_anchor: "roots".into(),
    };
    let preferred = Fido2Ceremony::SecurityKey(SecurityKeyVerification::Preferred);
    assert!(Fido2Ceremony::Passkey.accepts(&passkey(AAAA)));
    assert!(Fido2Ceremony::Passkey.accepts(&attested(AAAA, "roots")));
    assert!(!Fido2Ceremony::Passkey.accepts(&security_key(AAAA)));
    assert!(preferred.accepts(&security_key(AAAA)));
    assert!(!preferred.accepts(&passkey(AAAA)));
    assert!(attested_roots.accepts(&attested(AAAA, "roots")));
    assert!(!attested_roots.accepts(&attested(AAAA, "other")));
    assert!(!attested_roots.accepts(&passkey(AAAA)));
}

#[test]
fn an_attestation_that_does_not_verify_now_is_not_claimed() {
    let provider = provider();
    assert_eq!(
        provider.attests(&attested(AAAA, "roots")),
        None,
        "a credential whose attestation the held root does not cover"
    );
    assert_eq!(
        provider.attests(&attested(AAAA, "gone")),
        None,
        "an absent anchor"
    );
    assert_eq!(
        provider.attests(&passkey(AAAA)),
        None,
        "not an attested key"
    );
    assert_eq!(
        MockFido2Provider::new().attests(&attested(AAAA, "roots")),
        None
    );
}

#[test]
fn a_passkey_row_is_stored_as_earlier_releases_wrote_it_and_other_keys_under_key() {
    let at = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let stored = serde_json::to_value(Fido2Credential::new(passkey(AAAA), "laptop", at)).unwrap();
    assert!(stored.get("passkey").is_some() && stored.get("key").is_none());
    let back: Fido2Credential = serde_json::from_value(stored).unwrap();
    assert!(matches!(back.key, Fido2Key::Passkey(_)));

    for key in [security_key(BBBB), attested(BBBB, "roots")] {
        let stored = serde_json::to_value(Fido2Credential::new(key, "token", at)).unwrap();
        assert!(stored.get("passkey").is_none() && stored.get("key").is_some());
        let back: Fido2Credential = serde_json::from_value(stored).unwrap();
        assert_eq!(back.cred_id(), &CredentialID::from(b"bbbb".to_vec()));
    }
    let attested_back: Fido2Credential = serde_json::from_value(
        serde_json::to_value(Fido2Credential::new(attested(BBBB, "roots"), "t", at)).unwrap(),
    )
    .unwrap();
    assert_eq!(attested_back.key.trust_anchor(), Some("roots"));
}

#[test]
fn a_row_naming_no_key_or_two_is_refused() {
    let at = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let none = json!({ "name": "x", "registered_at": at, "last_used_at": null });
    assert!(serde_json::from_value::<Fido2Credential>(none).is_err());
    let mut both = serde_json::to_value(Fido2Credential::new(passkey(AAAA), "x", at)).unwrap();
    both["key"] = serde_json::to_value(security_key(BBBB)).unwrap();
    assert!(serde_json::from_value::<Fido2Credential>(both).is_err());
}

/// The default `on_credential_used` is a no-op and must not panic.
#[test]
fn default_on_credential_used_is_noop() {
    let provider = MockFido2Provider::new();
    let device_id = axess_identity::testing::device("d-fido2-noop");
    let cred = CredentialID::from(vec![0u8; 16]);
    provider.on_credential_used(&cred, &device_id);
}

/// An adopter's override of the hook is what the trait dispatches to.
#[test]
fn override_captures_credential_and_device_id() {
    struct CountingProvider {
        inner: MockFido2Provider,
        captured: Mutex<Vec<(Vec<u8>, DeviceId)>>,
    }
    impl Fido2Provider for CountingProvider {
        fn relying_party_id(&self) -> &str {
            self.inner.relying_party_id()
        }
        fn start_authentication(
            &self,
            ceremony: &Fido2Ceremony,
            credentials: &[Fido2Key],
        ) -> WebauthnResult<(RequestChallengeResponse, Fido2Authentication)> {
            self.inner.start_authentication(ceremony, credentials)
        }
        fn finish_authentication(
            &self,
            assertion: &PublicKeyCredential,
            state: &Fido2Authentication,
        ) -> WebauthnResult<AuthenticationResult> {
            self.inner.finish_authentication(assertion, state)
        }
        fn start_registration(
            &self,
            ceremony: &Fido2Ceremony,
            user_id: uuid::Uuid,
            user_name: &str,
            display_name: &str,
            exclude: Option<Vec<CredentialID>>,
        ) -> WebauthnResult<(CreationChallengeResponse, Fido2Registration)> {
            self.inner
                .start_registration(ceremony, user_id, user_name, display_name, exclude)
        }
        fn finish_registration(
            &self,
            response: &RegisterPublicKeyCredential,
            state: &Fido2Registration,
        ) -> WebauthnResult<Fido2Key> {
            self.inner.finish_registration(response, state)
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
        fn on_credential_used(&self, credential_id: &CredentialID, device_id: &DeviceId) {
            let bytes: Vec<u8> = credential_id.clone();
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
