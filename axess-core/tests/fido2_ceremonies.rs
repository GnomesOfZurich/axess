#![cfg(all(feature = "testing", feature = "fido2"))]
//! The FIDO2 ceremony is chosen per operation: registration and login from
//! `Fido2Options`, a step-up from the step-up that names it; a login offers
//! only the credentials its ceremony accepts; and an assertion records what
//! it proved.

mod common;

use axess_core::Clock;
use axess_core::authn::AuditContext;
use axess_core::authn::assurance::{CredentialBinding, StepUp};
use axess_core::authn::error::AuthnError;
use axess_core::authn::factor::{
    FactorConfig, FactorCredential, FactorKind, FactorStep, Fido2Config, Fido2Credential,
    Fido2Options,
};
use axess_core::authn::service::{
    AuthnService, FactorOutcome, PrepareOutcome, RequestAuthnService,
};
use axess_core::authn::store::{AuthMethod, FactorStore};
use axess_core::authn::types::AuthnScope;
use axess_core::session::extractor::AuthSession;
use axess_core::testing::{
    MockClock,
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use axess_factors::fido2::{
    DefaultFido2Provider, Fido2Authentication, Fido2Ceremony, Fido2Key, Fido2Provider,
    Fido2Registration, SecurityKeyVerification,
};
use common::{session_for, test_tenant, test_user, uid};
use std::sync::Mutex;
use url::Url;
use webauthn_rs::prelude::*;

/// URL-safe base64 of `aaaa`, `bbbb` and `cccc`.
const AAAA: &str = "YWFhYQ";
const BBBB: &str = "YmJiYg";
const CCCC: &str = "Y2NjYw";

fn cred(id: &str) -> serde_json::Value {
    let coord = "A".repeat(43);
    serde_json::json!({
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
    Fido2Key::Passkey(serde_json::from_value(cred(id)).unwrap())
}

fn security_key(id: &str) -> Fido2Key {
    Fido2Key::SecurityKey(serde_json::from_value(cred(id)).unwrap())
}

fn attested(id: &str) -> Fido2Key {
    Fido2Key::AttestedPasskey {
        key: serde_json::from_value(cred(id)).unwrap(),
        trust_anchor: "roots".into(),
    }
}

fn result(id: &str, user_verified: bool, synced: bool) -> AuthenticationResult {
    serde_json::from_value(serde_json::json!({
        "cred_id": id, "needs_update": true, "user_verified": user_verified,
        "backup_state": synced, "backup_eligible": synced,
        "counter": 5, "extensions": {}
    }))
    .unwrap()
}

fn assertion() -> PublicKeyCredential {
    serde_json::from_value(serde_json::json!({
        "id": "AAAA", "rawId": "AAAA", "type": "public-key",
        "response": { "authenticatorData": "AAAA", "clientDataJSON": "AAAA",
                      "signature": "AAAA", "userHandle": null }
    }))
    .unwrap()
}

fn registration() -> RegisterPublicKeyCredential {
    serde_json::from_value(serde_json::json!({
        "id": "AAAA", "rawId": "AAAA", "type": "public-key",
        "response": { "attestationObject": "AAAA", "clientDataJSON": "AAAA" }
    }))
    .unwrap()
}

/// A trust anchor holding one self-signed root.
fn roots() -> AttestationCaList {
    let params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let der = params.self_signed(&key).unwrap().der().to_vec();
    let mut builder = AttestationCaListBuilder::new();
    builder
        .insert_device_der(&der, Uuid::nil(), "test".into(), Default::default())
        .unwrap();
    builder.build()
}

/// Real ceremony starts, recorded; every finish accepts. An assertion
/// verifies as `asserts` with the configured flags, and a registration
/// yields a key of the type its ceremony registers.
struct RecordingProvider {
    inner: DefaultFido2Provider,
    asked: Mutex<Vec<Fido2Ceremony>>,
    asserts: AuthenticationResult,
    vouches: bool,
}

impl Fido2Provider for RecordingProvider {
    fn relying_party_id(&self) -> &str {
        self.inner.relying_party_id()
    }
    fn start_authentication(
        &self,
        ceremony: &Fido2Ceremony,
        credentials: &[Fido2Key],
    ) -> WebauthnResult<(RequestChallengeResponse, Fido2Authentication)> {
        self.asked.lock().unwrap().push(ceremony.clone());
        self.inner.start_authentication(ceremony, credentials)
    }
    fn finish_authentication(
        &self,
        _: &PublicKeyCredential,
        _: &Fido2Authentication,
    ) -> WebauthnResult<AuthenticationResult> {
        Ok(self.asserts.clone())
    }
    fn start_registration(
        &self,
        ceremony: &Fido2Ceremony,
        id: Uuid,
        name: &str,
        display: &str,
        exclude: Option<Vec<CredentialID>>,
    ) -> WebauthnResult<(CreationChallengeResponse, Fido2Registration)> {
        self.asked.lock().unwrap().push(ceremony.clone());
        self.inner
            .start_registration(ceremony, id, name, display, exclude)
    }
    fn finish_registration(
        &self,
        _: &RegisterPublicKeyCredential,
        state: &Fido2Registration,
    ) -> WebauthnResult<Fido2Key> {
        Ok(match state.ceremony() {
            Fido2Ceremony::Passkey => passkey(CCCC),
            Fido2Ceremony::SecurityKey(_) => security_key(CCCC),
            Fido2Ceremony::AttestedPasskey { .. } => attested(CCCC),
        })
    }
    fn start_discoverable_authentication(
        &self,
    ) -> WebauthnResult<(RequestChallengeResponse, DiscoverableAuthentication)> {
        self.inner.start_discoverable_authentication()
    }
    fn finish_discoverable_authentication(
        &self,
        a: &PublicKeyCredential,
        s: DiscoverableAuthentication,
        k: &[DiscoverableKey],
    ) -> WebauthnResult<AuthenticationResult> {
        self.inner.finish_discoverable_authentication(a, s, k)
    }
    fn attests(&self, key: &Fido2Key) -> Option<String> {
        self.vouches
            .then(|| key.trust_anchor().map(str::to_string))
            .flatten()
    }
}

struct Fixture {
    service: RequestAuthnService<MockIdentityStore, MockFactorStore>,
    provider: std::sync::Arc<RecordingProvider>,
    factors: MockFactorStore,
    clock: MockClock,
    scope: AuthnScope,
}

/// A user holding `keys`, with a FIDO2-only login method, served by a
/// recording provider that asserts as `asserts`.
fn fixture(
    keys: Vec<Fido2Key>,
    options: Fido2Options,
    asserts: AuthenticationResult,
    vouches: bool,
) -> Fixture {
    let user = test_user("u1", "alice");
    let scope = AuthnScope::User {
        tenant_id: user.tenant_id,
        user_id: user.id,
    };
    let clock = MockClock::now();
    let credentials = keys
        .into_iter()
        .map(|key| Fido2Credential::new(key, "key", clock.now()))
        .collect();
    let factors = MockFactorStore::new()
        .with_method(
            &uid("u1"),
            AuthMethod {
                name: "passkey".into(),
                steps: vec![FactorStep::Required(FactorKind::Fido2)],
                scope: scope.clone(),
            },
        )
        .with_factor(
            scope.clone(),
            FactorConfig::Fido2(Fido2Config { credentials }),
        );
    let webauthn =
        WebauthnBuilder::new("localhost", &Url::parse("https://localhost:8443").unwrap())
            .unwrap()
            .build()
            .unwrap();
    let provider = std::sync::Arc::new(RecordingProvider {
        inner: DefaultFido2Provider::new(webauthn).with_trust_anchor("roots", roots()),
        asked: Mutex::new(Vec::new()),
        asserts,
        vouches,
    });
    let identity = MockIdentityStore::new()
        .with_default_tenant(test_tenant())
        .with_user(user);
    let service = AuthnService::builder(identity, factors.clone())
        .with_fido2(SharedProvider(provider.clone()))
        .with_clock(clock.clone())
        .with_fido2_options(options)
        .build()
        .with_audit_context(AuditContext::default());
    Fixture {
        service,
        provider,
        factors,
        clock,
        scope,
    }
}

/// The recording provider shared between the service and the test.
struct SharedProvider(std::sync::Arc<RecordingProvider>);

impl Fido2Provider for SharedProvider {
    fn relying_party_id(&self) -> &str {
        self.0.relying_party_id()
    }
    fn start_authentication(
        &self,
        c: &Fido2Ceremony,
        k: &[Fido2Key],
    ) -> WebauthnResult<(RequestChallengeResponse, Fido2Authentication)> {
        self.0.start_authentication(c, k)
    }
    fn finish_authentication(
        &self,
        a: &PublicKeyCredential,
        s: &Fido2Authentication,
    ) -> WebauthnResult<AuthenticationResult> {
        self.0.finish_authentication(a, s)
    }
    fn start_registration(
        &self,
        c: &Fido2Ceremony,
        id: Uuid,
        name: &str,
        display: &str,
        exclude: Option<Vec<CredentialID>>,
    ) -> WebauthnResult<(CreationChallengeResponse, Fido2Registration)> {
        self.0.start_registration(c, id, name, display, exclude)
    }
    fn finish_registration(
        &self,
        r: &RegisterPublicKeyCredential,
        s: &Fido2Registration,
    ) -> WebauthnResult<Fido2Key> {
        self.0.finish_registration(r, s)
    }
    fn start_discoverable_authentication(
        &self,
    ) -> WebauthnResult<(RequestChallengeResponse, DiscoverableAuthentication)> {
        self.0.start_discoverable_authentication()
    }
    fn finish_discoverable_authentication(
        &self,
        a: &PublicKeyCredential,
        s: DiscoverableAuthentication,
        k: &[DiscoverableKey],
    ) -> WebauthnResult<AuthenticationResult> {
        self.0.finish_discoverable_authentication(a, s, k)
    }
    fn attests(&self, key: &Fido2Key) -> Option<String> {
        self.0.attests(key)
    }
}

fn last_asked(f: &Fixture) -> Fido2Ceremony {
    f.provider
        .asked
        .lock()
        .unwrap()
        .last()
        .cloned()
        .expect("a ceremony ran")
}

fn challenge_options(outcome: PrepareOutcome) -> serde_json::Value {
    match outcome {
        PrepareOutcome::Fido2Challenge { challenge } => challenge["publicKey"].clone(),
        other => panic!("expected a FIDO2 challenge, got {other:?}"),
    }
}

async fn log_in(f: &Fixture, session: &AuthSession) -> FactorOutcome {
    f.service
        .begin_login("alice", "default", session)
        .await
        .unwrap();
    f.service.prepare_factor(session).await.unwrap();
    let cred = FactorCredential::fido2_assertion(&assertion()).unwrap();
    f.service.verify_factor(&cred, session).await.unwrap()
}

#[tokio::test]
async fn the_login_step_runs_the_login_ceremony_and_offers_only_what_it_accepts() {
    let options = Fido2Options {
        login_ceremony: Fido2Ceremony::SecurityKey(SecurityKeyVerification::Preferred),
        ..Fido2Options::default()
    };
    let f = fixture(
        vec![passkey(AAAA), security_key(BBBB)],
        options,
        result(BBBB, true, false),
        false,
    );
    let session = test_session();
    f.service
        .begin_login("alice", "default", &session)
        .await
        .unwrap();
    let options = challenge_options(f.service.prepare_factor(&session).await.unwrap());
    assert_eq!(
        last_asked(&f),
        Fido2Ceremony::SecurityKey(SecurityKeyVerification::Preferred)
    );
    assert_eq!(options["userVerification"], "preferred");
    assert_eq!(
        options["allowCredentials"].as_array().unwrap().len(),
        1,
        "the security-key ceremony offers the security key alone"
    );
}

#[tokio::test]
async fn a_login_ceremony_no_credential_fits_is_refused() {
    let options = Fido2Options {
        login_ceremony: Fido2Ceremony::AttestedPasskey {
            trust_anchor: "roots".into(),
        },
        ..Fido2Options::default()
    };
    let f = fixture(
        vec![passkey(AAAA)],
        options,
        result(AAAA, true, false),
        false,
    );
    let session = test_session();
    f.service
        .begin_login("alice", "default", &session)
        .await
        .unwrap();
    let err = f.service.prepare_factor(&session).await.unwrap_err();
    assert!(matches!(err, AuthnError::NoFlow), "got {err:?}");
}

#[tokio::test]
async fn an_assertion_records_its_user_verification_and_binding_at_the_clocks_time() {
    for (synced, binding) in [
        (false, CredentialBinding::DeviceBound),
        (true, CredentialBinding::Synced),
    ] {
        let f = fixture(
            vec![passkey(AAAA)],
            Fido2Options::default(),
            result(AAAA, true, synced),
            false,
        );
        let session = test_session();
        assert!(matches!(
            log_in(&f, &session).await,
            FactorOutcome::Authenticated
        ));
        assert_eq!(
            last_asked(&f),
            Fido2Ceremony::Passkey,
            "the default ceremony"
        );
        let record = session.assurance().await;
        assert_eq!(record.len(), 1);
        assert_eq!(record[0].kind, FactorKind::Fido2);
        assert!(record[0].user_verified);
        assert_eq!(record[0].credential, binding);
        assert_eq!(record[0].trust_anchor, None, "no attested ceremony ran");
        assert_eq!(record[0].at, f.clock.now());
    }
}

#[tokio::test]
async fn a_step_up_runs_the_ceremony_it_names_and_only_its_own() {
    let f = fixture(
        vec![attested(AAAA)],
        Fido2Options::default(),
        result(AAAA, true, false),
        true,
    );
    let session = test_session();
    assert!(matches!(
        log_in(&f, &session).await,
        FactorOutcome::Authenticated
    ));
    assert_eq!(
        session.assurance().await[0].trust_anchor,
        None,
        "the passkey ceremony is not an attested one"
    );

    let step_up: StepUp = "attested_passkey:roots".parse().unwrap();
    f.service
        .begin_step_up_for(&session, &step_up)
        .await
        .unwrap();
    f.clock.advance_secs(30);
    let options = challenge_options(f.service.prepare_factor(&session).await.unwrap());
    assert_eq!(
        last_asked(&f),
        Fido2Ceremony::AttestedPasskey {
            trust_anchor: "roots".into()
        }
    );
    assert_eq!(options["userVerification"], "required");
    let cred = FactorCredential::fido2_assertion(&assertion()).unwrap();
    assert!(matches!(
        f.service.verify_factor(&cred, &session).await.unwrap(),
        FactorOutcome::Authenticated
    ));
    let record = session.assurance().await;
    assert_eq!(record[0].trust_anchor.as_deref(), Some("roots"));
    assert_eq!(record[0].at, f.clock.now(), "the step-up's own time");
    assert_eq!(
        session.get_custom("axess.step_up.ceremony").await,
        None,
        "the ceremony ended with its step-up"
    );

    f.service
        .begin_step_up(&session, vec![FactorKind::Fido2])
        .await
        .unwrap();
    f.service.prepare_factor(&session).await.unwrap();
    assert_eq!(
        last_asked(&f),
        Fido2Ceremony::Passkey,
        "a plain step-up runs the login ceremony"
    );
}

#[tokio::test]
async fn an_attested_ceremony_claims_no_anchor_the_provider_does_not_vouch_for() {
    let options = Fido2Options {
        login_ceremony: Fido2Ceremony::AttestedPasskey {
            trust_anchor: "roots".into(),
        },
        ..Fido2Options::default()
    };
    let f = fixture(
        vec![attested(AAAA)],
        options,
        result(AAAA, true, false),
        false,
    );
    let session = test_session();
    assert!(matches!(
        log_in(&f, &session).await,
        FactorOutcome::Authenticated
    ));
    assert_eq!(session.assurance().await[0].trust_anchor, None);
}

async fn stored(f: &Fixture) -> Vec<Fido2Credential> {
    match f
        .factors
        .load_factor(&f.scope, FactorKind::Fido2)
        .await
        .unwrap()
    {
        Some(FactorConfig::Fido2(cfg)) => cfg.credentials,
        _ => Vec::new(),
    }
}

#[tokio::test]
async fn a_registration_runs_the_chosen_ceremony_and_stores_the_key_it_typed() {
    let options = Fido2Options {
        registration_ceremony: Fido2Ceremony::SecurityKey(SecurityKeyVerification::Preferred),
        ..Fido2Options::default()
    };
    let f = fixture(
        vec![passkey(AAAA)],
        options,
        result(AAAA, true, false),
        false,
    );
    let user = test_user("u1", "alice");
    let session = session_for(&user).await;

    f.service
        .begin_fido2_registration(&user, &session)
        .await
        .unwrap();
    assert_eq!(
        last_asked(&f),
        Fido2Ceremony::SecurityKey(SecurityKeyVerification::Preferred),
        "the configured registration ceremony"
    );
    f.service
        .finish_fido2_registration(&user, &registration(), "token", &session)
        .await
        .unwrap();
    assert!(matches!(stored(&f).await[1].key, Fido2Key::SecurityKey(_)));

    let attested_ceremony = Fido2Ceremony::AttestedPasskey {
        trust_anchor: "roots".into(),
    };
    let unknown = Fido2Ceremony::AttestedPasskey {
        trust_anchor: "elsewhere".into(),
    };
    let err = f
        .service
        .begin_fido2_registration_with(&user, &session, &unknown)
        .await
        .unwrap_err();
    assert!(
        matches!(err, AuthnError::NoFlow),
        "an anchor the provider lacks: {err:?}"
    );
    f.service
        .begin_fido2_registration_with(&user, &session, &attested_ceremony)
        .await
        .unwrap();
    assert_eq!(last_asked(&f), attested_ceremony, "one call's own ceremony");
}
