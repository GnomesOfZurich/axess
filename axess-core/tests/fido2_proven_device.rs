#![cfg(all(feature = "testing", feature = "fido2", feature = "device"))]
//! The device-binding hook of a FIDO2 ceremony is handed the device the
//! request proved. A request that presents a session cookie and no proof of
//! the session's device (a stolen cookie, without the device token) keeps
//! that device as a label and proves nothing: a ceremony on it reports no
//! device to the hook, so the record of which device used a credential
//! never names a device for a ceremony another browser performed.

use axess_core::testing::fixtures as common;

use std::sync::{Arc, Mutex};

use axess_core::authn::AuditContext;
use axess_core::authn::factor::{
    FactorConfig, FactorCredential, FactorKind, FactorStep, Fido2Config, Fido2Credential,
};
use axess_core::authn::ids::DeviceId;
use axess_core::authn::service::{AuthnService, RequestAuthnService};
use axess_core::authn::store::AuthMethod;
use axess_core::authn::types::AuthnScope;
use axess_core::session::extractor::AuthSession;
use axess_core::testing::{
    AuthSessionTestExt,
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session_on_device, test_session_on_unproven_device,
};
use axess_factors::fido2::{
    DefaultFido2Provider, Fido2Authentication, Fido2Ceremony, Fido2Key, Fido2Provider,
    Fido2Registration,
};
use common::{start, test_clock, test_tenant, test_user, uid};
use url::Url;
use webauthn_rs::prelude::*;

/// URL-safe base64 of `aaaa` and `bbbb`.
const AAAA: &str = "YWFhYQ";
const BBBB: &str = "YmJiYg";

/// The WebAuthn user handle on Alice's record, and its URL-safe base64.
const ALICE_HANDLE: &[u8; 16] = b"alice-handle-001";
const ALICE_HANDLE_B64: &str = "YWxpY2UtaGFuZGxlLTAwMQ";

fn passkey(id: &str) -> Passkey {
    let coord = "A".repeat(43);
    serde_json::from_value(serde_json::json!({
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
    }))
    .expect("passkey fixture")
}

fn result_for(id: &str) -> AuthenticationResult {
    serde_json::from_value(serde_json::json!({
        "cred_id": id, "needs_update": true, "user_verified": true,
        "backup_state": false, "backup_eligible": false,
        "counter": 5, "extensions": {}
    }))
    .expect("authentication result fixture")
}

/// Alice as the application resolves her from a credential id: the stored
/// user, with her WebAuthn handle.
fn alice() -> axess_core::authn::types::User {
    let mut user = test_user("u1", "alice");
    user.webauthn_id = Some(uuid::Uuid::from_bytes(*ALICE_HANDLE));
    user
}

/// An assertion by Alice's passkey, naming Alice.
fn assertion() -> PublicKeyCredential {
    serde_json::from_value(serde_json::json!({
        "id": "AAAA", "rawId": "AAAA", "type": "public-key",
        "response": { "authenticatorData": "AAAA", "clientDataJSON": "AAAA",
                      "signature": "AAAA", "userHandle": ALICE_HANDLE_B64 }
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

/// Real ceremony starts; every finish step accepts anything (an assertion
/// verifies as the `AAAA` credential, a registration yields `BBBB`). Keeps
/// the device each call of the device-binding hook was handed.
struct RecordingProvider {
    inner: DefaultFido2Provider,
    used: Arc<Mutex<Vec<DeviceId>>>,
}

impl Fido2Provider for RecordingProvider {
    fn relying_party_id(&self) -> &str {
        self.inner.relying_party_id()
    }
    fn start_authentication(
        &self,
        ceremony: &Fido2Ceremony,
        c: &[Fido2Key],
    ) -> WebauthnResult<(RequestChallengeResponse, Fido2Authentication)> {
        self.inner.start_authentication(ceremony, c)
    }
    fn finish_authentication(
        &self,
        _: &PublicKeyCredential,
        _: &Fido2Authentication,
    ) -> WebauthnResult<AuthenticationResult> {
        Ok(result_for(AAAA))
    }
    fn start_registration(
        &self,
        ceremony: &Fido2Ceremony,
        id: uuid::Uuid,
        name: &str,
        display: &str,
        exclude: Option<Vec<CredentialID>>,
    ) -> WebauthnResult<(CreationChallengeResponse, Fido2Registration)> {
        self.inner
            .start_registration(ceremony, id, name, display, exclude)
    }
    fn finish_registration(
        &self,
        _: &RegisterPublicKeyCredential,
        _: &Fido2Registration,
    ) -> WebauthnResult<Fido2Key> {
        Ok(passkey(BBBB).into())
    }
    fn start_discoverable_authentication(
        &self,
    ) -> WebauthnResult<(RequestChallengeResponse, DiscoverableAuthentication)> {
        self.inner.start_discoverable_authentication()
    }
    fn finish_discoverable_authentication(
        &self,
        _: &PublicKeyCredential,
        _: DiscoverableAuthentication,
        keys: &[DiscoverableKey],
    ) -> WebauthnResult<AuthenticationResult> {
        if keys.is_empty() {
            return Err(WebauthnError::CredentialNotFound);
        }
        Ok(result_for(AAAA))
    }
    fn on_credential_used(&self, _: &CredentialID, device_id: &DeviceId) {
        self.used.lock().unwrap().push(*device_id);
    }
}

/// Alice, with the passkey `AAAA` and a passkey-only login method, and the
/// devices the hook was handed.
fn service() -> (
    RequestAuthnService<MockIdentityStore, MockFactorStore>,
    Arc<Mutex<Vec<DeviceId>>>,
) {
    let user = alice();
    let scope = AuthnScope::User {
        tenant_id: user.tenant_id,
        user_id: user.id,
    };
    let clock = test_clock();
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
            scope,
            FactorConfig::Fido2(Fido2Config {
                credentials: vec![Fido2Credential::new(passkey(AAAA), "first", start())],
            }),
        );
    let webauthn =
        WebauthnBuilder::new("localhost", &Url::parse("https://localhost:8443").unwrap())
            .unwrap()
            .build()
            .unwrap();
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_default_tenant(test_tenant())
        .with_user(user);
    let used = Arc::new(Mutex::new(Vec::new()));
    let service = AuthnService::builder(identity, factors)
        .with_fido2(RecordingProvider {
            inner: DefaultFido2Provider::new(webauthn),
            used: used.clone(),
        })
        .with_clock(clock)
        .build()
        .with_audit_context(AuditContext::default());
    (service, used)
}

fn device() -> DeviceId {
    axess_core::authn::ids::testing::device("alices-laptop")
}

/// The session of each case: on a request that proved the device, and on
/// one that only kept it. The hook is handed the device, and nothing.
fn cases() -> [(AuthSession, Vec<DeviceId>); 2] {
    [
        (test_session_on_device(device()), vec![device()]),
        (test_session_on_unproven_device(device()), Vec::new()),
    ]
}

#[tokio::test]
async fn a_passkey_login_hands_the_hook_the_device_the_request_proved() {
    for (session, expected) in cases() {
        let (service, used) = service();
        service
            .begin_login("alice", "default", &session)
            .await
            .unwrap();
        service.prepare_factor(&session).await.unwrap();
        let credential = FactorCredential::fido2_assertion(&assertion()).unwrap();
        service.verify_factor(&credential, &session).await.unwrap();
        assert!(session.is_authenticated().await);
        assert_eq!(*used.lock().unwrap(), expected);
    }
}

#[tokio::test]
async fn a_discoverable_login_hands_the_hook_the_device_the_request_proved() {
    for (session, expected) in cases() {
        let (service, used) = service();
        service.begin_discoverable_login(&session).await.unwrap();
        let stored = vec![Fido2Credential::new(passkey(AAAA), "first", start())];
        service
            .finish_discoverable_login(&assertion(), &alice(), &stored, &session)
            .await
            .unwrap();
        assert!(session.is_authenticated().await);
        assert_eq!(*used.lock().unwrap(), expected);
    }
}

#[tokio::test]
async fn a_registration_hands_the_hook_the_device_the_request_proved() {
    for (session, expected) in cases() {
        let (service, used) = service();
        let user = alice();
        session
            .set_authenticated(user.id, user.tenant_id, start())
            .await;
        service
            .begin_fido2_registration(&user, &session)
            .await
            .unwrap();
        service
            .finish_fido2_registration(&user, &registration(), "second", &session)
            .await
            .unwrap();
        assert_eq!(*used.lock().unwrap(), expected);
    }
}
