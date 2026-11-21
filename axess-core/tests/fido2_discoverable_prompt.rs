#![cfg(all(feature = "testing", feature = "fido2"))]
//! A discoverable login is one ceremony however the browser is asked to
//! present it: the prompt (autofill, a dialog, or a dialog led by another
//! device for cross-device authentication) changes the request options the
//! browser reads and nothing the finish verifies.

use axess_core::testing::fixtures as common;

use axess_core::authn::AuditContext;
use axess_core::authn::error::AuthnError;
use axess_core::authn::factor::{
    DiscoverablePrompt, FactorConfig, FactorKind, Fido2Config, Fido2Credential,
};
use axess_core::authn::service::{
    AuthnService, DiscoverableLogin, FactorOutcome, RequestAuthnService,
};
use axess_core::authn::store::AuthMethod;
use axess_core::authn::types::AuthnScope;
use axess_core::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use axess_factors::fido2::{
    DefaultFido2Provider, Fido2Authentication, Fido2Ceremony, Fido2Key, Fido2Provider,
    Fido2Registration,
};
use common::{start, test_clock, test_tenant, test_user};
use url::Url;
use webauthn_rs::prelude::*;

/// URL-safe base64 of `aaaa`.
const AAAA: &str = "YWFhYQ";

/// The stored passkey, as a phone reports one: reachable over the hybrid
/// transport and on the phone itself.
fn phone_passkey() -> Passkey {
    let coord = "A".repeat(43);
    serde_json::from_value(serde_json::json!({
        "cred": {
            "cred_id": AAAA,
            "cred": { "type_": "ES256",
                "key": { "EC_EC2": { "curve": "SECP256R1", "x": coord, "y": coord } } },
            "counter": 1,
            "transports": ["hybrid", "internal"],
            "user_verified": true,
            "backup_eligible": true,
            "backup_state": true,
            "registration_policy": "required",
            "extensions": {},
            "attestation": { "data": "None", "metadata": "None" },
            "attestation_format": "none"
        }
    }))
    .expect("passkey fixture")
}

/// The WebAuthn user handle on Alice's record, and its URL-safe base64.
const ALICE_HANDLE: &[u8; 16] = b"alice-handle-001";
const ALICE_HANDLE_B64: &str = "YWxpY2UtaGFuZGxlLTAwMQ";

/// Alice as the application resolves her from a credential id: the stored
/// user, with her WebAuthn handle.
fn alice() -> axess_core::authn::types::User {
    let mut user = test_user("u1", "alice");
    user.webauthn_id = Some(uuid::Uuid::from_bytes(*ALICE_HANDLE));
    user
}

/// An assertion by the phone's passkey, naming Alice.
fn assertion() -> PublicKeyCredential {
    serde_json::from_value(serde_json::json!({
        "id": "AAAA", "rawId": "AAAA", "type": "public-key",
        "response": { "authenticatorData": "AAAA", "clientDataJSON": "AAAA",
                      "signature": "AAAA", "userHandle": ALICE_HANDLE_B64 }
    }))
    .unwrap()
}

/// Real ceremony starts; an assertion verifies as the stored passkey when
/// there is a key to verify it against, as a phone's signature would. With
/// `issues_mediation` false its discoverable challenge carries no
/// mediation, as a provider of an adopter's own may issue it.
struct PhoneProvider {
    relying_party: DefaultFido2Provider,
    issues_mediation: bool,
}

impl Fido2Provider for PhoneProvider {
    fn relying_party_id(&self) -> &str {
        self.relying_party.relying_party_id()
    }
    fn start_authentication(
        &self,
        ceremony: &Fido2Ceremony,
        credentials: &[Fido2Key],
    ) -> WebauthnResult<(RequestChallengeResponse, Fido2Authentication)> {
        self.relying_party
            .start_authentication(ceremony, credentials)
    }
    fn finish_authentication(
        &self,
        assertion: &PublicKeyCredential,
        state: &Fido2Authentication,
    ) -> WebauthnResult<AuthenticationResult> {
        self.relying_party.finish_authentication(assertion, state)
    }
    fn start_registration(
        &self,
        ceremony: &Fido2Ceremony,
        id: uuid::Uuid,
        name: &str,
        display: &str,
        exclude: Option<Vec<CredentialID>>,
    ) -> WebauthnResult<(CreationChallengeResponse, Fido2Registration)> {
        self.relying_party
            .start_registration(ceremony, id, name, display, exclude)
    }
    fn finish_registration(
        &self,
        response: &RegisterPublicKeyCredential,
        state: &Fido2Registration,
    ) -> WebauthnResult<Fido2Key> {
        self.relying_party.finish_registration(response, state)
    }
    fn start_discoverable_authentication(
        &self,
    ) -> WebauthnResult<(RequestChallengeResponse, DiscoverableAuthentication)> {
        let (mut challenge, state) = self.relying_party.start_discoverable_authentication()?;
        if !self.issues_mediation {
            challenge.mediation = None;
        }
        Ok((challenge, state))
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
        Ok(serde_json::from_value(serde_json::json!({
            "cred_id": AAAA, "needs_update": true, "user_verified": true,
            "backup_state": true, "backup_eligible": true,
            "counter": 5, "extensions": {}
        }))
        .unwrap())
    }
}

struct Fixture {
    service: RequestAuthnService<MockIdentityStore, MockFactorStore>,
    credentials: Vec<Fido2Credential>,
}

/// Alice, with the phone's passkey stored and a passkey-only login method,
/// on a provider that issues the discoverable challenge as `webauthn-rs`
/// does.
fn fixture() -> Fixture {
    fixture_on(true)
}

/// [`fixture`], on a provider that issues mediation or none.
fn fixture_on(issues_mediation: bool) -> Fixture {
    let user = test_user("u1", "alice");
    let scope = AuthnScope::User {
        tenant_id: user.tenant_id,
        user_id: user.id,
    };
    let clock = test_clock();
    let credentials = vec![Fido2Credential::new(phone_passkey(), "phone", start())];
    let factors = MockFactorStore::new()
        .with_method(
            &user.id,
            AuthMethod::sequential("passkey", vec![FactorKind::Fido2], scope.clone()),
        )
        .with_factor(
            scope,
            FactorConfig::Fido2(Fido2Config {
                credentials: credentials.clone(),
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
    let service = AuthnService::builder(identity, factors)
        .with_fido2(PhoneProvider {
            relying_party: DefaultFido2Provider::new(webauthn),
            issues_mediation,
        })
        .with_clock(clock)
        .build()
        .with_audit_context(AuditContext::default());
    Fixture {
        service,
        credentials,
    }
}

#[tokio::test]
async fn the_plain_begin_of_the_default_provider_is_the_autofill_prompt() {
    let f = fixture();
    let plain = f
        .service
        .begin_discoverable_login(&test_session())
        .await
        .unwrap();
    let named = f
        .service
        .begin_discoverable_login_with(
            &test_session(),
            DiscoverableLogin::default().with_prompt(DiscoverablePrompt::Autofill),
        )
        .await
        .unwrap();
    for challenge in [plain, named] {
        assert_eq!(challenge["mediation"], "conditional", "{challenge}");
        assert!(challenge["publicKey"].get("hints").is_none(), "{challenge}");
    }
}

/// The begins that take no prompt send the challenge as the provider issued
/// it; only a prompt the caller chose rewrites it.
#[tokio::test]
async fn a_begin_without_a_prompt_keeps_the_providers_challenge() {
    let f = fixture_on(false);
    let plain = f
        .service
        .begin_discoverable_login(&test_session())
        .await
        .unwrap();
    let in_tenant = f
        .service
        .begin_discoverable_login_in_tenant(&test_tenant().id, &test_session())
        .await
        .unwrap();
    for challenge in [plain, in_tenant] {
        assert!(challenge.get("mediation").is_none(), "{challenge}");
        assert!(challenge["publicKey"].get("hints").is_none(), "{challenge}");
    }
    let chosen = f
        .service
        .begin_discoverable_login_with(&test_session(), DiscoverableLogin::default())
        .await
        .unwrap();
    assert_eq!(chosen["mediation"], "conditional", "{chosen}");
}

#[tokio::test]
async fn a_modal_prompt_asks_for_a_dialog_and_gives_no_hint() {
    let f = fixture();
    let challenge = f
        .service
        .begin_discoverable_login_with(
            &test_session(),
            DiscoverableLogin::default().with_prompt(DiscoverablePrompt::Modal),
        )
        .await
        .unwrap();
    assert!(challenge.get("mediation").is_none(), "{challenge}");
    assert!(challenge["publicKey"].get("hints").is_none(), "{challenge}");
}

/// The relying party's whole part in cross-device authentication: a dialog
/// hinted at the hybrid transport, over the request every discoverable
/// login sends (no credential named, user verification required).
#[tokio::test]
async fn a_cross_device_prompt_hints_at_the_hybrid_transport() {
    let f = fixture();
    let challenge = f
        .service
        .begin_discoverable_login_with(
            &test_session(),
            DiscoverableLogin::default().with_prompt(DiscoverablePrompt::CrossDevice),
        )
        .await
        .unwrap();
    assert!(challenge.get("mediation").is_none(), "{challenge}");
    let request = &challenge["publicKey"];
    assert_eq!(request["hints"], serde_json::json!(["hybrid"]));
    assert_eq!(request["userVerification"], "required");
    assert_eq!(request["allowCredentials"], serde_json::json!([]));
    assert_eq!(request["rpId"], "localhost");
}

#[tokio::test]
async fn a_cross_device_login_finishes_as_any_discoverable_login_does() {
    let f = fixture();
    let session = test_session();
    f.service
        .begin_discoverable_login_with(
            &session,
            DiscoverableLogin::default().with_prompt(DiscoverablePrompt::CrossDevice),
        )
        .await
        .unwrap();

    let outcome = f
        .service
        .finish_discoverable_login(&assertion(), &alice(), &f.credentials, &session)
        .await
        .unwrap();

    assert!(
        matches!(outcome, FactorOutcome::Authenticated),
        "{outcome:?}"
    );
    let proofs = session.assurance().await;
    assert_eq!(proofs.len(), 1);
    assert_eq!(proofs[0].kind, FactorKind::Fido2);
    assert!(proofs[0].user_verified);
}

#[tokio::test]
async fn a_cross_device_login_keeps_the_tenant_it_was_begun_for() {
    let f = fixture();
    let session = test_session();
    f.service
        .begin_discoverable_login_with(
            &session,
            DiscoverableLogin::default()
                .in_tenant(axess_identity::testing::tenant("another-tenant"))
                .with_prompt(DiscoverablePrompt::CrossDevice),
        )
        .await
        .unwrap();

    let err = f
        .service
        .finish_discoverable_login(&assertion(), &alice(), &f.credentials, &session)
        .await
        .unwrap_err();

    assert!(matches!(err, AuthnError::CrossTenant), "{err:?}");
    assert!(!session.is_authenticated().await);
}

/// A login step that names its credentials (a login method's FIDO2 step, a
/// step-up) needs no prompt to reach a phone: the request lists each
/// credential with the transports it registered, and the browser offers the
/// QR code for one that registered `hybrid`.
#[tokio::test]
async fn a_named_credential_carries_the_hybrid_transport_it_registered() {
    let webauthn =
        WebauthnBuilder::new("localhost", &Url::parse("https://localhost:8443").unwrap())
            .unwrap()
            .build()
            .unwrap();
    let (challenge, _) = DefaultFido2Provider::new(webauthn)
        .start_authentication(&Fido2Ceremony::Passkey, &[phone_passkey().into()])
        .unwrap();
    let challenge = serde_json::to_value(challenge).unwrap();
    assert_eq!(
        challenge["publicKey"]["allowCredentials"][0]["transports"],
        serde_json::json!(["hybrid", "internal"])
    );
    assert!(challenge["publicKey"].get("hints").is_none(), "{challenge}");
}
