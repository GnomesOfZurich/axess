#![cfg(all(feature = "testing", feature = "fido2"))]
//! A FIDO2 challenge is finished at most once and only within the ceremony
//! timeout, and a begin retires the ceremony of its kind the session held
//! before it: when the begin fails, the earlier challenge, which the browser
//! still holds, finishes nothing.

use axess_core::testing::fixtures as common;

use axess_core::authn::AuditContext;
use axess_core::authn::error::AuthnError;
use axess_core::authn::factor::{
    FactorConfig, FactorCredential, FactorKind, Fido2Config, Fido2Credential,
};
use axess_core::authn::service::{
    AuthnService, FactorOutcome, LoginOutcome, PrepareOutcome, RequestAuthnService,
};
use axess_core::authn::store::{AuthMethod, FactorStore};
use axess_core::authn::types::AuthnScope;
use axess_core::testing::{
    MockClock,
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use axess_factors::fido2::{
    DefaultFido2Provider, Fido2Authentication, Fido2Ceremony, Fido2Key, Fido2Provider,
    Fido2Registration,
};
use common::{session_for, start, test_clock, test_tenant, test_user};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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

fn asserted() -> AuthenticationResult {
    serde_json::from_value(serde_json::json!({
        "cred_id": AAAA, "needs_update": true, "user_verified": true,
        "backup_state": false, "backup_eligible": false,
        "counter": 5, "extensions": {}
    }))
    .expect("an authentication result")
}

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

/// Real ceremony starts, each refused while `refuses_starts` is set; every
/// finish accepts, so only the ceremony state the session holds stands
/// between a response and its effect.
struct Switchable {
    relying_party: DefaultFido2Provider,
    refuses_starts: Arc<AtomicBool>,
}

impl Switchable {
    fn refused<T>(&self) -> WebauthnResult<T> {
        Err(WebauthnError::Configuration)
    }
    fn refusing(&self) -> bool {
        self.refuses_starts.load(Ordering::SeqCst)
    }
}

impl Fido2Provider for Switchable {
    fn relying_party_id(&self) -> &str {
        self.relying_party.relying_party_id()
    }
    fn start_authentication(
        &self,
        ceremony: &Fido2Ceremony,
        credentials: &[Fido2Key],
    ) -> WebauthnResult<(RequestChallengeResponse, Fido2Authentication)> {
        if self.refusing() {
            return self.refused();
        }
        self.relying_party
            .start_authentication(ceremony, credentials)
    }
    fn finish_authentication(
        &self,
        assertion: &PublicKeyCredential,
        state: &Fido2Authentication,
    ) -> WebauthnResult<AuthenticationResult> {
        tracing::debug!(id = %assertion.id, ceremony = %state.ceremony(), "assertion accepted");
        Ok(asserted())
    }
    fn start_registration(
        &self,
        ceremony: &Fido2Ceremony,
        id: uuid::Uuid,
        name: &str,
        display: &str,
        exclude: Option<Vec<CredentialID>>,
    ) -> WebauthnResult<(CreationChallengeResponse, Fido2Registration)> {
        if self.refusing() {
            return self.refused();
        }
        self.relying_party
            .start_registration(ceremony, id, name, display, exclude)
    }
    fn finish_registration(
        &self,
        response: &RegisterPublicKeyCredential,
        state: &Fido2Registration,
    ) -> WebauthnResult<Fido2Key> {
        tracing::debug!(id = %response.id, ceremony = %state.ceremony(), "registration accepted");
        Ok(passkey(BBBB).into())
    }
    fn start_discoverable_authentication(
        &self,
    ) -> WebauthnResult<(RequestChallengeResponse, DiscoverableAuthentication)> {
        if self.refusing() {
            return self.refused();
        }
        self.relying_party.start_discoverable_authentication()
    }
    fn finish_discoverable_authentication(
        &self,
        assertion: &PublicKeyCredential,
        state: DiscoverableAuthentication,
        keys: &[DiscoverableKey],
    ) -> WebauthnResult<AuthenticationResult> {
        tracing::debug!(id = %assertion.id, ?state, "assertion accepted");
        if keys.is_empty() {
            return Err(WebauthnError::CredentialNotFound);
        }
        Ok(asserted())
    }
}

struct Fixture {
    service: RequestAuthnService<MockIdentityStore, MockFactorStore>,
    /// The clock the service and the identity store run on.
    clock: MockClock,
    factors: MockFactorStore,
    scope: AuthnScope,
    refuses_starts: Arc<AtomicBool>,
    credentials: Vec<Fido2Credential>,
}

/// Alice as the application resolves her: the stored user, with her handle.
fn alice() -> axess_core::authn::types::User {
    let mut user = test_user("u1", "alice");
    user.webauthn_id = Some(uuid::Uuid::from_bytes(*ALICE_HANDLE));
    user
}

/// Alice, with passkey `AAAA` stored and a passkey-only login method.
fn fixture() -> Fixture {
    let user = alice();
    let scope = AuthnScope::User {
        tenant_id: user.tenant_id,
        user_id: user.id,
    };
    let clock = test_clock();
    let credentials = vec![Fido2Credential::new(passkey(AAAA), "first", start())];
    let factors = MockFactorStore::new()
        .with_method(
            &user.id,
            AuthMethod::sequential("passkey", vec![FactorKind::Fido2], scope.clone()),
        )
        .with_factor(
            scope.clone(),
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
    let refuses_starts = Arc::new(AtomicBool::new(false));
    let service = AuthnService::builder(identity, factors.clone())
        .with_fido2(Switchable {
            relying_party: DefaultFido2Provider::new(webauthn),
            refuses_starts: refuses_starts.clone(),
        })
        .with_clock(clock.clone())
        .build()
        .with_audit_context(AuditContext::default());
    Fixture {
        service,
        clock,
        factors,
        scope,
        refuses_starts,
        credentials,
    }
}

async fn stored_ids(f: &Fixture) -> Vec<CredentialID> {
    match f
        .factors
        .load_factor(&f.scope, FactorKind::Fido2)
        .await
        .unwrap()
    {
        Some(FactorConfig::Fido2(cfg)) => cfg
            .credentials
            .iter()
            .map(|c| c.cred_id().clone())
            .collect(),
        _ => vec![],
    }
}

/// A passwordless ceremony bound to a tenant, then a begin that fails: the
/// first challenge must not finish, and above all not without the tenant it
/// was bound to.
#[tokio::test]
async fn a_failed_passwordless_begin_retires_the_earlier_tenant_bound_ceremony() {
    let f = fixture();
    let session = test_session();
    let another_tenant = axess_identity::testing::tenant("another-tenant");
    f.service
        .begin_discoverable_login_in_tenant(&another_tenant, &session)
        .await
        .unwrap();

    f.refuses_starts.store(true, Ordering::SeqCst);
    let second = f.service.begin_discoverable_login(&session).await;
    assert!(matches!(second, Err(AuthnError::NoFlow)), "{second:?}");
    f.refuses_starts.store(false, Ordering::SeqCst);

    let finished = f
        .service
        .finish_discoverable_login(&assertion(), &alice(), &f.credentials, &session)
        .await;
    assert!(
        matches!(finished, Err(AuthnError::NoFlow)),
        "the first challenge finished after a failed begin: {finished:?}"
    );
    assert!(!session.is_authenticated().await);
}

/// The same ceremony finished twice: the second finish finds nothing.
#[tokio::test]
async fn a_passwordless_challenge_is_finished_once() {
    let f = fixture();
    let session = test_session();
    f.service.begin_discoverable_login(&session).await.unwrap();
    let first = f
        .service
        .finish_discoverable_login(&assertion(), &alice(), &f.credentials, &session)
        .await;
    assert!(
        matches!(first, Ok(FactorOutcome::Authenticated)),
        "{first:?}"
    );

    let again = f
        .service
        .finish_discoverable_login(&assertion(), &alice(), &f.credentials, &session)
        .await;
    assert!(matches!(again, Err(AuthnError::NoFlow)), "{again:?}");
}

#[tokio::test]
async fn a_failed_registration_begin_retires_the_earlier_registration() {
    let f = fixture();
    let user = alice();
    let session = session_for(&user).await;
    f.service
        .begin_fido2_registration(&user, &session)
        .await
        .unwrap();

    f.refuses_starts.store(true, Ordering::SeqCst);
    let second = f.service.begin_fido2_registration(&user, &session).await;
    assert!(matches!(second, Err(AuthnError::NoFlow)), "{second:?}");
    f.refuses_starts.store(false, Ordering::SeqCst);

    let finished = f
        .service
        .finish_fido2_registration(&user, &registration(), "second", &session)
        .await;
    assert!(
        matches!(finished, Err(AuthnError::NoFlow)),
        "the first challenge finished after a failed begin: {finished:?}"
    );
    assert_eq!(stored_ids(&f).await.len(), 1, "nothing was registered");
}

#[tokio::test]
async fn a_failed_challenge_for_a_login_step_retires_the_earlier_challenge() {
    let f = fixture();
    let session = test_session();
    let begun = f
        .service
        .begin_login("alice", "default", &session)
        .await
        .unwrap();
    assert!(
        matches!(begun, LoginOutcome::FactorRequired(FactorKind::Fido2)),
        "{begun:?}"
    );
    let first = f.service.prepare_factor(&session).await;
    assert!(matches!(first, Ok(PrepareOutcome::Fido2Challenge { .. })));

    f.refuses_starts.store(true, Ordering::SeqCst);
    let second = f.service.prepare_factor(&session).await;
    assert!(matches!(second, Err(AuthnError::NoFlow)));
    f.refuses_starts.store(false, Ordering::SeqCst);

    let credential = FactorCredential::fido2_assertion(&assertion()).unwrap();
    let verified = f.service.verify_factor(&credential, &session).await;
    assert!(
        matches!(verified, Ok(FactorOutcome::InvalidCredential)),
        "the first challenge was answered after a failed one: {verified:?}"
    );
    assert!(!session.is_authenticated().await);
}

/// A login step's challenge, answered `seconds` after it was issued.
async fn answer_a_login_challenge_after(seconds: i64) -> (FactorOutcome, bool) {
    let f = fixture();
    let session = test_session();
    f.service
        .begin_login("alice", "default", &session)
        .await
        .unwrap();
    let challenge = f.service.prepare_factor(&session).await;
    assert!(matches!(
        challenge,
        Ok(PrepareOutcome::Fido2Challenge { .. })
    ));

    f.clock.advance_secs(seconds);
    let credential = FactorCredential::fido2_assertion(&assertion()).unwrap();
    let outcome = f
        .service
        .verify_factor(&credential, &session)
        .await
        .unwrap();
    (outcome, session.is_authenticated().await)
}

/// A challenge the page never answers and never reports does not stay
/// usable: past the ceremony timeout (five minutes by default) its answer
/// verifies nothing.
#[tokio::test]
async fn a_login_steps_challenge_is_refused_past_the_ceremony_timeout() {
    let (outcome, signed_in) = answer_a_login_challenge_after(301).await;
    assert!(
        matches!(outcome, FactorOutcome::InvalidCredential),
        "{outcome:?}"
    );
    assert!(!signed_in);
}

#[tokio::test]
async fn a_login_steps_challenge_is_answered_at_the_ceremony_timeout() {
    let (outcome, signed_in) = answer_a_login_challenge_after(300).await;
    assert!(
        matches!(outcome, FactorOutcome::Authenticated),
        "{outcome:?}"
    );
    assert!(signed_in);
}
