#![cfg(all(feature = "testing", feature = "fido2"))]
//! A FIDO2 login authenticates only while the passkey it used is still
//! stored, and the ceremony state of each flow is single-use and separate.

mod common;

use axess_core::Clock;
use axess_core::authn::AuditContext;
use axess_core::authn::error::AuthnError;
use axess_core::authn::factor::{
    FactorConfig, FactorCredential, FactorKind, Fido2Config, Fido2Credential, Fido2Options,
};
use axess_core::authn::service::FactorOutcome;
use axess_core::authn::service::{AuthnService, RequestAuthnService};
use axess_core::authn::store::{AuthMethod, FactorStore, IdentityAdmin};
use axess_core::authn::types::{AuthnScope, StatusDetail};
use axess_core::testing::{
    MockClock,
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use axess_factors::fido2::{DefaultFido2Provider, Fido2Provider};
use common::{session_for, test_tenant, test_user, uid};
use url::Url;
use webauthn_rs::prelude::*;

/// URL-safe base64 of `aaaa` and `bbbb`.
const AAAA: &str = "YWFhYQ";
const BBBB: &str = "YmJiYg";

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

/// Real ceremony starts; every finish step accepts anything. An assertion
/// verifies as the `AAAA` credential and a registration yields `BBBB`.
struct AcceptingProvider(DefaultFido2Provider);

impl Fido2Provider for AcceptingProvider {
    fn start_authentication(
        &self,
        c: &[Passkey],
    ) -> WebauthnResult<(RequestChallengeResponse, PasskeyAuthentication)> {
        self.0.start_authentication(c)
    }
    fn finish_authentication(
        &self,
        _: &PublicKeyCredential,
        _: &PasskeyAuthentication,
    ) -> WebauthnResult<AuthenticationResult> {
        Ok(result_for(AAAA))
    }
    fn start_registration(
        &self,
        id: uuid::Uuid,
        name: &str,
        display: &str,
        exclude: Option<Vec<CredentialID>>,
    ) -> WebauthnResult<(CreationChallengeResponse, PasskeyRegistration)> {
        self.0.start_registration(id, name, display, exclude)
    }
    fn finish_registration(
        &self,
        _: &RegisterPublicKeyCredential,
        _: &PasskeyRegistration,
    ) -> WebauthnResult<Passkey> {
        Ok(passkey(BBBB))
    }
    fn start_discoverable_authentication(
        &self,
    ) -> WebauthnResult<(RequestChallengeResponse, DiscoverableAuthentication)> {
        self.0.start_discoverable_authentication()
    }
    fn finish_discoverable_authentication(
        &self,
        _: &PublicKeyCredential,
        _: DiscoverableAuthentication,
        _: &[DiscoverableKey],
    ) -> WebauthnResult<AuthenticationResult> {
        Ok(result_for(AAAA))
    }
}

struct Fixture {
    service: RequestAuthnService<MockIdentityStore, MockFactorStore>,
    identity: MockIdentityStore,
    factors: MockFactorStore,
    clock: MockClock,
    scope: AuthnScope,
    stored_at: chrono::DateTime<chrono::Utc>,
}

/// A user with passkey `AAAA` stored (when `with_passkey`) and a
/// FIDO2-only login method.
fn fixture(with_passkey: bool) -> Fixture {
    fixture_with(
        with_passkey,
        vec![vec![FactorKind::Fido2]],
        axess_core::authn::types::EntityState::Active,
    )
}

/// As [`fixture`], with the user's login methods (each a list of required
/// factors, in order) and the tenant's status chosen by the test.
fn fixture_with(
    with_passkey: bool,
    methods: Vec<Vec<FactorKind>>,
    tenant_status: axess_core::authn::types::EntityState,
) -> Fixture {
    let user = test_user("u1", "alice");
    let scope = AuthnScope::User {
        tenant_id: user.tenant_id,
        user_id: user.id,
    };
    let clock = MockClock::now();
    let stored_at = chrono::Utc::now();
    let mut factors = MockFactorStore::new();
    for (n, kinds) in methods.into_iter().enumerate() {
        factors = factors.with_method(
            &uid("u1"),
            AuthMethod::sequential(format!("method-{n}"), kinds, scope.clone()),
        );
    }
    if with_passkey {
        factors = factors.with_factor(
            scope.clone(),
            FactorConfig::Fido2(Fido2Config {
                credentials: vec![Fido2Credential::new(passkey(AAAA), "first", stored_at)],
            }),
        );
    }
    let webauthn =
        WebauthnBuilder::new("localhost", &Url::parse("https://localhost:8443").unwrap())
            .unwrap()
            .build()
            .unwrap();
    let mut tenant = test_tenant();
    tenant.status = tenant_status;
    let identity = MockIdentityStore::new()
        .with_default_tenant(tenant)
        .with_user(user);
    let service = AuthnService::builder(identity.clone(), factors.clone())
        .with_fido2(AcceptingProvider(DefaultFido2Provider::new(webauthn)))
        .with_clock(clock.clone())
        .with_fido2_options(Fido2Options::default())
        .build()
        .with_audit_context(AuditContext::default());
    Fixture {
        service,
        identity,
        factors,
        clock,
        scope,
        stored_at,
    }
}

async fn stored(f: &Fixture) -> Option<Vec<Fido2Credential>> {
    match f
        .factors
        .load_factor(&f.scope, FactorKind::Fido2)
        .await
        .unwrap()
    {
        Some(FactorConfig::Fido2(cfg)) => Some(cfg.credentials),
        _ => None,
    }
}

async fn delete_first(f: &Fixture) {
    let removed = f
        .service
        .delete_fido2_credential(
            &test_user("u1", "alice"),
            &session_for(&test_user("u1", "alice")).await,
            passkey(AAAA).cred_id(),
            0,
        )
        .await
        .unwrap();
    assert!(removed);
}

/// Begin a discoverable ceremony and hand back the caller's list, taken
/// before any deletion, as a login that started earlier would hold it.
async fn begin_discoverable(
    f: &Fixture,
    session: &axess_core::session::extractor::AuthSession,
) -> Vec<Fido2Credential> {
    f.service.begin_discoverable_login(session).await.unwrap();
    stored(f).await.unwrap_or_default()
}

#[tokio::test]
async fn a_passkey_deleted_mid_login_cannot_finish_a_discoverable_login() {
    let f = fixture(true);
    let session = test_session();
    let stale = begin_discoverable(&f, &session).await;
    delete_first(&f).await;

    let err = f
        .service
        .finish_discoverable_login(&assertion(), &test_user("u1", "alice"), &stale, &session)
        .await
        .unwrap_err();

    assert!(matches!(err, AuthnError::InvalidAssertion), "got {err:?}");
    assert!(!session.is_authenticated().await);
    assert_eq!(f.identity.failed_attempts_for("u1"), 1);
    assert!(
        stored(&f).await.unwrap().is_empty(),
        "nothing was written back"
    );
}

#[tokio::test]
async fn a_stored_passkey_still_finishes_a_discoverable_login_and_records_use() {
    let f = fixture(true);
    let session = test_session();
    let list = begin_discoverable(&f, &session).await;

    f.service
        .finish_discoverable_login(&assertion(), &test_user("u1", "alice"), &list, &session)
        .await
        .unwrap();

    assert!(session.is_authenticated().await);
    let creds = stored(&f).await.unwrap();
    assert_eq!(creds.len(), 1);
    assert!(
        creds[0].last_used_at.is_some(),
        "the used passkey records its use"
    );
}

#[tokio::test]
async fn a_user_without_a_fido2_row_gets_none_from_a_discoverable_login() {
    let f = fixture(false);
    let session = test_session();
    f.service.begin_discoverable_login(&session).await.unwrap();
    let list = vec![Fido2Credential::new(passkey(AAAA), "ghost", f.stored_at)];

    let err = f
        .service
        .finish_discoverable_login(&assertion(), &test_user("u1", "alice"), &list, &session)
        .await
        .unwrap_err();

    assert!(matches!(err, AuthnError::InvalidAssertion), "got {err:?}");
    assert!(
        stored(&f).await.is_none(),
        "no empty FIDO2 factor row is created"
    );
    assert!(!session.is_authenticated().await);
}

#[tokio::test]
async fn a_passkey_deleted_mid_login_cannot_satisfy_the_fido2_factor() {
    let f = fixture(true);
    let session = test_session();
    f.service
        .begin_login("alice", "default", &session)
        .await
        .unwrap();
    f.service.prepare_factor(&session).await.unwrap();
    delete_first(&f).await;

    let cred = FactorCredential::fido2_assertion(&assertion()).unwrap();
    let outcome = f.service.verify_factor(&cred, &session).await.unwrap();

    assert!(
        matches!(
            outcome,
            axess_core::authn::service::FactorOutcome::InvalidCredential
        ),
        "got {outcome:?}"
    );
    assert!(!session.is_authenticated().await);
    assert_eq!(f.identity.failed_attempts_for("u1"), 1);
}

#[tokio::test]
async fn a_stored_passkey_still_satisfies_the_fido2_factor() {
    let f = fixture(true);
    let session = test_session();
    f.service
        .begin_login("alice", "default", &session)
        .await
        .unwrap();
    f.service.prepare_factor(&session).await.unwrap();

    let cred = FactorCredential::fido2_assertion(&assertion()).unwrap();
    let outcome = f.service.verify_factor(&cred, &session).await.unwrap();

    assert!(
        matches!(
            outcome,
            axess_core::authn::service::FactorOutcome::Authenticated
        ),
        "got {outcome:?}"
    );
    assert!(session.is_authenticated().await);
}

#[tokio::test]
async fn a_discoverable_failure_leaves_no_ceremony_timestamp() {
    let f = fixture(true);
    let session = test_session();
    // State that is not a `DiscoverableAuthentication`, with its timestamp.
    session
        .set_custom("axess.fido2.disc_state", serde_json::json!("not a state"))
        .await;
    session
        .set_custom(
            "axess.fido2.disc_started",
            serde_json::Value::String(f.clock.now().to_rfc3339()),
        )
        .await;
    let err = f
        .service
        .finish_discoverable_login(&assertion(), &test_user("u1", "alice"), &[], &session)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthnError::NoFlow), "got {err:?}");
    let ts = session.get_custom("axess.fido2.disc_started").await;
    assert!(
        ts.as_ref().is_none_or(|v| v.is_null()),
        "stamp left behind: {ts:?}"
    );

    // The failure that must record a factor failure clears the state first.
    let list = begin_discoverable(&f, &session).await;
    delete_first(&f).await;
    f.identity.arm_record_failed_attempt_failure();
    let _ = f
        .service
        .finish_discoverable_login(&assertion(), &test_user("u1", "alice"), &list, &session)
        .await;
    let state = session.get_custom("axess.fido2.disc_state").await;
    let ts = session.get_custom("axess.fido2.disc_started").await;
    assert!(state.as_ref().is_none_or(|v| v.is_null()));
    assert!(
        ts.as_ref().is_none_or(|v| v.is_null()),
        "stamp left behind: {ts:?}"
    );
}

#[tokio::test]
async fn a_registration_finishes_once_and_audits_once() {
    let f = fixture(true);
    let user = test_user("u1", "alice");
    let session = session_for(&user).await;
    f.service
        .begin_fido2_registration(&user, &session)
        .await
        .unwrap();

    f.service
        .finish_fido2_registration(&user, &registration(), "second", &session)
        .await
        .unwrap();
    let again = f
        .service
        .finish_fido2_registration(&user, &registration(), "second", &session)
        .await
        .unwrap_err();

    assert!(matches!(again, AuthnError::NoFlow), "got {again:?}");
    assert_eq!(stored(&f).await.unwrap().len(), 2);
    let setups = f
        .identity
        .events()
        .iter()
        .filter(|e| {
            matches!(
                e.event_type,
                axess_core::authn::event::AuthEventType::FactorSetup
            )
        })
        .count();
    assert_eq!(setups, 1);
}

#[tokio::test]
async fn a_registration_of_an_already_stored_passkey_is_refused_without_an_audit() {
    let f = fixture(true);
    let user = test_user("u1", "alice");
    let session = session_for(&user).await;
    f.service
        .begin_fido2_registration(&user, &session)
        .await
        .unwrap();
    f.service
        .finish_fido2_registration(&user, &registration(), "second", &session)
        .await
        .unwrap();
    f.service
        .begin_fido2_registration(&user, &session)
        .await
        .unwrap();

    let err = f
        .service
        .finish_fido2_registration(&user, &registration(), "again", &session)
        .await
        .unwrap_err();

    assert!(matches!(err, AuthnError::NoFlow), "got {err:?}");
    assert_eq!(stored(&f).await.unwrap().len(), 2);
}

#[tokio::test]
async fn a_failed_registration_finish_consumes_the_state() {
    let f = fixture(true);
    let user = test_user("u1", "alice");
    let session = session_for(&user).await;
    f.service
        .begin_fido2_registration(&user, &session)
        .await
        .unwrap();
    // The ceremony is live, but its state no longer parses.
    session
        .set_custom("axess.fido2.reg_state", serde_json::json!("not a state"))
        .await;
    let err = f
        .service
        .finish_fido2_registration(&user, &registration(), "x", &session)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthnError::NoFlow), "got {err:?}");
    let state = session.get_custom("axess.fido2.reg_state").await;
    assert!(
        state.as_ref().is_none_or(|v| v.is_null()),
        "state left: {state:?}"
    );
}

#[tokio::test]
async fn an_account_suspended_mid_registration_cannot_add_a_passkey() {
    let f = fixture(true);
    let user = test_user("u1", "alice");
    let session = session_for(&user).await;
    f.service
        .begin_fido2_registration(&user, &session)
        .await
        .unwrap();
    f.identity
        .suspend_user(
            &user.id,
            StatusDetail {
                reason: "test".into(),
                since: chrono::Utc::now(),
                until: None,
            },
        )
        .await
        .unwrap();

    let err = f
        .service
        .finish_fido2_registration(&user, &registration(), "late", &session)
        .await
        .unwrap_err();

    assert!(matches!(err, AuthnError::Locked { .. }), "got {err:?}");
    assert_eq!(stored(&f).await.unwrap().len(), 1, "no passkey was added");
}

#[tokio::test]
async fn starting_one_ceremony_does_not_refresh_another_ones_timeout() {
    let f = fixture(true);
    let user = test_user("u1", "alice");
    let session = session_for(&user).await;
    // A registration left in flight, then the clock runs past the timeout.
    f.service
        .begin_fido2_registration(&user, &session)
        .await
        .unwrap();
    f.clock.advance_secs(301);
    // A different ceremony starts and stamps its own timestamp.
    f.service.begin_discoverable_login(&session).await.unwrap();

    let err = f
        .service
        .finish_fido2_registration(&user, &registration(), "late", &session)
        .await
        .unwrap_err();

    assert!(matches!(err, AuthnError::NoFlow), "got {err:?}");
    assert_eq!(
        stored(&f).await.unwrap().len(),
        1,
        "the stale registration did not complete"
    );
}

// ── The passkey login honours the user's own method and the tenant ──────────

#[tokio::test]
async fn a_passkey_only_method_ends_authenticated_with_the_passkey_recorded() {
    let f = fixture(true);
    let session = test_session();
    let list = begin_discoverable(&f, &session).await;
    let outcome = f
        .service
        .finish_discoverable_login(&assertion(), &test_user("u1", "alice"), &list, &session)
        .await
        .unwrap();
    assert!(
        matches!(outcome, FactorOutcome::Authenticated),
        "{outcome:?}"
    );
    match session.auth_state().await {
        axess_core::session::data::AuthState::Authenticated {
            factors_completed, ..
        } => assert_eq!(factors_completed, vec![FactorKind::Fido2]),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_password_then_passkey_method_is_not_satisfied_by_the_passkey_alone() {
    let f = fixture_with(
        true,
        vec![vec![FactorKind::Password, FactorKind::Fido2]],
        axess_core::authn::types::EntityState::Active,
    );
    let session = test_session();
    let list = begin_discoverable(&f, &session).await;
    let err = f
        .service
        .finish_discoverable_login(&assertion(), &test_user("u1", "alice"), &list, &session)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthnError::NoFlow), "{err:?}");
    assert!(!session.is_authenticated().await);
}

#[tokio::test]
async fn a_passkey_then_more_method_continues_with_the_next_factor() {
    let f = fixture_with(
        true,
        vec![vec![FactorKind::Fido2, FactorKind::Totp]],
        axess_core::authn::types::EntityState::Active,
    );
    let session = test_session();
    let list = begin_discoverable(&f, &session).await;
    let outcome = f
        .service
        .finish_discoverable_login(&assertion(), &test_user("u1", "alice"), &list, &session)
        .await
        .unwrap();
    assert!(
        matches!(outcome, FactorOutcome::FactorRequired(FactorKind::Totp)),
        "{outcome:?}"
    );
    assert!(!session.is_authenticated().await);
}

#[tokio::test]
async fn a_suspended_tenant_refuses_the_passkey_login() {
    use axess_core::authn::types::{EntityState, StatusDetail};
    let f = fixture_with(
        true,
        vec![vec![FactorKind::Fido2]],
        EntityState::Suspended(StatusDetail {
            reason: "hold".into(),
            since: chrono::Utc::now(),
            until: None,
        }),
    );
    let session = test_session();
    let list = begin_discoverable(&f, &session).await;
    let err = f
        .service
        .finish_discoverable_login(&assertion(), &test_user("u1", "alice"), &list, &session)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthnError::InvalidAssertion), "{err:?}");
    assert!(!session.is_authenticated().await);
}

#[tokio::test]
async fn a_tenant_bound_ceremony_refuses_a_user_of_another_tenant() {
    let f = fixture(true);
    let session = test_session();
    f.service
        .begin_discoverable_login_in_tenant(&axess_identity::testing::tenant("t2"), &session)
        .await
        .unwrap();
    let list = stored(&f).await.unwrap_or_default();
    let err = f
        .service
        .finish_discoverable_login(&assertion(), &test_user("u1", "alice"), &list, &session)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthnError::CrossTenant), "{err:?}");
    assert!(!session.is_authenticated().await);
}

#[tokio::test]
async fn a_missing_ceremony_state_does_not_leave_its_timestamp_behind() {
    let f = fixture(true);
    let session = test_session();
    session
        .set_custom(
            "axess.fido2.disc_started",
            serde_json::Value::String(f.clock.now().to_rfc3339()),
        )
        .await;
    let err = f
        .service
        .finish_discoverable_login(&assertion(), &test_user("u1", "alice"), &[], &session)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthnError::NoFlow), "{err:?}");
    let left = session.get_custom("axess.fido2.disc_started").await;
    assert!(
        left.as_ref().is_none_or(|v| v.is_null()),
        "stamp left behind: {left:?}"
    );
}
