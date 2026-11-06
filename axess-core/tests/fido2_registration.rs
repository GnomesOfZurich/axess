#![cfg(all(feature = "testing", feature = "fido2"))]
//! Registering a passkey must never replace the passkeys a user already has.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axess_core::authn::AuditContext;
use axess_core::authn::factor::{FactorConfig, FactorKind, Fido2Config, Fido2Credential};
use axess_core::authn::store::{AuthMethod, FactorStore, ResolvedFactor};
use axess_core::authn::types::AuthnScope;
use axess_core::{
    authn::service::{AuthnService, RequestAuthnService},
    testing::{
        mock_authn::{MockFactorStore, MockIdentityStore, MockStoreError},
        test_session,
    },
};
use axess_factors::fido2::{DefaultFido2Provider, Fido2Provider};
use common::{session_for, test_tenant, test_user};
use url::Url;
use webauthn_rs::prelude::*;

/// URL-safe base64 of `aaaa` and `bbbb`.
const AAAA: &str = "YWFhYQ";
const BBBB: &str = "YmJiYg";
const CCCC: &str = "Y2NjYw";
const DDDD: &str = "ZGRkZA";

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

/// Real ceremony start (so the session holds genuine state); the finish
/// step accepts any response and yields the `BBBB` passkey.
struct AcceptingProvider(DefaultFido2Provider);

impl Fido2Provider for AcceptingProvider {
    fn relying_party_id(&self) -> &str {
        self.0.relying_party_id()
    }
    fn start_authentication(
        &self,
        c: &[Passkey],
    ) -> WebauthnResult<(RequestChallengeResponse, PasskeyAuthentication)> {
        self.0.start_authentication(c)
    }
    fn finish_authentication(
        &self,
        a: &PublicKeyCredential,
        s: &PasskeyAuthentication,
    ) -> WebauthnResult<AuthenticationResult> {
        self.0.finish_authentication(a, s)
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
        a: &PublicKeyCredential,
        s: DiscoverableAuthentication,
        k: &[DiscoverableKey],
    ) -> WebauthnResult<AuthenticationResult> {
        self.0.finish_discoverable_authentication(a, s, k)
    }
}

/// A factor store whose next `load_factor` can be made to fail.
#[derive(Clone)]
struct FlakyFactors {
    inner: MockFactorStore,
    fail_next_load: Arc<AtomicBool>,
    fail_next_write: Arc<AtomicBool>,
    /// Written to the store right after the next load returns, as a
    /// concurrent request landing between this request's read and write.
    race_after_next_load: Arc<std::sync::Mutex<Option<FactorConfig>>>,
}

impl FactorStore for FlakyFactors {
    type Error = MockStoreError;

    async fn resolve_factor(
        &self,
        scope: &AuthnScope,
        kind: FactorKind,
    ) -> Result<Option<ResolvedFactor>, Self::Error> {
        self.inner.resolve_factor(scope, kind).await
    }
    async fn load_factor(
        &self,
        scope: &AuthnScope,
        kind: FactorKind,
    ) -> Result<Option<FactorConfig>, Self::Error> {
        if self.fail_next_load.swap(false, Ordering::SeqCst) {
            return Err(MockStoreError::NotFound);
        }
        let loaded = self.inner.load_factor(scope, kind).await?;
        let racer = self.race_after_next_load.lock().unwrap().take();
        if let Some(config) = racer {
            self.inner.save_factor(scope, config).await?;
        }
        Ok(loaded)
    }
    async fn save_factor(&self, scope: &AuthnScope, c: FactorConfig) -> Result<(), Self::Error> {
        if self.fail_next_write.swap(false, Ordering::SeqCst) {
            return Err(MockStoreError::NotFound);
        }
        self.inner.save_factor(scope, c).await
    }
    async fn compare_and_save_factor(
        &self,
        scope: &AuthnScope,
        prior: &FactorConfig,
        updated: FactorConfig,
    ) -> Result<bool, Self::Error> {
        if self.fail_next_write.swap(false, Ordering::SeqCst) {
            return Err(MockStoreError::NotFound);
        }
        self.inner
            .compare_and_save_factor(scope, prior, updated)
            .await
    }
    async fn insert_factor_if_absent(
        &self,
        scope: &AuthnScope,
        config: FactorConfig,
    ) -> Result<bool, Self::Error> {
        self.inner.insert_factor_if_absent(scope, config).await
    }
    async fn available_methods(
        &self,
        u: &axess_core::authn::ids::UserId,
        t: &axess_core::authn::ids::TenantId,
    ) -> Result<Vec<AuthMethod>, Self::Error> {
        self.inner.available_methods(u, t).await
    }
    async fn save_method(&self, s: &AuthnScope, m: AuthMethod) -> Result<(), Self::Error> {
        self.inner.save_method(s, m).await
    }
    async fn remove_method(&self, s: &AuthnScope, n: &str) -> Result<(), Self::Error> {
        self.inner.remove_method(s, n).await
    }
    async fn set_method_enabled(
        &self,
        s: &AuthnScope,
        n: &str,
        e: bool,
    ) -> Result<bool, Self::Error> {
        self.inner.set_method_enabled(s, n, e).await
    }
    async fn fido2_credential_holder(
        &self,
        t: &axess_core::authn::ids::TenantId,
        id: &[u8],
    ) -> Result<Option<axess_core::authn::ids::UserId>, Self::Error> {
        self.inner.fido2_credential_holder(t, id).await
    }
}

fn dummy_response() -> RegisterPublicKeyCredential {
    serde_json::from_value(serde_json::json!({
        "id": "AAAA", "rawId": "AAAA", "type": "public-key",
        "response": { "attestationObject": "AAAA", "clientDataJSON": "AAAA" }
    }))
    .unwrap()
}

struct Fixture {
    service: RequestAuthnService<MockIdentityStore, FlakyFactors>,
    factors: FlakyFactors,
    scope: AuthnScope,
    identity: MockIdentityStore,
}

fn fixture() -> Fixture {
    fixture_with(axess_core::authn::factor::Fido2Options::default())
}

fn fixture_with(options: axess_core::authn::factor::Fido2Options) -> Fixture {
    let user = test_user("u1", "alice");
    let scope = AuthnScope::User {
        tenant_id: user.tenant_id,
        user_id: user.id,
    };
    let existing = Fido2Credential::new(passkey(AAAA), "first", chrono::Utc::now());
    let inner = MockFactorStore::new().with_factor(
        scope.clone(),
        FactorConfig::Fido2(Fido2Config {
            credentials: vec![existing],
        }),
    );
    let factors = FlakyFactors {
        inner,
        fail_next_load: Arc::new(AtomicBool::new(false)),
        fail_next_write: Arc::new(AtomicBool::new(false)),
        race_after_next_load: Arc::new(std::sync::Mutex::new(None)),
    };
    let rp_origin = Url::parse("https://localhost:8443").unwrap();
    let webauthn = WebauthnBuilder::new("localhost", &rp_origin)
        .unwrap()
        .build()
        .unwrap();
    let identity = MockIdentityStore::new()
        .with_default_tenant(test_tenant())
        .with_user(user);
    let service = AuthnService::builder(identity.clone(), factors.clone())
        .with_fido2(AcceptingProvider(DefaultFido2Provider::new(webauthn)))
        .with_fido2_options(options)
        .build()
        .with_audit_context(AuditContext::default());
    Fixture {
        service,
        factors,
        scope,
        identity,
    }
}

async fn stored_count(f: &Fixture) -> usize {
    match f
        .factors
        .inner
        .load_factor(&f.scope, FactorKind::Fido2)
        .await
        .unwrap()
    {
        Some(FactorConfig::Fido2(cfg)) => cfg.credentials.len(),
        _ => 0,
    }
}

#[tokio::test]
async fn registration_adds_to_the_existing_passkeys() {
    let f = fixture();
    let user = test_user("u1", "alice");
    let session = session_for(&user).await;
    f.service
        .begin_fido2_registration(&user, &session)
        .await
        .unwrap();
    f.service
        .finish_fido2_registration(&user, &dummy_response(), "second", &session)
        .await
        .unwrap();
    assert_eq!(stored_count(&f).await, 2);
}

#[tokio::test]
async fn failed_read_during_registration_keeps_the_existing_passkeys() {
    let f = fixture();
    let user = test_user("u1", "alice");
    let session = session_for(&user).await;
    f.service
        .begin_fido2_registration(&user, &session)
        .await
        .unwrap();

    f.factors.fail_next_load.store(true, Ordering::SeqCst);
    let result = f
        .service
        .finish_fido2_registration(&user, &dummy_response(), "second", &session)
        .await;

    assert!(result.is_err(), "a failed read must fail the registration");
    assert_eq!(
        stored_count(&f).await,
        1,
        "the existing passkey must survive"
    );
}

#[tokio::test]
async fn failed_read_when_beginning_registration_is_an_error() {
    let f = fixture();
    let user = test_user("u1", "alice");
    f.factors.fail_next_load.store(true, Ordering::SeqCst);
    let result = f
        .service
        .begin_fido2_registration(&user, &session_for(&user).await)
        .await;
    assert!(result.is_err());
}

fn suspended_until(until: chrono::DateTime<chrono::Utc>) -> axess_core::authn::types::EntityState {
    use axess_core::authn::types::{EntityState, StatusDetail};
    EntityState::Suspended(
        StatusDetail::administrative("test", until - chrono::Duration::days(1))
            .with_until(Some(until)),
    )
}

fn fixture_with_status(
    status: axess_core::authn::types::EntityState,
) -> (
    RequestAuthnService<MockIdentityStore, FlakyFactors>,
    axess_core::authn::types::User,
) {
    let mut user = test_user("u1", "alice");
    user.status = status;
    let f = fixture();
    let rp_origin = Url::parse("https://localhost:8443").unwrap();
    let webauthn = WebauthnBuilder::new("localhost", &rp_origin)
        .unwrap()
        .build()
        .unwrap();
    let identity = MockIdentityStore::new()
        .with_default_tenant(test_tenant())
        .with_user(user.clone());
    let service = AuthnService::builder(identity, f.factors)
        .with_fido2(AcceptingProvider(DefaultFido2Provider::new(webauthn)))
        .build()
        .with_audit_context(AuditContext::default());
    (service, user)
}

#[tokio::test]
async fn an_ended_suspension_no_longer_blocks_passkey_registration() {
    let past = chrono::Utc::now() - chrono::Duration::hours(1);
    let (service, user) = fixture_with_status(suspended_until(past));
    service
        .begin_fido2_registration(&user, &session_for(&user).await)
        .await
        .unwrap();
}

#[tokio::test]
async fn a_running_suspension_still_blocks_passkey_registration() {
    let future = chrono::Utc::now() + chrono::Duration::hours(1);
    let (service, user) = fixture_with_status(suspended_until(future));
    assert!(
        service
            .begin_fido2_registration(&user, &session_for(&user).await)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn an_ended_suspension_no_longer_blocks_discoverable_login() {
    use axess_core::authn::error::AuthnError;
    let past = chrono::Utc::now() - chrono::Duration::hours(1);
    let (service, user) = fixture_with_status(suspended_until(past));
    let assertion: PublicKeyCredential = serde_json::from_value(serde_json::json!({
        "id": "AAAA", "rawId": "AAAA", "type": "public-key",
        "response": { "authenticatorData": "AAAA", "clientDataJSON": "AAAA",
                      "signature": "AAAA", "userHandle": null }
    }))
    .unwrap();
    let err = service
        .finish_discoverable_login(&assertion, &user, &[], &test_session())
        .await
        .unwrap_err();
    // Past the status check it stops at the missing ceremony, not at the suspension.
    assert!(matches!(err, AuthnError::NoFlow), "got {err:?}");
}

fn config_of(ids: &[&str]) -> FactorConfig {
    FactorConfig::Fido2(Fido2Config {
        credentials: ids
            .iter()
            .map(|id| Fido2Credential::new(passkey(id), "k", chrono::Utc::now()))
            .collect(),
    })
}

async fn stored_ids(f: &Fixture) -> Vec<CredentialID> {
    match f
        .factors
        .inner
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

fn cred_id(id: &str) -> CredentialID {
    passkey(id).cred_id().clone()
}

#[tokio::test]
async fn failed_read_during_delete_is_an_error_not_a_refusal() {
    let f = fixture();
    let user = test_user("u1", "alice");
    f.factors.fail_next_load.store(true, Ordering::SeqCst);
    let result = f
        .service
        .delete_fido2_credential(&user, &session_for(&user).await, &cred_id(AAAA), 0)
        .await;
    assert!(result.is_err(), "got {result:?}");
    assert_eq!(stored_count(&f).await, 1);
}

#[tokio::test]
async fn failed_write_during_delete_is_an_error_and_the_credential_stays() {
    let f = fixture();
    let user = test_user("u1", "alice");
    f.factors.fail_next_write.store(true, Ordering::SeqCst);
    let result = f
        .service
        .delete_fido2_credential(&user, &session_for(&user).await, &cred_id(AAAA), 0)
        .await;
    assert!(result.is_err(), "got {result:?}");
    assert_eq!(stored_ids(&f).await, vec![cred_id(AAAA)]);
}

#[tokio::test]
async fn registration_racing_another_registration_keeps_both() {
    let f = fixture();
    let user = test_user("u1", "alice");
    let session = session_for(&user).await;
    f.service
        .begin_fido2_registration(&user, &session)
        .await
        .unwrap();
    *f.factors.race_after_next_load.lock().unwrap() = Some(config_of(&[AAAA, CCCC]));
    f.service
        .finish_fido2_registration(&user, &dummy_response(), "second", &session)
        .await
        .unwrap();
    assert_eq!(
        stored_ids(&f).await,
        vec![cred_id(AAAA), cred_id(CCCC), cred_id(BBBB)]
    );
}

#[tokio::test]
async fn delete_racing_a_registration_keeps_the_new_passkey() {
    let f = fixture();
    let user = test_user("u1", "alice");
    f.factors
        .inner
        .save_factor(&f.scope, config_of(&[AAAA, CCCC]))
        .await
        .unwrap();
    *f.factors.race_after_next_load.lock().unwrap() = Some(config_of(&[AAAA, CCCC, DDDD]));
    let deleted = f
        .service
        .delete_fido2_credential(&user, &session_for(&user).await, &cred_id(AAAA), 1)
        .await
        .unwrap();
    assert!(deleted);
    assert_eq!(stored_ids(&f).await, vec![cred_id(CCCC), cred_id(DDDD)]);
}

#[tokio::test]
async fn delete_racing_a_delete_respects_the_minimum_on_the_fresh_list() {
    let f = fixture();
    let user = test_user("u1", "alice");
    f.factors
        .inner
        .save_factor(&f.scope, config_of(&[AAAA, CCCC]))
        .await
        .unwrap();
    // A concurrent request removes CCCC; deleting AAAA would now leave none.
    *f.factors.race_after_next_load.lock().unwrap() = Some(config_of(&[AAAA]));
    let deleted = f
        .service
        .delete_fido2_credential(&user, &session_for(&user).await, &cred_id(AAAA), 1)
        .await
        .unwrap();
    assert!(!deleted, "the minimum must hold against the fresh list");
    assert_eq!(stored_ids(&f).await, vec![cred_id(AAAA)]);
}

// ── Who may enrol and delete ─────────────────────────────────────────────────

#[tokio::test]
async fn a_guest_session_cannot_begin_a_registration() {
    use axess_core::authn::error::AuthnError;
    let f = fixture();
    let user = test_user("u1", "alice");
    let err = f
        .service
        .begin_fido2_registration(&user, &test_session())
        .await
        .unwrap_err();
    assert!(matches!(err, AuthnError::NoFlow), "got {err:?}");
}

#[tokio::test]
async fn another_users_session_cannot_begin_finish_or_delete() {
    use axess_core::authn::error::AuthnError;
    let f = fixture();
    let alice = test_user("u1", "alice");
    let mallory = test_user("u2", "mallory");
    let session = session_for(&mallory).await;
    let err = f
        .service
        .begin_fido2_registration(&alice, &session)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthnError::NoFlow), "begin: {err:?}");
    let err = f
        .service
        .finish_fido2_registration(&alice, &dummy_response(), "evil", &session)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthnError::NoFlow), "finish: {err:?}");
    let err = f
        .service
        .delete_fido2_credential(&alice, &session, &cred_id(AAAA), 0)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthnError::NoFlow), "delete: {err:?}");
    assert_eq!(stored_count(&f).await, 1, "nothing was added or removed");
}

#[tokio::test]
async fn a_session_of_the_same_id_in_another_tenant_is_refused() {
    use axess_core::authn::error::AuthnError;
    let f = fixture();
    let alice = test_user("u1", "alice");
    let impostor = common::test_user_in_tenant("u1", "alice", "t2");
    let err = f
        .service
        .begin_fido2_registration(&alice, &session_for(&impostor).await)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthnError::NoFlow), "got {err:?}");
}

#[tokio::test]
async fn a_signup_session_can_enrol_its_first_passkey_but_only_its_own() {
    use axess_core::authn::error::AuthnError;
    let f = fixture();
    let alice = test_user("u1", "alice");
    let session = common::signup_session_for(&alice).await;
    f.service
        .begin_fido2_registration(&alice, &session)
        .await
        .unwrap();
    f.service
        .finish_fido2_registration(&alice, &dummy_response(), "first", &session)
        .await
        .unwrap();
    let bob = test_user("u3", "bob");
    let err = f
        .service
        .begin_fido2_registration(&bob, &session)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthnError::NoFlow), "got {err:?}");
}

#[tokio::test]
async fn a_refused_enrolment_leaves_a_failed_audit_row() {
    use axess_core::authn::event::{AuthEventStatus, AuthEventType};
    let f = fixture();
    let alice = test_user("u1", "alice");
    let _ = f
        .service
        .begin_fido2_registration(&alice, &test_session())
        .await;
    let rows = f.identity.events();
    assert!(
        rows.iter()
            .any(|e| e.event_type == AuthEventType::FactorEnabled
                && e.event_status == AuthEventStatus::Failure),
        "{rows:?}"
    );
}

/// A session authenticated as `user` `age` ago.
async fn session_aged(
    user: &axess_core::authn::types::User,
    age: chrono::Duration,
) -> axess_core::session::extractor::AuthSession {
    let session = test_session();
    axess_core::testing::AuthSessionTestExt::set_authenticated(
        &session,
        user.id,
        user.tenant_id,
        chrono::Utc::now() - age,
    )
    .await;
    session
}

#[tokio::test]
async fn a_session_authenticated_too_long_ago_cannot_change_credentials() {
    use axess_core::authn::error::AuthnError;
    use axess_core::authn::factor::Fido2Options;
    let f = fixture_with(Fido2Options {
        max_authn_age: Some(std::time::Duration::from_secs(5 * 60)),
        ..Fido2Options::default()
    });
    let alice = test_user("u1", "alice");
    let fresh = session_aged(&alice, chrono::Duration::minutes(1)).await;
    f.service
        .begin_fido2_registration(&alice, &fresh)
        .await
        .expect("a minute-old authentication is recent enough");

    let stale = session_aged(&alice, chrono::Duration::minutes(10)).await;
    let err = f
        .service
        .begin_fido2_registration(&alice, &stale)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthnError::NoFlow), "begin: {err:?}");
    let err = f
        .service
        .finish_fido2_registration(&alice, &dummy_response(), "late", &stale)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthnError::NoFlow), "finish: {err:?}");
    let err = f
        .service
        .delete_fido2_credential(&alice, &stale, &cred_id(AAAA), 0)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthnError::NoFlow), "delete: {err:?}");
    assert_eq!(stored_count(&f).await, 1, "nothing was added or removed");
}

#[tokio::test]
async fn an_impersonated_session_cannot_change_credentials() {
    use axess_core::authn::error::AuthnError;
    let f = fixture();
    let alice = test_user("u1", "alice");
    let session = session_for(&alice).await;
    // The marker `begin_impersonation` leaves; only server code writes it.
    assert!(
        axess_core::testing::AuthSessionTestExt::set_impersonator(
            &session,
            test_user("u9", "admin").id,
            chrono::Utc::now(),
        )
        .await,
        "the session is impersonated"
    );
    let err = f
        .service
        .begin_fido2_registration(&alice, &session)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthnError::Impersonated), "begin: {err:?}");
    let err = f
        .service
        .delete_fido2_credential(&alice, &session, &cred_id(AAAA), 0)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthnError::Impersonated), "delete: {err:?}");
    assert_eq!(stored_count(&f).await, 1, "nothing was added or removed");
}

#[tokio::test]
async fn a_signup_session_cannot_delete_a_passkey() {
    use axess_core::authn::error::AuthnError;
    let f = fixture();
    let alice = test_user("u1", "alice");
    let session = common::signup_session_for(&alice).await;
    let err = f
        .service
        .delete_fido2_credential(&alice, &session, &cred_id(AAAA), 0)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthnError::NoFlow), "got {err:?}");
    assert_eq!(stored_count(&f).await, 1, "the passkey stays");
}

// ── Status and audit rows on the management paths ───────────────────────────

/// Deleting checked the session and nothing else: a suspended account
/// could still remove its passkeys, where it could neither enrol one nor
/// finish enrolling one.
#[tokio::test]
async fn a_suspended_account_cannot_delete_a_passkey() {
    use axess_core::authn::error::AuthnError;
    let future = chrono::Utc::now() + chrono::Duration::hours(1);
    let (service, alice) = fixture_with_status(suspended_until(future));
    let session = session_for(&alice).await;

    let res = service
        .delete_fido2_credential(&alice, &session, &cred_id(AAAA), 0)
        .await;

    assert!(matches!(res, Err(AuthnError::Locked { .. })), "{res:?}");
}

/// The success rows of a registration and a deletion carry the session
/// that made the change, as every refusal row does.
#[tokio::test]
async fn the_registration_and_deletion_rows_carry_the_session() {
    use axess_core::authn::event::{AuthEventStatus, AuthEventType};
    let f = fixture();
    let alice = test_user("u1", "alice");
    let session = session_for(&alice).await;
    let sid = session.session_id().await;
    f.service
        .begin_fido2_registration(&alice, &session)
        .await
        .unwrap();
    f.service
        .finish_fido2_registration(&alice, &dummy_response(), "second", &session)
        .await
        .unwrap();
    assert!(
        f.service
            .delete_fido2_credential(&alice, &session, &cred_id(AAAA), 0)
            .await
            .unwrap()
    );

    for kind in [AuthEventType::FactorSetup, AuthEventType::FactorDisabled] {
        let rows: Vec<_> = f
            .identity
            .events()
            .into_iter()
            .filter(|e| e.event_type == kind && e.event_status == AuthEventStatus::Success)
            .collect();
        assert_eq!(rows.len(), 1, "{kind:?}");
        assert_eq!(rows[0].session_id, Some(sid), "{kind:?}: {rows:?}");
    }
}

/// A finish refused for an account suspended since the ceremony began is
/// recorded under the finish's own kind, `FactorSetup`, which its success
/// row and its other refusals use; it used to be a `FactorEnabled` row.
#[tokio::test]
async fn an_inactive_account_refused_at_finish_is_recorded_as_a_setup() {
    use axess_core::authn::error::AuthnError;
    use axess_core::authn::event::{AuthEventStatus, AuthEventType};
    use axess_core::authn::store::IdentityAdmin as _;
    let f = fixture();
    let alice = test_user("u1", "alice");
    let session = session_for(&alice).await;
    f.service
        .begin_fido2_registration(&alice, &session)
        .await
        .unwrap();
    f.identity
        .suspend_user(
            &alice.id,
            axess_core::authn::types::StatusDetail::administrative("test", chrono::Utc::now()),
        )
        .await
        .unwrap();

    let err = f
        .service
        .finish_fido2_registration(&alice, &dummy_response(), "late", &session)
        .await
        .unwrap_err();

    assert!(matches!(err, AuthnError::Locked { .. }), "{err:?}");
    let rows: Vec<_> = f
        .identity
        .events()
        .into_iter()
        .filter(|e| e.event_status == AuthEventStatus::Locked)
        .collect();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].event_type, AuthEventType::FactorSetup);
    assert_eq!(rows[0].session_id, Some(session.session_id().await));
}

#[tokio::test]
async fn beginning_registration_fails_when_the_ceremony_state_cannot_be_stored() {
    let f = fixture();
    let user = test_user("u1", "alice");
    let session = session_for(&user).await;
    assert!(
        session
            .set_custom("pad", serde_json::json!("x".repeat(65_500)))
            .await
    );

    let result = f.service.begin_fido2_registration(&user, &session).await;

    assert!(
        matches!(result, Err(axess_core::authn::error::AuthnError::NoFlow)),
        "a challenge whose state was not stored can never be finished: {result:?}"
    );
}

/// A registration the authenticator's answer fails to verify is audited, and
/// its row names the session it came from like the other rows of the flow.
#[tokio::test]
async fn a_rejected_registration_row_names_its_session() {
    use axess_core::authn::error::AuthnError;
    use axess_core::authn::event::{AuthEventStatus, AuthEventType};
    let f = fixture();
    let alice = test_user("u1", "alice");
    let webauthn =
        WebauthnBuilder::new("localhost", &Url::parse("https://localhost:8443").unwrap())
            .unwrap()
            .build()
            .unwrap();
    // The real verifier: the placeholder attestation does not verify.
    let service = AuthnService::builder(f.identity.clone(), f.factors.clone())
        .with_fido2(DefaultFido2Provider::new(webauthn))
        .build()
        .with_audit_context(AuditContext::default());
    let session = session_for(&alice).await;
    service
        .begin_fido2_registration(&alice, &session)
        .await
        .unwrap();

    let err = service
        .finish_fido2_registration(&alice, &dummy_response(), "bad", &session)
        .await
        .unwrap_err();

    assert!(matches!(err, AuthnError::NoFlow), "{err:?}");
    let rows: Vec<_> = f
        .identity
        .events()
        .into_iter()
        .filter(|e| {
            e.event_type == AuthEventType::FactorSetup && e.event_status == AuthEventStatus::Failure
        })
        .collect();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].session_id, Some(session.session_id().await));
}

/// Bob's finish yields the `BBBB` credential; `holder` already stores it.
async fn bob_finishes_with_a_credential_held_by(
    holder: &str,
) -> (
    Fixture,
    Result<(), axess_core::authn::error::AuthnError<MockStoreError>>,
) {
    let f = fixture();
    let owner = test_user(holder, "owner");
    f.factors
        .inner
        .save_factor(
            &AuthnScope::User {
                tenant_id: owner.tenant_id,
                user_id: owner.id,
            },
            FactorConfig::Fido2(Fido2Config {
                credentials: vec![Fido2Credential::new(
                    passkey(BBBB),
                    "theirs",
                    chrono::Utc::now(),
                )],
            }),
        )
        .await
        .unwrap();
    let bob = test_user("u3", "bob");
    let _ = f.identity.clone().with_user(bob.clone());
    let session = session_for(&bob).await;
    f.service
        .begin_fido2_registration(&bob, &session)
        .await
        .unwrap();
    let result = f
        .service
        .finish_fido2_registration(&bob, &dummy_response(), "mine", &session)
        .await;
    (f, result)
}

#[tokio::test]
async fn a_credential_id_another_user_of_the_tenant_holds_is_refused_and_audited() {
    use axess_core::authn::error::AuthnError;
    use axess_core::authn::event::{AuthEventStatus, AuthEventType};
    let (f, result) = bob_finishes_with_a_credential_held_by("u2").await;
    assert!(matches!(result, Err(AuthnError::NoFlow)), "got {result:?}");
    let bob_scope = AuthnScope::User {
        tenant_id: test_user("u3", "bob").tenant_id,
        user_id: test_user("u3", "bob").id,
    };
    assert!(
        f.factors
            .inner
            .load_factor(&bob_scope, FactorKind::Fido2)
            .await
            .unwrap()
            .is_none(),
        "nothing was stored for the second user"
    );
    let rows = f.identity.events();
    assert!(
        rows.iter()
            .any(|e| e.event_type == AuthEventType::FactorSetup
                && e.event_status == AuthEventStatus::Failure),
        "{rows:?}"
    );
    assert!(
        !rows
            .iter()
            .any(|e| e.event_type == AuthEventType::FactorSetup
                && e.event_status == AuthEventStatus::Success),
        "{rows:?}"
    );
}

#[tokio::test]
async fn a_credential_id_held_in_another_tenant_is_not_a_conflict() {
    let f = fixture();
    let owner = common::test_user_in_tenant("u2", "owner", "t2");
    f.factors
        .inner
        .save_factor(
            &AuthnScope::User {
                tenant_id: owner.tenant_id,
                user_id: owner.id,
            },
            FactorConfig::Fido2(Fido2Config {
                credentials: vec![Fido2Credential::new(
                    passkey(BBBB),
                    "theirs",
                    chrono::Utc::now(),
                )],
            }),
        )
        .await
        .unwrap();
    let user = test_user("u1", "alice");
    let session = session_for(&user).await;
    f.service
        .begin_fido2_registration(&user, &session)
        .await
        .unwrap();
    f.service
        .finish_fido2_registration(&user, &dummy_response(), "mine", &session)
        .await
        .unwrap();
}
