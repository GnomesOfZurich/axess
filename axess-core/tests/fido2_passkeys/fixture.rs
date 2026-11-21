//! The passkey registration fixture shared by the passkey test files: a
//! provider that accepts any response, a factor store whose next read,
//! write, claim or release can be made to fail, and the helpers that read
//! what it stored.

use axess_clock::testing::Shift;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axess_clock::testing::MockClock;
use axess_core::authn::AuditContext;
use axess_core::authn::factor::{FactorConfig, FactorKind, Fido2Config, Fido2Credential};
use axess_core::authn::store::{AuthMethod, FactorStore, Fido2CredentialClaim, ResolvedFactor};
use axess_core::authn::types::AuthnScope;
use axess_core::testing::fixtures as common;
use axess_core::{
    authn::service::{AuthnService, RequestAuthnService},
    testing::{
        mock_authn::{MockFactorStore, MockIdentityStore, MockStoreError},
        test_session,
    },
};
use axess_factors::fido2::{
    DefaultFido2Provider, Fido2Authentication, Fido2Ceremony, Fido2Key, Fido2Provider,
    Fido2Registration,
};
use common::{session_for, start, test_clock, test_tenant, test_user};
use url::Url;
use webauthn_rs::prelude::*;

/// URL-safe base64 of `aaaa` and `bbbb`.
pub const AAAA: &str = "YWFhYQ";
pub const BBBB: &str = "YmJiYg";
pub const CCCC: &str = "Y2NjYw";
pub const DDDD: &str = "ZGRkZA";

pub fn passkey(id: &str) -> Passkey {
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
pub struct AcceptingProvider(pub DefaultFido2Provider);

impl Fido2Provider for AcceptingProvider {
    fn relying_party_id(&self) -> &str {
        self.0.relying_party_id()
    }
    fn start_authentication(
        &self,
        ceremony: &Fido2Ceremony,
        c: &[Fido2Key],
    ) -> WebauthnResult<(RequestChallengeResponse, Fido2Authentication)> {
        self.0.start_authentication(ceremony, c)
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
        ceremony: &Fido2Ceremony,
        id: uuid::Uuid,
        name: &str,
        display: &str,
        exclude: Option<Vec<CredentialID>>,
    ) -> WebauthnResult<(CreationChallengeResponse, Fido2Registration)> {
        self.0
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
pub struct FlakyFactors {
    pub inner: MockFactorStore,
    pub fail_next_load: Arc<AtomicBool>,
    pub fail_next_write: Arc<AtomicBool>,
    /// Written to the store right after the next load returns, as a
    /// concurrent request landing between this request's read and write.
    pub race_after_next_load: Arc<std::sync::Mutex<Option<FactorConfig>>>,
    pub fail_next_release: Arc<AtomicBool>,
    /// What the next claim answers, without asking the store.
    pub next_claim: Arc<std::sync::Mutex<Option<Fido2CredentialClaim>>>,
    /// The credential ids whose claim the service released.
    pub released: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    /// Played right before the next `resolve_factor` answers: another
    /// request landing between this request's first read and its write.
    pub before_next_resolve: Arc<std::sync::Mutex<Option<Racer>>>,
}

/// A concurrent request, played to its end at a chosen point of another.
pub type Racer = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

impl FactorStore for FlakyFactors {
    type Error = MockStoreError;

    async fn resolve_factor(
        &self,
        scope: &AuthnScope,
        kind: FactorKind,
    ) -> Result<Option<ResolvedFactor>, Self::Error> {
        let racer = self.before_next_resolve.lock().unwrap().take();
        if let Some(racer) = racer {
            racer.await;
        }
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
    async fn claim_fido2_credential(
        &self,
        t: &axess_core::authn::ids::TenantId,
        u: &axess_core::authn::ids::UserId,
        id: &[u8],
    ) -> Result<Fido2CredentialClaim, Self::Error> {
        let answer = self.next_claim.lock().unwrap().take();
        if let Some(answer) = answer {
            return Ok(answer);
        }
        self.inner.claim_fido2_credential(t, u, id).await
    }
    async fn release_fido2_credential(
        &self,
        t: &axess_core::authn::ids::TenantId,
        u: &axess_core::authn::ids::UserId,
        id: &[u8],
    ) -> Result<(), Self::Error> {
        if self.fail_next_release.swap(false, Ordering::SeqCst) {
            return Err(MockStoreError::Unavailable);
        }
        self.released.lock().unwrap().push(id.to_vec());
        self.inner.release_fido2_credential(t, u, id).await
    }
}
pub fn dummy_response() -> RegisterPublicKeyCredential {
    serde_json::from_value(serde_json::json!({
        "id": "AAAA", "rawId": "AAAA", "type": "public-key",
        "response": { "attestationObject": "AAAA", "clientDataJSON": "AAAA" }
    }))
    .unwrap()
}

pub struct Fixture {
    pub service: RequestAuthnService<MockIdentityStore, FlakyFactors>,
    /// The clock the service and the identity store run on.
    pub clock: MockClock,
    pub factors: FlakyFactors,
    pub scope: AuthnScope,
    pub identity: MockIdentityStore,
}

pub fn fixture() -> Fixture {
    fixture_with(axess_core::authn::factor::Fido2Options::default())
}

pub fn fixture_with(options: axess_core::authn::factor::Fido2Options) -> Fixture {
    let user = test_user("u1", "alice");
    let scope = AuthnScope::User {
        tenant_id: user.tenant_id,
        user_id: user.id,
    };
    let clock = test_clock();
    let existing = Fido2Credential::new(passkey(AAAA), "first", start());
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
        fail_next_release: Arc::new(AtomicBool::new(false)),
        next_claim: Arc::new(std::sync::Mutex::new(None)),
        released: Arc::new(std::sync::Mutex::new(Vec::new())),
        before_next_resolve: Arc::new(std::sync::Mutex::new(None)),
    };
    let rp_origin = Url::parse("https://localhost:8443").unwrap();
    let webauthn = WebauthnBuilder::new("localhost", &rp_origin)
        .unwrap()
        .build()
        .unwrap();
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_default_tenant(test_tenant())
        .with_user(user);
    let service = AuthnService::builder(identity.clone(), factors.clone())
        .with_clock(clock.clone())
        .with_fido2(AcceptingProvider(DefaultFido2Provider::new(webauthn)))
        .with_fido2_options(options)
        .build()
        .with_audit_context(AuditContext::default());
    Fixture {
        service,
        clock,
        factors,
        scope,
        identity,
    }
}
pub async fn stored_count(f: &Fixture) -> usize {
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
pub fn suspended_until(until: axess_clock::Timestamp) -> axess_core::authn::types::EntityState {
    use axess_core::authn::types::{EntityState, StatusDetail};
    EntityState::Suspended(
        StatusDetail::administrative("test", until.minus(axess_clock::SignedDuration::days(1)))
            .with_until(Some(axess_clock::Until::At(until))),
    )
}
pub fn fixture_with_status(
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
        .with_clock(f.clock.clone())
        .with_default_tenant(test_tenant())
        .with_user(user.clone());
    let service = AuthnService::builder(identity, f.factors)
        .with_clock(f.clock)
        .with_fido2(AcceptingProvider(DefaultFido2Provider::new(webauthn)))
        .build()
        .with_audit_context(AuditContext::default());
    (service, user)
}
pub fn config_of(ids: &[&str]) -> FactorConfig {
    FactorConfig::Fido2(Fido2Config {
        credentials: ids
            .iter()
            .map(|id| Fido2Credential::new(passkey(id), "k", start()))
            .collect(),
    })
}
pub async fn stored_ids(f: &Fixture) -> Vec<CredentialID> {
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
pub fn cred_id(id: &str) -> CredentialID {
    passkey(id).cred_id().clone()
}

/// The credential ids whose claim the service gave back.
pub fn released(f: &Fixture) -> Vec<Vec<u8>> {
    f.factors.released.lock().unwrap().clone()
}

/// A session authenticated as `user` `age` before [`start`].
pub async fn session_aged(
    user: &axess_core::authn::types::User,
    age: axess_clock::SignedDuration,
) -> axess_core::session::extractor::AuthSession {
    let session = test_session();
    axess_core::testing::AuthSessionTestExt::set_authenticated(
        &session,
        user.id,
        user.tenant_id,
        start().minus(age),
    )
    .await;
    session
}

/// Bob's finish yields the `BBBB` credential; `holder` already stores it.
pub async fn bob_finishes_with_a_credential_held_by(
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
                credentials: vec![Fido2Credential::new(passkey(BBBB), "theirs", start())],
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
