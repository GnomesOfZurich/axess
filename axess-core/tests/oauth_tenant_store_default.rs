//! A tenant OAuth provider store of an adopter's own implements
//! `put_if_revision`; one that cannot compare and write in one step answers
//! with the named refusal instead of as if a concurrent writer had won. The
//! start-up pass then drops no credential: it counts each record it could
//! not move and names it in a warning. At use, under the cipher's default a
//! credential still under the earlier binding is refused and logged by name
//! with the reason; under the opt-out it serves, with a warning that says
//! what the store lacks.
//!
//! Run with: `cargo test -p axess-core --features testing,oauth,jwt-aws-lc --test oauth_tenant_store_default`

#![cfg(all(feature = "testing", feature = "oauth"))]

use axess_clock::testing::MockClock;
use axess_core::authn::factor::{FactorKind, FederatedProvider};
use axess_core::authn::factor_secret::{FactorSecretBinding, FactorSecretCipher};
use axess_core::authn::ids::TenantId;
use axess_core::authn::types::AuthnScope;
use axess_core::federation::oauth_tenant::{
    MemoryTenantOAuthProviderStore, ReassignedPair, ResealReport, StoredTenantOAuthProviders,
    TenantClientCredential, TenantDpop, TenantOAuthProviderRecord, TenantOAuthProviderStore,
    TenantOAuthProviderStoreError, TenantOAuthProviders,
};
use axess_core::session::legacy_blobs::LegacyBlobs;
use axess_factors::FactorSecret;
use axess_testing::mock_tracing::TracingCapture;
use axess_testing::oauth_wiremock::{oauth_generate_rsa_keypair, oauth_mount_oidc_endpoints};
use std::sync::Arc;
use wiremock::MockServer;

/// A store that forwards to the memory store and cannot compare and write,
/// or remove and write, in one step.
struct OwnStore(MemoryTenantOAuthProviderStore);

impl TenantOAuthProviderStore for OwnStore {
    async fn get(
        &self,
        tenant: &TenantId,
        name: &str,
    ) -> Result<Option<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
        self.0.get(tenant, name).await
    }
    async fn put(
        &self,
        record: TenantOAuthProviderRecord,
    ) -> Result<TenantOAuthProviderRecord, TenantOAuthProviderStoreError> {
        self.0.put(record).await
    }
    async fn put_if_revision(
        &self,
        _: TenantOAuthProviderRecord,
        _: u64,
    ) -> Result<Option<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
        Err(TenantOAuthProviderStoreError::put_if_revision_unsupported())
    }
    async fn reassign_pair(
        &self,
        _: TenantOAuthProviderRecord,
    ) -> Result<ReassignedPair, TenantOAuthProviderStoreError> {
        Err(TenantOAuthProviderStoreError::reassign_pair_unsupported())
    }
    async fn delete(
        &self,
        tenant: &TenantId,
        name: &str,
    ) -> Result<bool, TenantOAuthProviderStoreError> {
        self.0.delete(tenant, name).await
    }
    async fn list_by_issuer(
        &self,
        issuer: &str,
    ) -> Result<Vec<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
        self.0.list_by_issuer(issuer).await
    }
    async fn list(
        &self,
        tenant: &TenantId,
    ) -> Result<Vec<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
        self.0.list(tenant).await
    }
    async fn list_all(
        &self,
    ) -> Result<Vec<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
        self.0.list_all().await
    }
}

fn tenant() -> TenantId {
    axess_core::authn::ids::testing::tenant("acme")
}

fn record(issuer: &str, credential: TenantClientCredential) -> TenantOAuthProviderRecord {
    TenantOAuthProviderRecord {
        tenant_id: tenant(),
        name: "sso".into(),
        issuer: issuer.to_string(),
        client_id: "client-1".into(),
        redirect_url: "http://localhost:3000/callback".into(),
        scopes: vec![],
        credential,
        dpop: TenantDpop::Advertised,
        kind: None,
        revision: 0,
    }
}

#[tokio::test]
async fn a_store_that_cannot_compare_and_write_refuses_by_name() {
    let store = OwnStore(MemoryTenantOAuthProviderStore::new());
    let stored = store
        .put(record(
            "https://idp.example",
            TenantClientCredential::Secret(FactorSecret::Plain("s".into())),
        ))
        .await
        .unwrap();

    let refused = store
        .put_if_revision(stored.clone(), stored.revision)
        .await
        .expect_err("a store that cannot do it says so");
    assert!(
        refused.to_string().contains("put_if_revision"),
        "the refusal names the method: {refused}"
    );
    let unchanged = store.get(&tenant(), "sso").await.unwrap().unwrap();
    assert_eq!(unchanged.revision, stored.revision, "nothing was written");
}

const KEY: [u8; 32] = *b"0123456789abcdef0123456789abcdeF";

/// The credential `s3cret` of the record named `name` of `issuer` and
/// `client`, sealed as 0.15 to 0.19 sealed it: bound to the tenant and name
/// with the issuer and client id as the only context.
fn earlier_binding(
    cipher: &FactorSecretCipher,
    name: &str,
    issuer: &str,
    client: &str,
) -> FactorSecret {
    let scope = AuthnScope::Tenant(tenant());
    let kind = FactorKind::Federated(FederatedProvider::Custom(name.into()));
    let sealed = cipher
        .seal(
            "s3cret",
            FactorSecretBinding::new(&scope, &kind).with_context(&[issuer, client]),
        )
        .unwrap();
    FactorSecret::Sealed(sealed)
}

/// A directory over `OwnStore` holding one record named `sso` of `issuer`
/// under the earlier binding, with `cipher`; the store handle and the
/// stored record beside it.
async fn directory_over_own_store(
    clock: &MockClock,
    cipher: FactorSecretCipher,
    issuer: &str,
) -> (
    StoredTenantOAuthProviders<Arc<OwnStore>>,
    TenantOAuthProviderRecord,
) {
    let credential = earlier_binding(&cipher, "sso", issuer, "client-1");
    let store = Arc::new(OwnStore(MemoryTenantOAuthProviderStore::new()));
    let held = store
        .put(record(issuer, TenantClientCredential::Secret(credential)))
        .await
        .unwrap();
    let directory = StoredTenantOAuthProviders::new(
        store,
        Arc::new(cipher),
        axess_core::testing::oauth_tenant::ownership_assumed(),
    )
    .with_clock(Arc::new(clock.clone()))
    .with_egress_policy(axess_factors::egress::EgressPolicy::screened_allowing_loopback_http());
    (directory, held)
}

/// Under the opt-out a record under the earlier binding keeps serving from
/// such a store, and the directory's warning carries the reason it was not
/// moved.
#[tokio::test]
async fn under_the_opt_out_a_store_without_it_keeps_serving_and_the_warning_names_the_gap() {
    let clock = MockClock::at_reference();
    let server = MockServer::start().await;
    let (_, jwk, _) = oauth_generate_rsa_keypair();
    oauth_mount_oidc_endpoints(&server, &jwk).await;
    let issuer = server.uri();
    let cipher = FactorSecretCipher::new(KEY)
        .with_clock(Arc::new(clock.clone()))
        .with_earlier_tenant_binding(LegacyBlobs::Accept);
    let (directory, held) = directory_over_own_store(&clock, cipher, &issuer).await;

    let capture = TracingCapture::install();
    let directory = directory.started().await.expect("the pass drops nothing");
    directory
        .provider(&tenant(), "sso")
        .await
        .expect("the record still opens")
        .expect("and builds");

    let after = directory
        .store()
        .get(&tenant(), "sso")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.revision, held.revision, "the store wrote nothing");
    let warned = capture
        .events()
        .into_iter()
        .filter(|e| e.level == tracing::Level::WARN)
        .filter(|e| e.message.contains("put_if_revision"))
        .count();
    assert!(
        warned >= 2,
        "the pass and the use each warn naming the missing method: {:?}",
        capture.events()
    );
}

/// Under the default the same record is not dropped and not served: the
/// pass counts it and names it, and the use is refused and logged naming the
/// record and the earlier binding as the reason.
#[tokio::test]
async fn under_the_default_a_store_without_it_leaves_the_record_refused_by_name() {
    let clock = MockClock::at_reference();
    let (directory, held) = directory_over_own_store(
        &clock,
        FactorSecretCipher::new(KEY).with_clock(Arc::new(clock.clone())),
        "https://idp.example",
    )
    .await;

    let capture = TracingCapture::install();
    let report = directory
        .reseal_earlier_bindings()
        .await
        .expect("an unsupported store does not fail the pass");
    assert_eq!(
        report,
        ResealReport {
            moved: 0,
            not_moved: 1
        }
    );
    let named = format!("tenant {} provider \"sso\"", tenant());
    assert!(
        capture.contains_at_level(tracing::Level::WARN, &named)
            && capture.contains("put_if_revision")
            && capture.contains("refused at use"),
        "the pass's warning names the record, the gap and its effect: {:?}",
        capture.events()
    );

    let refused = directory.provider(&tenant(), "sso").await;
    assert!(
        refused.is_err(),
        "a credential under the earlier binding was served under the default"
    );
    assert!(
        capture
            .events()
            .iter()
            .any(|e| e.message.contains(&named) && e.message.contains("earlier binding")),
        "the refusal is not logged naming the record and the reason: {:?}",
        capture.events()
    );
    let kept = directory
        .store()
        .get(&tenant(), "sso")
        .await
        .unwrap()
        .expect("the record is kept");
    assert_eq!(kept.revision, held.revision, "the store wrote nothing");
    let rolling = FactorSecretCipher::new(KEY)
        .with_clock(Arc::new(clock.clone()))
        .with_earlier_tenant_binding(LegacyBlobs::Accept);
    let (text, _) = kept
        .open_credential(Some(&rolling))
        .expect("the credential is kept as it was");
    assert_eq!(&*text, "s3cret");
}

/// The pass counts every record it could not move and every one it moved.
#[tokio::test]
async fn the_pass_counts_the_records_it_could_not_move() {
    let clock = MockClock::at_reference();
    let cipher = FactorSecretCipher::new(KEY).with_clock(Arc::new(clock.clone()));
    let store = Arc::new(OwnStore(MemoryTenantOAuthProviderStore::new()));
    for (name, client) in [("a", "client-a"), ("b", "client-b")] {
        let credential = earlier_binding(&cipher, name, "https://idp.example", client);
        let mut earlier = record(
            "https://idp.example",
            TenantClientCredential::Secret(credential),
        );
        earlier.name = name.into();
        earlier.client_id = client.into();
        store.put(earlier).await.unwrap();
    }
    let mut current = record(
        "https://idp.example",
        TenantClientCredential::Secret(FactorSecret::Plain("s3cret".into())),
    );
    current.name = "c".into();
    current.client_id = "client-c".into();
    current.seal(&cipher).unwrap();
    store.put(current).await.unwrap();

    let directory = StoredTenantOAuthProviders::new(
        store,
        Arc::new(cipher),
        axess_core::testing::oauth_tenant::ownership_assumed(),
    )
    .with_clock(Arc::new(clock.clone()));
    assert_eq!(
        directory.reseal_earlier_bindings().await.unwrap(),
        ResealReport {
            moved: 0,
            not_moved: 2
        }
    );
}
