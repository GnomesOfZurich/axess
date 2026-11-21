//! The directory over a store that fails where a test asks it to: each
//! named refusal answers its own predicate and no other, a backend failure
//! of a write is the directory's error, never a named refusal, and a
//! credential that does not open is logged with the reason it did not.

use super::directory_tests::{record, secret};
use super::*;
use crate::authn::factor::{FactorKind, FederatedProvider};
use crate::authn::factor_secret::{FactorSecretBinding, FactorSecretCipher, FactorSecretError};
use crate::authn::ids::testing::tenant;
use crate::authn::types::AuthnScope;
use crate::session::legacy_blobs::LegacyBlobs;
use axess_clock::testing::MockClock;
use axess_factors::FactorSecret;
use axess_factors::oauth::OAuthError;
use axess_testing::mock_tracing::TracingCapture;
use std::sync::atomic::{AtomicBool, Ordering};

const KEY: [u8; 32] = *b"0123456789abcdef0123456789abcdeF";

/// The test's cipher on `clock`.
fn cipher(clock: &MockClock) -> FactorSecretCipher {
    FactorSecretCipher::new(KEY).with_clock(Arc::new(clock.clone()))
}

/// A directory over `store` with `cipher`, on `clock`.
fn directory<S: TenantOAuthProviderStore>(
    store: S,
    cipher: FactorSecretCipher,
    clock: &MockClock,
) -> StoredTenantOAuthProviders<S> {
    StoredTenantOAuthProviders::new(
        store,
        Arc::new(cipher),
        crate::testing::oauth_tenant::ownership_assumed(),
    )
    .with_clock(Arc::new(clock.clone()))
}

/// A memory store whose `put_if_revision` fails as a backend does while
/// `fail_conditional_write` is set.
#[derive(Default)]
struct FailingStore {
    inner: MemoryTenantOAuthProviderStore,
    fail_conditional_write: AtomicBool,
}

impl TenantOAuthProviderStore for FailingStore {
    async fn get(
        &self,
        tenant: &TenantId,
        name: &str,
    ) -> Result<Option<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
        self.inner.get(tenant, name).await
    }
    async fn put(
        &self,
        record: TenantOAuthProviderRecord,
    ) -> Result<TenantOAuthProviderRecord, TenantOAuthProviderStoreError> {
        self.inner.put(record).await
    }
    async fn put_if_revision(
        &self,
        record: TenantOAuthProviderRecord,
        expected: u64,
    ) -> Result<Option<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
        if self.fail_conditional_write.load(Ordering::SeqCst) {
            return Err(TenantOAuthProviderStoreError::new(std::io::Error::other(
                "store unreachable",
            )));
        }
        self.inner.put_if_revision(record, expected).await
    }
    async fn reassign_pair(
        &self,
        record: TenantOAuthProviderRecord,
    ) -> Result<ReassignedPair, TenantOAuthProviderStoreError> {
        self.inner.reassign_pair(record).await
    }
    async fn delete(
        &self,
        tenant: &TenantId,
        name: &str,
    ) -> Result<bool, TenantOAuthProviderStoreError> {
        self.inner.delete(tenant, name).await
    }
    async fn list_by_issuer(
        &self,
        issuer: &str,
    ) -> Result<Vec<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
        self.inner.list_by_issuer(issuer).await
    }
    async fn list(
        &self,
        tenant: &TenantId,
    ) -> Result<Vec<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
        self.inner.list(tenant).await
    }
    async fn list_all(
        &self,
    ) -> Result<Vec<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
        self.inner.list_all().await
    }
}

/// The test's record with its credential sealed under the earlier binding: the
/// issuer and client id as the only context.
fn in_the_earlier_binding(cipher: &FactorSecretCipher) -> TenantOAuthProviderRecord {
    let mut record = record("acme", "https://idp.example", "client-1", secret());
    let scope = AuthnScope::Tenant(record.tenant_id);
    let kind = FactorKind::Federated(FederatedProvider::Custom(record.name.clone()));
    let sealed = cipher
        .seal(
            "s3cret",
            FactorSecretBinding::new(&scope, &kind)
                .with_context(&[record.issuer.as_str(), record.client_id.as_str()]),
        )
        .expect("seal");
    record.credential = TenantClientCredential::Secret(FactorSecret::Sealed(sealed));
    record
}

/// Each named refusal answers its own predicate only, and a backend error
/// answers none.
#[test]
fn each_named_refusal_answers_its_own_predicate_only() {
    let backend = TenantOAuthProviderStoreError::new(std::io::Error::other("down"));
    assert!(!backend.is_pair_held());
    assert!(!backend.is_put_if_revision_unsupported());

    let held = TenantOAuthProviderStoreError::pair_held();
    assert!(held.is_pair_held());
    assert!(!held.is_put_if_revision_unsupported());

    let unsupported = TenantOAuthProviderStoreError::put_if_revision_unsupported();
    assert!(unsupported.is_put_if_revision_unsupported());
    assert!(!unsupported.is_pair_held());

    let reassign = TenantOAuthProviderStoreError::reassign_pair_unsupported();
    assert!(!reassign.is_pair_held());
    assert!(!reassign.is_put_if_revision_unsupported());
    assert!(reassign.to_string().contains("reassign_pair"), "{reassign}");
}

/// A store whose conditional write fails as a backend does stops the
/// start-up pass with a store error: the record is not counted as one the
/// store cannot move, and the directory does not start.
#[tokio::test]
async fn a_backend_failure_of_the_conditional_write_stops_the_pass() {
    let clock = MockClock::at_reference();
    let cipher = cipher(&clock);
    let directory = directory(FailingStore::default(), self::cipher(&clock), &clock);
    directory
        .raw_store()
        .put(in_the_earlier_binding(&cipher))
        .await
        .expect("put");
    directory
        .raw_store()
        .fail_conditional_write
        .store(true, Ordering::SeqCst);

    let failed = directory
        .reseal_earlier_bindings()
        .await
        .expect_err("a store that cannot be reached is not a store that cannot move");

    assert!(
        matches!(&failed, OAuthError::Store(e) if e.to_string().contains("store unreachable")),
        "{failed:?}"
    );
}

/// The message the directory logs for a credential that does not open, once
/// a resolution of acme's `sso` has failed on `record`, written past the
/// directory after its start-up pass.
async fn refusal_logged_for(
    record: TenantOAuthProviderRecord,
    directory_cipher: FactorSecretCipher,
    clock: &MockClock,
) -> String {
    let store = Arc::new(MemoryTenantOAuthProviderStore::new());
    let directory = directory(store.clone(), directory_cipher, clock)
        .started()
        .await
        .expect("an empty store starts");
    store.put(record).await.expect("put");
    let capture = TracingCapture::install();
    assert!(
        directory.provider(&tenant("acme"), "sso").await.is_err(),
        "the credential opened"
    );
    capture
        .events()
        .into_iter()
        .find(|event| event.message.contains("does not open"))
        .map(|event| event.message)
        .unwrap_or_else(|| panic!("no refusal logged: {:?}", capture.events()))
}

/// A credential still under the earlier binding, refused by the cipher's
/// policy, is logged as that, not as a credential that does not
/// authenticate.
#[tokio::test]
async fn a_credential_under_a_refused_earlier_binding_is_logged_as_that() {
    let clock = MockClock::at_reference();
    let earlier = in_the_earlier_binding(&cipher(&clock));
    let refusing = cipher(&clock).with_earlier_tenant_binding(LegacyBlobs::Reject);

    let logged = refusal_logged_for(earlier, refusing, &clock).await;

    assert!(
        logged.contains("still sealed under the earlier binding"),
        "{logged}"
    );
    assert!(
        logged.contains(&format!("tenant {} provider \"sso\"", tenant("acme"))),
        "{logged}"
    );
}

/// A credential whose record was rewritten in the store after it was sealed
/// does not authenticate under any binding, and is logged with the cipher's
/// own error, not as one under the earlier binding.
#[tokio::test]
async fn a_credential_that_does_not_authenticate_is_logged_with_the_ciphers_error() {
    let clock = MockClock::at_reference();
    let mut rewritten = record("acme", "https://idp.example", "client-1", secret());
    rewritten.seal(&cipher(&clock)).expect("seal");
    rewritten.redirect_url = "https://elsewhere.example/callback".into();
    let refusing = cipher(&clock).with_earlier_tenant_binding(LegacyBlobs::Reject);

    let logged = refusal_logged_for(rewritten, refusing, &clock).await;

    assert!(
        logged.contains(&FactorSecretError::Open.to_string()),
        "{logged}"
    );
    assert!(!logged.contains("earlier binding"), "{logged}");
}

/// A credential that opens under no binding the cipher knows stops the
/// start-up pass with an error that names its record and says why.
#[tokio::test]
async fn a_credential_that_opens_under_no_binding_stops_the_pass_by_name() {
    let clock = MockClock::at_reference();
    let mut rewritten = record("acme", "https://idp.example", "client-1", secret());
    rewritten.seal(&cipher(&clock)).expect("seal");
    rewritten.redirect_url = "https://elsewhere.example/callback".into();
    let directory = directory(
        MemoryTenantOAuthProviderStore::new(),
        cipher(&clock),
        &clock,
    );
    directory.raw_store().put(rewritten).await.expect("put");

    let failed = directory
        .reseal_earlier_bindings()
        .await
        .expect_err("a credential that opens under no binding stops the pass");

    let text = failed.to_string();
    assert!(
        text.contains("the credential opens under no binding the cipher knows"),
        "{text}"
    );
    assert!(
        text.contains(&FactorSecretError::Open.to_string()),
        "{text}"
    );
    assert!(
        text.contains(&format!("tenant {} provider \"sso\"", tenant("acme"))),
        "{text}"
    );
}
