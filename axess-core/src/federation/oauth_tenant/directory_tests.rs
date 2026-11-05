//! The directory against an IdP served by `wiremock`: what a broken record
//! does to the other providers of its issuer, and how often concurrent
//! resolutions discover.

use super::*;
use crate::authn::ids::testing::tenant;
use crate::testing::oauth_wiremock::{oauth_generate_rsa_keypair, oauth_mount_oidc_endpoints};
use axess_factors::FactorSecret;
use axess_factors::client_assertion::{ClientAssertionError, SignerSpec};
use axess_factors::oauth::OAuthError;
use wiremock::MockServer;

const DISCOVERY: &str = "/.well-known/openid-configuration";

/// An IdP with discovery and a JWKS, and its issuer.
async fn idp() -> (MockServer, String) {
    let server = MockServer::start().await;
    let (_, jwk, _) = oauth_generate_rsa_keypair();
    oauth_mount_oidc_endpoints(&server, &jwk).await;
    let issuer = server.uri();
    (server, issuer)
}

async fn discoveries(server: &MockServer) -> usize {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|r| r.url.path() == DISCOVERY)
        .count()
}

fn record(
    tenant_label: &str,
    issuer: &str,
    client_id: &str,
    credential: TenantClientCredential,
) -> TenantOAuthProviderRecord {
    TenantOAuthProviderRecord {
        tenant_id: tenant(tenant_label),
        name: "sso".into(),
        issuer: issuer.to_string(),
        client_id: client_id.to_string(),
        redirect_url: "http://localhost:3000/callback".into(),
        scopes: vec![],
        credential,
        dpop: TenantDpop::Advertised,
        revision: 0,
    }
}

fn secret() -> TenantClientCredential {
    TenantClientCredential::Secret(FactorSecret::Plain("s3cret".into()))
}

/// A `private_key_jwt` credential whose key is not a key: the provider is
/// never built.
fn unloadable_key() -> TenantClientCredential {
    TenantClientCredential::PrivateKeyJwt {
        key_pem: FactorSecret::Plain("not a key".into()),
        signer: SignerSpec::new(jsonwebtoken::Algorithm::RS256),
    }
}

type Directory = StoredTenantOAuthProviders<MemoryTenantOAuthProviderStore>;

fn directory() -> Directory {
    StoredTenantOAuthProviders::new(MemoryTenantOAuthProviderStore::new())
}

/// `n` resolutions of acme's `sso` at once; every one must build.
async fn resolve_concurrently(directory: &Arc<Directory>, n: usize) -> Vec<Arc<dyn OAuthProvider>> {
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..n {
        let directory = directory.clone();
        set.spawn(async move {
            let acme = tenant("acme");
            directory.provider(&acme, "sso").await
        });
    }
    let mut built = Vec::with_capacity(n);
    while let Some(joined) = set.join_next().await {
        built.push(
            joined
                .expect("the task ran")
                .expect("the provider builds")
                .expect("the record exists"),
        );
    }
    built
}

/// One tenant's record that does not build (here a key that does not load)
/// leaves the other tenants on the same issuer resolvable: a back-channel
/// logout token from a shared IdP still finds them.
#[tokio::test]
async fn a_broken_record_does_not_hide_the_other_providers_of_its_issuer() {
    let (_server, issuer) = idp().await;
    let directory = directory();
    directory
        .upsert(record("acme", &issuer, "client-a", secret()))
        .await
        .unwrap();
    directory
        .upsert(record("beta", &issuer, "client-b", unloadable_key()))
        .await
        .unwrap();
    assert!(
        directory.provider(&tenant("beta"), "sso").await.is_err(),
        "the case exists: beta's record does not build"
    );

    let found = directory
        .providers_for_issuer(&issuer)
        .await
        .expect("one broken record is not a failure of the whole issuer");
    let built: Vec<_> = found.providers.iter().map(|p| p.tenant).collect();
    assert_eq!(built, vec![tenant("acme")]);
    let broken: Vec<_> = found
        .broken
        .iter()
        .map(|b| (b.tenant, b.client_id.as_str()))
        .collect();
    assert_eq!(broken, vec![(tenant("beta"), "client-b")]);
    // "not a key" is no PEM block: the signer refuses it with its own error.
    assert!(
        matches!(
            found.broken[0].error,
            OAuthError::ClientAssertion(ClientAssertionError::NotPem)
        ),
        "{:?}",
        found.broken[0].error
    );
}

/// Resolutions of one revision that arrive together share one build: one
/// discovery, one provider. A new revision is built once again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_resolutions_of_one_revision_discover_once() {
    let (server, issuer) = idp().await;
    let directory = Arc::new(directory());
    directory
        .upsert(record("acme", &issuer, "client-a", secret()))
        .await
        .unwrap();

    let first = resolve_concurrently(&directory, 8).await;
    assert_eq!(discoveries(&server).await, 1, "one build for eight logins");
    assert!(first.iter().all(|p| Arc::ptr_eq(p, &first[0])));

    directory
        .upsert(record("acme", &issuer, "client-a2", secret()))
        .await
        .unwrap();
    let second = resolve_concurrently(&directory, 8).await;
    assert_eq!(
        discoveries(&server).await,
        2,
        "the new revision is built once"
    );
    assert!(second.iter().all(|p| Arc::ptr_eq(p, &second[0])));
    assert_eq!(second[0].client_id(), Some("client-a2"));
}

/// A record deleted and written again by another process starts again at
/// revision 1. A provider held for the old record at the same revision is
/// not the new record's.
#[tokio::test]
async fn a_record_replaced_at_the_same_revision_is_built_afresh() {
    let (_server, issuer) = idp().await;
    let directory = directory();
    let acme = tenant("acme");
    directory
        .upsert(record("acme", &issuer, "client-old", secret()))
        .await
        .unwrap();
    let old = directory.provider(&acme, "sso").await.unwrap().unwrap();
    assert_eq!(old.client_id(), Some("client-old"));

    // Another process: the row goes and a new one takes its place, which
    // this directory's `remove` never saw.
    directory.store().delete(&acme, "sso").await.unwrap();
    let stored = directory
        .store()
        .put(record("acme", &issuer, "client-new", secret()))
        .await
        .unwrap();
    assert_eq!(stored.revision, 1, "the revision starts again");

    let new = directory.provider(&acme, "sso").await.unwrap().unwrap();
    assert_eq!(new.client_id(), Some("client-new"));
}

/// The same, where the new record's revision is lower than the held one:
/// it is built once and held, not discovered again on every resolution.
#[tokio::test]
async fn a_record_replaced_at_a_lower_revision_is_discovered_once() {
    let (server, issuer) = idp().await;
    let directory = directory();
    let acme = tenant("acme");
    for _ in 0..3 {
        directory
            .upsert(record("acme", &issuer, "client-old", secret()))
            .await
            .unwrap();
    }
    directory.provider(&acme, "sso").await.unwrap().unwrap();
    assert_eq!(discoveries(&server).await, 1);

    directory.store().delete(&acme, "sso").await.unwrap();
    directory
        .store()
        .put(record("acme", &issuer, "client-new", secret()))
        .await
        .unwrap();

    for _ in 0..3 {
        let provider = directory.provider(&acme, "sso").await.unwrap().unwrap();
        assert_eq!(provider.client_id(), Some("client-new"));
    }
    assert_eq!(
        discoveries(&server).await,
        2,
        "the replacement is discovered once, not on every resolution"
    );
}

/// A credential as the first release sealed it: bound to the tenant and the
/// name only, with that binding written out by hand.
fn sealed_by_the_first_release(
    key: &[u8; 32],
    key_id: String,
    tenant_id: &TenantId,
    name: &str,
) -> FactorSecret {
    use aes_gcm::aead::{Aead, Payload};
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let tenant_text = tenant_id.to_string();
    let mut aad = b"axess.factor-secret.v1".to_vec();
    for part in [tenant_text.as_str(), "", name] {
        aad.extend_from_slice(&(part.len() as u32).to_be_bytes());
        aad.extend_from_slice(part.as_bytes());
    }
    let nonce_bytes = [3u8; 12];
    let ciphertext = Aes256Gcm::new_from_slice(key)
        .unwrap()
        .encrypt(
            &Nonce::try_from(&nonce_bytes[..]).unwrap(),
            Payload {
                msg: b"s3cret",
                aad: &aad,
            },
        )
        .unwrap();
    FactorSecret::Sealed(axess_factors::SealedFactorSecret {
        key_id,
        nonce: URL_SAFE_NO_PAD.encode(nonce_bytes),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    })
}

/// A record sealed in the first release's binding is stored under the current
/// binding the first time it is used, so a cipher that refuses the old
/// binding still reads it afterwards.
#[tokio::test]
async fn a_record_in_the_first_binding_is_stored_in_the_current_one_on_first_use() {
    use crate::authn::factor_secret::FactorSecretCipher;
    use crate::session::legacy_blobs::LegacyBlobs;
    const KEY: [u8; 32] = *b"0123456789abcdef0123456789abcdeF";
    let (_server, issuer) = idp().await;
    let cipher = Arc::new(FactorSecretCipher::new(KEY));
    let directory = StoredTenantOAuthProviders::new(MemoryTenantOAuthProviderStore::new())
        .with_cipher(cipher.clone());
    let acme = tenant("acme");
    let mut probe = record("acme", &issuer, "client-1", secret());
    probe.seal(&cipher).unwrap();
    let key_id = match &probe.credential {
        TenantClientCredential::Secret(FactorSecret::Sealed(s)) => s.key_id.clone(),
        _ => unreachable!("sealed above"),
    };
    let old = sealed_by_the_first_release(&KEY, key_id, &acme, "sso");
    directory
        .store()
        .put(record(
            "acme",
            &issuer,
            "client-1",
            TenantClientCredential::Secret(old),
        ))
        .await
        .unwrap();

    directory.provider(&acme, "sso").await.unwrap().unwrap();

    let stored = directory.store().get(&acme, "sso").await.unwrap().unwrap();
    assert_eq!(stored.revision, 2, "the record was written back once");
    let strict = FactorSecretCipher::new(KEY).with_first_binding(LegacyBlobs::Reject);
    let (text, rotated) = stored.open_credential(Some(&strict)).unwrap();
    assert_eq!(&*text, "s3cret");
    assert!(!rotated);
}

/// A store that lists a stale record and fails the read that follows, as a
/// store does when it blips between the two.
struct StaleListing {
    inner: MemoryTenantOAuthProviderStore,
    stale: std::sync::Mutex<Option<TenantOAuthProviderRecord>>,
    fail_get: std::sync::atomic::AtomicBool,
}

impl TenantOAuthProviderStore for StaleListing {
    async fn get(
        &self,
        tenant: &TenantId,
        name: &str,
    ) -> Result<Option<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
        if self.fail_get.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(TenantOAuthProviderStoreError::new(std::io::Error::other(
                "store blip",
            )));
        }
        self.inner.get(tenant, name).await
    }
    async fn put(
        &self,
        record: TenantOAuthProviderRecord,
    ) -> Result<TenantOAuthProviderRecord, TenantOAuthProviderStoreError> {
        self.inner.put(record).await
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
        _: &str,
    ) -> Result<Vec<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
        Ok(self.stale.lock().unwrap().iter().cloned().collect())
    }
    async fn list(
        &self,
        tenant: &TenantId,
    ) -> Result<Vec<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
        self.inner.list(tenant).await
    }
}

/// A resolution that read an older revision than the one held reads the
/// record again; when that read fails, the failure is the answer and the
/// older record is not served.
#[tokio::test]
async fn a_failed_re_read_is_reported_not_answered_with_the_older_record() {
    let (_server, issuer) = idp().await;
    let directory = StoredTenantOAuthProviders::new(StaleListing {
        inner: MemoryTenantOAuthProviderStore::new(),
        stale: std::sync::Mutex::new(None),
        fail_get: std::sync::atomic::AtomicBool::new(false),
    });
    let acme = tenant("acme");
    let first = directory
        .upsert(record("acme", &issuer, "client-old", secret()))
        .await
        .unwrap();
    *directory.store().stale.lock().unwrap() = Some(first);
    directory
        .upsert(record("acme", &issuer, "client-new", secret()))
        .await
        .unwrap();
    let held = directory.provider(&acme, "sso").await.unwrap().unwrap();
    assert_eq!(held.client_id(), Some("client-new"));

    directory
        .store()
        .fail_get
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let found = directory.providers_for_issuer(&issuer).await.unwrap();

    assert!(found.providers.is_empty(), "the older record was served");
    assert_eq!(found.broken.len(), 1);
    assert!(matches!(found.broken[0].error, OAuthError::Store(_)));
}
