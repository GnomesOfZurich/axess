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
