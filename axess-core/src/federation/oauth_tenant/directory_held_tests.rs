//! The providers a directory holds built: what `built_providers` lists, what
//! `invalidate_tenant` drops, and that a shared (`Arc`) source answers as
//! the directory it shares.

use super::directory_tests::{directory, idp, record, secret};
use super::*;
use crate::authn::ids::testing::tenant;

type Directory = StoredTenantOAuthProviders<MemoryTenantOAuthProviderStore>;

/// A directory with a record for acme and one for beta on `issuer`, neither
/// built yet.
async fn two_tenants_on(issuer: &str) -> Directory {
    let directory = directory();
    for (label, client_id) in [("acme", "client-a"), ("beta", "client-b")] {
        directory
            .upsert(record(label, issuer, client_id, secret()))
            .await
            .expect("upsert");
    }
    directory
}

async fn resolved(directory: &Directory, label: &str) -> Arc<dyn OAuthProvider> {
    directory
        .provider(&tenant(label), "sso")
        .await
        .expect("the provider builds")
        .expect("the record exists")
}

#[tokio::test]
async fn the_built_providers_are_the_ones_resolved_so_far() {
    let (server, issuer) = idp().await;
    let directory = two_tenants_on(&issuer).await;
    assert!(
        directory.built_providers().is_empty(),
        "a record is not built until it is asked for"
    );

    let acme = resolved(&directory, "acme").await;

    let built = directory.built_providers();
    assert_eq!(built.len(), 1);
    assert!(Arc::ptr_eq(&built[0], &acme));
    drop(server);
}

#[tokio::test]
async fn invalidating_a_tenant_drops_its_providers_and_no_other_tenants() {
    let (server, issuer) = idp().await;
    let directory = two_tenants_on(&issuer).await;
    resolved(&directory, "acme").await;
    let beta = resolved(&directory, "beta").await;
    assert_eq!(directory.built_providers().len(), 2);
    let before = directory.generation();

    directory.invalidate_tenant(&tenant("acme"));

    let built = directory.built_providers();
    assert_eq!(built.len(), 1);
    assert!(Arc::ptr_eq(&built[0], &beta), "beta's provider is kept");
    assert_ne!(directory.generation(), before, "the change is announced");
    drop(server);
}

/// The builder is handed a clone of an `Arc` to the directory. What it reads
/// through the `Arc` is the directory's own generation and providers, not
/// the trait's defaults.
#[tokio::test]
async fn a_shared_directory_answers_as_the_directory_it_shares() {
    let (server, issuer) = idp().await;
    let shared = Arc::new(two_tenants_on(&issuer).await);
    let through =
        |shared: &Arc<Directory>| <Arc<Directory> as TenantOAuthProviders>::generation(shared);
    let own = |shared: &Arc<Directory>| <Directory as TenantOAuthProviders>::generation(shared);

    let mut seen = vec![own(&shared)];
    assert_eq!(through(&shared), seen[0]);
    shared.invalidate(&tenant("acme"), "sso");
    seen.push(own(&shared));
    assert_eq!(through(&shared), seen[1]);
    shared.invalidate_tenant(&tenant("beta"));
    seen.push(own(&shared));
    assert_eq!(through(&shared), seen[2]);
    seen.dedup();
    assert_eq!(seen.len(), 3, "the generation moved each time: {seen:?}");

    let acme = resolved(&shared, "acme").await;
    let built = <Arc<Directory> as TenantOAuthProviders>::built_providers(&shared);
    assert_eq!(built.len(), 1);
    assert!(Arc::ptr_eq(&built[0], &acme));
    drop(server);
}
