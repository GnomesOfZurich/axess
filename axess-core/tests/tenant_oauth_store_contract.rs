#![cfg(all(feature = "oauth", feature = "memory"))]
//! What every tenant OAuth provider store must offer: a listing of every
//! record. That the conditional write and the listing are required methods,
//! so a store without them does not compile, is checked by the
//! `compile_fail` doctests beside the trait.

use axess_core::authn::ids::testing::tenant;
use axess_core::federation::oauth_tenant::{
    MemoryTenantOAuthProviderStore, TenantClientCredential, TenantDpop, TenantOAuthProviderRecord,
    TenantOAuthProviderStore,
};
use axess_factors::FactorSecret;

fn record(tenant_label: &str, name: &str, client_id: &str) -> TenantOAuthProviderRecord {
    TenantOAuthProviderRecord {
        tenant_id: tenant(tenant_label),
        name: name.into(),
        issuer: "https://idp.example".into(),
        client_id: client_id.into(),
        redirect_url: "http://localhost:3000/callback".into(),
        scopes: vec![],
        credential: TenantClientCredential::Secret(FactorSecret::Plain("s3cret".into())),
        dpop: TenantDpop::Advertised,
        kind: None,
        revision: 0,
    }
}

/// Every record of every tenant, in tenant and name order.
async fn lists_every_record(store: &impl TenantOAuthProviderStore) {
    for (t, n, c) in [("t2", "b", "c1"), ("t1", "z", "c2"), ("t1", "a", "c3")] {
        store.put(record(t, n, c)).await.unwrap();
    }
    let all = store.list_all().await.unwrap();
    let mut want: Vec<(String, String)> = [("t1", "a"), ("t1", "z"), ("t2", "b")]
        .iter()
        .map(|(t, n)| (tenant(t).to_string(), n.to_string()))
        .collect();
    want.sort();
    let got: Vec<(String, String)> = all
        .iter()
        .map(|r| (r.tenant_id.to_string(), r.name.clone()))
        .collect();
    assert_eq!(got, want);
}

#[tokio::test]
async fn the_memory_store_lists_every_record() {
    lists_every_record(&MemoryTenantOAuthProviderStore::new()).await;
}

#[cfg(any(feature = "sqlite", feature = "sqlite-unbundled"))]
#[tokio::test]
async fn the_sqlite_store_lists_every_record() {
    use axess_core::federation::oauth_tenant::SqliteTenantOAuthProviderStore;
    let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
    let store = SqliteTenantOAuthProviderStore::new(pool);
    store.init_schema().await.unwrap();
    lists_every_record(&store).await;
}
