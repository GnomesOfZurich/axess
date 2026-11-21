//! `TenantOAuthProviderStore::reassign_pair` on the shipped stores: the
//! records that held a pair are removed and the new holder written in one
//! step, so a writer in another process that tries the old holder's record
//! afterwards is refused by the store's own constraint.
//!
//! Run with: `cargo test -p axess-core --features testing,oauth,jwt-aws-lc,sqlite --test oauth_tenant_reassign_pair`

#![cfg(all(feature = "testing", feature = "oauth"))]

use axess_core::authn::ids::TenantId;
use axess_core::federation::oauth_tenant::{
    MemoryTenantOAuthProviderStore, TenantClientCredential, TenantDpop, TenantOAuthProviderRecord,
    TenantOAuthProviderStore,
};
use axess_factors::FactorSecret;

const ISSUER: &str = "https://idp.example";

fn tenant(label: &str) -> TenantId {
    axess_core::authn::ids::testing::tenant(label)
}

fn record(tenant_label: &str, name: &str, client_id: &str) -> TenantOAuthProviderRecord {
    TenantOAuthProviderRecord {
        tenant_id: tenant(tenant_label),
        name: name.into(),
        issuer: ISSUER.into(),
        client_id: client_id.into(),
        redirect_url: "http://localhost:3000/callback".into(),
        scopes: vec![],
        credential: TenantClientCredential::Secret(FactorSecret::Plain("s3cret".into())),
        dpop: TenantDpop::Advertised,
        kind: None,
        revision: 0,
    }
}

/// What every store does: `here` hands the pair over; `elsewhere`, the same
/// table seen by another process, then tries the squatter's record again.
async fn reassign_contract<S: TenantOAuthProviderStore, T: TenantOAuthProviderStore>(
    here: &S,
    elsewhere: &T,
) {
    here.put(record("squatter", "borrowed", "owners-client"))
        .await
        .unwrap();
    here.put(record("squatter", "second", "owners-client-2"))
        .await
        .unwrap();
    here.put(record("owner", "sso", "old-client"))
        .await
        .unwrap();

    let reassigned = here
        .reassign_pair(record("owner", "sso", "owners-client"))
        .await
        .expect("reassigned");

    let removed: Vec<_> = reassigned
        .removed
        .iter()
        .map(|record| (record.tenant_id, record.name.clone()))
        .collect();
    assert_eq!(removed, [(tenant("squatter"), "borrowed".to_string())]);
    assert_eq!(
        reassigned.removed[0].client_id, "owners-client",
        "the removed record is the one that held the pair, as it was stored"
    );
    assert_eq!(
        reassigned.stored.revision, 2,
        "the owner's record replaced its earlier revision"
    );
    let refused = elsewhere
        .put(record("squatter", "borrowed", "owners-client"))
        .await
        .expect_err("the squatter cannot take the pair back");
    assert!(refused.is_pair_held(), "{refused}");
    let holders: Vec<_> = elsewhere
        .list_by_issuer(ISSUER)
        .await
        .unwrap()
        .into_iter()
        .map(|r| (r.tenant_id, r.name, r.client_id))
        .collect();
    assert_eq!(holders.len(), 2, "{holders:?}");
    assert!(holders.contains(&(tenant("owner"), "sso".into(), "owners-client".into())));
    assert!(
        holders.contains(&(
            tenant("squatter"),
            "second".into(),
            "owners-client-2".into()
        )),
        "a record over another pair stays"
    );

    let again = here
        .reassign_pair(record("owner", "sso", "owners-client"))
        .await
        .unwrap();
    assert!(again.removed.is_empty(), "the pair is the record's own");
    assert_eq!(again.stored.revision, 3);
}

#[tokio::test]
async fn the_memory_store_hands_a_pair_over_in_one_step() {
    let store = MemoryTenantOAuthProviderStore::new();
    reassign_contract(&store, &store).await;
}

#[cfg(any(feature = "sqlite", feature = "sqlite-unbundled"))]
#[tokio::test]
async fn the_sqlite_store_hands_a_pair_over_in_one_transaction() {
    use axess_core::federation::oauth_tenant::SqliteTenantOAuthProviderStore;
    let dir = tempfile::tempdir().expect("a temporary directory");
    let url = format!(
        "sqlite://{}?mode=rwc",
        dir.path().join("providers.db").display()
    );
    let pool = || async {
        sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .expect("pool")
    };
    let here = SqliteTenantOAuthProviderStore::new(pool().await);
    here.init_schema().await.expect("schema");
    let elsewhere = SqliteTenantOAuthProviderStore::new(pool().await);

    reassign_contract(&here, &elsewhere).await;
}
