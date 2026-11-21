//! The Valkey device store against a cluster, ignored by default
//! (`VALKEY_CLUSTER_URL`). Every script of the store addresses several keys,
//! so the store is given a prefix with a hash tag, which puts all of them in
//! one slot; the checks are the backend-independent ones every store runs.
//! Each test removes what it wrote, also when it fails.

use super::*;
use crate::device::store::{consistency as shared, key_contract};

/// A store on the cluster under `prefix`.
async fn store_under(prefix: String) -> ValkeyDeviceStore {
    let client = crate::testing::valkey_cluster::cluster_client().await;
    ValkeyDeviceStore::plaintext_insecure(client).with_prefix(prefix)
}

/// A store on the cluster under a hash-tagged prefix no other run used,
/// held with the sweep that removes its keys when the test ends, also when
/// it fails.
///
/// A contract that takes its store by value is handed a clone, in the
/// statement that made the swept store: the swept store is a temporary of
/// that statement, so its keys are removed when the contract has run.
async fn store(tag: &str) -> Swept<ValkeyDeviceStore> {
    let sweep = crate::testing::valkey_sweep::on_cluster(&format!("dc_{tag}")).hash_tagged();
    let store = store_under(sweep.prefix().to_owned()).await;
    sweep.hold(store)
}

#[tokio::test]
#[ignore = "requires a Valkey cluster (VALKEY_CLUSTER_URL)"]
async fn the_device_key_contract_holds_on_a_cluster() {
    key_contract::a_key_binding_round_trips(store("keyrt").await.clone()).await;
    key_contract::a_challenge_is_replaced_by_one_compare_and_swap(store("keyswap").await.clone())
        .await;
    key_contract::a_registration_beside_a_sighting_loses_neither(store("keysight").await.clone())
        .await;
}

#[tokio::test]
#[ignore = "requires a Valkey cluster (VALKEY_CLUSTER_URL)"]
async fn the_shared_contract_holds_on_a_cluster() {
    shared::ties_are_broken_by_the_smaller_id(store("ties").await.clone()).await;
    shared::a_shared_fingerprint_stays_findable_while_any_device_carries_it(
        store("twins").await.clone(),
    )
    .await;
    shared::a_sighting_never_rewinds_and_skips_a_revoked_row(store("sight").await.clone()).await;
    shared::a_save_never_un_revokes(store("unrevoke").await.clone()).await;
    // Each store the contract asks for is under a hash tag of its own
    // inside the one sweep's.
    let neverback = crate::testing::valkey_sweep::on_cluster("dc_neverback");
    let made = std::sync::atomic::AtomicUsize::new(0);
    shared::a_revoked_device_never_comes_back(|| {
        let n = made.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        store_under(format!("{{{}_{n}}}", neverback.prefix()))
    })
    .await;
    shared::a_sighting_reports_the_level_it_found(store("reports").await.clone()).await;
}
