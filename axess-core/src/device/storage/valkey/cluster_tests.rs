//! The device store against a Valkey cluster (`VALKEY_CLUSTER_URL`): ignored
//! by default, run by `scripts/check-live-stores.sh`.
//!
//! Every write of a device is one script over several keys (the row, the
//! fingerprint index, the tenant, user and refresh-family indexes, the
//! create guard), and the batched reads fetch many rows at once. A cluster
//! runs either only when the keys share a hash slot. Under a prefix with a
//! hash tag they do: the scripts run, the server refuses none, and the store
//! keeps the contract every backend keeps. A prefix without one is refused
//! where the store is built, and a store left on the default prefix refuses
//! its writes by name. The reason is shown on a store built past that
//! check: its writes are refused whole, with an error and nothing written,
//! by whichever party sees the keys apart first, the clustered client when
//! they are on two primaries, the server when they are in two slots of one.
//!
//! Every test writes under prefixes inside one sweep's and removes what it
//! wrote, also when it fails. The two tests of a store on the default
//! prefix write nothing: the store refuses before it sends a command, which
//! each asserts.

use std::collections::BTreeSet;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::row::{
    create_guard_key, fingerprint_hex, fingerprint_key, fingerprint_set_key, fingerprint_user_key,
    fingerprint_zset_key,
};
use super::*;
use crate::device::store::consistency::{self as shared, at, device, tenant, user};
use crate::health::{HealthCheck, HealthStatus};
use crate::testing::valkey_cluster::{
    Primary, cluster_client, eval_stats, primaries, refused_scripts_ledger,
};
use crate::testing::valkey_sweep::{KeySweep, Swept};
use fred::util::redis_keyslot;

/// The sweep of one test's keys on the cluster, named by `tag`.
fn sweep(tag: &str) -> KeySweep {
    crate::testing::valkey_sweep::on_cluster(&format!("dcl_{tag}"))
}

/// The prefix named `name` inside `sweep`'s, with or without a hash tag:
/// one test's stores, each under a prefix of its own, all removed by the
/// one sweep.
fn prefix_in(sweep: &KeySweep, name: impl std::fmt::Display, tagged: bool) -> String {
    if tagged {
        format!("{{{}_{name}}}", sweep.prefix())
    } else {
        format!("{}_{name}", sweep.prefix())
    }
}

/// An encrypted store on the cluster under `prefix`.
async fn store_under(prefix: &str) -> ValkeyDeviceStore {
    ValkeyDeviceStore::new(cluster_client().await, crate::testing::test_key(6))
        .with_prefix(prefix.to_string())
}

/// A store on the cluster under a hash-tag prefix of its own, held with the
/// sweep that removes its keys when the test ends, also when it fails.
async fn tagged_store(tag: &str) -> Swept<ValkeyDeviceStore> {
    let sweep = sweep(tag).hash_tagged();
    let store = store_under(sweep.prefix()).await;
    sweep.hold(store)
}

/// An encrypted store on the cluster under `prefix`, built past the check
/// that refuses a prefix without a hash tag there, to show what the
/// cluster does to the writes of such a store.
async fn store_past_the_check(prefix: &str) -> ValkeyDeviceStore {
    let mut store = ValkeyDeviceStore::new(cluster_client().await, crate::testing::test_key(6));
    store.prefix = prefix.into();
    store.keys_apart = false;
    store
}

/// A hash-tag prefix inside `sweep`'s whose one slot is served by the
/// primary at `turn`, counted round the primaries.
fn tagged_prefix_on(sweep: &KeySweep, nodes: &[Primary], turn: usize) -> String {
    let primary = &nodes[turn % nodes.len()];
    (0..10_000)
        .map(|n| prefix_in(sweep, format_args!("{turn}_{n}"), true))
        .find(|p| primary.serves(redis_keyslot(p.as_bytes())))
        .expect("a hash tag whose slot the primary serves")
}

/// A prefix without a hash tag, inside `sweep`'s, under which the keys of
/// one write of `d` are in several slots. With `one_primary` every key of a create is on
/// the same primary, so the client sends the create's script; without it
/// the row and the fingerprint index, the two keys every write script is
/// given, are on two primaries, so the client refuses a save and a create
/// alike.
fn untagged_prefix_for(
    sweep: &KeySweep,
    nodes: &[Primary],
    d: &Device,
    one_primary: bool,
) -> String {
    (0..100_000)
        .map(|n| prefix_in(sweep, n, false))
        .find(|p| {
            if one_primary {
                let created = create_keys_of(p, d);
                nodes_of(nodes, &created).len() == 1 && slots_of(&created).len() > 1
            } else {
                nodes_of(nodes, &keys_of(p, d)[..2]).len() > 1
            }
        })
        .expect("a prefix that spreads the keys of a write as asked")
}

/// The text of a refused write, which names who refused it.
fn refusal(result: Result<impl std::fmt::Debug, ValkeyDeviceStoreError>) -> String {
    match result {
        Err(ValkeyDeviceStoreError::Connection(e)) => e.to_string(),
        other => panic!("a write across slots was not refused: {other:?}"),
    }
}

/// Nothing of `d` is stored under the store's prefix: no key of the write
/// exists, and each read answers that nothing is there.
async fn assert_nothing_stored(s: &ValkeyDeviceStore, d: &Device, keys: &[String]) {
    assert_eq!(existing(&s.client, keys).await, 0, "nothing was written");
    assert!(s.load(&d.tenant_id, &d.id).await.unwrap().is_none());
    assert!(
        s.find_by_fingerprint(&d.tenant_id, &d.fingerprint_hash)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        s.find_for_user(&d.tenant_id, &user(), 10)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        s.find_by_refresh_family(&d.tenant_id, "cl-fam-u")
            .await
            .unwrap()
            .is_empty()
    );
}

fn refresh(family: &str, now: Timestamp) -> DeviceBinding {
    DeviceBinding::Refresh {
        family_id: family.into(),
        issued_at: now,
        last_used_at: now,
    }
}

/// Every key a save or a create of `d` addresses under `prefix`: the row
/// and the fingerprint index first (the two keys both scripts are given),
/// then the two fingerprint keys of earlier releases that a save cleans up,
/// the tenant index, the create guard, the owner's index and
/// per-fingerprint set, and the index of each refresh family the device is
/// bound to.
fn keys_of(prefix: &str, d: &Device) -> Vec<String> {
    let (t, id) = (d.tenant_id.to_string(), d.id.to_string());
    let hex = fingerprint_hex(&d.fingerprint_hash);
    let owner = d.user_id.map(|u| u.to_string());
    let mut keys = vec![
        device_key(prefix, &t, &id),
        fingerprint_zset_key(prefix, &t, &hex),
        fingerprint_set_key(prefix, &t, &hex),
        fingerprint_key(prefix, &t, &hex),
        tenant_index_key(prefix, &t),
        create_guard_key(prefix, &t, &hex, owner.as_deref()),
    ];
    if let Some(owner) = &owner {
        keys.push(user_index_key(prefix, &t, owner));
        keys.push(fingerprint_user_key(prefix, &t, &hex, owner));
    }
    for binding in &d.bindings {
        if let DeviceBinding::Refresh { family_id, .. } = binding {
            keys.push(family_index_key(prefix, &t, family_id));
        }
    }
    keys
}

/// The keys a create of `d` addresses under `prefix`: every key of
/// [`keys_of`] but the two fingerprint keys of earlier releases, which only
/// a save is given.
fn create_keys_of(prefix: &str, d: &Device) -> Vec<String> {
    let t = d.tenant_id.to_string();
    let hex = fingerprint_hex(&d.fingerprint_hash);
    let only_a_save = [
        fingerprint_set_key(prefix, &t, &hex),
        fingerprint_key(prefix, &t, &hex),
    ];
    keys_of(prefix, d)
        .into_iter()
        .filter(|key| !only_a_save.contains(key))
        .collect()
}

fn slots_of(keys: &[String]) -> BTreeSet<u16> {
    keys.iter().map(|k| redis_keyslot(k.as_bytes())).collect()
}

/// The primaries serving `keys`.
fn nodes_of<'a>(nodes: &'a [Primary], keys: &[String]) -> BTreeSet<&'a str> {
    slots_of(keys)
        .into_iter()
        .map(|slot| {
            nodes
                .iter()
                .find(|p| p.serves(slot))
                .map(|p| p.addr.as_str())
                .expect("every slot is served")
        })
        .collect()
}

/// How many of `keys` exist, each asked on its own so the question never
/// spans two slots.
async fn existing(client: &Client, keys: &[String]) -> usize {
    let mut found = 0;
    for key in keys {
        let n: i64 = client.exists(key.as_str()).await.expect("EXISTS");
        found += n as usize;
    }
    found
}

/// The tests that need the cluster. `valkey_cluster` is the name a run
/// leaves them out by (`--skip valkey_cluster`); the module inside is the
/// device store's own, the name the live-store gate counts this suite by,
/// apart from the session store's and the authorization cache's.
mod valkey_cluster {
    use super::*;

    mod device_cluster {
        use super::*;

        /// Under a hash tag every key of a write is in one slot, so each
        /// multi-key script runs: a create with its guard, a sighting, a
        /// conditional trust change, a bindings swap that moves the family
        /// index, an owner claim and a delete. The server refuses none of
        /// them, and the indexes agree with the rows after each.
        #[tokio::test]
        #[ignore = "requires a Valkey cluster (VALKEY_CLUSTER_URL)"]
        async fn under_a_hash_tag_every_multi_key_script_runs() {
            let counting = refused_scripts_ledger().await;
            let s = tagged_store("scripts").await;
            let nodes = primaries(&s.client).await;
            let (calls_before, refused_before) = eval_stats(&nodes).await;
            let (t, u) = (tenant(), user());

            let mut d = device("cl-owned", 0xc1, DeviceTrustLevel::Seen, at(0));
            d.bindings = vec![refresh("cl-fam-a", at(0))];
            let keys = keys_of(&s.prefix, &d);
            assert_eq!(slots_of(&keys).len(), 1, "one slot under a hash tag");
            assert!(
                slots_of(&keys_of("axess", &d)).len() > 1,
                "the same keys without a hash tag are in several slots"
            );

            let created = s.create_or_find(&d, at(0)).await.expect("create");
            assert_eq!(created.id, d.id);
            let mut twin = device("cl-twin", 0xc1, DeviceTrustLevel::Seen, at(1));
            twin.bindings = d.bindings.clone();
            let found = s.create_or_find(&twin, at(1)).await.expect("find");
            assert_eq!(found.id, d.id, "the create guard answers the first device");
            assert!(s.load(&t, &twin.id).await.unwrap().is_none());

            let level = s.record_sighting(&t, &d.id, at(600)).await.unwrap();
            assert_eq!(level, DeviceTrustLevel::Seen);
            let promoted = s
                .set_trust_level_if(
                    &t,
                    &d.id,
                    DeviceTrustLevel::Seen,
                    DeviceTrustLevel::Trusted,
                    at(601),
                )
                .await
                .unwrap();
            assert_eq!(promoted, TrustTransition::Applied);

            let moved = s
                .replace_bindings(
                    &t,
                    &d.id,
                    &d.bindings,
                    &[refresh("cl-fam-b", at(602))],
                    at(602),
                )
                .await
                .unwrap();
            assert_eq!(moved, BindingsUpdate::Written);
            assert!(
                s.find_by_refresh_family(&t, "cl-fam-a")
                    .await
                    .unwrap()
                    .is_empty()
            );
            let in_family = s.find_by_refresh_family(&t, "cl-fam-b").await.unwrap();
            assert_eq!(in_family.len(), 1);
            assert_eq!(in_family[0].trust_level, DeviceTrustLevel::Trusted);

            let mut guest = device("cl-guest", 0xc2, DeviceTrustLevel::Seen, at(0));
            guest.user_id = None;
            s.save(&guest, at(0)).await.expect("save");
            let claim = s.claim_owner(&t, &guest.id, &u, at(603)).await.unwrap();
            assert_eq!(claim, OwnerClaim::Claimed);

            let mine = s.find_for_user(&t, &u, 10).await.unwrap();
            let ids: BTreeSet<String> = mine.iter().map(|x| x.id.to_string()).collect();
            assert_eq!(
                ids,
                BTreeSet::from([d.id.to_string(), guest.id.to_string()]),
                "a batched read of two rows"
            );
            let by_fingerprint = s
                .find_by_fingerprint_for_user(&t, &u, &d.fingerprint_hash)
                .await
                .unwrap();
            assert_eq!(by_fingerprint.map(|x| x.id), Some(d.id));
            let any_owner = s
                .find_by_fingerprint(&t, &d.fingerprint_hash)
                .await
                .unwrap();
            assert_eq!(any_owner.map(|x| x.id), Some(d.id));

            s.delete(&t, &d.id).await.expect("delete");
            assert!(s.load(&t, &d.id).await.unwrap().is_none());
            assert!(
                s.find_by_refresh_family(&t, "cl-fam-b")
                    .await
                    .unwrap()
                    .is_empty()
            );
            let left = s.find_for_user(&t, &u, 10).await.unwrap();
            assert_eq!(left.len(), 1);
            assert_eq!(left[0].id, guest.id);

            let (calls_after, refused_after) = eval_stats(&nodes).await;
            assert!(calls_after > calls_before, "no script reached the cluster");
            assert_eq!(
                refused_after, refused_before,
                "a script was sent that the server refused"
            );
            counting.release().await;
        }

        /// Under a hash tag the store keeps the contract every backend
        /// keeps, the single-step conditional writes two concurrent callers
        /// cannot both win included, and the sweep walks a tenant whose
        /// rows it reads in one batch. Each case gets a store of its own,
        /// and the stores are placed on the primaries in turn, so the run
        /// uses every primary and could not pass on a cluster of one. Where
        /// a store is placed is read from the slot of its own prefix, not
        /// from the turn it was asked for.
        #[tokio::test]
        #[ignore = "requires a Valkey cluster (VALKEY_CLUSTER_URL)"]
        async fn under_a_hash_tag_the_store_keeps_the_shared_contract() {
            let counting = refused_scripts_ledger().await;
            let nodes = primaries(&cluster_client().await).await;
            assert!(
                nodes.len() >= 2,
                "one primary serves every slot, which shows nothing: {nodes:?}"
            );
            let (_, refused_before) = eval_stats(&nodes).await;
            let keys_of_the_test = sweep("contract");
            let turn = AtomicUsize::new(0);
            let placed = Mutex::new(BTreeSet::new());
            let store = || {
                let on = turn.fetch_add(1, Ordering::SeqCst);
                let prefix = tagged_prefix_on(&keys_of_the_test, &nodes, on);
                let serving = nodes_of(&nodes, std::slice::from_ref(&prefix));
                placed
                    .lock()
                    .unwrap()
                    .extend(serving.into_iter().map(str::to_owned));
                async move { store_under(&prefix).await }
            };

            shared::ties_are_broken_by_the_smaller_id(store().await).await;
            shared::a_shared_fingerprint_stays_findable_while_any_device_carries_it(store().await)
                .await;
            shared::a_sighting_never_rewinds_and_skips_a_revoked_row(store().await).await;
            shared::a_save_never_un_revokes(store().await).await;
            shared::a_revoked_device_never_comes_back(&store).await;
            shared::the_fingerprint_lookup_follows_the_newest_sighting(store().await).await;
            shared::sub_second_instants_compare_as_whole_seconds(store().await).await;
            shared::a_revoked_row_keeps_its_revocation_time(store().await).await;
            shared::a_sighting_reports_the_level_it_found(store().await).await;
            shared::a_revoked_save_without_a_time_is_stamped_and_purged(store().await).await;
            shared::two_swaps_from_one_read_have_one_winner(store().await).await;
            shared::two_trust_changes_from_one_level_have_one_winner(store().await).await;
            shared::two_claims_of_one_unowned_device_have_one_winner(store().await).await;
            shared::sweep_decisions_agree_to_the_second(
                store().await.with_sweep_config(shared::tight_config()),
            )
            .await;

            assert_eq!(
                placed.lock().unwrap().len(),
                nodes.len(),
                "the stores of the run were placed on every primary"
            );
            let (_, refused_after) = eval_stats(&nodes).await;
            assert_eq!(
                refused_after, refused_before,
                "a script was sent that the server refused"
            );
            counting.release().await;
        }

        /// Two creates of one key at once, and two claims of one unowned
        /// device at once, each have one winner on a cluster as on a single
        /// node.
        #[tokio::test]
        #[ignore = "requires a Valkey cluster (VALKEY_CLUSTER_URL)"]
        async fn under_a_hash_tag_concurrent_creates_and_claims_have_one_winner() {
            let counting = refused_scripts_ledger().await;
            let s = tagged_store("race").await;
            let t = tenant();

            let first = device("cl-race-a", 0xc3, DeviceTrustLevel::Seen, at(0));
            let second = device("cl-race-b", 0xc3, DeviceTrustLevel::Seen, at(0));
            let (a, b) = tokio::join!(
                s.create_or_find(&first, at(0)),
                s.create_or_find(&second, at(0))
            );
            let (a, b) = (a.expect("create"), b.expect("create"));
            assert_eq!(a.id, b.id, "both creates answer one device");
            let rows = s.find_for_user(&t, &user(), 10).await.unwrap();
            assert_eq!(rows.len(), 1, "and one row exists");

            let mut unowned = device("cl-race-claim", 0xc4, DeviceTrustLevel::Seen, at(0));
            unowned.user_id = None;
            s.save(&unowned, at(0)).await.expect("save");
            let (x, y) = (
                crate::authn::ids::testing::user("cl-claimant-x"),
                crate::authn::ids::testing::user("cl-claimant-y"),
            );
            let (cx, cy) = tokio::join!(
                s.claim_owner(&t, &unowned.id, &x, at(1)),
                s.claim_owner(&t, &unowned.id, &y, at(1))
            );
            let (cx, cy) = (cx.unwrap(), cy.unwrap());
            let winner = match (cx, cy) {
                (OwnerClaim::Claimed, OwnerClaim::OwnedByOther) => x,
                (OwnerClaim::OwnedByOther, OwnerClaim::Claimed) => y,
                other => panic!("one claim wins and one is refused: {other:?}"),
            };
            let owner = s.load(&t, &unowned.id).await.unwrap().unwrap().user_id;
            assert_eq!(owner, Some(winner));
            counting.release().await;
        }

        /// Without a hash tag the keys of one write are in several slots, and
        /// the write is refused whole: an error, no row, and no index entry
        /// that would point at a row that is not there. Under this prefix
        /// the keys are on several primaries, where the clustered client
        /// refuses the script itself and the server is never asked.
        #[tokio::test]
        #[ignore = "requires a Valkey cluster (VALKEY_CLUSTER_URL)"]
        async fn without_a_hash_tag_the_client_refuses_a_write_across_primaries() {
            let counting = refused_scripts_ledger().await;
            let client = cluster_client().await;
            let nodes = primaries(&client).await;
            let mut d = device("cl-untagged", 0xc5, DeviceTrustLevel::Seen, at(0));
            d.bindings = vec![refresh("cl-fam-u", at(0))];
            let keys_of_the_test = sweep("primaries");
            let prefix = untagged_prefix_for(&keys_of_the_test, &nodes, &d, false);
            let keys = keys_of(&prefix, &d);
            assert!(nodes_of(&nodes, &keys[..2]).len() > 1, "two primaries");
            let s = store_past_the_check(&prefix).await;
            let (_, refused_before) = eval_stats(&nodes).await;

            for said in [
                refusal(s.save(&d, at(0)).await),
                refusal(s.create_or_find(&d, at(0)).await),
            ] {
                assert!(said.contains("same cluster node"), "the client's: {said}");
            }

            let (_, refused_after) = eval_stats(&nodes).await;
            assert_eq!(refused_after, refused_before, "the server was not asked");
            assert_nothing_stored(&s, &d, &keys).await;
            counting.release().await;
        }

        /// The other way a write without a hash tag is refused: the keys
        /// of a create are in several slots of one primary, so the client
        /// sends the script and the server answers `CROSSSLOT` before
        /// running any of it. The write is refused whole here too: an
        /// error, the refusal in the server's own count, no key written,
        /// and reads that find nothing.
        ///
        /// It is a create because a save cannot be put there. A save is
        /// also given the fingerprint index and the set an earlier release
        /// kept in its place, two keys of one length that differ in one
        /// letter, so their slots differ by the same amount under every
        /// prefix; where three primaries share the slots evenly that
        /// amount always spans two primaries, and the client refuses the
        /// save itself. The save under this prefix is refused as well, by
        /// whichever of the two sees its keys apart.
        #[tokio::test]
        #[ignore = "requires a Valkey cluster (VALKEY_CLUSTER_URL)"]
        async fn without_a_hash_tag_the_server_refuses_a_create_across_slots() {
            let counting = refused_scripts_ledger().await;
            let client = cluster_client().await;
            let nodes = primaries(&client).await;
            let mut d = device("cl-untagged", 0xc6, DeviceTrustLevel::Seen, at(0));
            d.bindings = vec![refresh("cl-fam-u", at(0))];
            let keys_of_the_test = sweep("slots");
            let prefix = untagged_prefix_for(&keys_of_the_test, &nodes, &d, true);
            let created = create_keys_of(&prefix, &d);
            assert_eq!(nodes_of(&nodes, &created).len(), 1, "one primary");
            assert!(slots_of(&created).len() > 1, "several slots");
            let keys = keys_of(&prefix, &d);
            let s = store_past_the_check(&prefix).await;
            let (ran_before, refused_before) = eval_stats(&nodes).await;

            let said = refusal(s.create_or_find(&d, at(0)).await);
            let (ran_after, refused_after) = eval_stats(&nodes).await;
            println!(
                "observed: the server's answer to a create whose keys are in several slots \
                 of one primary: {said:?}; scripts the server refused, {refused_before} before \
                 and {refused_after} after; scripts it ran, {ran_before} before and \
                 {ran_after} after"
            );
            assert!(said.contains("CROSSSLOT"), "the server's: {said}");
            assert!(
                refused_after > refused_before,
                "the server counted the refusal: {refused_before} then {refused_after}"
            );
            let saved = refusal(s.save(&d, at(0)).await);
            assert!(
                saved.contains("CROSSSLOT") || saved.contains("same cluster node"),
                "a save across slots is refused for its slots: {saved}"
            );
            assert_nothing_stored(&s, &d, &keys).await;
            counting.release().await;
        }

        /// A store built on the cluster and left on the default prefix,
        /// which has no hash tag, refuses a save and a create by name: the
        /// error says what is wrong and what to do, the server is asked to
        /// run nothing it would refuse, and nothing is written.
        #[tokio::test]
        #[ignore = "requires a Valkey cluster (VALKEY_CLUSTER_URL)"]
        async fn a_store_left_on_the_default_prefix_refuses_its_writes_by_name() {
            let counting = refused_scripts_ledger().await;
            let client = cluster_client().await;
            let nodes = primaries(&client).await;
            let s = ValkeyDeviceStore::new(client, crate::testing::test_key(6));
            let mut d = device("cl-default-prefix", 0xc7, DeviceTrustLevel::Seen, at(0));
            d.bindings = vec![refresh("cl-fam-u", at(0))];
            let keys = keys_of(&s.prefix, &d);
            let (_, refused_before) = eval_stats(&nodes).await;

            let saved = s.save(&d, at(0)).await;
            assert!(
                matches!(
                    saved,
                    Err(ValkeyDeviceStoreError::PrefixWithoutHashTag { .. })
                ),
                "a save: {saved:?}"
            );
            let refused = s
                .create_or_find(&d, at(0))
                .await
                .expect_err("a create under the default prefix is refused");
            assert!(
                matches!(refused, ValkeyDeviceStoreError::PrefixWithoutHashTag { .. }),
                "a create: {refused:?}"
            );
            let said = refused.to_string();
            assert!(
                said.contains("hash tag") && said.contains("`{axess}`"),
                "{said}"
            );

            let (_, refused_after) = eval_stats(&nodes).await;
            assert_eq!(refused_after, refused_before, "the server was not asked");
            assert_nothing_stored(&s, &d, &keys).await;
            counting.release().await;
        }

        /// The health check of such a store gives the reason before any
        /// write is tried, in the words of the error its writes are refused
        /// with, and it is the store's answer and not the cluster's: a
        /// store on the same cluster whose prefix has a hash tag is healthy.
        /// Neither check sends a script.
        #[tokio::test]
        #[ignore = "requires a Valkey cluster (VALKEY_CLUSTER_URL)"]
        async fn a_store_left_on_the_default_prefix_is_unhealthy_on_a_cluster_that_answers() {
            let s = ValkeyDeviceStore::new(cluster_client().await, crate::testing::test_key(6));
            let named = ValkeyDeviceStoreError::PrefixWithoutHashTag {
                prefix: s.prefix.to_string(),
            };

            assert_eq!(
                s.check().await,
                HealthStatus::Unhealthy(named.to_string()),
                "unhealthy by the name of the refusal"
            );
            assert_eq!(
                tagged_store("health").await.check().await,
                HealthStatus::Healthy,
                "the cluster answers"
            );
        }
    }
}
