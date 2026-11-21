//! The session store and registry against a Valkey cluster
//! (`VALKEY_CLUSTER_URL`): ignored by default, run by
//! `scripts/check-live-stores.sh`. Every test writes under a prefix of its
//! own and removes what it wrote on every primary, also when it fails.
//!
//! Without a hash tag the two keys of a rotation hash to different slots.
//! The rotation then takes its sequenced form without sending a script (the
//! server counts no refused `EVAL`), says so once, and still does its work;
//! with a hash tag the script runs. A user's registry keys carry the user id
//! as their hash tag, so the registry's scripts run as scripts under any
//! prefix it accepts.

use super::internal::{session_row_key, user_keys};
use super::layout_tests::names_under;
use super::move_tests;
use super::registry::ValkeySessionRegistry;
use super::store::ValkeySessionStore;
use crate::authn::ids::UserId;
use crate::session::data::SessionData;
use crate::session::id::{SessionId, SessionKey};
use crate::session::store::{CutOff, CycleOutcome, SessionRegistry, SessionStore};
use crate::testing::valkey_cluster::{
    Primary, cluster_client, eval_stats, primaries, refused_scripts_ledger,
};
use axess_rng::SystemRng;
use axess_testing::mock_tracing::TracingCapture;
use fred::prelude::*;
use fred::util::redis_keyslot;
use std::time::Duration;
use tracing::Level;

const TTL: Duration = Duration::from_secs(60);

/// The primary serving `key`.
fn node_of<'a>(nodes: &'a [Primary], key: &str) -> &'a str {
    let slot = redis_keyslot(key.as_bytes());
    nodes
        .iter()
        .find(|p| p.serves(slot))
        .map(|p| p.addr.as_str())
        .expect("every slot is served")
}

/// Two session keys whose rows under `prefix` hash to different slots, served
/// by one primary when `same_node`, by two otherwise.
fn two_slots(prefix: &str, nodes: &[Primary], same_node: bool) -> (SessionKey, SessionKey) {
    let old = SessionKey::of(&SessionId::new(&SystemRng));
    let old_key = session_row_key(prefix, &old);
    for _ in 0..10_000 {
        let new = SessionKey::of(&SessionId::new(&SystemRng));
        let new_key = session_row_key(prefix, &new);
        let slots_differ = redis_keyslot(old_key.as_bytes()) != redis_keyslot(new_key.as_bytes());
        let one_node = node_of(nodes, &old_key) == node_of(nodes, &new_key);
        if slots_differ && one_node == same_node {
            return (old, new);
        }
    }
    panic!("no pair of keys found");
}

/// The warnings axess logged.
fn axess_warnings(capture: &TracingCapture) -> Vec<String> {
    capture
        .events()
        .into_iter()
        .filter(|e| e.level == Level::WARN && e.target.starts_with("axess"))
        .map(|e| e.to_string())
        .collect()
}

/// The tests that need the cluster. `valkey_cluster` is the name a run
/// leaves them out by (`--skip valkey_cluster`); the module inside is the
/// session store's own, the name the live-store gate counts this suite by,
/// apart from the device store's and the authorization cache's.
mod valkey_cluster {
    use super::*;

    mod session_cluster {
        use super::*;

        /// A rotation whose two keys are in different slots rotates, on one node
        /// and across two, without a script the server refuses, and the store says
        /// so once however many rotations take that form.
        #[tokio::test]
        #[ignore = "requires a Valkey cluster (VALKEY_CLUSTER_URL)"]
        async fn a_rotation_across_slots_sends_no_script_and_warns_once() {
            let sweep = move_tests::Sweep::cluster("clacross");
            let prefix = sweep.prefix().to_owned();
            let counting = refused_scripts_ledger().await;
            let client = cluster_client().await;
            let nodes = primaries(&client).await;
            let store =
                ValkeySessionStore::new(client, crate::testing::test_key(5)).with_prefix(&*prefix);
            let capture = TracingCapture::install();
            let (_, refused_before) = eval_stats(&nodes).await;

            for same_node in [true, false] {
                let (old, new) = two_slots(&prefix, &nodes, same_node);
                store
                    .save(&old, &SessionData::default(), TTL)
                    .await
                    .unwrap();
                let outcome = store
                    .cycle(&old, &new, &SessionData::default(), TTL, true)
                    .await
                    .expect("the rotation across two slots");
                assert_eq!(outcome, CycleOutcome::Rotated, "same node: {same_node}");
                assert!(store.load(&old).await.unwrap().is_none());
                assert!(store.load(&new).await.unwrap().is_some());
            }

            let (_, refused_after) = eval_stats(&nodes).await;
            assert_eq!(
                refused_after, refused_before,
                "a script was sent that the server refused"
            );
            let warnings = axess_warnings(&capture);
            assert_eq!(warnings.len(), 1, "{warnings:#?}");
            counting.release().await;
        }

        /// A rotation whose TTL is zero removes both keys, one delete each, and the
        /// session is gone; through the revision check as through `cycle`.
        #[tokio::test]
        #[ignore = "requires a Valkey cluster (VALKEY_CLUSTER_URL)"]
        async fn a_rotation_whose_ttl_is_zero_removes_both_keys() {
            let sweep = move_tests::Sweep::cluster("clzero");
            let prefix = sweep.prefix().to_owned();
            let counting = refused_scripts_ledger().await;
            let client = cluster_client().await;
            let nodes = primaries(&client).await;
            let store =
                ValkeySessionStore::new(client, crate::testing::test_key(6)).with_prefix(&*prefix);

            let (old, new) = two_slots(&prefix, &nodes, false);
            store
                .save(&old, &SessionData::default(), TTL)
                .await
                .unwrap();
            store
                .save(&new, &SessionData::default(), TTL)
                .await
                .unwrap();
            let outcome = store
                .cycle(&old, &new, &SessionData::default(), Duration::ZERO, true)
                .await
                .expect("a zero-TTL rotation across two slots");
            assert_eq!(outcome, CycleOutcome::SessionGone);
            assert!(store.load(&old).await.unwrap().is_none());
            assert!(store.load(&new).await.unwrap().is_none());

            let (old, new) = two_slots(&prefix, &nodes, false);
            store
                .save(&old, &SessionData::default(), TTL)
                .await
                .unwrap();
            let revision = store.load(&old).await.unwrap().expect("stored").revision;
            let outcome = store
                .cycle_if_revision(
                    &old,
                    &new,
                    &SessionData::default(),
                    Duration::ZERO,
                    true,
                    revision,
                )
                .await
                .expect("a zero-TTL rotation by revision");
            assert_eq!(outcome, CycleOutcome::SessionGone);
            assert!(store.load(&old).await.unwrap().is_none());
            assert!(store.load(&new).await.unwrap().is_none());
            counting.release().await;
        }

        /// The rotation of a stored session, a compare-and-delete of the old key and
        /// a write of the new one, holds across two nodes.
        #[tokio::test]
        #[ignore = "requires a Valkey cluster (VALKEY_CLUSTER_URL)"]
        async fn a_stored_session_rotates_by_revision_across_nodes() {
            let sweep = move_tests::Sweep::cluster("clrevision");
            let prefix = sweep.prefix().to_owned();
            let counting = refused_scripts_ledger().await;
            let client = cluster_client().await;
            let nodes = primaries(&client).await;
            let store =
                ValkeySessionStore::new(client, crate::testing::test_key(7)).with_prefix(&*prefix);
            let (old, new) = two_slots(&prefix, &nodes, false);
            store
                .save(&old, &SessionData::default(), TTL)
                .await
                .unwrap();
            let revision = store.load(&old).await.unwrap().expect("stored").revision;

            let outcome = store
                .cycle_if_revision(&old, &new, &SessionData::default(), TTL, true, revision)
                .await
                .expect("the rotation by revision");

            assert_eq!(outcome, CycleOutcome::Rotated);
            assert!(store.load(&old).await.unwrap().is_none());
            assert!(store.load(&new).await.unwrap().is_some());
            counting.release().await;
        }

        /// Under a hash tag every key of the store is in one slot: the rotation
        /// script runs, and nothing is said about a sequenced form.
        #[tokio::test]
        #[ignore = "requires a Valkey cluster (VALKEY_CLUSTER_URL)"]
        async fn a_hash_tag_prefix_runs_the_rotation_script() {
            let sweep = move_tests::Sweep::cluster_tagged("clscript");
            let prefix = sweep.prefix().to_owned();
            let counting = refused_scripts_ledger().await;
            let client = cluster_client().await;
            let nodes = primaries(&client).await;
            let store =
                ValkeySessionStore::new(client, crate::testing::test_key(8)).with_prefix(&*prefix);
            let capture = TracingCapture::install();
            let (old, new) = (SessionId::new(&SystemRng), SessionId::new(&SystemRng));
            store
                .save(&SessionKey::of(&old), &SessionData::default(), TTL)
                .await
                .unwrap();
            let (calls_before, refused_before) = eval_stats(&nodes).await;

            let outcome = store
                .cycle(
                    &SessionKey::of(&old),
                    &SessionKey::of(&new),
                    &SessionData::default(),
                    TTL,
                    true,
                )
                .await
                .expect("the rotation under a hash tag");

            let (calls_after, refused_after) = eval_stats(&nodes).await;
            assert_eq!(outcome, CycleOutcome::Rotated);
            assert!(
                calls_after > calls_before,
                "the rotation script did not run"
            );
            assert_eq!(refused_after, refused_before);
            assert!(axess_warnings(&capture).is_empty());
            counting.release().await;
        }

        /// Every key name under `prefix` on every primary of the cluster.
        async fn names_on_every_primary(nodes: &[Primary], prefix: &str) -> Vec<String> {
            let mut found = Vec::new();
            for node in nodes {
                let config = Config::from_url(&format!("redis://{}", node.addr))
                    .expect("a primary's address");
                let client = Client::new(config, None, None, None);
                client.init().await.expect("connect to a primary");
                found.append(&mut names_under(&client, prefix).await);
                let _ = client.quit().await;
            }
            found.sort();
            found
        }

        /// A registry built on the cluster by its constructor, under `prefix`.
        async fn registry_under(client: Client, prefix: &str) -> ValkeySessionRegistry {
            ValkeySessionRegistry::with_options(client, prefix, TTL)
                .await
                .expect("a registry built on the cluster")
        }

        /// Under a prefix with no hash tag, which put a user's two sets in
        /// two slots before, the orphan sweep and the cut-off of a user's
        /// other sessions run as the scripts they are: the sweep removes the
        /// orphan's registration time, the cut-off ends the other session,
        /// and nothing is said about a sweep that was skipped.
        #[tokio::test]
        #[ignore = "requires a Valkey cluster (VALKEY_CLUSTER_URL)"]
        async fn the_registry_runs_its_scripts_under_a_prefix_without_a_tag() {
            let sweep = move_tests::Sweep::cluster("clscripts");
            let prefix = sweep.prefix().to_owned();
            let registry = registry_under(cluster_client().await, &prefix).await;
            let capture = TracingCapture::install();
            let user = UserId::new(&SystemRng);
            let [gone, kept, other] = [(); 3].map(|()| SessionKey::of(&SessionId::new(&SystemRng)));
            for session in [&gone, &kept, &other] {
                registry.register(&user, session).await.expect("register");
            }
            let keys = user_keys(&prefix, &user).expect("one slot");
            registry
                .client
                .zrem::<(), _, _>(&keys.registry, gone.to_string())
                .await
                .expect("the orphan made");

            let active = registry.active_sessions(&user).await.expect("the sweep");
            // Registered in one tick, the two are equally old and in no
            // promised order.
            assert_eq!(
                move_tests::sorted(&active),
                move_tests::sorted(&[kept, other])
            );
            let at: Option<f64> = registry
                .client
                .zscore(&keys.registered_at, gone.to_string())
                .await
                .expect("ZSCORE");
            assert_eq!(at, None, "the orphan kept its registration time");

            let ended = registry
                .invalidate_other_sessions(&user, &kept)
                .await
                .expect("the cut-off");
            assert_eq!(ended, CutOff::KeptOne(vec![other]));
            assert_eq!(
                registry.active_sessions(&user).await.expect("listed"),
                vec![kept]
            );
            assert!(
                axess_warnings(&capture).is_empty(),
                "{:#?}",
                capture.events()
            );
        }

        /// Both constructors build a registry on the cluster under a prefix
        /// with no hash tag, and the probe they send writes nothing under it
        /// on any primary.
        #[tokio::test]
        #[ignore = "requires a Valkey cluster (VALKEY_CLUSTER_URL)"]
        async fn the_registry_is_built_on_the_cluster_and_writes_nothing() {
            let sweep = move_tests::Sweep::cluster("clbuilt");
            let prefix = sweep.prefix().to_owned();
            let client = cluster_client().await;
            let nodes = primaries(&client).await;
            ValkeySessionRegistry::new(client.clone())
                .await
                .expect("built with the default prefix");
            registry_under(client, &prefix).await;
            assert_eq!(
                names_on_every_primary(&nodes, &prefix).await,
                Vec::<String>::new()
            );
        }

        /// Under a prefix that closes its own hash tag every key of every
        /// user lies in the tag's slot, and every call works there.
        #[tokio::test]
        #[ignore = "requires a Valkey cluster (VALKEY_CLUSTER_URL)"]
        async fn a_tagged_prefix_holds_every_user_in_its_slot() {
            let sweep = move_tests::Sweep::cluster_tagged("cltag");
            let prefix = sweep.prefix().to_owned();
            let tag = prefix.trim_start_matches('{').trim_end_matches('}');
            let slot = redis_keyslot(tag.as_bytes());
            let registry = registry_under(cluster_client().await, &prefix).await;
            for _ in 0..2 {
                let user = UserId::new(&SystemRng);
                let keys = user_keys(&prefix, &user).expect("one slot");
                for key in [&keys.registry, &keys.registered_at] {
                    assert_eq!(redis_keyslot(key.as_bytes()), slot, "{key}");
                }
                let (kept, other) = (
                    SessionKey::of(&SessionId::new(&SystemRng)),
                    SessionKey::of(&SessionId::new(&SystemRng)),
                );
                registry.register(&user, &kept).await.expect("register");
                registry.register(&user, &other).await.expect("register");
                assert!(registry.is_valid(&user, &kept).await.expect("is_valid"));
                // Registered in one tick, the two are equally old and in no
                // promised order.
                let listed = registry.active_sessions(&user).await.expect("listed");
                assert_eq!(
                    move_tests::sorted(&listed),
                    move_tests::sorted(&[kept, other])
                );
                assert_eq!(
                    registry
                        .invalidate_other_sessions(&user, &kept)
                        .await
                        .expect("the cut-off"),
                    CutOff::KeptOne(vec![other])
                );
            }
        }

        /// Under a prefix with no hash tag the registry keeps the whole
        /// registry contract on the cluster: its move, current key, ending
        /// by key and cut-off run over a user's four keys in one slot.
        #[tokio::test]
        #[ignore = "requires a Valkey cluster (VALKEY_CLUSTER_URL)"]
        async fn the_registry_keeps_the_registry_contract_on_the_cluster() {
            let sweep = move_tests::Sweep::cluster("mvkit_cl");
            let registry = sweep.registry().await;
            crate::testing::registry_contract::assert_registry_contract(&registry).await;
        }

        #[tokio::test]
        #[ignore = "requires a Valkey cluster (VALKEY_CLUSTER_URL)"]
        async fn a_moved_session_keeps_its_place_on_the_cluster() {
            let sweep = move_tests::Sweep::cluster("mvplace_cl");
            let clock = axess_clock::testing::MockClock::at_reference();
            let registry = sweep
                .registry()
                .await
                .with_clock(std::sync::Arc::new(clock.clone()));
            move_tests::a_moved_session_keeps_its_place(&registry, &clock).await;
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        #[ignore = "requires a Valkey cluster (VALKEY_CLUSTER_URL)"]
        async fn of_two_moves_of_one_key_exactly_one_moves_it_on_the_cluster() {
            let sweep = move_tests::Sweep::cluster("mvrace2_cl");
            let (one, two) = (sweep.registry().await, sweep.registry().await);
            move_tests::of_two_moves_of_one_key_exactly_one_moves_it(&one, &two).await;
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        #[ignore = "requires a Valkey cluster (VALKEY_CLUSTER_URL)"]
        async fn a_move_racing_the_end_of_every_session_leaves_none_on_the_cluster() {
            let sweep = move_tests::Sweep::cluster("mvraceuser_cl");
            let (mover, ender) = (sweep.registry().await, sweep.registry().await);
            move_tests::a_move_racing_the_end_of_every_session_leaves_none(&mover, &ender).await;
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        #[ignore = "requires a Valkey cluster (VALKEY_CLUSTER_URL)"]
        async fn a_move_racing_a_cut_off_ends_in_one_of_two_states_on_the_cluster() {
            let sweep = move_tests::Sweep::cluster("mvracecut_cl");
            let (mover, cutter) = (sweep.registry().await, sweep.registry().await);
            move_tests::a_move_racing_a_cut_off_ends_in_one_of_two_states(&mover, &cutter).await;
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        #[ignore = "requires a Valkey cluster (VALKEY_CLUSTER_URL)"]
        async fn a_move_racing_an_ending_by_the_old_key_leaves_none_on_the_cluster() {
            let sweep = move_tests::Sweep::cluster("mvraceend_cl");
            let (mover, ender) = (sweep.registry().await, sweep.registry().await);
            move_tests::a_move_racing_an_ending_by_the_old_key_leaves_none(&mover, &ender).await;
        }
    }
}
