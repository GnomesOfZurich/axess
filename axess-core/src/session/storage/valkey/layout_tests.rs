//! The names of the registry's keys: one user's keys share a cluster slot
//! under any prefix the registry accepts, the registry refuses a prefix that
//! would split them (at every call and when it is built), it is built only on
//! a server that runs its scripts, and nothing an earlier release named
//! without braces is read or written. The tests that need a server run
//! against a single node (`VALKEY_URL`), each under a prefix of its own whose
//! keys it removes, also when it fails; the cluster's are in
//! `cluster_tests.rs`.

use super::fallback_tests::with_scripting_refused;
use super::internal::{ValkeyStoreError, user_keys};
use super::move_tests::{Sweep, sorted};
use super::registry::ValkeySessionRegistry;
use super::registry_keys::PREFIX_SPLITS_A_USER;
use super::registry_tests::connect;
use crate::authn::ids::UserId;
use crate::health::{HealthCheck, HealthStatus};
use crate::session::id::{SessionId, SessionKey};
use crate::session::store::{CutOff, SessionRegistry};
use axess_rng::SystemRng;
use axess_testing::mock_tracing::TracingCapture;
use fred::prelude::*;
use fred::types::{ClusterHash, CustomCommand};
use fred::util::redis_keyslot;
use std::collections::BTreeSet;
use std::time::Duration;
use tracing::Level;

const TTL: Duration = Duration::from_secs(60);

/// A user whose slots are written out below, computed by the cluster's rule.
fn fixed_user() -> UserId {
    "6f1c2b1e-0a55-4c8e-9d3a-1b2c3d4e5f60"
        .parse()
        .expect("a user id")
}

/// The slot of each key of `user` under `prefix`.
fn slots(prefix: &str, user: &UserId) -> [u16; 2] {
    let keys = user_keys(prefix, user).expect("one slot");
    [&keys.registry, &keys.registered_at].map(|key| redis_keyslot(key.as_bytes()))
}

/// Every key name under `prefix` on the node `client` talks to, by `SCAN`,
/// in byte order. The pattern's braces are plain characters of a glob.
pub(super) async fn names_under(client: &Client, prefix: &str) -> Vec<String> {
    let pattern = format!("{prefix}:*");
    let mut cursor = "0".to_string();
    let mut found = Vec::new();
    loop {
        let (next, mut page): (String, Vec<String>) = client
            .custom(
                CustomCommand::new_static("SCAN", ClusterHash::FirstKey, false),
                vec![cursor.as_str(), "MATCH", pattern.as_str(), "COUNT", "1000"],
            )
            .await
            .expect("SCAN");
        found.append(&mut page);
        if next == "0" {
            break;
        }
        cursor = next;
    }
    found.sort();
    found
}

/// Whether `answer` is the refusal of a prefix that splits a user's keys.
fn split_refused<T>(answer: &Result<T, ValkeyStoreError>) -> bool {
    matches!(answer, Err(ValkeyStoreError::Unsupported(text)) if *text == PREFIX_SPLITS_A_USER)
}

/// For 64 users, every key `user_keys` builds for one user lies in one
/// slot, and under the default prefix the users spread over the slots; the
/// slots of one user are the ones the cluster's rule gives, and the layout
/// without braces put that user's two keys in two slots.
#[test]
fn one_users_keys_share_a_slot_and_users_spread() {
    let mut seen = BTreeSet::new();
    for _ in 0..64 {
        let user = UserId::new(&SystemRng);
        let [registry, registered_at] = slots("axess", &user);
        assert_eq!(registry, registered_at, "the keys of {user} are apart");
        seen.insert(registry);
    }
    assert!(seen.len() > 1, "every user in one slot: {seen:?}");

    let user = fixed_user();
    assert_eq!(slots("axess", &user), [7363, 7363]);
    let unbraced = [format!("axess:reg:{user}"), format!("axess:reg-at:{user}")]
        .map(|key| redis_keyslot(key.as_bytes()));
    assert_eq!(unbraced, [16377, 5880]);
}

/// A prefix that opens a brace it does not close, or holds an empty tag
/// first, is refused with the error that names the fault, for any user: the
/// keys it would build lie in two slots.
#[test]
fn a_prefix_that_splits_a_users_keys_is_refused() {
    for (prefix, apart) in [("a{b", [10355, 562]), ("{}x", [3973, 5957])] {
        let user = fixed_user();
        let built = [
            format!("{prefix}:reg:{{{user}}}"),
            format!("{prefix}:reg-at:{{{user}}}"),
        ]
        .map(|key| redis_keyslot(key.as_bytes()));
        assert_eq!(built, apart, "{prefix}");
        for user in [user, UserId::NIL] {
            let refused = user_keys(prefix, &user).map(|_| ());
            assert!(split_refused(&refused), "{prefix}: {refused:?}");
        }
    }
    let error = ValkeyStoreError::Unsupported(PREFIX_SPLITS_A_USER).to_string();
    assert!(error.contains("one user's keys would lie in different cluster slots"));
}

/// A prefix that closes its own tag is accepted, and every user's keys lie
/// in the tag's one slot: the slots are compared, not the prefix's text.
#[test]
fn a_tagged_prefix_puts_every_user_in_the_tags_slot() {
    assert_eq!(redis_keyslot(b"axess"), 5982);
    for user in (0..64)
        .map(|_| UserId::new(&SystemRng))
        .chain([UserId::NIL])
    {
        assert_eq!(slots("{axess}", &user), [5982, 5982], "{user}");
    }
}

/// The constructors answer the refusal of a splitting prefix before they
/// send anything: on a client that is configured and never connected, for a
/// single node and for a cluster, the answer is the refusal and not a
/// connection error. On such a client with a sound prefix they never answer
/// `Ok`.
#[tokio::test]
async fn the_constructors_refuse_a_splitting_prefix_before_sending() {
    let configured = [
        Client::new(Config::default(), None, None, None),
        Client::new(
            Config::from_url("redis-cluster://127.0.0.1:7001").expect("a cluster URL"),
            None,
            None,
            None,
        ),
    ];
    for client in configured {
        let refused = ValkeySessionRegistry::with_options(client.clone(), "a{b", TTL).await;
        assert!(split_refused(&refused), "{:?}", refused.map(|_| ()));

        let unasked = ValkeySessionRegistry::with_options(client.clone(), "axess", TTL).await;
        assert!(
            matches!(unasked, Err(ValkeyStoreError::Connection(_))),
            "{:?}",
            unasked.map(|_| ())
        );
        let unasked = ValkeySessionRegistry::new(client).await;
        assert!(
            matches!(unasked, Err(ValkeyStoreError::Connection(_))),
            "{:?}",
            unasked.map(|_| ())
        );
    }
}

/// A registry built past the constructors' checks on a splitting prefix
/// answers every call with the refusal and writes nothing under its prefix;
/// its watch ends at once and its health check names the fault. The
/// constructor refuses the same prefix on a connected client too.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_a_splitting_prefix_fails_every_call_and_writes_nothing() {
    // Under a prefix that opens a brace it does not close, the fixed user's
    // keys and the nil user's lie in two slots each.
    let sweep = Sweep::node_unclosed("split");
    let prefix = sweep.prefix().to_owned();
    let registry = ValkeySessionRegistry::assembled(connect().await, prefix.as_str().into(), TTL);
    let (user, session) = (fixed_user(), SessionKey::of(&SessionId::new(&SystemRng)));
    let registered = registry.register(&user, &session).await;
    assert!(split_refused(&registered), "{registered:?}");
    assert!(split_refused(&registry.is_valid(&user, &session).await));
    assert!(split_refused(
        &registry.invalidate_session(&user, &session).await
    ));
    assert!(split_refused(
        &registry.invalidate_other_sessions(&user, &session).await
    ));
    assert!(split_refused(&registry.active_sessions(&user).await));
    assert!(split_refused(&registry.invalidate_user(&user).await));
    tokio::time::timeout(
        Duration::from_secs(1),
        registry.watch_revocation(&user, &session),
    )
    .await
    .expect("the watch ends at once");
    assert!(
        matches!(registry.check().await, HealthStatus::Unhealthy(text) if text.contains("different cluster slots"))
    );

    assert_eq!(
        names_under(&connect().await, &prefix).await,
        Vec::<String>::new()
    );

    let refused = ValkeySessionRegistry::with_options(connect().await, prefix.as_str(), TTL).await;
    assert!(split_refused(&refused), "{:?}", refused.map(|_| ()));
}

/// On a server that runs scripts both constructors build a registry, the
/// probe writes nothing under the prefix, and the health check is healthy.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_the_registry_is_built_on_a_server_that_runs_scripts() {
    let sweep = Sweep::node("built");
    let prefix = sweep.prefix().to_owned();
    ValkeySessionRegistry::new(connect().await)
        .await
        .expect("built with the default prefix");
    let registry = ValkeySessionRegistry::with_options(connect().await, prefix.as_str(), TTL)
        .await
        .expect("built under a prefix of its own");

    assert_eq!(
        names_under(&connect().await, &prefix).await,
        Vec::<String>::new()
    );
    assert!(matches!(registry.check().await, HealthStatus::Healthy));
}

/// On a server whose ACL refuses scripts to the registry's user, both
/// constructors refuse with the error that names it, and nothing is written.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_the_registry_is_refused_on_a_server_that_refuses_scripts() {
    let sweep = Sweep::node("noscript");
    let prefix = sweep.prefix().to_owned();
    with_scripting_refused(move |admin, restricted| async move {
        let by_new = ValkeySessionRegistry::new(restricted.clone()).await;
        assert!(
            matches!(by_new, Err(ValkeyStoreError::ScriptsRefused(_))),
            "{:?}",
            by_new.map(|_| ())
        );
        let by_options =
            ValkeySessionRegistry::with_options(restricted, prefix.as_str(), TTL).await;
        let Err(error) = by_options else {
            panic!("a registry was built on a server that refuses scripts");
        };
        assert!(
            matches!(error, ValkeyStoreError::ScriptsRefused(_)),
            "{error:?}"
        );
        assert!(error.to_string().contains("refuses scripts"), "{error}");
        assert_eq!(names_under(&admin, &prefix).await, Vec::<String>::new());
    })
    .await;
}

/// A sorted set's members with their scores, as the server holds them.
async fn members_with_scores(client: &Client, key: &str) -> Vec<(String, f64)> {
    client
        .zrange(key, 0_i64, -1_i64, None, false, None, true)
        .await
        .expect("ZRANGE WITHSCORES")
}

/// The two sets of a user under the names without braces, as the earlier
/// release wrote them, are neither read nor written by any call for that
/// user: they are the same member for member and score for score afterwards,
/// their members are not counted as the user's sessions, and the entries of
/// the calls are only under the braced names.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_what_the_earlier_release_left_is_neither_read_nor_written() {
    let sweep = Sweep::node("earlier");
    let prefix = sweep.prefix().to_owned();
    let admin = connect().await;
    let user = UserId::new(&SystemRng);
    let earlier = [
        format!("{prefix}:reg:{user}"),
        format!("{prefix}:reg-at:{user}"),
    ];
    let (first, second) = (
        SessionKey::of(&SessionId::new(&SystemRng)),
        SessionKey::of(&SessionId::new(&SystemRng)),
    );
    for key in &earlier {
        let _: i64 = admin
            .zadd(
                key,
                None,
                None,
                false,
                false,
                vec![
                    (1_800_000_000_000.0, first.to_string()),
                    (1_800_000_001_000.0, second.to_string()),
                ],
            )
            .await
            .expect("ZADD");
        let _: i64 = admin.expire(key, 600, None).await.expect("EXPIRE");
    }
    let mut before = Vec::new();
    for key in &earlier {
        before.push(members_with_scores(&admin, key).await);
    }

    let registry = ValkeySessionRegistry::with_options(connect().await, prefix.as_str(), TTL)
        .await
        .expect("a registry");
    let session = SessionKey::of(&SessionId::new(&SystemRng));
    registry.register(&user, &session).await.expect("register");
    assert!(registry.is_valid(&user, &session).await.expect("is_valid"));
    assert!(
        !registry.is_valid(&user, &first).await.expect("is_valid"),
        "a member of the earlier set was read"
    );
    assert_eq!(
        registry.active_sessions(&user).await.expect("listed"),
        vec![session]
    );
    assert_eq!(
        registry
            .invalidate_other_sessions(&user, &session)
            .await
            .expect("the cut-off"),
        CutOff::KeptOne(Vec::new())
    );

    let mut after = Vec::new();
    for key in &earlier {
        after.push(members_with_scores(&admin, key).await);
    }
    eprintln!("earlier sets before: {before:?}");
    eprintln!("earlier sets after:  {after:?}");
    assert_eq!(after, before, "a set of the earlier release was written");

    let braced = user_keys(&prefix, &user).expect("one slot");
    let mut expected = vec![
        earlier[0].clone(),
        earlier[1].clone(),
        braced.registry,
        braced.registered_at,
    ];
    expected.sort();
    let names = names_under(&admin, &prefix).await;
    eprintln!("names under the prefix: {names:?}");
    assert_eq!(names, expected);
}

/// The warnings axess logged whose text holds `needle`.
fn warnings_holding(capture: &TracingCapture, needle: &str) -> usize {
    capture
        .events()
        .iter()
        .filter(|e| {
            e.level == Level::WARN && e.target.starts_with("axess") && e.message.contains(needle)
        })
        .count()
}

/// A server that stops running scripts after the registry was built (an ACL
/// changed under it): registration, the check, a single sign-out and the
/// listing still work; the cut-off of a user's other sessions fails and ends
/// nothing; the orphan sweep is skipped with one warning and nothing in its
/// place; the health check names the refusal.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_a_server_that_stops_running_scripts_serves_all_but_the_cut_off() {
    let capture = TracingCapture::install();
    let sweep = Sweep::node("stopped");
    let prefix = sweep.prefix().to_owned();
    let user = UserId::new(&SystemRng);
    let [kept, later, gone] = [(); 3].map(|()| SessionKey::of(&SessionId::new(&SystemRng)));
    with_scripting_refused(move |admin, restricted| async move {
        let registry = ValkeySessionRegistry::assembled(restricted, prefix.as_str().into(), TTL);
        for session in [&gone, &kept, &later] {
            registry.register(&user, session).await.expect("register");
        }
        let keys = user_keys(&prefix, &user).expect("one slot");
        let _: i64 = admin
            .zrem(&keys.registry, gone.to_string())
            .await
            .expect("the orphan made");
        assert!(registry.is_valid(&user, &kept).await.expect("is_valid"));

        let cut = registry.invalidate_other_sessions(&user, &kept).await;
        assert!(
            matches!(cut, Err(ValkeyStoreError::Unsupported(_))),
            "{cut:?}"
        );

        // Registered in one tick, the two are equally old and in no promised
        // order.
        let listed = registry.active_sessions(&user).await.expect("listed");
        assert_eq!(
            sorted(&listed),
            sorted(&[kept, later]),
            "the cut-off ended a session"
        );
        let orphan: Option<f64> = admin
            .zscore(&keys.registered_at, gone.to_string())
            .await
            .expect("ZSCORE");
        assert!(orphan.is_some(), "a sweep ran in another form");

        registry
            .invalidate_session(&user, &later)
            .await
            .expect("a single sign-out");
        assert_eq!(
            registry.active_sessions(&user).await.expect("listed"),
            vec![kept]
        );

        let health = registry.check().await;
        assert!(
            matches!(&health, HealthStatus::Unhealthy(text) if text.contains("refuses scripts")),
            "{health:?}"
        );
    })
    .await;
    assert_eq!(
        warnings_holding(&capture, "orphan sweep was skipped"),
        2,
        "{:#?}",
        capture.events()
    );
}
