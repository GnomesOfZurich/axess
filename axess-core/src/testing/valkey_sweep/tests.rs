//! The sweep's prefix, its pattern and the cluster's primaries, without a
//! server; and against a live Valkey and a cluster (ignored by default:
//! `VALKEY_URL`, `VALKEY_CLUSTER_URL`), that a sweep removes every key
//! holding its prefix and no other, when the test passes and when it fails.

use super::*;

/// A node nothing listens on: a sweep made in a test without a server
/// reaches nothing when it is dropped, and says so in a warning.
const NOWHERE: &str = "redis://127.0.0.1:1";

#[test]
fn a_token_is_one_to_thirty_two_lowercase_letters_and_digits() {
    for good in ["a", "0", "run1", &"z".repeat(MAX_RUN_LEN)] {
        assert!(is_token(good), "{good:?}");
    }
    for bad in [
        "",
        &"z".repeat(MAX_RUN_LEN + 1),
        "Run",
        "a-b",
        "a_b",
        "a*",
        "a?",
        "[a]",
        "{a}",
        "a b",
        "\u{e9}",
    ] {
        assert!(!is_token(bad), "{bad:?}");
    }
}

#[test]
fn a_tag_holds_no_wildcard_and_no_brace() {
    for good in ["cas", "mv_kit", "a1"] {
        assert!(is_tag(good), "{good:?}");
    }
    for bad in ["", "A", "a-b", "a*", "a?", "a[b]", "{a}", "a\\b", "a:b"] {
        assert!(!is_tag(bad), "{bad:?}");
    }
}

#[test]
#[should_panic(expected = "a sweep's tag is lowercase letters, digits and underscores")]
fn a_tag_with_a_wildcard_is_refused() {
    drop(KeySweep::node(NOWHERE, "a*"));
}

/// The prefix names the run and the test and is fresh each time; the hash
/// tag wraps the same prefix; the pattern is the prefix between two
/// wildcards and holds no other.
#[test]
fn a_prefix_holds_the_run_and_the_tag_and_no_two_are_alike() {
    let first = KeySweep::node(NOWHERE, "cas");
    let second = KeySweep::node(NOWHERE, "cas");
    let start = format!("axt_{}_cas_", run());
    assert!(first.prefix().starts_with(&start), "{}", first.prefix());
    assert_ne!(first.prefix(), second.prefix());
    assert_eq!(first.pattern(), format!("*{}*", first.prefix()));
    let inner = &first.pattern()[1..first.pattern().len() - 1];
    assert!(
        !inner.contains(['*', '?', '[', ']', '\\', '{', '}']),
        "{inner}"
    );

    let root = first.prefix().to_owned();
    let tagged = first.hash_tagged();
    assert_eq!(tagged.prefix(), format!("{{{root}}}"));
    assert_eq!(tagged.pattern(), format!("*{root}*"));
}

/// A text of the test's other keys is taken where it is long and plain,
/// and given its own pattern beside the prefix's.
#[test]
fn another_text_is_long_and_holds_no_wildcard() {
    let session = "a".repeat(64);
    let sweep = KeySweep::node(NOWHERE, "also").also_holding(&session);
    assert_eq!(
        sweep.patterns(),
        vec![sweep.pattern(), format!("*{session}*")]
    );
    for bad in [
        "short",
        "0123456789abcde*",
        "0123456789abcde?",
        "0123456789abcd[]",
        "0123456789abcde\\",
        "0123456789abcde\n",
    ] {
        let refused = std::panic::catch_unwind(|| {
            drop(KeySweep::node(NOWHERE, "also").also_holding(bad));
        });
        assert!(refused.is_err(), "{bad:?}");
    }
}

/// The run's token is the same for every sweep of a process.
#[test]
fn every_sweep_of_a_process_carries_one_token() {
    assert!(is_token(run()));
    assert_eq!(run(), run());
}

#[test]
fn the_primaries_are_the_master_lines_with_their_slots() {
    let nodes = "\
a1 127.0.0.1:7001@17001 myself,master - 0 0 1 connected 0-5460
b2 127.0.0.1:7002@17002 master - 0 0 2 connected 5461-10922 [5461->-a1]
c3 127.0.0.1:7004@17004 slave b2 0 0 2 connected
d4 127.0.0.1:7003@17003 master - 0 0 3 connected 10923 10924-16383
short line
";
    assert_eq!(
        primaries_of(nodes),
        vec![
            ("127.0.0.1:7001".to_owned(), vec![(0, 5460)]),
            ("127.0.0.1:7002".to_owned(), vec![(5461, 10922)]),
            (
                "127.0.0.1:7003".to_owned(),
                vec![(10923, 10923), (10924, 16383)]
            ),
        ]
    );
}

#[test]
fn a_swept_value_reads_as_the_value_maps_and_parts_into_both() {
    let sweep = KeySweep::node(NOWHERE, "held");
    let prefix = sweep.prefix().to_owned();
    let mut held = Swept::map(sweep.hold(vec![1]), |mut v| {
        v.push(2);
        v
    });
    held.push(3);
    assert_eq!(held.len(), 3);
    assert_eq!(Swept::sweep(&held).prefix(), prefix);
    let (value, sweep) = Swept::into_parts(held);
    assert_eq!(value, [1, 2, 3]);
    assert_eq!(sweep.prefix(), prefix);
}

async fn connected(url: &str) -> Client {
    let client = Client::new(Config::from_url(url).expect("a URL"), None, None, None);
    client.init().await.expect("connect");
    client
}

/// The names of the keys `pattern` matches on the node `client` talks to.
async fn names(client: &Client, pattern: &str) -> Vec<String> {
    let mut cursor = "0".to_owned();
    let mut found = Vec::new();
    loop {
        let (next, mut page): (String, Vec<String>) = client
            .custom(
                CustomCommand::new_static("SCAN", ClusterHash::FirstKey, false),
                vec![cursor.as_str(), "MATCH", pattern, "COUNT", "1000"],
            )
            .await
            .expect("SCAN");
        found.append(&mut page);
        if next == "0" {
            found.sort();
            return found;
        }
        cursor = next;
    }
}

/// The names a test builds around a prefix: the prefix itself with a
/// suffix, inside a hash tag, with text before it.
fn names_around(prefix: &str) -> [String; 3] {
    [
        format!("{prefix}:row"),
        format!("{{{prefix}}}:tagged"),
        format!("before:{prefix}:after"),
    ]
}

/// Every key whose name holds the prefix is gone when the sweep is
/// dropped, and a key of another sweep, whose prefix the first one's is
/// not, is still there.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_a_sweep_removes_every_key_holding_its_prefix_and_no_other() {
    let client = connected(&node_url()).await;
    let sweep = KeySweep::node(node_url(), "removes");
    let other = KeySweep::node(node_url(), "removes");
    let pattern = sweep.pattern();
    for name in names_around(sweep.prefix()) {
        client
            .set::<(), _, _>(name.as_str(), "1", None, None, false)
            .await
            .expect("SET");
    }
    let kept = format!("{}:row", other.prefix());
    client
        .set::<(), _, _>(kept.as_str(), "1", None, None, false)
        .await
        .expect("SET");
    assert_eq!(names(&client, &pattern).await.len(), 3);

    drop(sweep);
    assert_eq!(names(&client, &pattern).await, Vec::<String>::new());
    assert_eq!(names(&client, &other.pattern()).await, vec![kept]);

    let other_pattern = other.pattern();
    drop(other);
    assert_eq!(names(&client, &other_pattern).await, Vec::<String>::new());
    let _ = client.quit().await;
}

/// A key outside the prefix whose name holds a text the sweep was given
/// goes with the prefix's keys.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_a_sweep_removes_the_keys_that_hold_its_other_text() {
    let client = connected(&node_url()).await;
    let session = uuid::Uuid::new_v4().simple().to_string();
    let sweep = KeySweep::node(node_url(), "also").also_holding(&session);
    let outside = format!("axess:sess:{session}");
    let under = format!("{}:row", sweep.prefix());
    for name in [&outside, &under] {
        client
            .set::<(), _, _>(name.as_str(), "1", None, None, false)
            .await
            .expect("SET");
    }
    drop(sweep);
    for name in [&outside, &under] {
        let left: i64 = client.exists(name.as_str()).await.expect("EXISTS");
        assert_eq!(left, 0, "{name}");
    }
    let _ = client.quit().await;
}

/// A test that fails after it wrote leaves nothing: the sweep it held is
/// dropped as the failure unwinds.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_a_sweep_removes_its_keys_when_the_test_fails() {
    let (sent, pattern) = std::sync::mpsc::channel();
    let failing = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime")
            .block_on(async move {
                let sweep = KeySweep::node(node_url(), "fails");
                let client = connected(&node_url()).await;
                for name in names_around(sweep.prefix()) {
                    client
                        .set::<(), _, _>(name.as_str(), "1", None, None, false)
                        .await
                        .expect("SET");
                }
                sent.send(sweep.pattern()).expect("send");
                let left = names(&client, &sweep.pattern()).await;
                assert!(left.is_empty(), "the test fails on purpose: {left:?}");
            });
    });
    assert!(failing.join().is_err(), "the test failed");
    let pattern = pattern.recv().expect("the pattern");
    let client = connected(&node_url()).await;
    assert_eq!(names(&client, &pattern).await, Vec::<String>::new());
    let _ = client.quit().await;
}

/// Counted by its own module's name where a run against the live stores is
/// judged, inside the module a run without a cluster skips by name.
mod valkey_cluster {
    mod sweep_cluster {
        use super::super::*;
        use crate::testing::valkey_cluster::{cluster_client, cluster_url, primaries};

        /// Keys under a prefix with no hash tag lie in many slots, on every
        /// primary; a sweep removes them from each, and the keys in the
        /// slot of a hash tag around the prefix as well.
        #[tokio::test]
        #[ignore = "requires a Valkey cluster (VALKEY_CLUSTER_URL)"]
        async fn a_cluster_sweep_removes_the_keys_on_every_primary() {
            let client = cluster_client().await;
            let sweep = KeySweep::cluster(cluster_url(), "spread");
            let pattern = sweep.pattern();
            for n in 0..64 {
                let spread = format!("{}:{n}", sweep.prefix());
                let tagged = format!("{{{}}}:{n}", sweep.prefix());
                for name in [spread, tagged] {
                    client
                        .set::<(), _, _>(name.as_str(), "1", None, None, false)
                        .await
                        .expect("SET");
                }
            }
            let nodes = primaries(&client).await;
            let mut on = Vec::new();
            for primary in &nodes {
                let node = connected(&format!("redis://{}", primary.addr)).await;
                on.push(names(&node, &pattern).await.len());
                let _ = node.quit().await;
            }
            assert_eq!(on.iter().sum::<usize>(), 128);
            assert!(on.iter().all(|&n| n > 0), "keys on every primary: {on:?}");

            drop(sweep);
            for primary in &nodes {
                let node = connected(&format!("redis://{}", primary.addr)).await;
                assert_eq!(names(&node, &pattern).await, Vec::<String>::new());
                let _ = node.quit().await;
            }
            let _ = client.quit().await;
        }
    }
}
