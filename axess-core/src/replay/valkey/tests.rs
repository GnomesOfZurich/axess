//! The shared replay store against a live server, ignored by default
//! (`VALKEY_URL`, and `VALKEY_CLUSTER_URL` for the cluster module). A test
//! that records removes what it wrote, also when it fails.

use super::*;

/// A client that is never connected: building one sends nothing.
fn idle_client() -> Client {
    Client::new(Config::default(), None, None, None)
}

#[tokio::test]
async fn a_key_is_the_prefix_and_the_digest_of_the_jti() {
    let store = ValkeyJtiReplayStore::new(idle_client());
    assert_eq!(
        store.key("a"),
        "axess:jti:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
    );
    let other = store.with_prefix("p");
    assert_eq!(
        other.key("a"),
        "p:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
    );
    assert_eq!(
        format!("{other:?}"),
        "ValkeyJtiReplayStore { prefix: \"p\", .. }"
    );
    assert_eq!(expiry_millis(Duration::ZERO), 1);
    assert_eq!(expiry_millis(Duration::from_secs(2)), 2000);
    assert_eq!(expiry_millis(Duration::MAX), i64::MAX);
}

/// A keyspace of the tests' own behind the one command, or a server that
/// does not answer.
#[derive(Default)]
struct Keys {
    held: std::sync::Mutex<Vec<(String, i64)>>,
    down: bool,
    policy: &'static str,
}

impl sealed::Sealed for Keys {}

impl SetOnce for Keys {
    async fn set_once(&self, key: &str, expiry_ms: i64) -> Result<bool, Error> {
        if self.down {
            return Err(Error::new(fred::error::ErrorKind::Unknown, "down"));
        }
        let mut held = self.held.lock().unwrap();
        if held.iter().any(|(name, _)| name == key) {
            return Ok(false);
        }
        held.push((key.to_owned(), expiry_ms));
        Ok(true)
    }

    async fn eviction_policy(&self) -> Result<String, Error> {
        if self.down {
            return Err(Error::new(fred::error::ErrorKind::Unknown, "down"));
        }
        Ok(self.policy.to_owned())
    }
}

/// Only a server that never evicts keeps every record: `noeviction` passes,
/// any other policy is refused by name, and a server that does not say is
/// refused as unknown.
#[tokio::test]
async fn only_a_server_that_never_evicts_passes_the_policy_check() {
    let with = |policy: &'static str, down: bool| {
        ValkeyJtiReplayStore::over(Keys {
            policy,
            down,
            ..Keys::default()
        })
    };
    assert_eq!(
        with("noeviction", false).check_eviction_policy().await,
        Ok(())
    );
    for policy in ["allkeys-lru", "volatile-ttl", "volatile-lru", ""] {
        assert_eq!(
            with(policy, false).check_eviction_policy().await,
            Err(EvictionPolicyError::Evicts(policy.to_owned())),
            "{policy}"
        );
    }
    assert!(matches!(
        with("noeviction", true).check_eviction_policy().await,
        Err(EvictionPolicyError::Unknown(_))
    ));
}

/// A `jti` is recorded once, under its key and for the ttl asked; a second
/// record of it is a replay, and a command that fails is a store that
/// cannot answer.
#[tokio::test]
async fn a_jti_is_recorded_once_and_a_failed_command_refuses() {
    let store = ValkeyJtiReplayStore::over(Keys::default());
    let ttl = Duration::from_secs(120);
    assert!(store.check_and_record("jti-1", ttl).await.is_ok());
    assert!(matches!(
        store.check_and_record("jti-1", ttl).await,
        Err(JtiReplayError::AlreadyUsed(text)) if !text.as_str().contains("jti-1")
    ));
    assert!(store.check_and_record("jti-2", ttl).await.is_ok());
    assert_eq!(
        store.client.held.lock().unwrap().as_slice(),
        &[(store.key("jti-1"), 120_000), (store.key("jti-2"), 120_000)]
    );
    let down = ValkeyJtiReplayStore::over(Keys {
        down: true,
        ..Keys::default()
    });
    assert!(matches!(
        down.check_and_record("jti-1", ttl).await,
        Err(JtiReplayError::Backend(_))
    ));
}

async fn records_once(store: &ValkeyJtiReplayStore, client: &Client) {
    let ttl = Duration::from_secs(120);
    assert!(store.check_and_record("jti-1", ttl).await.is_ok());
    assert!(matches!(
        store.check_and_record("jti-1", ttl).await,
        Err(JtiReplayError::AlreadyUsed(_))
    ));
    assert!(store.check_and_record("jti-2", ttl).await.is_ok());
    // The record expires with the ttl the verifier asked for.
    let left: i64 = client.pttl(store.key("jti-1")).await.unwrap();
    assert!(left > 0 && left <= 120_000, "{left}");
    // Of two nodes recording one jti at once, exactly one succeeds.
    let (a, b) = tokio::join!(
        store.check_and_record("jti-3", ttl),
        store.check_and_record("jti-3", ttl)
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
}

/// The answer of `checked`, without the store.
async fn checked(client: &Client) -> Result<(), EvictionPolicyError> {
    ValkeyJtiReplayStore::checked(client.clone())
        .await
        .map(|_| ())
}

mod valkey {
    use super::*;
    use crate::testing::valkey_server::{HeldPolicy, set_policy};

    async fn live_client(version: fred::types::RespVersion) -> Client {
        let url = crate::testing::valkey_sweep::node_url();
        let config = Config {
            version,
            ..Config::from_url(&url).expect("url")
        };
        let client = Client::new(config, None, None, None);
        client.init().await.expect("connect");
        client
    }

    #[tokio::test]
    #[ignore = "requires a running Valkey (VALKEY_URL)"]
    async fn a_jti_is_recorded_once_and_expires_with_its_ttl() {
        let client = live_client(fred::types::RespVersion::RESP2).await;
        let sweep = crate::testing::valkey_sweep::on_node("jti");
        let store = ValkeyJtiReplayStore::new(client.clone()).with_prefix(sweep.prefix());
        records_once(&store, &client).await;
    }

    /// `checked` reads what a live server answers `CONFIG GET` with, in the
    /// reply shape of each protocol version the client speaks: a server
    /// that runs `noeviction` passes, and the same server set to evict is
    /// refused with the policy's name. The server is left as it was found,
    /// also when the test fails ([`HeldPolicy`]).
    ///
    /// The policy is changed on the shared server because what is tested
    /// is a live server's answer to a server that evicts, and every server
    /// these tests reach runs `noeviction`; no other answer exists to read.
    #[tokio::test]
    #[ignore = "requires a running Valkey (VALKEY_URL)"]
    async fn checked_reads_a_live_servers_policy_under_both_protocols() {
        use fred::types::RespVersion;
        for version in [RespVersion::RESP2, RespVersion::RESP3] {
            let client = live_client(version.clone()).await;
            let node = client.client_config();
            let held = HeldPolicy::take(&node, node.clone(), &client).await;
            set_policy(&client, "noeviction").await;
            let kept = checked(&client).await;
            set_policy(&client, "allkeys-lru").await;
            let evicting = checked(&client).await;
            held.restore(&client).await;

            assert_eq!(kept, Ok(()), "{version:?}");
            assert_eq!(
                evicting,
                Err(EvictionPolicyError::Evicts("allkeys-lru".into())),
                "{version:?}"
            );
        }
    }
}

mod valkey_cluster {
    use super::*;
    use crate::testing::valkey_server::{HeldPolicy, set_policy};

    #[tokio::test]
    #[ignore = "requires a Valkey cluster (VALKEY_CLUSTER_URL)"]
    async fn a_jti_is_recorded_once_on_a_cluster() {
        let client = crate::testing::valkey_cluster::cluster_client().await;
        let sweep = crate::testing::valkey_sweep::on_cluster("jti");
        let store = ValkeyJtiReplayStore::new(client.clone()).with_prefix(sweep.prefix());
        records_once(&store, &client).await;
    }

    /// On a cluster every node is asked: with one node of three set to
    /// evict, `checked` refuses each time it is called, where asking one
    /// node at random would pass two times in three. The node is left as it
    /// was found, also when the test fails ([`HeldPolicy`]).
    #[tokio::test]
    #[ignore = "requires a Valkey cluster (VALKEY_CLUSTER_URL)"]
    async fn checked_asks_every_node_of_a_cluster() {
        use crate::testing::valkey_cluster::{cluster_client, cluster_config};
        let client = cluster_client().await;
        let nodes = client.active_connections();
        assert!(nodes.len() >= 3, "a cluster of three primaries: {nodes:?}");
        let last = &nodes[nodes.len() - 1];
        let one = client.with_cluster_node(last);
        let node = Config {
            server: fred::types::config::ServerConfig::Centralized {
                server: last.clone(),
            },
            ..cluster_config()
        };
        let held = HeldPolicy::take(&cluster_config(), node, &one).await;
        for node in &nodes {
            let found = policy_of(&client.with_cluster_node(node)).await.unwrap();
            assert_eq!(found, "noeviction", "{node:?}: the test cluster's default");
        }
        let all_keep = checked(&client).await;

        set_policy(&one, "volatile-ttl").await;
        let mut answers = Vec::new();
        for _ in 0..8 {
            answers.push(checked(&client).await);
        }
        held.restore(&one).await;

        assert_eq!(all_keep, Ok(()));
        for answer in answers {
            assert_eq!(
                answer,
                Err(EvictionPolicyError::Evicts("volatile-ttl".into()))
            );
        }
    }
}
