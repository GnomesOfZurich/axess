//! Whether the keys of one write can share a hash slot.
//!
//! Every write of a device is one script over several keys. A Valkey
//! cluster runs a script only when all of its keys hash to one slot, and it
//! hashes a key by its hash tag (the text between the first `{` and the
//! next `}`) when the key has one. The store's keys differ after the
//! prefix, so on a cluster they share a slot exactly when the prefix holds
//! a hash tag. A store whose client is a cluster's and whose prefix has
//! none could run no write at all, so it is refused by name: by
//! [`ValkeyDeviceStore::try_with_prefix`] and
//! [`ValkeyDeviceStore::with_prefix`] where the prefix is given, and at its
//! first write when it was left on the default prefix, which has no hash
//! tag (the constructor cannot tell that no prefix will follow).

use fred::prelude::*;

use super::{ValkeyDeviceStore, ValkeyDeviceStoreError};

/// Whether `prefix` holds a hash tag: a `{`, and after the first one a `}`
/// with at least one character between them. Valkey looks at the first `{`
/// of a key only, and hashes the whole key when nothing stands between it
/// and the next `}`.
pub(super) fn has_hash_tag(prefix: &str) -> bool {
    let Some(open) = prefix.find('{') else {
        return false;
    };
    prefix[open + 1..].find('}').is_some_and(|close| close > 0)
}

/// Whether the keys of one write would be apart: `client` is a cluster's
/// and `prefix` has no hash tag. Read from the client's configuration, so
/// it is known before the client connects.
pub(super) fn keys_apart(client: &Client, prefix: &str) -> bool {
    client.is_clustered() && !has_hash_tag(prefix)
}

impl ValkeyDeviceStore {
    /// `Ok` when the keys of a write share a slot. A store built on a
    /// cluster and left on a prefix without a hash tag is refused here, at
    /// every write, with the error [`try_with_prefix`](Self::try_with_prefix)
    /// returns; the log says so once, at `error`.
    pub(super) fn keys_together(&self) -> Result<(), ValkeyDeviceStoreError> {
        if !self.keys_apart {
            return Ok(());
        }
        static SAID: std::sync::Once = std::sync::Once::new();
        let refused = ValkeyDeviceStoreError::PrefixWithoutHashTag {
            prefix: self.prefix.to_string(),
        };
        SAID.call_once(|| {
            tracing::error!(
                error = %refused,
                "ValkeyDeviceStore refuses every write: it was built on a cluster with a \
                 prefix that has no hash tag"
            );
        });
        Err(refused)
    }
}

#[cfg(test)]
mod tests {
    use super::super::row::{device_key, tenant_index_key};
    use super::super::scripts::WRITE_ROW;
    use super::*;
    use fred::util::redis_keyslot;

    /// A client configured for a cluster and never connected: what the
    /// store reads is the configuration.
    fn cluster_configured() -> Client {
        let config = Config::from_url("redis-cluster://127.0.0.1:7001").expect("a cluster URL");
        Client::new(config, None, None, None)
    }

    /// A client configured for one node and never connected.
    fn single_node_configured() -> Client {
        Client::new(Config::default(), None, None, None)
    }

    fn store_on(client: Client) -> ValkeyDeviceStore {
        ValkeyDeviceStore::new(client, crate::testing::test_key(7))
    }

    /// The prefixes with a hash tag, and the ones without: a `{` that is
    /// never closed, an empty tag, and a tag that comes after an empty one
    /// are no tag at all.
    const TAGGED: [&str; 4] = ["{axess}", "axess{t}", "a}b{c}", "{a}{b}"];
    const UNTAGGED: [&str; 6] = ["axess", "axess{", "{}", "{}axess", "{}{x}", "a}b"];

    /// The rule is the server's: under a prefix the rule calls tagged, two
    /// keys of one write hash to one slot, and under one it calls untagged
    /// they do not.
    #[test]
    fn a_prefix_has_a_hash_tag_exactly_when_its_keys_share_a_slot() {
        let slots = |prefix: &str| {
            let row = device_key(prefix, "tenant-1", "device-1");
            let index = tenant_index_key(prefix, "tenant-1");
            (
                redis_keyslot(row.as_bytes()),
                redis_keyslot(index.as_bytes()),
            )
        };
        for prefix in TAGGED {
            assert!(has_hash_tag(prefix), "{prefix}");
            let (row, index) = slots(prefix);
            assert_eq!(row, index, "{prefix}: one slot");
        }
        for prefix in UNTAGGED {
            assert!(!has_hash_tag(prefix), "{prefix}");
            let (row, index) = slots(prefix);
            assert_ne!(row, index, "{prefix}: two slots");
        }
    }

    /// On a cluster a prefix without a hash tag is refused where it is
    /// given, by name, and the error says what to do about it.
    #[test]
    fn a_cluster_refuses_a_prefix_without_a_hash_tag_by_name() {
        for prefix in UNTAGGED {
            let refused = store_on(cluster_configured()).try_with_prefix(prefix);
            let Err(ValkeyDeviceStoreError::PrefixWithoutHashTag { prefix: named }) = refused
            else {
                panic!("{prefix}: built on a cluster without a hash tag");
            };
            assert_eq!(named, prefix);
        }
        let said = ValkeyDeviceStoreError::PrefixWithoutHashTag {
            prefix: "axess".into(),
        }
        .to_string();
        assert!(said.contains("`axess`"), "names the prefix: {said}");
        assert!(said.contains("cluster"), "names the cause: {said}");
        assert!(said.contains("`{axess}`"), "names the remedy: {said}");
    }

    /// The builder that cannot return an error refuses the same prefix by
    /// panicking with the same text.
    #[test]
    #[should_panic(expected = "has no hash tag")]
    fn with_prefix_refuses_a_prefix_without_a_hash_tag_on_a_cluster() {
        drop(store_on(cluster_configured()).with_prefix("axess"));
    }

    /// A prefix with a hash tag builds on a cluster, and any prefix builds
    /// on a single node, where one slot holds every key.
    #[test]
    fn a_tagged_prefix_builds_on_a_cluster_and_any_prefix_on_one_node() {
        for prefix in TAGGED {
            let store = store_on(cluster_configured())
                .try_with_prefix(prefix)
                .unwrap_or_else(|e| panic!("{prefix}: {e}"));
            assert_eq!(&*store.prefix, prefix);
            assert!(store.keys_together().is_ok(), "{prefix}");
            assert_eq!(
                &*store_on(cluster_configured()).with_prefix(prefix).prefix,
                prefix
            );
        }
        for prefix in TAGGED.into_iter().chain(UNTAGGED) {
            let store = store_on(single_node_configured())
                .try_with_prefix(prefix)
                .unwrap_or_else(|e| panic!("{prefix}: {e}"));
            assert!(store.keys_together().is_ok(), "{prefix}");
        }
        assert!(
            store_on(single_node_configured()).keys_together().is_ok(),
            "the default prefix on one node"
        );
    }

    /// A store built on a cluster and left on the default prefix, which has
    /// no hash tag, cannot be refused where it is built (a prefix may still
    /// follow). It is refused at its first write, and at every one after
    /// it, with the same named error, before anything is sent. The client
    /// here never connected, and a script that reached it would be refused
    /// by the client at once with an error of its own: a clustered client
    /// checks the slots of a script's keys against the cluster's routing
    /// table before it queues the script, and one that never connected has
    /// none (`Missing cluster routing state.`).
    #[tokio::test]
    async fn a_cluster_store_left_on_the_default_prefix_refuses_every_write_by_name() {
        let store = store_on(cluster_configured());
        for _ in 0..2 {
            let refused = store.run_script(WRITE_ROW, Vec::new(), Vec::new()).await;
            let Err(ValkeyDeviceStoreError::PrefixWithoutHashTag { prefix }) = refused else {
                panic!("a write reached the cluster: {refused:?}");
            };
            assert_eq!(prefix, "axess");
        }
        let fixed = store
            .try_with_prefix("{axess}")
            .expect("a hash tag is the remedy");
        assert!(fixed.keys_together().is_ok());
    }
}
