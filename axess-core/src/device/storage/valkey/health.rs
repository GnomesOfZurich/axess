//! The store's health: whether it can write at all, then whether the server
//! answers.

use std::time::Duration;

use fred::prelude::*;

use super::{ValkeyDeviceStore, ValkeyDeviceStoreError};
use crate::health::{HealthCheck, HealthStatus};

/// How long the server has to answer a `PING`.
const PING_TIMEOUT: Duration = Duration::from_secs(2);

/// A store that refuses every write is unhealthy however well the server
/// answers: one built on a cluster and left on a prefix without a hash tag
/// reports the text of [`ValkeyDeviceStoreError::PrefixWithoutHashTag`], so
/// the cause is read at the first health check and not at the first device
/// write. The server is asked (`PING`, two seconds) only by a store whose
/// writes can run.
impl HealthCheck for ValkeyDeviceStore {
    fn check(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HealthStatus> + Send + '_>> {
        Box::pin(async {
            let writes: Result<(), ValkeyDeviceStoreError> = self.keys_together();
            if let Err(refused) = writes {
                return HealthStatus::Unhealthy(refused.to_string());
            }
            match tokio::time::timeout(PING_TIMEOUT, self.client.ping::<()>(None)).await {
                Ok(Ok(_)) => HealthStatus::Healthy,
                Ok(Err(e)) => HealthStatus::Unhealthy(format!("valkey PING failed: {e}")),
                Err(_) => HealthStatus::Unhealthy("valkey PING timeout (2s)".into()),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A client configured for a cluster and never connected: the refusal
    /// is read from the configuration, and a `PING` handed to it is never
    /// answered. The client queues a command in a buffer that only a
    /// connection reads, sets no command timeout unless told to, and checks
    /// whether it is connected before queueing only for a command marked
    /// fail-fast, which a `PING` is not by default.
    fn store_on_a_cluster() -> ValkeyDeviceStore {
        let config = Config::from_url("redis-cluster://127.0.0.1:7001").expect("a cluster URL");
        let client = Client::new(config, None, None, None);
        ValkeyDeviceStore::new(client, crate::testing::test_key(7))
    }

    /// A store on a cluster whose prefix has no hash tag is unhealthy, and
    /// the reason it gives is the named error its writes are refused with.
    /// The server is not asked: the answer is there at once, on a client
    /// that never connected and would keep a `PING` waiting.
    #[tokio::test(start_paused = true)]
    async fn a_store_whose_prefix_a_cluster_refuses_is_unhealthy_by_that_name() {
        let store = store_on_a_cluster();

        let health = tokio::time::timeout(Duration::from_millis(1), store.check())
            .await
            .expect("answered without waiting for the server");

        let named = ValkeyDeviceStoreError::PrefixWithoutHashTag {
            prefix: "axess".into(),
        };
        assert_eq!(health, HealthStatus::Unhealthy(named.to_string()));
    }

    /// With a hash tag in the prefix the same store is judged by the
    /// server: here its `PING` is never answered, and the check reports
    /// the timeout, not a refusal of the prefix.
    #[tokio::test(start_paused = true)]
    async fn a_store_whose_writes_can_run_is_judged_by_the_servers_answer() {
        let store = store_on_a_cluster()
            .try_with_prefix("{axess}")
            .expect("a prefix with a hash tag");

        let health = store.check().await;

        assert_eq!(
            health,
            HealthStatus::Unhealthy("valkey PING timeout (2s)".into())
        );
    }
}
