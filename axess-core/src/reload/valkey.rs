//! A [`ReloadCoordinator`] on Valkey pub/sub.

use std::num::NonZeroUsize;

use fred::clients::SubscriberClient;
use fred::prelude::*;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tracing::warn;

use super::{CoordinationError, ReloadCoordinator, ReloadFuture, ReloadNotice, ReloadReceiver};

/// Announces and receives policy reloads over Valkey (or Redis) pub/sub.
///
/// The channel is `{prefix}:authz-policy-reloaded`, a sibling of the
/// `{prefix}:authz-entities-invalidated:{principal}` channel the entity cache
/// documents. The payload is the digest, for logs; a receiver applies nothing
/// from it and re-reads its own source.
///
/// The subscription lives on its own connection (`SubscriberClient`) and is
/// re-established after a reconnect. Pub/sub is at most once; a notice sent
/// while a subscriber is disconnected is missed, and the follower's poll
/// covers it.
pub struct ValkeyReloadCoordinator {
    publisher: Client,
    channel: String,
    notices: broadcast::Sender<ReloadNotice>,
    bridge: JoinHandle<()>,
    resubscribe: JoinHandle<()>,
}

impl ValkeyReloadCoordinator {
    /// Subscribe on `subscriber` and publish on `publisher`.
    ///
    /// Both clients must be built and `init()`ed by the caller (two clients,
    /// because a connection in subscriber mode cannot publish on every
    /// protocol). `capacity` bounds the unread notices per local subscriber
    /// before one lags.
    ///
    /// # Errors
    ///
    /// [`CoordinationError`] when the subscription is refused.
    pub async fn start(
        publisher: Client,
        subscriber: SubscriberClient,
        prefix: &str,
        capacity: NonZeroUsize,
    ) -> Result<Self, CoordinationError> {
        Self::start_named(
            publisher,
            subscriber,
            prefix,
            "authz-policy-reloaded",
            capacity,
        )
        .await
    }

    /// As [`start`](Self::start), on the channel `{prefix}:{name}`.
    ///
    /// A second concern that reloads (the authentication providers use
    /// `provider-reloaded`) takes its own channel, so a notice for one is
    /// never read as a notice for the other.
    ///
    /// # Errors
    ///
    /// [`CoordinationError`] when the subscription is refused.
    pub async fn start_named(
        publisher: Client,
        subscriber: SubscriberClient,
        prefix: &str,
        name: &str,
        capacity: NonZeroUsize,
    ) -> Result<Self, CoordinationError> {
        let channel = format!("{prefix}:{name}");
        let (notices, _) = broadcast::channel(capacity.get());
        let mut messages = subscriber.message_rx();
        let resubscribe = subscriber.manage_subscriptions();
        subscriber
            .subscribe(channel.clone())
            .await
            .map_err(|e| CoordinationError(format!("subscribe to {channel}: {e}")))?;

        let forward = notices.clone();
        let bridge = tokio::spawn(async move {
            // The subscriber client is moved in to keep its connection alive.
            let _keep = subscriber;
            loop {
                match messages.recv().await {
                    Ok(message) => {
                        let digest = message.value.as_string().unwrap_or_default();
                        let _ = forward.send(ReloadNotice { digest });
                    }
                    // Messages were dropped locally: tell the followers they
                    // missed something, which they treat as a notice.
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        warn!(
                            target: "axess::reload",
                            "the Valkey subscription lagged; followers will re-read their source",
                        );
                        let _ = forward.send(ReloadNotice {
                            digest: String::new(),
                        });
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });
        Ok(Self {
            publisher,
            channel,
            notices,
            bridge,
            resubscribe,
        })
    }
}

impl Drop for ValkeyReloadCoordinator {
    fn drop(&mut self) {
        self.bridge.abort();
        self.resubscribe.abort();
    }
}

impl ReloadCoordinator for ValkeyReloadCoordinator {
    fn announce<'a>(&'a self, digest: &'a str) -> ReloadFuture<'a, Result<(), CoordinationError>> {
        Box::pin(async move {
            self.publisher
                .publish::<i64, _, _>(self.channel.as_str(), digest)
                .await
                .map(|_| ())
                .map_err(|e| CoordinationError(format!("publish to {}: {e}", self.channel)))
        })
    }

    fn subscribe(&self) -> ReloadFuture<'_, Result<ReloadReceiver, CoordinationError>> {
        Box::pin(async move { Ok(self.notices.subscribe()) })
    }
}
