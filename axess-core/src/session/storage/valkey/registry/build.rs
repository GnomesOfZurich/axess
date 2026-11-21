//! How a [`ValkeySessionRegistry`] is built: the two constructors and the
//! checks they make before it serves a call, and the health check that
//! sends the same probe.

use super::super::internal::{
    DEFAULT_PREFIX, UserKeys, ValkeyStoreError, script_unavailable, user_keys,
};
use super::super::subscriber::SharedSubscriber;
use super::ValkeySessionRegistry;
use crate::authn::ids::UserId;
use crate::health::{HealthCheck, HealthStatus};
use axess_rng::SystemRng;
use fred::prelude::*;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

/// The lifetime of a registry entry when the caller names none.
const DEFAULT_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// The script that asks whether the server runs the registry's scripts. It
/// reads and writes nothing.
const PROBE_SCRIPT: &str = "return 1";

/// Send [`PROBE_SCRIPT`] over `keys`, a user's registry keys, so that a
/// cluster routes it exactly as it routes every script of the registry.
/// `Ok` only on the reply `1`. A client that is not connected is an error
/// before anything is sent: a registry is not built, and not reported
/// healthy, on a server it could not ask.
async fn probe(client: &Client, keys: &UserKeys) -> Result<(), fred::error::Error> {
    if !client.is_connected() {
        return Err(fred::error::Error::new(
            fred::error::ErrorKind::IO,
            "the Valkey client is not connected",
        ));
    }
    let reply: i64 = client
        .eval(PROBE_SCRIPT, keys.all(), Vec::<Value>::new())
        .await?;
    if reply == 1 {
        Ok(())
    } else {
        Err(fred::error::Error::new(
            fred::error::ErrorKind::Protocol,
            "the probe script answered other than 1",
        ))
    }
}

impl ValkeySessionRegistry {
    /// A registry with the default prefix and a 24-hour lifetime. `client`
    /// must be connected. Fails when the server refuses scripts
    /// ([`ValkeyStoreError::ScriptsRefused`]) or does not answer.
    pub async fn new(client: Client) -> Result<Self, ValkeyStoreError> {
        Self::checked(client, DEFAULT_PREFIX.into(), DEFAULT_TTL).await
    }

    /// The same with a prefix and a lifetime of the caller's. Fails as `new`
    /// does, and when the prefix would put one user's keys in different
    /// cluster slots ([`ValkeyStoreError::Unsupported`]): one that opens a
    /// hash tag it does not close, such as `a{b`.
    pub async fn with_options(
        client: Client,
        prefix: impl Into<Arc<str>>,
        ttl: Duration,
    ) -> Result<Self, ValkeyStoreError> {
        Self::checked(client, prefix.into(), ttl).await
    }

    /// What both constructors check, in this order, before the registry is
    /// built: that `prefix` keeps a user's keys in one cluster slot, before
    /// anything is sent; then that the server runs a script over a user's
    /// keys. Every call checks the first again, and the move of a session to
    /// a new key, the cut-off of a user's other sessions and the orphan sweep
    /// are scripts with no other form, so a registry that passed here does
    /// not start and then fail at the first of them.
    async fn checked(
        client: Client,
        prefix: Arc<str>,
        ttl: Duration,
    ) -> Result<Self, ValkeyStoreError> {
        let keys = user_keys(&prefix, &UserId::NIL)?;
        probe(&client, &keys).await.map_err(|e| {
            if script_unavailable(&e) {
                ValkeyStoreError::ScriptsRefused(e)
            } else {
                ValkeyStoreError::Connection(e)
            }
        })?;
        Ok(Self::assembled(client, prefix, ttl))
    }

    /// The registry's fields, without the constructors' checks. The two
    /// constructors build through it after their checks pass; the tests of
    /// what a call does where the checks would have refused build through
    /// it directly.
    pub(in crate::session::storage::valkey) fn assembled(
        client: Client,
        prefix: Arc<str>,
        ttl: Duration,
    ) -> Self {
        Self {
            client,
            prefix,
            ttl,
            clock: None,
            rng: Arc::new(SystemRng),
            subscriber: SharedSubscriber::new(),
        }
    }
}

// ── HealthCheck ──────────────────────────────────────────────────────────────

/// Health check timeout for the registry's probe.
const HEALTH_CHECK_TIMEOUT: Duration = Duration::from_secs(2);

/// Healthy when the server answers the probe the constructors send: a
/// script over a user's keys, so a server that answers a `PING` but refuses
/// the scripts the registry runs is reported as what it is.
impl HealthCheck for ValkeySessionRegistry {
    fn check(&self) -> Pin<Box<dyn Future<Output = HealthStatus> + Send + '_>> {
        Box::pin(async {
            let keys = match user_keys(&self.prefix, &UserId::NIL) {
                Ok(keys) => keys,
                Err(e) => return HealthStatus::Unhealthy(e.to_string()),
            };
            match tokio::time::timeout(HEALTH_CHECK_TIMEOUT, probe(&self.client, &keys)).await {
                Ok(Ok(())) => HealthStatus::Healthy,
                Ok(Err(e)) if script_unavailable(&e) => HealthStatus::Unhealthy(format!(
                    "the valkey server refuses scripts, which the session registry needs: {e}"
                )),
                Ok(Err(e)) => HealthStatus::Unhealthy(format!("valkey probe failed: {e}")),
                Err(_) => HealthStatus::Unhealthy("valkey probe timeout (2s)".into()),
            }
        })
    }
}
