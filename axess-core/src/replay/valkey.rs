//! The replay store on Valkey (or Redis), which every node of a fleet
//! reaches.

use std::future::Future;
use std::time::Duration;

use axess_factors::jwt::verifier::{JtiReplayError, JtiReplayStore};
use fred::prelude::*;
use sha2::{Digest, Sha256};

/// The key prefix a store uses unless told otherwise.
pub const DEFAULT_JTI_PREFIX: &str = "axess:jti";

/// A [`JtiReplayStore`] on Valkey (or Redis).
///
/// A record is one key, `<prefix>:<hex of SHA-256 of the jti>`, written with
/// `SET NX PX`: the write is the check, so of two nodes recording one `jti`
/// at once exactly one succeeds, and the key expires with the `ttl` the
/// verifier asks for. The `jti` is hashed because the sender chose it: the
/// key has one length whatever it sent, and nothing it sends can name
/// another key or a hash slot. One key per record, so the store works on a
/// cluster as it does on one server.
///
/// Give each verifier a prefix of its own (`with_prefix`): two kinds of
/// token that share one would refuse each other's `jti` values.
///
/// A store that cannot answer is an error, which every verifier of this
/// crate turns into a refusal.
///
/// **The server must not evict.** Every record carries a time to live, so
/// under memory pressure every `maxmemory-policy` but `noeviction` may drop
/// a live record, and a dropped record is a token accepted twice. Keep the
/// replay records on a server (or a logical instance with memory of its
/// own) that runs `noeviction`; when it is full it refuses the write, which
/// this store reports as a store that cannot answer. Build the store with
/// [`checked`](ValkeyJtiReplayStore::checked), which asks the server at
/// start and refuses any other policy; [`new`](ValkeyJtiReplayStore::new)
/// asks nothing, for a managed server that does not answer `CONFIG GET`,
/// where the policy is the operator's to confirm.
///
/// `C` is what the store's one command goes through ([`SetOnce`]): a
/// [`Client`], which [`new`](ValkeyJtiReplayStore::new) takes.
#[derive(Clone)]
pub struct ValkeyJtiReplayStore<C = Client> {
    client: C,
    prefix: String,
}

impl ValkeyJtiReplayStore {
    /// A store on `client`, which the caller built and `init()`ed. The
    /// server's eviction policy is not checked: see
    /// [`checked`](Self::checked).
    pub fn new(client: Client) -> Self {
        Self::over(client)
    }

    /// [`new`](Self::new), after asking the server for its
    /// `maxmemory-policy`: anything but `noeviction` may drop a live record
    /// and is refused, as is a server that does not say. Every node of a
    /// cluster is asked, since each evicts by its own setting.
    pub async fn checked(client: Client) -> Result<Self, EvictionPolicyError> {
        let store = Self::over(client);
        store.check_eviction_policy().await?;
        Ok(store)
    }
}

/// Why a replay store's server is not known to keep its records.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EvictionPolicyError {
    /// The server evicts keys under memory pressure, so a live `jti` can be
    /// forgotten. Carries the policy it reported.
    #[error(
        "the replay store's server runs maxmemory-policy `{0}`, which may evict a live jti; \
         it must be `noeviction`"
    )]
    Evicts(String),
    /// The server did not report its policy (some managed services refuse
    /// `CONFIG GET`). Carries the server's or the client's message.
    #[error("the replay store's server did not report its maxmemory-policy: {0}")]
    Unknown(String),
}

impl<C> ValkeyJtiReplayStore<C> {
    /// A store that sends its one command through `client`.
    fn over(client: C) -> Self {
        Self {
            client,
            prefix: DEFAULT_JTI_PREFIX.to_string(),
        }
    }

    /// Use another key prefix (default [`DEFAULT_JTI_PREFIX`]).
    #[must_use]
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    /// Ask the server whether it keeps what this store writes: `Ok` only
    /// when its `maxmemory-policy` is `noeviction`.
    pub async fn check_eviction_policy(&self) -> Result<(), EvictionPolicyError>
    where
        C: SetOnce,
    {
        match self.client.eviction_policy().await {
            Ok(policy) if policy == NOEVICTION => Ok(()),
            Ok(policy) => Err(EvictionPolicyError::Evicts(policy)),
            Err(e) => Err(EvictionPolicyError::Unknown(e.to_string())),
        }
    }

    /// The key a `jti` is recorded under.
    fn key(&self, jti: &str) -> String {
        format!(
            "{}:{}",
            self.prefix,
            axess_rng::hex::encode(Sha256::digest(jti.as_bytes()))
        )
    }
}

impl<C> std::fmt::Debug for ValkeyJtiReplayStore<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValkeyJtiReplayStore")
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

/// The expiry of a record in milliseconds: at least one, so a record is
/// never written already expired, and at most what Valkey takes.
fn expiry_millis(ttl: Duration) -> i64 {
    i64::try_from(ttl.as_millis()).unwrap_or(i64::MAX).max(1)
}

/// The one command the store sends, `SET <key> 1 NX PX <expiry_ms>`. The
/// store is written over it, so how the command's answer is read is tested
/// without a server; [`Client`] is the one implementation outside tests.
pub trait SetOnce: sealed::Sealed + Send + Sync {
    /// Write `key` unless it exists, to expire after `expiry_ms`; whether it
    /// was written.
    fn set_once(
        &self,
        key: &str,
        expiry_ms: i64,
    ) -> impl Future<Output = Result<bool, Error>> + Send;

    /// The server's `maxmemory-policy`, as `CONFIG GET` reports it. For a
    /// cluster, `noeviction` only when every node says so, and otherwise
    /// the policy of a node that evicts.
    fn eviction_policy(&self) -> impl Future<Output = Result<String, Error>> + Send;
}

mod sealed {
    /// Keeps [`SetOnce`](super::SetOnce) to this crate's implementations.
    pub trait Sealed {}
    impl Sealed for fred::prelude::Client {}
}

impl SetOnce for Client {
    async fn set_once(&self, key: &str, expiry_ms: i64) -> Result<bool, Error> {
        let written: Option<String> = self
            .set(
                key,
                "1",
                Some(Expiration::PX(expiry_ms)),
                Some(SetOptions::NX),
                false,
            )
            .await?;
        Ok(written.is_some())
    }

    async fn eviction_policy(&self) -> Result<String, Error> {
        if !self.is_clustered() {
            return policy_of(self).await;
        }
        // Each node of a cluster evicts by its own setting, and a record
        // lives on the node its key hashes to: every node the client holds
        // a connection to is asked, and the first that does not say
        // `noeviction` is the answer.
        let mut policy = None;
        for node in self.active_connections() {
            let said = policy_of(&self.with_cluster_node(node)).await?;
            if said != NOEVICTION {
                return Ok(said);
            }
            policy = Some(said);
        }
        policy.ok_or_else(|| {
            Error::new(
                ErrorKind::Unknown,
                "no cluster node to ask for its maxmemory-policy",
            )
        })
    }
}

/// The one policy under which a server keeps every record.
const NOEVICTION: &str = "noeviction";

/// The `maxmemory-policy` the server behind `client` reports.
async fn policy_of<C: ClientLike>(client: &C) -> Result<String, Error> {
    let command =
        fred::types::CustomCommand::new_static("CONFIG", fred::types::ClusterHash::Random, false);
    // `[name, value]`, and under RESP3 a map of the one name to its value,
    // which the client reads as the same two strings.
    let reply: Vec<String> = client
        .custom(command, vec!["GET", "maxmemory-policy"])
        .await?;
    reply.into_iter().nth(1).ok_or_else(|| {
        Error::new(
            ErrorKind::Unknown,
            "CONFIG GET maxmemory-policy answered no value",
        )
    })
}

impl<C: SetOnce> JtiReplayStore for ValkeyJtiReplayStore<C> {
    async fn check_and_record(&self, jti: &str, ttl: Duration) -> Result<(), JtiReplayError> {
        match self
            .client
            .set_once(&self.key(jti), expiry_millis(ttl))
            .await
        {
            Ok(true) => Ok(()),
            // The sender's `jti` is not echoed: the key names the record.
            Ok(false) => Err(JtiReplayError::already_used(
                "a jti this store already holds",
            )),
            Err(e) => Err(JtiReplayError::Backend(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests;
