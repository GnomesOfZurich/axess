//! The receiving side: re-read a [`ProviderSource`] on a notice and on a poll.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::broadcast::error::RecvError;
use tokio::task::JoinHandle;
use tracing::{debug, error, warn};

use super::ProviderKey;
use crate::authn::service::AuthnService;
use crate::authn::store::{FactorStore, IdentityStore};
use crate::reload::{CoordinationError, ReloadFuture, ReloadReceiver};

const TARGET: &str = "axess::authn::provider_reload";

/// A provider a [`ProviderSource`] built, by category.
pub enum BuiltProvider {
    /// An OAuth/OIDC provider.
    #[cfg(feature = "oauth")]
    OAuth(Arc<dyn axess_factors::oauth::OAuthProvider>),
    /// The FIDO2/WebAuthn provider.
    #[cfg(feature = "fido2")]
    Fido2(Arc<dyn axess_factors::fido2::Fido2Provider>),
    /// The FIDO2/WebAuthn provider, with the source stating that a change of
    /// relying-party id is intended and the registered passkeys may be
    /// orphaned. The plain [`Fido2`](Self::Fido2) variant is refused when the
    /// id differs from the one in force.
    #[cfg(feature = "fido2")]
    Fido2AllowingRpIdChange(Arc<dyn axess_factors::fido2::Fido2Provider>),
    /// The LDAP provider.
    #[cfg(feature = "ldap")]
    Ldap(Arc<dyn axess_factors::ldap::LdapProvider>),
}

/// A provider the source says should be running, with an opaque revision.
///
/// The follower rebuilds a provider only when its revision differs from the
/// one it last applied, so `revision` must change whenever the configuration
/// does (a version number, an updated-at stamp, a content hash) and must be
/// cheap to produce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderEntry {
    /// Which provider.
    pub key: ProviderKey,
    /// The configuration's revision.
    pub revision: String,
}

/// The source could not answer.
#[derive(Debug, thiserror::Error)]
#[error("provider source: {0}")]
pub struct ProviderSourceError(pub String);

/// Where the providers an instance should run are configured: a database
/// table, a file, a secrets manager.
///
/// This is the trust boundary of a coordinated reload. A follower builds what
/// the source describes, never what a notice says.
pub trait ProviderSource: Send + Sync {
    /// The providers that should be running and their revisions. Cheap and
    /// without network calls to the IdPs: it runs on every poll.
    fn desired(&self) -> ReloadFuture<'_, Result<Vec<ProviderEntry>, ProviderSourceError>>;

    /// Build the provider `key` names, discovery and parsing included. Called
    /// only for a key whose revision moved.
    fn build<'a>(
        &'a self,
        key: &'a ProviderKey,
    ) -> ReloadFuture<'a, Result<BuiltProvider, ProviderSourceError>>;
}

/// Why a follower read its source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadCause {
    /// The first read, when following began.
    Start,
    /// A coordinator notice arrived.
    Notice,
    /// The receiver lagged and missed notices, so it read as for a notice.
    Lagged,
    /// The poll interval elapsed.
    Poll,
}

impl ReadCause {
    fn index(self) -> usize {
        match self {
            Self::Start => 0,
            Self::Notice => 1,
            Self::Lagged => 2,
            Self::Poll => 3,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Notice => "notice",
            Self::Lagged => "lagged",
            Self::Poll => "poll",
        }
    }
}

/// How often a follower read its source, by cause.
#[derive(Debug, Default)]
struct ReadCounts([std::sync::atomic::AtomicU64; 4]);

impl ReadCounts {
    fn record(&self, cause: ReadCause) {
        self.0[cause.index()].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn get(&self, cause: ReadCause) -> u64 {
        self.0[cause.index()].load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// A running follower. Dropping it stops the task.
#[derive(Debug)]
pub struct ProviderFollower {
    task: JoinHandle<()>,
    reads: Arc<ReadCounts>,
}

impl ProviderFollower {
    /// Stop following.
    pub fn stop(self) {}

    /// How many times the follower started a read of its source for `cause`.
    ///
    /// The count moves when the read begins, before the source answers, so a
    /// source that cannot be read still counts. A deployment that sees reads
    /// by `Poll` but never by `Notice` has a coordinator that does not
    /// deliver; one that sees `Lagged` has a channel too small for its burst
    /// of changes.
    pub fn reads(&self, cause: ReadCause) -> u64 {
        self.reads.get(cause)
    }
}

impl Drop for ProviderFollower {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl<I, F> AuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Keep this instance's providers on what `source` describes.
    ///
    /// Reconciles once at start (to catch up on what was missed), then on
    /// every coordinator notice, after a lagged receiver, and every
    /// `poll_every`: each entry whose revision moved is built and installed
    /// through the same checks as a direct reload, and not announced again;
    /// a provider of any category the follower installed earlier and the source no
    /// longer lists is removed. Providers the source never named, such as
    /// those registered at construction, are left alone. A source that cannot
    /// be read, or a build or check that fails, is logged and counted and
    /// retried at the next notice or poll, with the previous provider serving.
    ///
    /// The task holds a handle to the service, so the service lives as long
    /// as the follower; drop the [`ProviderFollower`] to release it.
    ///
    /// # Errors
    ///
    /// [`CoordinationError`] when no coordinator was set with
    /// [`with_provider_coordinator`](super::AuthnServiceBuilder::with_provider_coordinator),
    /// when `poll_every` is zero, or when subscribing fails.
    pub async fn follow_provider_reloads(
        &self,
        source: Arc<dyn ProviderSource>,
        poll_every: Duration,
    ) -> Result<ProviderFollower, CoordinationError>
    where
        I: 'static,
        F: 'static,
    {
        let Some(coordinator) = self.inner.provider_reload.coordinator.clone() else {
            return Err(CoordinationError(
                "follow_provider_reloads needs a coordinator; set one with with_provider_coordinator"
                    .into(),
            ));
        };
        if poll_every.is_zero() {
            return Err(CoordinationError(
                "poll_every must be longer than zero".into(),
            ));
        }
        let notices = coordinator.subscribe().await?;
        let service = self.clone();
        let reads = Arc::new(ReadCounts::default());
        let counted = reads.clone();
        let task = tokio::spawn(async move {
            service.follow(source, poll_every, notices, counted).await;
        });
        Ok(ProviderFollower { task, reads })
    }

    async fn follow(
        self,
        source: Arc<dyn ProviderSource>,
        poll_every: Duration,
        notices: ReloadReceiver,
        reads: Arc<ReadCounts>,
    ) {
        let mut notices = Some(notices);
        let mut started = false;
        let mut applied: HashMap<ProviderKey, String> = HashMap::new();
        let mut ticker = tokio::time::interval(poll_every);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            let cause = tokio::select! {
                _ = ticker.tick() => if std::mem::replace(&mut started, true) {
                    ReadCause::Poll
                } else {
                    ReadCause::Start
                },
                received = next_notice(&mut notices) => match received {
                    Ok(()) => ReadCause::Notice,
                    // A lagged receiver missed notices: re-read like for one.
                    Err(RecvError::Lagged(_)) => ReadCause::Lagged,
                    Err(RecvError::Closed) => {
                        error!(
                            target: TARGET,
                            "the provider coordinator closed; following by poll only",
                        );
                        notices = None;
                        continue;
                    }
                },
            };
            reads.record(cause);
            debug!(target: TARGET, cause = cause.as_str(), "reading the provider source");
            self.reconcile(source.as_ref(), &mut applied).await;
        }
    }

    async fn reconcile(
        &self,
        source: &dyn ProviderSource,
        applied: &mut HashMap<ProviderKey, String>,
    ) {
        let desired = match source.desired().await {
            Ok(desired) => desired,
            Err(e) => {
                warn!(
                    target: TARGET,
                    error = %e,
                    "the provider source could not be read; the previous providers stay in force",
                );
                return;
            }
        };
        for entry in &desired {
            if applied.get(&entry.key) == Some(&entry.revision) {
                continue;
            }
            if self.apply_entry(source, entry).await {
                applied.insert(entry.key.clone(), entry.revision.clone());
            }
        }
        let wanted: HashSet<&ProviderKey> = desired.iter().map(|e| &e.key).collect();
        let withdrawn: Vec<ProviderKey> = applied
            .keys()
            .filter(|key| !wanted.contains(key))
            .cloned()
            .collect();
        for key in withdrawn {
            self.withdraw(&key).await;
            applied.remove(&key);
        }
    }

    /// Build and install one entry; `true` when it is now in force.
    async fn apply_entry(&self, source: &dyn ProviderSource, entry: &ProviderEntry) -> bool {
        let key = &entry.key;
        let built = self.candidate(key, async { source.build(key).await }).await;
        let installed = match built {
            Ok(built) => self.install_built(key, built).await,
            Err(e) => Err(e),
        };
        self.settle(key, installed, false).await.is_ok()
    }

    /// The source stopped listing `key`.
    async fn withdraw(&self, key: &ProviderKey) {
        let removed = self.remove_key(key);
        // A provider already gone is the state the source asks for.
        if !matches!(removed, Err(super::ProviderReloadError::NotFound { .. })) {
            let _ = self.settle(key, removed, false).await;
        }
    }
}

/// The next notice, or never when the coordinator is gone.
async fn next_notice(notices: &mut Option<ReloadReceiver>) -> Result<(), RecvError> {
    match notices {
        Some(receiver) => receiver.recv().await.map(|_| ()),
        None => std::future::pending().await,
    }
}
