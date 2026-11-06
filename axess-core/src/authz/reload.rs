//! Live policy reload: replace the Cedar policy set of a running
//! [`AuthzStore`] without a restart.
//!
//! The design, the invariants and the failure modes are in the book chapter
//! "Live policy reload". In short:
//!
//! - [`AuthzStore::reload_policies`] compiles the new text, validates it
//!   against the new schema, checks the entity provider against that schema,
//!   and only then swaps the set the next decision uses. A refusal leaves the
//!   previous set in force.
//! - After a swap the store drops the caches registered with
//!   [`AuthzStore::with_cache_invalidator`] and, when a [`ReloadCoordinator`]
//!   is set, announces the new digest to the other instances.
//! - [`AuthzStore::follow_reloads`] is the receiving side: on a notice, and on
//!   a poll, it re-reads a [`PolicySource`] the adopter supplies and applies
//!   what differs. A notice carries no policy.

mod follower;

use std::error::Error as StdError;
use std::sync::Arc;

use tracing::{error, info, warn};

#[cfg(feature = "valkey")]
#[cfg_attr(docsrs, doc(cfg(feature = "valkey")))]
pub use crate::reload::ValkeyReloadCoordinator;
pub use crate::reload::{
    CoordinationError, InProcessCoordinator, ReloadCoordinator, ReloadFuture, ReloadNotice,
    ReloadReceiver,
};
pub use follower::{PolicyBundle, PolicySource, ReloadFollower, ReloadOrigin};

use super::{
    cache::CacheInvalidator,
    error::AuthzError,
    provider::AuthzEntityProvider,
    session::AuthzStore,
    store::{PolicyEvaluator, PolicyStore},
};
use crate::metrics::MetricSinks;

/// What a successful [`AuthzStore::reload_policies`] did.
///
/// The swap is the part that cannot be half done; the two steps after it can
/// fail without undoing it, and say so here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reloaded {
    /// The digest of the policy set now in force, see
    /// [`policy_set_digest`](super::store::policy_set_digest).
    pub digest: String,
    /// Whether every registered cache dropped its entries. `false` means at
    /// least one failed; its entries age out by their TTL.
    pub cache_invalidated: bool,
    /// Whether the other instances were told. `false` means there is no
    /// coordinator, or announcing failed; peers catch up by their poll.
    pub announced: bool,
}

/// Called after a policy swap, to drop state built for the retired policies.
///
/// [`AuthzStore::with_cache_invalidator`] registers a cache through the
/// provided adapter; implement this for anything else that must forget.
pub trait ReloadHook: Send + Sync {
    /// The policy set was just replaced.
    fn policies_reloaded(&self) -> ReloadFuture<'_, Result<(), Box<dyn StdError + Send + Sync>>>;
}

struct InvalidateAll<C>(Arc<C>);

impl<C: CacheInvalidator> ReloadHook for InvalidateAll<C> {
    fn policies_reloaded(&self) -> ReloadFuture<'_, Result<(), Box<dyn StdError + Send + Sync>>> {
        Box::pin(async move {
            self.0
                .invalidate_all()
                .await
                .map_err(|e| Box::new(e) as Box<dyn StdError + Send + Sync>)
        })
    }
}

/// The reload machinery an [`AuthzStore`] carries.
#[derive(Default)]
pub(super) struct ReloadState {
    /// Serialises reloads; the request path never takes it.
    lock: tokio::sync::Mutex<()>,
    hooks: Vec<Arc<dyn ReloadHook>>,
    coordinator: Option<Arc<dyn ReloadCoordinator>>,
    metrics: Option<MetricSinks>,
}

impl<P: AuthzEntityProvider> AuthzStore<P> {
    /// Drop `cache` with [`invalidate_all`](CacheInvalidator::invalidate_all)
    /// after every successful policy swap.
    ///
    /// Register every entity cache the provider reads through. A cached
    /// entity set was built for the retired policies and schema; a schema
    /// that dropped an attribute would deny the requests that hit it until
    /// the TTL ran out.
    #[must_use]
    pub fn with_cache_invalidator<C: CacheInvalidator>(mut self, cache: Arc<C>) -> Self {
        self.reload.hooks.push(Arc::new(InvalidateAll(cache)));
        self
    }

    /// Run `hook` after every successful policy swap.
    #[must_use]
    pub fn with_reload_hook(mut self, hook: Arc<dyn ReloadHook>) -> Self {
        self.reload.hooks.push(hook);
        self
    }

    /// Announce every local reload on `coordinator`, and let
    /// [`follow_reloads`](Self::follow_reloads) listen on it.
    #[must_use]
    pub fn with_coordinator(mut self, coordinator: Arc<dyn ReloadCoordinator>) -> Self {
        self.reload.coordinator = Some(coordinator);
        self
    }

    /// Count reloads and refusals on the authorization sink of `metrics`
    /// ([`AuthzCacheMetrics`](crate::metrics::AuthzCacheMetrics)).
    #[must_use]
    pub fn with_metrics(mut self, metrics: MetricSinks) -> Self {
        self.reload.metrics = Some(metrics);
        self
    }

    /// The digest of the policy set in force, or `None` when the evaluator
    /// has none (a mock, or a custom [`PolicyEvaluator`]).
    pub fn policy_digest(&self) -> Option<String> {
        self.evaluator.load().digest()
    }

    /// Replace the policy set and schema in force.
    ///
    /// The new text is parsed and validated in strict mode against the new
    /// schema, and the entity provider is checked against that schema with
    /// [`AuthzEntityProvider::validate_schema`], all before the swap. If any
    /// step fails the previous set stays in force and the error names the
    /// step: [`AuthzError::PolicyParse`], [`AuthzError::SchemaParse`],
    /// [`AuthzError::PolicyValidation`], or the provider's error.
    ///
    /// On success the next decision uses the new set, the registered caches
    /// are dropped, and the other instances are told. A decision already past
    /// its snapshot finishes against the set it started with.
    ///
    /// Reloads are serialised; concurrent calls apply one after the other,
    /// each fully validated.
    pub async fn reload_policies(
        &self,
        policy_text: &str,
        schema_json: &str,
    ) -> Result<Reloaded, AuthzError> {
        self.reload_from(policy_text, schema_json, ReloadOrigin::Local)
            .await
    }

    pub(super) async fn reload_from(
        &self,
        policy_text: &str,
        schema_json: &str,
        origin: ReloadOrigin,
    ) -> Result<Reloaded, AuthzError> {
        let outcome = self.swap_policies(policy_text, schema_json, origin).await;
        if let Some(metrics) = &self.reload.metrics {
            match &outcome {
                Ok(_) => metrics.authz_cache().authz_policy_reloaded(),
                Err(_) => metrics.authz_cache().authz_policy_reload_refused(),
            }
        }
        if let Err(e) = &outcome {
            warn!(
                target: "axess::authz::reload",
                origin = origin.as_str(),
                error = %e,
                "policy reload refused; the previous policy set stays in force",
            );
        }
        outcome
    }

    async fn swap_policies(
        &self,
        policy_text: &str,
        schema_json: &str,
        origin: ReloadOrigin,
    ) -> Result<Reloaded, AuthzError> {
        let _serialised = self.reload.lock.lock().await;

        // Validate before swap: nothing below the next three lines runs for
        // a set that failed to parse, validate or fit the provider.
        let store = PolicyStore::from_text(policy_text, schema_json)?;
        self.provider.validate_schema(store.schema())?;
        let digest = store.digest().to_string();

        let next: Arc<dyn PolicyEvaluator> = Arc::new(store);
        let previous = self.evaluator.swap(Arc::new(next));

        let mut cache_invalidated = true;
        for hook in &self.reload.hooks {
            if let Err(e) = hook.policies_reloaded().await {
                cache_invalidated = false;
                error!(
                    target: "axess::authz::reload",
                    error = %e,
                    "a cache did not drop its entries after the policy swap; they age out by TTL",
                );
            }
        }

        let mut announced = false;
        if origin == ReloadOrigin::Local
            && let Some(coordinator) = &self.reload.coordinator
        {
            match coordinator.announce(&digest).await {
                Ok(()) => announced = true,
                Err(e) => error!(
                    target: "axess::authz::reload",
                    error = %e,
                    "the reload was not announced; other instances catch up by their poll",
                ),
            }
        }

        info!(
            target: "axess::authz::reload",
            origin = origin.as_str(),
            digest = %digest,
            previous_digest = previous.digest().as_deref().unwrap_or(""),
            cache_invalidated,
            announced,
            "policy set reloaded",
        );
        Ok(Reloaded {
            digest,
            cache_invalidated,
            announced,
        })
    }
}
