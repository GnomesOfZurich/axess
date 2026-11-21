//! [`AuthzInstallation`]: everything a `require_authz!` gate decides with,
//! built in one call and installed as one layer.
//!
//! A gate needs the policies, the provider of the entities they are decided
//! over and, when the policies read `context`, the provider of that context.
//! The three only work together, so they are handed over together, where the
//! router is built, and a set that cannot work is refused there instead of
//! at the first gated request.

use std::sync::Arc;

use super::context::RequestContextProvider;
use super::error::AuthzError;
use super::provider::RequestEntityProvider;
use super::store::PolicyStore;

/// What every `require_authz!` gate under it decides with: the policy
/// store, the entity provider and, when the policies read `context`, the
/// context provider.
///
/// Build it once with [`new`](Self::new) and add it as a layer outside the
/// gates. It is the one thing a gate reads from the request: a gate that
/// finds none answers 500 and logs an error, and nothing else installs a
/// policy store for a gate.
///
/// ```rust,ignore
/// let policies = Arc::new(PolicyStore::from_text(policy_text, schema_json)?);
/// let installation = AuthzInstallation::new(
///     policies.clone(),
///     Arc::new(MyEntities::new(db)),
///     Some(Arc::new(MyContext::new(clock))),
/// )?;
///
/// let app = Router::new()
///     .route(
///         "/ledgers/{id}",
///         get(get_ledger).layer(require_authz!(
///             "MyApp", "ViewLedger", "Ledger:{id}",
///             validator = authn.session_validator())),
///     )
///     // Layers added last run first: the installation sits outside the gates.
///     .layer(installation);
/// ```
///
/// # The context provider
///
/// A store whose policies or templates read the `context` variable
/// ([`PolicyStore::mentions_context`]) cannot be decided without the
/// context: on an empty one a rule that requires `context.mfa_verified`
/// denies every request, and a `forbid` written as
/// `context has mfa_verified && !context.mfa_verified` stops matching, so
/// the `permit` beside it allows. [`new`](Self::new) therefore refuses such
/// a store without a provider. A store that never reads `context` takes
/// `None` and its gates decide on an empty context.
///
/// # Policy reload
///
/// The store is held by `Arc`, so a reload through
/// [`AuthzStore::reload_policies`](super::session::AuthzStore::reload_policies)
/// on the same `Arc<PolicyStore>` reaches the gates. [`new`](Self::new)
/// judges the policies in force when it is called and cannot judge a later
/// reload: an installation built with `None` whose store is reloaded to a
/// set that reads `context` is refused by the gate, per request, with a 500
/// and an error log, until a set that does not read it is back in force. An
/// application that reloads policies passes a provider from the start.
///
/// Cloning is one reference count; every clone is the same installation.
#[derive(Clone)]
pub struct AuthzInstallation {
    parts: Arc<Parts>,
}

/// The three parts, behind one `Arc` so a request clones one pointer.
struct Parts {
    store: Arc<PolicyStore>,
    entities: Arc<dyn RequestEntityProvider>,
    context: Option<Arc<dyn RequestContextProvider>>,
}

impl AuthzInstallation {
    /// Put together what the gates decide with.
    ///
    /// - `store`: the compiled policies. Hand the same `Arc` to
    ///   [`AuthzStore::try_new`](super::session::AuthzStore::try_new) when
    ///   the application reloads policies, so a reload reaches the gates.
    /// - `entities`: builds the Cedar entities of each request. Wrap it in
    ///   the caching decorators of [`cache`](super::cache) where building
    ///   them is costly.
    /// - `context`: builds the Cedar context of each request. Required when
    ///   the store reads `context`; `None` for a store that never does.
    ///
    /// # Errors
    ///
    /// [`AuthzError::ContextProviderRequired`] when the store's policies
    /// read `context` and `context` is `None`.
    pub fn new(
        store: Arc<PolicyStore>,
        entities: Arc<dyn RequestEntityProvider>,
        context: Option<Arc<dyn RequestContextProvider>>,
    ) -> Result<Self, AuthzError> {
        // The one rule: a set that reads `context` is never decided on a
        // context nobody supplied. It holds for every store because it asks
        // the store itself, which answers from the parsed policies.
        if context.is_none() && store.mentions_context() {
            return Err(AuthzError::ContextProviderRequired);
        }
        Ok(Self {
            parts: Arc::new(Parts {
                store,
                entities,
                context,
            }),
        })
    }

    /// The policy store the gates decide with.
    pub fn store(&self) -> &Arc<PolicyStore> {
        &self.parts.store
    }

    /// The provider of each request's entities.
    pub fn entities(&self) -> &Arc<dyn RequestEntityProvider> {
        &self.parts.entities
    }

    /// The provider of each request's context, when one was given.
    pub fn context(&self) -> Option<&Arc<dyn RequestContextProvider>> {
        self.parts.context.as_ref()
    }
}

impl std::fmt::Debug for AuthzInstallation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthzInstallation")
            .field("policy_digest", &self.parts.store.digest())
            .field("context_provider", &self.parts.context.is_some())
            .finish()
    }
}

/// Adds the installation to the extensions of every request that passes, so
/// the gates inside find it. The same as an `Extension` layer holding it.
impl<S> tower::Layer<S> for AuthzInstallation {
    type Service = <axum::Extension<Self> as tower::Layer<S>>::Service;

    fn layer(&self, inner: S) -> Self::Service {
        tower::Layer::layer(&axum::Extension(self.clone()), inner)
    }
}

#[cfg(test)]
mod tests;
