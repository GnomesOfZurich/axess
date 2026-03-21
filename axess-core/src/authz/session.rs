//! [`AuthzStore`] and [`AuthzSession`] — the runtime authorization layer.
//!
//! # Overview
//!
//! [`AuthzStore`] is the Arc-able, application-scoped component held in Axum
//! state. It owns the policy evaluator, the entity provider, and the namespace.
//! It builds [`AuthzSession`] values per request.
//!
//! [`AuthzSession`] is the per-request handle. Calling `.require()` on it
//! builds the Cedar entity set (using the provider), evaluates the policy,
//! and returns `Ok(())` or `Err(`[`AuthzDenied`]`)`.
//!
//! # Typical handler usage
//!
//! ```rust,ignore
//! async fn view_ledger(
//!     State(state): State<AppState>,
//!     session: AuthSession<OurBackend, OurRegistry, SystemRng>,
//!     Path(ledger_id): Path<Uuid>,
//! ) -> Result<impl IntoResponse, AppError> {
//!     let user_id = session.get_user_id().ok_or(AuthzDenied)?;
//!
//!     let authz = state.authz.for_user_id(&user_id.to_string())?;
//!     authz.require("ViewLedger", &ledger_id).await?;
//!
//!     // ...handler body
//! }
//! ```
//!
//! # With ABAC context
//!
//! ```rust,ignore
//! use axess_core::authz::context::StandardRequestContext;
//!
//! let ctx = StandardRequestContext {
//!     mfa_verified: session.is_mfa_complete(),
//!     ip_address: ip_from_headers(request.headers()),
//! };
//! let authz = state.authz.for_user_id_with_context(&user_id, ctx)?;
//! authz.require("PostJournalEntry", &ledger_id).await?;
//! ```

use cedar_policy::{Context, Entities, EntityUid};
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::warn;

use super::{
    context::{BuildRequestContext, NoContext},
    error::{AuthzDenied, AuthzError},
    provider::AuthzEntityProvider,
    store::{AuthzDecision, PolicyEvaluator, make_uid},
};

// ── AuthzStore ────────────────────────────────────────────────────────────────

/// Application-scoped authorization configuration.
///
/// Holds the policy evaluator, entity provider, and Cedar namespace. Construct
/// once at startup and store in `Arc<AuthzStore<P>>` inside your Axum state.
///
/// ```rust,ignore
/// let authz_store = Arc::new(
///     AuthzStore::new(Arc::new(policy_store), Arc::new(my_entity_provider), "MyApp")
/// );
/// ```
pub struct AuthzStore<P: AuthzEntityProvider> {
    pub(super) evaluator: Arc<dyn PolicyEvaluator>,
    pub(super) provider: Arc<P>,
    pub(super) namespace: Arc<str>,
}

impl<P: AuthzEntityProvider> AuthzStore<P> {
    /// Create a new `AuthzStore`.
    ///
    /// - `evaluator` — production: `Arc::new(PolicyStore::from_text(...)?)`.
    ///   Tests: `Arc::new(MockPolicyEvaluator::new())`.
    /// - `provider` — your [`AuthzEntityProvider`] implementation.
    /// - `namespace` — the Cedar entity namespace used in your schema and
    ///   policy files (e.g. `"MyApp"`). All UID builders on this store use it.
    pub fn new(
        evaluator: Arc<dyn PolicyEvaluator>,
        provider: Arc<P>,
        namespace: impl Into<Arc<str>>,
    ) -> Self {
        Self {
            evaluator,
            provider,
            namespace: namespace.into(),
        }
    }

    /// Optional startup check: validate the entity provider against the Cedar schema.
    ///
    /// Call this after constructing the store to catch type mismatches between
    /// your provider and the compiled policy schema before accepting traffic.
    pub fn validate(&self) -> Result<(), AuthzError> {
        if let Some(schema) = self.evaluator.schema() {
            self.provider.validate_against_schema(schema)?;
        }
        Ok(())
    }

    // ── UID builders ──────────────────────────────────────────────────────────

    /// Build a Cedar `User` entity UID in this store's namespace.
    pub fn user_uid(&self, id: &str) -> Result<EntityUid, AuthzError> {
        make_uid(&self.namespace, "User", id)
    }

    /// Build a Cedar `Role` entity UID in this store's namespace.
    pub fn role_uid(&self, name: &str) -> Result<EntityUid, AuthzError> {
        make_uid(&self.namespace, "Role", name)
    }

    /// Build a Cedar `Action` entity UID in this store's namespace.
    pub fn action_uid(&self, name: &str) -> Result<EntityUid, AuthzError> {
        make_uid(&self.namespace, "Action", name)
    }

    /// Build a Cedar `Tenant` entity UID in this store's namespace.
    pub fn tenant_uid(&self, id: &str) -> Result<EntityUid, AuthzError> {
        make_uid(&self.namespace, "Tenant", id)
    }

    /// Build a Cedar `Platform` entity UID in this store's namespace.
    pub fn platform_uid(&self, id: &str) -> Result<EntityUid, AuthzError> {
        make_uid(&self.namespace, "Platform", id)
    }

    /// Build a Cedar entity UID for an arbitrary type in this store's namespace.
    ///
    /// Use this for application-specific entity types not covered by the
    /// named builder methods above.
    pub fn entity_uid(&self, type_name: &str, id: &str) -> Result<EntityUid, AuthzError> {
        make_uid(&self.namespace, type_name, id)
    }

    // ── Session builders ──────────────────────────────────────────────────────

    /// Begin a per-request authz session for the given user ID.
    ///
    /// The session uses an empty Cedar `Context` — suitable when all access
    /// control is role-based or relationship-based only.
    ///
    /// For ABAC policies (IP checks, MFA requirements, etc.) use
    /// [`for_user_id_with_context`][Self::for_user_id_with_context].
    pub fn for_user_id(
        self: &Arc<Self>,
        user_id: &str,
    ) -> Result<AuthzSession<P, NoContext>, AuthzError> {
        let principal = self.user_uid(user_id)?;
        Ok(AuthzSession {
            store: Arc::clone(self),
            principal,
            context: Context::empty(),
            cache: RefCell::new(HashMap::new()),
            _ctx: std::marker::PhantomData,
        })
    }

    /// Begin a per-request authz session with an ABAC context.
    ///
    /// The context is built immediately and stored for the lifetime of the
    /// session — it is not rebuilt per check.
    pub fn for_user_id_with_context<Ctx: BuildRequestContext>(
        self: &Arc<Self>,
        user_id: &str,
        ctx: Ctx,
    ) -> Result<AuthzSession<P, Ctx>, AuthzError> {
        let principal = self.user_uid(user_id)?;
        let context = ctx.to_cedar_context()?;
        Ok(AuthzSession {
            store: Arc::clone(self),
            principal,
            context,
            cache: RefCell::new(HashMap::new()),
            _ctx: std::marker::PhantomData,
        })
    }
}

// ── AuthzSession ──────────────────────────────────────────────────────────────

/// Per-request authorization session.
///
/// Created by [`AuthzStore::for_user_id`] or [`AuthzStore::for_user_id_with_context`].
/// Not `Sync` (holds a `RefCell` for the entity cache); intended to be used
/// within a single request task.
pub struct AuthzSession<P: AuthzEntityProvider, Ctx = NoContext> {
    store: Arc<AuthzStore<P>>,
    principal: EntityUid,
    context: Context,
    // Per-request entity cache: (action_uid_str, resource_uid_str) → entities.
    // Deduplicates repeated identical checks within one request.
    cache: RefCell<HashMap<(String, String), Arc<Entities>>>,
    _ctx: std::marker::PhantomData<Ctx>,
}

impl<P: AuthzEntityProvider, Ctx> AuthzSession<P, Ctx> {
    /// Check access and return an error on denial.
    ///
    /// Returns `Ok(())` if Cedar permits, `Err(AuthzDenied)` otherwise.
    /// `Err(AuthzDenied)` implements [`IntoResponse`][axum::response::IntoResponse]
    /// and converts to a 403 JSON response — handlers can propagate it directly
    /// with `?`.
    ///
    /// Fail-closed: any error in entity building or evaluation returns `Deny`.
    pub async fn require(
        &self,
        action: &str,
        resource: &P::ResourceId,
    ) -> Result<(), AuthzDenied> {
        match self.check(action, resource).await {
            AuthzDecision::Allow => Ok(()),
            AuthzDecision::Deny => Err(AuthzDenied),
        }
    }

    /// Check access and return a boolean.
    ///
    /// Returns `true` if Cedar permits, `false` on denial or any error.
    /// Use this for UI capability hints (which buttons to show) where a hard
    /// 403 is not wanted.
    pub async fn is_permitted(&self, action: &str, resource: &P::ResourceId) -> bool {
        matches!(self.check(action, resource).await, AuthzDecision::Allow)
    }

    /// Check multiple (action, resource) pairs in sequence.
    ///
    /// Returns a vec of `(action_name, decision)` in the same order as `checks`.
    /// Entity results are cached across the batch, so repeated resource loads
    /// within the batch are deduplicated.
    ///
    /// Useful for computing per-resource capability sets (which toolbar buttons
    /// are enabled) without N separate handler round-trips.
    pub async fn batch_check(
        &self,
        checks: &[(&str, &P::ResourceId)],
    ) -> Vec<(String, AuthzDecision)> {
        let mut results = Vec::with_capacity(checks.len());
        for (action, resource) in checks {
            let decision = self.check(action, resource).await;
            results.push(((*action).to_string(), decision));
        }
        results
    }

    /// Return the principal [`EntityUid`] for this session.
    pub fn principal(&self) -> &EntityUid {
        &self.principal
    }

    // ── Internal evaluation ───────────────────────────────────────────────────

    async fn check(&self, action: &str, resource: &P::ResourceId) -> AuthzDecision {
        // 1. Build action UID.
        let action_uid = match self.store.action_uid(action) {
            Ok(uid) => uid,
            Err(e) => {
                warn!("authz: invalid action UID '{}': {e}", action);
                return AuthzDecision::Deny;
            }
        };

        // 2. Build resource UID.
        let resource_uid = match self.store.provider.resource_uid(resource) {
            Ok(uid) => uid,
            Err(e) => {
                warn!("authz: invalid resource UID: {e}");
                return AuthzDecision::Deny;
            }
        };

        // 3. Check per-request entity cache.
        let cache_key = (action_uid.to_string(), resource_uid.to_string());
        let entities = {
            let cached = self.cache.borrow().get(&cache_key).cloned();
            if let Some(arc) = cached {
                arc
            } else {
                // 4. Build entities via the provider.
                match self
                    .store
                    .provider
                    .entities_for(&self.principal, resource, &action_uid)
                    .await
                {
                    Ok(ent) => {
                        let arc = Arc::new(ent);
                        self.cache.borrow_mut().insert(cache_key, Arc::clone(&arc));
                        arc
                    }
                    Err(e) => {
                        warn!("authz: entity provider error: {e}");
                        return AuthzDecision::Deny;
                    }
                }
            }
        };

        // 5. Evaluate Cedar policy.
        self.store.evaluator.is_authorized(
            &entities,
            self.principal.clone(),
            action_uid,
            resource_uid,
            self.context.clone(),
        )
    }
}
