//! [`AuthzStore`] and [`AuthzSession`]: the runtime authorization layer.
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
//! use axess_core::client_ip::ClientIp;   // handler argument,
//!                                         // filled by `client_ip::layer`
//!
//! // `mfa_complete` is the application's own fact, derived from what it
//! // recorded when the user finished the factors its policy demands (the
//! // session carries the authentication state, not an MFA flag).
//! let ctx = StandardRequestContext::new(
//!     mfa_complete,
//!     client_ip.get(),
//! );
//! let authz = state.authz.for_user_id_with_context(&user_id, ctx)?;
//! authz.require("PostJournalEntry", &ledger_id).await?;
//! ```

use arc_swap::ArcSwap;
use cedar_policy::{Context, Entities, EntityUid};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::warn;

use super::{
    context::{BuildRequestContext, NoContext},
    error::{AuthzDenied, AuthzError},
    provider::AuthzEntityProvider,
    reload::ReloadState,
    store::{AuthzDecision, PolicyEvaluator, make_uid},
};

// ── AuthzStore ────────────────────────────────────────────────────────────────

/// Application-scoped authorization configuration.
///
/// Holds the policy evaluator, entity provider, and Cedar namespace. Construct
/// once at startup and store in `Arc<AuthzStore<P>>` inside your Axum state.
///
/// Wiring an `AuthzStore` requires both a [`PolicyEvaluator`] (production:
/// `PolicyStore::from_text(...)`) and an adopter-supplied
/// [`AuthzEntityProvider`] impl; the moving parts are non-trivial to set up
/// inside a single doc-test, so a runnable end-to-end example lives in
/// `examples/authz/` and the module-level rustdoc above shows the
/// handler-side usage.
///
/// The policy evaluator sits in a swap slot: [`reload_policies`] replaces it
/// while requests are being decided, and a decision uses the one set it read
/// (see [`reload`](super::reload)).
///
/// [`reload_policies`]: Self::reload_policies
pub struct AuthzStore<P: AuthzEntityProvider> {
    pub(super) evaluator: ArcSwap<Arc<dyn PolicyEvaluator>>,
    pub(super) reload: ReloadState,
    pub(super) provider: Arc<P>,
    pub(super) namespace: Arc<str>,
}

impl<P: AuthzEntityProvider> AuthzStore<P> {
    /// Create an `AuthzStore` and validate the entity provider against the
    /// evaluator's Cedar schema, so a mismatch between the two (a misspelled
    /// `Role` type, say) is a startup error instead of denials, or a
    /// bypassed `forbid`, found in production.
    ///
    /// - `evaluator`: production: `Arc::new(PolicyStore::from_text(...)?)`.
    ///   Tests: `Arc::new(MockPolicyEvaluator::new())`, which has no schema
    ///   and so validates nothing.
    /// - `provider`: your [`AuthzEntityProvider`] implementation.
    /// - `namespace`: the Cedar entity namespace used in your schema and
    ///   policy files (e.g. `"MyApp"`). All UID builders on this store use it.
    ///
    /// # Errors
    ///
    /// Whatever [`AuthzEntityProvider::validate_schema`] returns for the
    /// evaluator's schema.
    pub fn try_new(
        evaluator: Arc<dyn PolicyEvaluator>,
        provider: Arc<P>,
        namespace: impl Into<Arc<str>>,
    ) -> Result<Self, AuthzError> {
        let store = Self::new_unvalidated(evaluator, provider, namespace);
        store.validate()?;
        Ok(store)
    }

    /// Create an `AuthzStore` without checking the provider against the
    /// schema.
    ///
    /// **Prefer [`try_new`](Self::try_new).** A provider whose entity types do
    /// not match the schema denies silently, or lets a `forbid` that names a
    /// type the provider never produces match nothing; nothing reports it
    /// until a request is wrong. Use this only where the provider is
    /// deliberately not valid against the schema, such as a test of the
    /// failure itself.
    pub fn new_unvalidated(
        evaluator: Arc<dyn PolicyEvaluator>,
        provider: Arc<P>,
        namespace: impl Into<Arc<str>>,
    ) -> Self {
        Self {
            evaluator: ArcSwap::from_pointee(evaluator),
            reload: ReloadState::default(),
            provider,
            namespace: namespace.into(),
        }
    }

    /// Validate the entity provider against the Cedar schema.
    ///
    /// [`try_new`](Self::try_new) runs this, and
    /// [`reload_policies`](Self::reload_policies) runs the same check against
    /// the new schema before it swaps, so a provider that does not fit a
    /// reloaded schema refuses the reload.
    pub fn validate(&self) -> Result<(), AuthzError> {
        if let Some(schema) = self.evaluator.load().schema() {
            self.provider.validate_schema(&schema)?;
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
    /// The session uses an **empty** Cedar `Context`, and says so only here:
    /// a policy that reads `context.mfa_verified` (or any other context
    /// attribute) is evaluated with nothing to read. With a schema that
    /// declares the attribute required, `PolicyStore` denies every request
    /// (the request is invalid); a policy that guards the attribute with
    /// `context has ..` and treats absence as allowed would permit. Use this
    /// builder only when all access control is role-based or
    /// relationship-based.
    ///
    /// For ABAC policies (IP checks, MFA requirements, etc.) use
    /// [`for_user_id_with_context`][Self::for_user_id_with_context].
    ///
    /// The session has no tenant; use
    /// [`for_user_in_tenant`][Self::for_user_in_tenant] or
    /// [`for_session`][Self::for_session] when the provider needs one.
    pub fn for_user_id(
        self: &Arc<Self>,
        user_id: &str,
    ) -> Result<AuthzSession<P, NoContext>, AuthzError> {
        let principal = self.user_uid(user_id)?;
        Ok(AuthzSession {
            store: Arc::clone(self),
            principal,
            tenant: None,
            context: Context::empty(),
            cache: Mutex::new(HashMap::new()),
            _ctx: std::marker::PhantomData,
        })
    }

    /// Begin a per-request authz session for a user acting in `tenant`.
    ///
    /// The tenant reaches the provider through
    /// [`AuthzEntityProvider::entities_for_tenant`]. As with
    /// [`for_user_id`][Self::for_user_id] the Cedar `Context` is empty.
    pub fn for_user_in_tenant(
        self: &Arc<Self>,
        user_id: &str,
        tenant: &str,
    ) -> Result<AuthzSession<P, NoContext>, AuthzError> {
        let mut session = self.for_user_id(user_id)?;
        session.tenant = Some(tenant.to_string());
        Ok(session)
    }

    /// Begin a per-request authz session for the authenticated user and
    /// tenant of `session`, with an ABAC context.
    ///
    /// Reads the user and tenant from one snapshot of the session, so they
    /// cannot come from different states. Returns
    /// [`AuthzError::InvalidEntityUid`] when the session is not
    /// authenticated.
    pub async fn for_session<Ctx: BuildRequestContext>(
        self: &Arc<Self>,
        session: &crate::session::AuthSession,
        ctx: Ctx,
    ) -> Result<AuthzSession<P, Ctx>, AuthzError> {
        let snapshot = session.snapshot().await.ok_or(AuthzError::NoPrincipal)?;
        let mut authz = self.for_user_id_with_context(&snapshot.user_id.to_string(), ctx)?;
        authz.tenant = Some(snapshot.tenant_id.to_string());
        Ok(authz)
    }

    /// Begin a per-request authz session with an ABAC context.
    ///
    /// The context is built immediately and stored for the lifetime of the
    /// session; it is not rebuilt per check.
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
            tenant: None,
            context,
            cache: Mutex::new(HashMap::new()),
            _ctx: std::marker::PhantomData,
        })
    }
}

// ── AuthzSession ──────────────────────────────────────────────────────────────

/// Per-request authorization session.
///
/// Created by [`AuthzStore::for_user_id`] or [`AuthzStore::for_user_id_with_context`].
/// `Send`: safe to hold across `.await` in Axum handlers.
pub struct AuthzSession<P: AuthzEntityProvider, Ctx = NoContext> {
    store: Arc<AuthzStore<P>>,
    principal: EntityUid,
    tenant: Option<String>,
    context: Context,
    // Per-request entity cache: (action_uid_str, resource_uid_str) → entities.
    // Deduplicates repeated identical checks within one request.
    // Uses Mutex (not RefCell) so the session is Send for Axum handlers.
    // The lock is never held across .await points.
    cache: Mutex<HashMap<(String, String), Arc<Entities>>>,
    _ctx: std::marker::PhantomData<Ctx>,
}

impl<P: AuthzEntityProvider, Ctx> AuthzSession<P, Ctx> {
    /// Check access and return an error on denial.
    ///
    /// Returns `Ok(())` if Cedar permits, `Err(AuthzDenied)` otherwise.
    /// `Err(AuthzDenied)` implements [`IntoResponse`][axum::response::IntoResponse]
    /// and converts to a 403 JSON response; handlers can propagate it directly
    /// with `?`.
    ///
    /// Fail-closed: any error in entity building or evaluation returns `Deny`.
    #[tracing::instrument(skip(self, resource))]
    pub async fn require(&self, action: &str, resource: &P::ResourceId) -> Result<(), AuthzDenied> {
        match self.check(action, resource).await {
            AuthzDecision::Allow => Ok(()),
            AuthzDecision::Deny => Err(AuthzDenied),
        }
    }

    /// Check access, and on a denial say whether a step-up would cure it.
    ///
    /// `Err(AuthzRefusal::StepUpRequired(step_up))` when the policies would
    /// permit after the step-up their `@step_up` annotations name (see
    /// [`PolicyEvaluator::step_up_for`]),
    /// `Err(AuthzRefusal::Denied)` for every other denial. Both convert to a
    /// 403; the step-up's body names it and nothing of the policy. Needs a
    /// context that carries `assurance`
    /// ([`StandardRequestContext::with_assurance`](super::context::StandardRequestContext::with_assurance)).
    #[tracing::instrument(skip(self, resource))]
    pub async fn require_with_step_up(
        &self,
        action: &str,
        resource: &P::ResourceId,
    ) -> Result<(), super::assurance::AuthzRefusal> {
        match self.evaluate(action, resource).await {
            Evaluated::Decided {
                decision: AuthzDecision::Allow,
                ..
            } => Ok(()),
            Evaluated::Decided {
                decision: AuthzDecision::Deny,
                question,
            } => {
                let evaluator = self.store.evaluator.load();
                match evaluator.step_up_for(
                    &question.entities,
                    self.principal.clone(),
                    question.action,
                    question.resource,
                    self.context.clone(),
                ) {
                    Some(step_up) => Err(super::assurance::AuthzRefusal::StepUpRequired(step_up)),
                    None => Err(super::assurance::AuthzRefusal::Denied),
                }
            }
            Evaluated::Refused => Err(super::assurance::AuthzRefusal::Denied),
        }
    }

    /// Check access and return a boolean.
    ///
    /// Returns `true` if Cedar permits, `false` on denial or any error.
    /// Use this for UI capability hints (which buttons to show) where a hard
    /// 403 is not wanted.
    #[tracing::instrument(skip(self, resource))]
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
    #[tracing::instrument(skip(self, checks))]
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
        match self.evaluate(action, resource).await {
            Evaluated::Decided { decision, .. } => decision,
            Evaluated::Refused => AuthzDecision::Deny,
        }
    }

    async fn evaluate(&self, action: &str, resource: &P::ResourceId) -> Evaluated {
        // 1. Build action UID.
        let action_uid = match self.store.action_uid(action) {
            Ok(uid) => uid,
            Err(e) => {
                warn!("authz: invalid action UID '{}': {e}", action);
                super::audit::emit_early_deny(
                    &self.principal.to_string(),
                    action,
                    "",
                    "invalid_action",
                );
                return Evaluated::Refused;
            }
        };

        // 2. Build resource UID.
        let resource_uid = match self.store.provider.resource_uid(resource) {
            Ok(uid) => uid,
            Err(e) => {
                warn!("authz: invalid resource UID: {e}");
                super::audit::emit_early_deny(
                    &self.principal.to_string(),
                    &action_uid.to_string(),
                    "",
                    "invalid_resource",
                );
                return Evaluated::Refused;
            }
        };

        // 3. Check per-request entity cache.
        let cache_key = (action_uid.to_string(), resource_uid.to_string());
        let entities = {
            let cached = self
                .cache
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&cache_key)
                .cloned();
            if let Some(arc) = cached {
                arc
            } else {
                // 4. Build entities via the provider.
                match self
                    .store
                    .provider
                    .entities_for_tenant(
                        &self.principal,
                        self.tenant.as_deref(),
                        resource,
                        &action_uid,
                    )
                    .await
                {
                    Ok(ent) => {
                        let arc = Arc::new(ent);
                        self.cache
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .insert(cache_key, Arc::clone(&arc));
                        arc
                    }
                    Err(e) => {
                        warn!("authz: entity provider error: {e}");
                        super::audit::emit_early_deny(
                            &self.principal.to_string(),
                            &action_uid.to_string(),
                            &resource_uid.to_string(),
                            "entity_provider_error",
                        );
                        return Evaluated::Refused;
                    }
                }
            }
        };

        // 5. Evaluate Cedar policy against one snapshot of the swap slot: a
        // wait-free read, dropped with the decision, so a reload that lands
        // now applies to the next request and never splits this one.
        let decision = self.store.evaluator.load().is_authorized(
            &entities,
            self.principal.clone(),
            action_uid.clone(),
            resource_uid.clone(),
            self.context.clone(),
        );
        Evaluated::Decided {
            decision,
            question: Box::new(Question {
                entities,
                action: action_uid,
                resource: resource_uid,
            }),
        }
    }
}

/// One check's outcome: decided by the policies (with what they were asked,
/// for a step-up question), or refused before they ran.
enum Evaluated {
    Decided {
        decision: AuthzDecision,
        question: Box<Question>,
    },
    Refused,
}

/// What the policies were asked.
struct Question {
    entities: Arc<Entities>,
    action: EntityUid,
    resource: EntityUid,
}

#[cfg(test)]
mod authz_session_tests;
