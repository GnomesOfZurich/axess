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
//! `for_user_id` supplies no request context and is for policies that read
//! none. When the policies in force read `context` it answers
//! [`AuthzError::ContextRequired`]; the form below is the way through.
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
//!
//! # For any principal
//!
//! [`AuthzStore::for_principal`] begins a session for a [`Principal`], a
//! human or a workload, as the entity [`ToCedarEntity`] makes of it:
//! `axess::Human::"<user id>"` or `axess::Workload::"<SPIFFE URI>"`, with
//! its attributes, in its tenant. The session adds that entity to the ones
//! the provider supplies, so one policy that reads `principal.tenant_id`
//! decides for both kinds:
//!
//! ```rust,ignore
//! async fn read_report(
//!     State(state): State<AppState>,
//!     principal: AuthPrincipal,
//!     Path(report_id): Path<String>,
//! ) -> Result<impl IntoResponse, AppError> {
//!     let authz = state.authz.for_principal(&principal)?;
//!     authz.require("read", &report_id).await?;
//!     // ...handler body
//! }
//! ```
//!
//! The user-id constructors are the same path for a principal given as a
//! user id: the principal is `<namespace>::User::"<id>"`, and its entity is
//! the provider's to supply.

use arc_swap::ArcSwap;
use axess_identity::Principal;
use cedar_policy::{Context, Entities, Entity, EntityUid};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::{error, warn};

use super::{
    context::{BuildRequestContext, NoContext},
    error::{AuthzDenied, AuthzError},
    provider::AuthzEntityProvider,
    reload::ReloadState,
    store::{AuthzDecision, PolicyEvaluator, make_uid},
};
use crate::principal::cedar::ToCedarEntity;

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
    ///   policy files (e.g. `"MyApp"`). The principal and action UIDs this
    ///   store builds are in it; a provider builds its own with
    ///   [`make_entity_uid`](super::provider::make_entity_uid).
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

    /// Build a Cedar `Action` entity UID in this store's namespace.
    pub fn action_uid(&self, name: &str) -> Result<EntityUid, AuthzError> {
        make_uid(&self.namespace, "Action", name)
    }

    // ── Session builders ──────────────────────────────────────────────────────

    /// Begin a per-request authz session for the given user ID, without a
    /// request context.
    ///
    /// For a policy set that never reads `context`: access control that is
    /// role-based or relationship-based throughout. When the policies in
    /// force read `context` (a `context.mfa_verified` rule, an IP check, an
    /// assurance requirement) this answers
    /// [`AuthzError::ContextRequired`] and begins nothing: on an empty
    /// context a `forbid` that guards an optional attribute with
    /// `context has ..` stops applying and the `permit` beside it allows,
    /// so a session without a context is never decided against such a set.
    /// Use [`for_user_id_with_context`][Self::for_user_id_with_context] (or
    /// [`for_session`][Self::for_session]) there.
    ///
    /// The question is asked of the policies in force at this call, and
    /// asked again at every check the session makes: a session begun here
    /// and still held when a reload brings a read of `context` in is denied
    /// from then on.
    ///
    /// The session has no tenant; use
    /// [`for_user_in_tenant`][Self::for_user_in_tenant] or
    /// [`for_session`][Self::for_session] when the provider needs one.
    ///
    /// # Errors
    ///
    /// [`AuthzError::ContextRequired`] when the policies in force read
    /// `context`; [`AuthzError::InvalidEntityUid`] for a user id that is not
    /// one.
    pub fn for_user_id(
        self: &Arc<Self>,
        user_id: &str,
    ) -> Result<AuthzSession<P, NoContext>, AuthzError> {
        self.for_user_id_with_context(user_id, NoContext)
    }

    /// Begin a per-request authz session for a user acting in `tenant`,
    /// without a request context.
    ///
    /// The tenant reaches the provider through
    /// [`AuthzEntityProvider::entities_for_tenant`]. As with
    /// [`for_user_id`][Self::for_user_id], this is for a policy set that
    /// never reads `context`; when the policies in force read it, use
    /// [`for_user_in_tenant_with_context`][Self::for_user_in_tenant_with_context].
    ///
    /// # Errors
    ///
    /// As [`for_user_id`][Self::for_user_id].
    pub fn for_user_in_tenant(
        self: &Arc<Self>,
        user_id: &str,
        tenant: &str,
    ) -> Result<AuthzSession<P, NoContext>, AuthzError> {
        self.for_user_in_tenant_with_context(user_id, tenant, NoContext)
    }

    /// Begin a per-request authz session for a user acting in `tenant`, with
    /// the request context the policies read.
    ///
    /// The tenant reaches the provider through
    /// [`AuthzEntityProvider::entities_for_tenant`]; the context is built at
    /// once, as in [`for_user_id_with_context`][Self::for_user_id_with_context].
    ///
    /// # Errors
    ///
    /// As [`for_user_id_with_context`][Self::for_user_id_with_context].
    pub fn for_user_in_tenant_with_context<Ctx: BuildRequestContext>(
        self: &Arc<Self>,
        user_id: &str,
        tenant: &str,
        ctx: Ctx,
    ) -> Result<AuthzSession<P, Ctx>, AuthzError> {
        let mut session = self.for_user_id_with_context(user_id, ctx)?;
        session.tenant = Some(tenant.to_string());
        Ok(session)
    }

    /// Begin a per-request authz session for the authenticated user and
    /// tenant of `session`, with an ABAC context.
    ///
    /// Reads the user and tenant from one snapshot of the session, so they
    /// cannot come from different states. Returns
    /// [`AuthzError::NoPrincipal`] when the session is not authenticated,
    /// and otherwise what
    /// [`for_user_id_with_context`][Self::for_user_id_with_context] returns.
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

    /// Begin a per-request authz session with the request context the
    /// policies read: the way to a decision whenever a policy reads
    /// `context`.
    ///
    /// The context is built immediately and stored for the lifetime of the
    /// session; it is not rebuilt per check. Build it from the authenticated
    /// session and from what the application's own layers established about
    /// the request, never from a value the caller writes.
    ///
    /// A `ctx` that supplies nothing ([`NoContext`]) makes this the same
    /// call as [`for_user_id`][Self::for_user_id], with the same refusal.
    ///
    /// # Errors
    ///
    /// [`AuthzError::ContextRequired`] when `ctx` supplies no context and
    /// the policies in force read `context`; [`AuthzError::Context`] when
    /// the context cannot be built; [`AuthzError::InvalidEntityUid`] for a
    /// user id that is not one.
    pub fn for_user_id_with_context<Ctx: BuildRequestContext>(
        self: &Arc<Self>,
        user_id: &str,
        ctx: Ctx,
    ) -> Result<AuthzSession<P, Ctx>, AuthzError> {
        self.begin(|| Ok((self.user_uid(user_id)?, None)), None, ctx)
    }

    /// Begin a per-request authz session for `principal`, a human or a
    /// workload, without a request context.
    ///
    /// The principal is the entity [`ToCedarEntity`] makes of it
    /// (`axess::Human::"<user id>"` or `axess::Workload::"<SPIFFE URI>"`,
    /// with its attributes), and the session is in the principal's tenant,
    /// which reaches the provider through
    /// [`AuthzEntityProvider::entities_for_tenant`]. As with
    /// [`for_user_id`][Self::for_user_id], this is for a policy set that
    /// never reads `context`; when the policies in force read it, use
    /// [`for_principal_with_context`][Self::for_principal_with_context].
    ///
    /// # Errors
    ///
    /// As [`for_principal_with_context`][Self::for_principal_with_context].
    pub fn for_principal(
        self: &Arc<Self>,
        principal: &Principal,
    ) -> Result<AuthzSession<P, NoContext>, AuthzError> {
        self.for_principal_with_context(principal, NoContext)
    }

    /// Begin a per-request authz session for `principal`, a human or a
    /// workload, with the request context the policies read.
    ///
    /// The session adds the principal's entity to the entities the provider
    /// supplies for each check, so the provider need not build it and one
    /// policy decides for both kinds. The principal's entity is the
    /// library's, with no parents: a provider that supplies an entity of
    /// the same UID must supply the same entity, and one that differs (other
    /// attributes, or parents) denies the check, as a decision cannot hold
    /// two entities of one UID. Groups come from the provider as entities
    /// of their own, with their parent links between them and their members
    /// named on them, so a policy reads `principal in Group::"g".members`
    /// (the principal chapter's "Groups and other parents"). The schema, when the store has one, declares
    /// `axess::Human` and `axess::Workload` with the attributes the
    /// principal module documents, or the request is refused at evaluation.
    ///
    /// # Errors
    ///
    /// [`AuthzError::ContextRequired`] when `ctx` supplies no context and
    /// the policies in force read `context`; [`AuthzError::Context`] when
    /// the context cannot be built; [`AuthzError::InvalidEntityUid`] or
    /// [`AuthzError::EntityBuild`] when the principal's entity cannot be
    /// built.
    pub fn for_principal_with_context<Ctx: BuildRequestContext>(
        self: &Arc<Self>,
        principal: &Principal,
        ctx: Ctx,
    ) -> Result<AuthzSession<P, Ctx>, AuthzError> {
        self.begin(
            || {
                let entity = principal.to_cedar_entity()?;
                Ok((entity.uid(), Some(entity)))
            },
            Some(principal.tenant_id().to_string()),
            ctx,
        )
    }

    /// The one way a session begins: the context rule first, then the
    /// principal's UID (and, for a [`Principal`], its entity), then the
    /// context.
    fn begin<Ctx: BuildRequestContext>(
        self: &Arc<Self>,
        principal: impl FnOnce() -> Result<(EntityUid, Option<Entity>), AuthzError>,
        tenant: Option<String>,
        ctx: Ctx,
    ) -> Result<AuthzSession<P, Ctx>, AuthzError> {
        let context_supplied = ctx.supplies_context();
        // The one rule of this module: a policy set that reads `context` is
        // never decided for a session nobody gave a context. It is asked of
        // the evaluator itself, so it holds for every policy set, and it is
        // asked again at each decision (`AuthzSession::evaluate`), because a
        // reload can change the answer under a session already begun.
        if !context_supplied && self.evaluator.load().mentions_context() {
            return Err(AuthzError::ContextRequired);
        }
        let (principal, principal_entity) = principal()?;
        let context = ctx.to_cedar_context()?;
        Ok(AuthzSession {
            store: Arc::clone(self),
            principal,
            principal_entity,
            tenant,
            context,
            context_supplied,
            cache: Mutex::new(HashMap::new()),
            ctx: std::marker::PhantomData,
        })
    }
}

// ── AuthzSession ──────────────────────────────────────────────────────────────

/// Per-request authorization session.
///
/// Created by [`AuthzStore::for_principal`], [`AuthzStore::for_user_id`],
/// their `_with_context` forms and their siblings.
/// `Send`: safe to hold across `.await` in Axum handlers.
pub struct AuthzSession<P: AuthzEntityProvider, Ctx = NoContext> {
    store: Arc<AuthzStore<P>>,
    principal: EntityUid,
    /// The principal's entity, for a session begun for a [`Principal`]:
    /// added to the provider's entities at each check.
    principal_entity: Option<Entity>,
    tenant: Option<String>,
    context: Context,
    /// Whether the session was begun with a request context. A session
    /// without one is denied by any policy set that reads `context`.
    context_supplied: bool,
    // Per-request entity cache: (action_uid_str, resource_uid_str) → entities.
    // Deduplicates repeated identical checks within one request.
    // Uses Mutex (not RefCell) so the session is Send for Axum handlers.
    // The lock is never held across .await points.
    cache: Mutex<HashMap<(String, String), Arc<Entities>>>,
    ctx: std::marker::PhantomData<Ctx>,
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
                        let ent = match self.with_principal_entity(ent) {
                            Ok(ent) => ent,
                            Err(reason) => {
                                warn!(
                                    "authz: the provider's entities do not admit the principal's \
                                     own entity ({reason}); denied"
                                );
                                super::audit::emit_early_deny(
                                    &self.principal.to_string(),
                                    &action_uid.to_string(),
                                    &resource_uid.to_string(),
                                    reason,
                                );
                                return Evaluated::Refused;
                            }
                        };
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
        let evaluator = self.store.evaluator.load();
        // A session begun without a context is refused where it is begun
        // when the policies read `context`. A reload can bring that read in
        // while the session is held, so the set that is about to decide is
        // asked once more, and a session without a context is denied by it.
        if !self.context_supplied && evaluator.mentions_context() {
            // Who and what is in the decision event below; the error line
            // says what the operator has to change.
            error!(
                "authz: the policies in force read `context` and this session was begun \
                 without one (a policy reload brought the read in); denied"
            );
            super::audit::emit_early_deny(
                &self.principal.to_string(),
                &action_uid.to_string(),
                &resource_uid.to_string(),
                "context_required",
            );
            return Evaluated::Refused;
        }
        let decision = evaluator.is_authorized(
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

impl<P: AuthzEntityProvider, Ctx> AuthzSession<P, Ctx> {
    /// `entities` with the principal's own entity in it, for a session
    /// begun for a [`Principal`]; the provider's set as it is otherwise. A
    /// provider entity of the principal's UID that is not the same entity is
    /// refused, with the reason the decision log records.
    fn with_principal_entity(&self, entities: Entities) -> Result<Entities, &'static str> {
        let Some(entity) = &self.principal_entity else {
            return Ok(entities);
        };
        match entities.get(&entity.uid()) {
            Some(supplied) if supplied.deep_eq(entity) => Ok(entities),
            Some(_) => Err("principal_entity_conflict"),
            None => entities
                .add_entities([entity.clone()], None)
                .map_err(|_| "principal_entity_merge_failed"),
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

#[cfg(test)]
mod principal_tests;

#[cfg(test)]
mod principal_group_tests;
