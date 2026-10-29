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

use cedar_policy::{Context, Entities, EntityUid};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
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
/// Wiring an `AuthzStore` requires both a [`PolicyEvaluator`] (production:
/// `PolicyStore::from_text(...)`) and an adopter-supplied
/// [`AuthzEntityProvider`] impl; the moving parts are non-trivial to set up
/// inside a single doc-test, so a runnable end-to-end example lives in
/// `examples/authz/` and the module-level rustdoc above shows the
/// handler-side usage.
pub struct AuthzStore<P: AuthzEntityProvider> {
    pub(super) evaluator: Arc<dyn PolicyEvaluator>,
    pub(super) provider: Arc<P>,
    pub(super) namespace: Arc<str>,
}

impl<P: AuthzEntityProvider> AuthzStore<P> {
    /// Create a new `AuthzStore`.
    ///
    /// - `evaluator`: production: `Arc::new(PolicyStore::from_text(...)?)`.
    ///   Tests: `Arc::new(MockPolicyEvaluator::new())`.
    /// - `provider`: your [`AuthzEntityProvider`] implementation.
    /// - `namespace`: the Cedar entity namespace used in your schema and
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
            self.provider.validate_schema(schema)?;
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
        let snapshot = session.snapshot().await.ok_or_else(|| {
            AuthzError::InvalidEntityUid("the session is not authenticated".to_string())
        })?;
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
                return AuthzDecision::Deny;
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
                return AuthzDecision::Deny;
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

#[cfg(test)]
mod authz_session_tests {
    use super::*;
    use crate::authz::store::PolicyStore;
    use cedar_policy::{Entities, EntityUid, Schema};

    const SCHEMA_JSON: &str = r#"{
        "TestApp": {
            "entityTypes": {
                "User": { "memberOfTypes": [] },
                "Resource": { "memberOfTypes": [] }
            },
            "actions": {
                "View": {
                    "appliesTo": {
                        "principalTypes": ["User"],
                        "resourceTypes": ["Resource"]
                    }
                }
            }
        }
    }"#;

    const POLICY_TEXT: &str = r#"permit(
        principal == TestApp::User::"alice",
        action == TestApp::Action::"View",
        resource == TestApp::Resource::"doc1"
    );"#;

    struct ErroringProvider;

    impl AuthzEntityProvider for ErroringProvider {
        type ResourceId = String;
        type Error = std::convert::Infallible;

        async fn entities_for(
            &self,
            principal: &EntityUid,
            resource_id: &Self::ResourceId,
            action: &EntityUid,
        ) -> Result<Entities, Self::Error> {
            tracing::trace!(
                target: "axess::authz::test_stub",
                ?principal,
                ?resource_id,
                ?action,
                "ErroringProvider::entities_for: returning empty entities",
            );
            Ok(Entities::empty())
        }

        fn resource_uid(&self, id: &Self::ResourceId) -> Result<EntityUid, AuthzError> {
            super::super::store::make_uid("TestApp", "Resource", id)
        }

        fn validate_schema(&self, schema: &Schema) -> Result<(), AuthzError> {
            tracing::trace!(
                target: "axess::authz::test_stub",
                ?schema,
                "ErroringProvider::validate_schema: synthetic failure",
            );
            Err(AuthzError::SchemaParse(
                "synthetic schema validation failure".to_string(),
            ))
        }
    }

    #[test]
    fn validate_propagates_provider_validation_error() {
        // Pins `AuthzStore::validate -> Ok(())` mutation. The
        // mutation skips the inner `provider.validate_schema`
        // call. With a provider that errors, the genuine path returns
        // `Err`; the mutation would silently return `Ok(())` and
        // mask startup-time schema mismatches.
        let evaluator: Arc<dyn PolicyEvaluator> =
            Arc::new(PolicyStore::from_text(POLICY_TEXT, SCHEMA_JSON).unwrap());
        let store = AuthzStore::new(evaluator, Arc::new(ErroringProvider), "TestApp");
        let result = store.validate();
        assert!(
            matches!(result, Err(AuthzError::SchemaParse(_))),
            "validate() must propagate provider's validate_schema error, got {result:?}"
        );
    }

    /// Records the tenant it was asked for; refuses the resource id `bad`.
    struct TenantRecordingProvider {
        seen: Mutex<Vec<Option<String>>>,
    }

    impl AuthzEntityProvider for TenantRecordingProvider {
        type ResourceId = String;
        type Error = std::convert::Infallible;

        async fn entities_for(
            &self,
            principal: &EntityUid,
            resource_id: &Self::ResourceId,
            action: &EntityUid,
        ) -> Result<Entities, Self::Error> {
            tracing::trace!(?principal, ?resource_id, ?action, "tenant-less path");
            self.seen.lock().unwrap().push(None);
            Ok(Entities::empty())
        }

        async fn entities_for_tenant(
            &self,
            principal: &EntityUid,
            tenant: Option<&str>,
            resource_id: &Self::ResourceId,
            action: &EntityUid,
        ) -> Result<Entities, Self::Error> {
            tracing::trace!(?principal, ?resource_id, ?action, "tenant path");
            self.seen.lock().unwrap().push(tenant.map(str::to_string));
            Ok(Entities::empty())
        }

        fn resource_uid(&self, id: &Self::ResourceId) -> Result<EntityUid, AuthzError> {
            if id == "bad" {
                return Err(AuthzError::InvalidEntityUid("bad".to_string()));
            }
            super::super::store::make_uid("TestApp", "Resource", id)
        }

        fn validate_schema(&self, schema: &Schema) -> Result<(), AuthzError> {
            tracing::trace!(?schema, "accepted");
            Ok(())
        }
    }

    fn tenant_store() -> Arc<AuthzStore<TenantRecordingProvider>> {
        let evaluator: Arc<dyn PolicyEvaluator> =
            Arc::new(PolicyStore::from_text(POLICY_TEXT, SCHEMA_JSON).unwrap());
        Arc::new(AuthzStore::new(
            evaluator,
            Arc::new(TenantRecordingProvider {
                seen: Mutex::new(Vec::new()),
            }),
            "TestApp",
        ))
    }

    /// The tenant a session was opened for reaches the provider.
    #[tokio::test]
    async fn the_session_tenant_reaches_the_provider() {
        let store = tenant_store();
        let authz = store.for_user_in_tenant("alice", "tenant-a").unwrap();
        assert!(authz.is_permitted("View", &"doc1".to_string()).await);
        let authz = store.for_user_id("alice").unwrap();
        assert!(authz.is_permitted("View", &"doc1".to_string()).await);
        let seen = store.provider.seen.lock().unwrap().clone();
        assert_eq!(seen, vec![Some("tenant-a".to_string()), None]);
    }

    /// A denial before Cedar is asked still emits the decision event.
    #[tokio::test]
    async fn a_denial_before_evaluation_emits_a_decision_event() {
        use tracing_subscriber::layer::SubscriberExt;

        #[derive(Clone, Default)]
        struct Capture(Arc<Mutex<Vec<String>>>);
        struct Fields(String);
        impl tracing::field::Visit for Fields {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.push_str(&format!("{}={value:?} ", field.name()));
            }
        }
        impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Capture {
            fn on_event(
                &self,
                event: &tracing::Event<'_>,
                _ctx: tracing_subscriber::layer::Context<'_, S>,
            ) {
                if event.metadata().target() == super::super::audit::DECISION_TARGET {
                    let mut fields = Fields(String::new());
                    event.record(&mut fields);
                    self.0.lock().unwrap().push(fields.0);
                }
            }
        }

        let capture = Capture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        let _guard = tracing::subscriber::set_default(subscriber);

        let store = tenant_store();
        let authz = store.for_user_id("alice").unwrap();
        assert!(!authz.is_permitted("View", &"bad".to_string()).await);

        let events = capture.0.lock().unwrap().clone();
        assert!(
            events
                .iter()
                .any(|e| e.contains("invalid_resource") && e.contains("deny")),
            "events: {events:?}"
        );
    }
}
