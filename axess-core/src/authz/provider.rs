//! The `AuthzEntityProvider` trait: the application's bridge between its data
//! layer and Cedar's entity graph.
//!
//! # Why this trait exists
//!
//! Cedar evaluates policies against an *entity set*: a graph of typed entities
//! with attributes and parent relationships. The library has no knowledge of
//! your schema: you own your tables, your IDs, and your relationship model.
//! Implementing this trait is how you teach Axess what to load and how to
//! represent it as Cedar entities.
//!
//! # What `entities_for` must return
//!
//! The returned [`cedar_policy::Entities`] should include everything Cedar needs
//! to evaluate the (principal, action, resource) triple:
//!
//! - The **principal** entity (the authenticated user) with its attributes
//!   (tenant, any ABAC attributes) and **parents** set to its role entity UIDs.
//! - The **role** entities: one per role the principal holds, with their
//!   own parent hierarchy if roles are hierarchical.
//! - The **resource** entity (the specific instance being accessed) with
//!   attributes (tenant, owner, status, etc.).
//! - Any other entities referenced by your Cedar policies (e.g. a tenant
//!   entity if policies check `principal.tenant == resource.tenant`).
//!
//! The `action` parameter is provided so that read-only actions can skip
//! loading attributes only needed for write policies: purely optional
//! optimisation; loading more than needed is always safe.
//!
//! # Example
//!
//! ```rust,ignore
//! use axess_core::authz::{AuthzEntityProvider, AuthzError};
//! use cedar_policy::{Entities, EntityUid};
//!
//! pub struct MyEntityProvider {
//!     db: sqlx::SqlitePool,
//!     namespace: String,
//! }
//!
//! impl AuthzEntityProvider for MyEntityProvider {
//!     type ResourceId = uuid::Uuid;
//!     type Error = sqlx::Error;
//!
//!     async fn entities_for(
//!         &self,
//!         principal: &EntityUid,
//!         resource_id: &uuid::Uuid,
//!         _action: &EntityUid,
//!     ) -> Result<Entities, sqlx::Error> {
//!         // load user, roles, document from DB and build Entities
//!         todo!()
//!     }
//!
//!     fn resource_uid(&self, id: &uuid::Uuid) -> Result<EntityUid, AuthzError> {
//!         // build Document::"uuid" UID
//!         todo!()
//!     }
//! }
//! ```

use cedar_policy::{Entities, EntityUid, Schema};

use super::error::AuthzError;

/// Application-supplied bridge between the data layer and Cedar entity graphs.
///
/// Implement this trait once per application (or per resource domain). Axess
/// calls [`entities_for`][Self::entities_for] for every authorization check,
/// passing the result directly to Cedar for evaluation.
///
/// Native `async fn`: no `async-trait` macro required (Rust 1.75+).
///
/// # Tenant-qualified Cedar IDs are mandatory in multi-tenant deployments
///
/// Cedar's `EntityUid` has no built-in awareness of axess tenants. Two
/// tenants both with a user "alice" produce the *same* `EntityUid`
/// `"App::User::\"alice\""` if the implementation forms ids from the
/// raw identifier alone. The Cedar policy engine then evaluates rules
/// against a graph where Alice-from-tenant-A and Alice-from-tenant-B
/// are indistinguishable: a cross-tenant authorisation hole.
///
/// Implementations MUST qualify resource and principal ids by tenant.
/// Three workable conventions:
///
/// * **Composite-id encoding:** `App::User::"<tenant_id>:<user_id>"`,
///   simple, opaque, requires schema awareness in callers that emit
///   Cedar requests.
/// * **Per-tenant Cedar namespace:** `Tenant_<id>::User::"alice"`,
///   isolates each tenant in a separate type cluster; works well when
///   tenants are statically known.
/// * **Tenant attribute on every entity:** `App::User::"<user_id>"` with
///   a `tenant: Tenant::"<id>"` attribute and policies that always
///   constrain `principal.tenant == resource.tenant`. Most flexible;
///   easiest to forget a single policy.
///
/// Pick one and apply it consistently. The convenience helpers
/// [`make_entity_uid`] / [`make_action_uid`] do not enforce a choice;
/// the caller controls the id string. A future axess release may add a
/// schema-validation pass that rejects untenanted entity types; until
/// then this is a load-bearing application invariant.
pub trait AuthzEntityProvider: Send + Sync {
    /// The type used to identify a resource in your application domain
    /// (e.g. `uuid::Uuid`, `i64`, a domain-specific newtype).
    type ResourceId: Send + Sync;

    /// The error type returned when entity materialization fails.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Build the Cedar entity set for a single authorization check.
    ///
    /// Called once per `require` / `is_permitted` call unless the result is
    /// already in the request-scoped entity cache. See the module-level docs
    /// for what must be included in the returned [`Entities`].
    ///
    /// Any error from this method is treated as a denial (fail-closed).
    fn entities_for(
        &self,
        principal: &EntityUid,
        resource_id: &Self::ResourceId,
        action: &EntityUid,
    ) -> impl std::future::Future<Output = Result<Entities, Self::Error>> + Send;

    /// Build the Cedar [`EntityUid`] for a resource instance.
    ///
    /// Must produce a UID whose type matches the Cedar schema. The namespace
    /// is the provider's responsibility: typically captured at construction
    /// time from the same value passed to [`AuthzStore::new`][super::session::AuthzStore::new].
    fn resource_uid(&self, id: &Self::ResourceId) -> Result<EntityUid, AuthzError>;

    /// Optional startup validation: assert that this provider's entity types
    /// exist in the compiled Cedar schema.
    ///
    /// Called by [`AuthzStore::validate`][super::session::AuthzStore::validate]
    /// if you invoke it at startup. Default implementation is a no-op.
    fn validate_against_schema(&self, schema: &Schema) -> Result<(), AuthzError> {
        let _ = schema;
        Ok(())
    }
}

// ── RequestEntityProvider ───────────────────────────────────────────────────

/// Object-safe entity provider: sibling of [`AuthzEntityProvider`] for
/// runtime polymorphism.
///
/// `AuthzEntityProvider` keeps a typed associated `ResourceId`, which is
/// great for ergonomic handler code that knows its concrete provider but
/// makes the trait non-object-safe. `RequestEntityProvider` erases the
/// resource type to [`EntityUid`] so it can live behind
/// `Arc<dyn RequestEntityProvider>` in axum extensions and be consumed
/// generically by macros and cache decorators that don't know the
/// application's concrete provider type.
///
/// # When to implement
///
/// You implement *both* traits when you want both ergonomic typed APIs
/// and the `require_authz!` route macro. The implementations share their
/// data layer; `RequestEntityProvider::entities_for` is typically a thin
/// adapter calling the typed `AuthzEntityProvider::entities_for` after
/// reconstructing your `ResourceId` from the supplied `EntityUid`.
///
/// Apps that only use `require_authz!` (and not `AuthzStore`/`AuthzSession`
/// directly) can implement `RequestEntityProvider` alone.
///
/// # Wrapping with caches
///
/// The cache decorators in [`crate::authz::cache`] are parameterised over
/// `RequestEntityProvider` so the same cache stack composes regardless of
/// the concrete inner provider:
///
/// ```rust,ignore
/// let provider: PlatformProvider = ...;                                    // typed
/// let provider: Arc<dyn RequestEntityProvider> = Arc::new(
///     MokaEntityCache::new(
///         ValkeyEntityCache::new(provider, valkey, Duration::from_secs(60))
///     )
/// );
/// ```
///
/// # Why `&AuthSession` is in the signature
///
/// Cedar policies frequently key off attributes that depend on the
/// session's current state, most commonly the active tenant in
/// multi-tenant deployments, but also things like the authenticated-at
/// time, MFA recency, or app-defined custom session data. The principal
/// `EntityUid` alone cannot convey these; the session is the natural
/// per-request anchor for them.
///
/// Implementations that don't need any session state should still take
/// the parameter (it's part of the trait contract) and acknowledge the
/// non-use explicitly with `let _ = session;` at the top of the method
/// body, matching the established axess pattern for trait methods with
/// optional inputs (e.g. `SessionStore::find_sessions_for_user`'s
/// `let _ = (user_id, limit);`). Do NOT prefix the parameter with `_`
/// axess forbids `_`-prefixed parameter names in trait impls, since
/// the prefix hides the contract from readers and tooling.
///
/// # Async return shape
///
/// Returns `Pin<Box<dyn Future + Send + 'a>>`: the standard object-safe
/// pattern for async trait methods on stable Rust. axess does not depend
/// on `async-trait`; the boxed-future return is one allocation per call,
/// which is dominated by the underlying DB / network work.
pub trait RequestEntityProvider: Send + Sync {
    /// Build the Cedar entity set required to evaluate
    /// `(principal, action, resource)` for this session's request.
    ///
    /// All UIDs are passed by reference so the implementation can dispatch
    /// on principal type, action verb, and resource type without having
    /// to clone. The returned `Entities` must include every entity
    /// transitively referenced by Cedar policies that could fire for this
    /// request; see `AuthzEntityProvider`'s module docs for the full
    /// inclusion contract.
    ///
    /// `session` provides access to the session-state surface
    /// (tenant_id, user_id, custom bag) for attributes the provider
    /// needs to set on the principal entity.
    ///
    /// Returning an `Err` is treated as authorization denial (fail-closed)
    /// by callers. Errors from this method are NOT cached by the
    /// decorators in [`crate::authz::cache`]; transient failures retry
    /// on the next call.
    fn entities_for<'a>(
        &'a self,
        session: &'a crate::session::AuthSession,
        principal: &'a EntityUid,
        resource: &'a EntityUid,
        action: &'a EntityUid,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Entities, AuthzError>> + Send + 'a>,
    >;
}

// ── Entity UID helpers ──────────────────────────────────────────────────────

/// Build a Cedar [`EntityUid`] from a namespace, type name, and entity ID.
///
/// Example: `make_entity_uid("MyApp", "User", "alice")` produces `MyApp::User::"alice"`.
///
/// Returns an error if the resulting type or ID string is invalid per Cedar's grammar.
pub fn make_entity_uid(
    namespace: &str,
    type_name: &str,
    entity_id: &str,
) -> Result<EntityUid, AuthzError> {
    let full_type = if namespace.is_empty() {
        type_name.to_string()
    } else {
        format!("{namespace}::{type_name}")
    };
    let type_name = full_type.parse().map_err(|e| {
        AuthzError::InvalidEntityUid(format!("invalid entity type `{full_type}`: {e}"))
    })?;
    let eid = cedar_policy::EntityId::new(entity_id);
    Ok(EntityUid::from_type_name_and_id(type_name, eid))
}

/// Build a Cedar action [`EntityUid`] from a namespace and action name.
///
/// Example: `make_action_uid("MyApp", "ReadDocument")` produces `MyApp::Action::"ReadDocument"`.
pub fn make_action_uid(namespace: &str, action_name: &str) -> Result<EntityUid, AuthzError> {
    make_entity_uid(namespace, "Action", action_name)
}
