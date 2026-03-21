//! The `AuthzEntityProvider` trait — the application's bridge between its data
//! layer and Cedar's entity graph.
//!
//! # Why this trait exists
//!
//! Cedar evaluates policies against an *entity set*: a graph of typed entities
//! with attributes and parent relationships. The library has no knowledge of
//! your schema — you own your tables, your IDs, and your relationship model.
//! Implementing this trait is how you teach Axess what to load and how to
//! represent it as Cedar entities.
//!
//! # What `entities_for` must return
//!
//! The returned [`cedar_policy::Entities`] should include everything Cedar needs
//! to evaluate the (principal, action, resource) triple:
//!
//! - The **principal** entity — the authenticated user — with its attributes
//!   (tenant, any ABAC attributes) and **parents** set to its role entity UIDs.
//! - The **role** entities — one per role the principal holds, with their
//!   own parent hierarchy if roles are hierarchical.
//! - The **resource** entity — the specific instance being accessed — with
//!   attributes (tenant, owner, status, etc.).
//! - Any other entities referenced by your Cedar policies (e.g. a tenant
//!   entity if policies check `principal.tenant == resource.tenant`).
//!
//! The `action` parameter is provided so that read-only actions can skip
//! loading attributes only needed for write policies — purely optional
//! optimisation; loading more than needed is always safe.
//!
//! # Example
//!
//! ```rust,ignore
//! use axess_core::authz::{AuthzEntityProvider, AuthzError};
//! use cedar_policy::{Entities, EntityUid};
//! use async_trait::async_trait;
//!
//! pub struct MyEntityProvider {
//!     db: sqlx::SqlitePool,
//!     namespace: String,
//! }
//!
//! #[async_trait]
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
/// Native `async fn` — no `async-trait` macro required (Rust 1.75+).
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
    /// is the provider's responsibility — typically captured at construction
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
