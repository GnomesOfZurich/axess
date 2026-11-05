//! The audit-log query capability: [`AuditQuery`] and its
//! [`EventQueryFilter`], split out of `store` so the core storage traits
//! stay in one readable file. Both are re-exported from `store`.

use crate::authn::{
    event::AuthEvent,
    ids::{TenantId, UserId},
};
use serde::{Deserialize, Serialize};

/// Optional filters for [`AuditQuery::query_events`].
///
/// All fields are optional and combined with AND. The outer `tenant_id`
/// is supplied as a separate argument and is always required.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventQueryFilter {
    /// Restrict to events for this user. Cross-checked against
    /// `tenant_id` at query time; an out-of-tenant `user_id` returns
    /// an empty result rather than leaking events.
    pub user_id: Option<UserId>,
    /// Restrict to events of this type. `None` means all types.
    pub event_type: Option<crate::authn::event::AuthEventType>,
    /// Restrict to events with this status. `None` means all statuses.
    pub status: Option<crate::authn::event::AuthEventStatus>,
    /// Inclusive lower bound on `event_time`.
    pub from: Option<chrono::DateTime<chrono::Utc>>,
    /// Exclusive upper bound on `event_time`.
    pub until: Option<chrono::DateTime<chrono::Utc>>,
    /// When `true`, also return events with `tenant_id IS NULL`: the
    /// platform-level rail events (a login attempt for an unknown user that
    /// never resolved a tenant, a global OAuth login whose begin named no
    /// tenant, a refresh run outside any tenant scope). Those rows are not
    /// the tenant's: the same rows come back for every tenant that asks,
    /// so a view that shows them to a tenant's administrators shows
    /// cross-tenant platform activity. Leave it `false` (the `Default`) for
    /// a tenant's own audit screen; set it for an operator view. Federated
    /// rows carry the tenant whenever the ceremony or scope named one
    /// (`begin_oauth_login_with_tenant_provider`, `oauth_in_tenant`, `oauth_for_session`
    /// on an authenticated session).
    pub include_unscoped: bool,
    /// Maximum number of rows to return (newest-first). 0 means
    /// "backend default"; implementations should pick a safe cap
    /// (e.g. 1000) so a forgotten limit cannot scan the whole table.
    pub limit: u32,
}

/// Tenant-scoped audit-log query, exposed as an opt-in
/// capability trait separate from [`IdentityStore`](super::IdentityStore).
///
/// `IdentityStore` is required of every backend (mock, in-memory,
/// SQLite, etc). Most of those backends have no audit table and no
/// way to answer a query, and putting the method on `IdentityStore`
/// with a default `Ok(Vec::new())` would silently turn unsupported
/// backends into "no events found" lies on a SOC dashboard. The
/// capability split makes support explicit: an application generic
/// over `S: IdentityStore + AuditQuery` won't compile against a
/// store that lacks audit support, and a runtime caller can probe
/// via downcast or trait-object dispatch.
///
/// # Tenant scoping
///
/// Every returned event MUST satisfy
/// `event.tenant_id == Some(tenant_id)
/// OR (filter.include_unscoped AND event.tenant_id IS NULL)`.
/// The outer `tenant_id` is required: this trait centralises the
/// `WHERE tenant_id = ? OR tenant_id IS NULL` rail so applications
/// no longer hand-roll it (the common bug: dropping the second
/// clause hides platform-level events; dropping the first clause
/// leaks events across tenants; both seen in the wild).
pub trait AuditQuery: Send + Sync + 'static {
    /// Backend error type. Typically aliased to the matching
    /// `IdentityStore::Error` so downstream `Result` types stay
    /// homogeneous.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Tenant-scoped query over the audit log. Newest first, capped
    /// at `filter.limit` (or the backend's safe default when 0).
    fn query_events(
        &self,
        tenant_id: &TenantId,
        filter: &EventQueryFilter,
    ) -> impl std::future::Future<Output = Result<Vec<AuthEvent>, Self::Error>> + Send;
}
