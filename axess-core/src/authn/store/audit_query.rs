//! The audit-log query capability: [`AuditQuery`], its [`EventQueryFilter`]
//! and its answer, [`AuditTrail`], split out of `store` so the core storage
//! traits stay in one readable file. All are re-exported from `store`.

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
    pub from: Option<axess_clock::Timestamp>,
    /// Exclusive upper bound on `event_time`.
    pub until: Option<axess_clock::Timestamp>,
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
/// do not hand-roll it (the common bug: dropping the second
/// clause hides platform-level events; dropping the first clause
/// leaks events across tenants; both seen in the wild).
///
/// # A row that cannot be read
///
/// A stored row the implementation cannot read as an [`AuthEvent`] (a
/// session field that names no session, an event type this release does
/// not know, a field that does not decode) is answered as a count in
/// [`AuditTrail::unreadable`], once, under its [`UnreadableReason`]. It is
/// neither dropped in silence, which hides it from the auditor, nor allowed
/// to fail the query, which lets one bad row hide every other. The count
/// carries no text of the row, and an implementation logs none: a session
/// field may hold a value a cookie carried, and any field may hold text a
/// writer chose. `testing::store_contract::assert_unreadable_rows_contract`
/// holds a store to this.
pub trait AuditQuery: Send + Sync + 'static {
    /// Backend error type. Typically aliased to the matching
    /// `IdentityStore::Error` so downstream `Result` types stay
    /// homogeneous.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Tenant-scoped query over the audit log: the events read, newest
    /// first, capped at `filter.limit` (or the backend's safe default when
    /// 0), and the count of the rows the query matched and could not read.
    ///
    /// A row that cannot be read is counted under its reason in
    /// [`AuditTrail::unreadable`]; it does not make this method return an
    /// error, and it is not left out uncounted. An error is for a query
    /// that could not run (the store is unreachable, the statement failed).
    /// A caller that shows the trail shows the count when it is not zero.
    fn query_events(
        &self,
        tenant_id: &TenantId,
        filter: &EventQueryFilter,
    ) -> impl std::future::Future<Output = Result<AuditTrail, Self::Error>> + Send;
}

/// What [`AuditQuery::query_events`] answers: the events it read, and the
/// rows it matched and could not read, counted by reason.
#[derive(Debug, Clone, Default)]
pub struct AuditTrail {
    /// The events read, newest first.
    pub events: Vec<AuthEvent>,
    /// The rows the query matched and could not read.
    pub unreadable: UnreadableRows,
}

/// Rows of an audit query that could not be read, counted by reason. Only
/// the counts are kept: the text of such a row is neither returned nor
/// logged.
///
/// The reasons are three because the trait is the same for every backend,
/// and each reason asks the operator for something different: a session
/// field that names no session is a row a writer corrupted where a bearer
/// value may sit, an unknown event type is most often a row a newer release
/// wrote, and the rest is a row whose fields do not decode. A finer split
/// (by column, by codec) would name one backend's schema.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct UnreadableRows {
    /// Rows whose session field names no session.
    pub session: u32,
    /// Rows whose event type this release does not know.
    pub event_type: u32,
    /// Rows that could not be read for another reason: a status this
    /// release does not know, a time or another field that does not
    /// decode.
    pub other: u32,
}

impl UnreadableRows {
    /// How many rows could not be read.
    pub fn total(&self) -> u32 {
        self.session
            .saturating_add(self.event_type)
            .saturating_add(self.other)
    }

    /// Count one row that could not be read, under `reason`.
    pub fn count(&mut self, reason: UnreadableReason) {
        let slot = match reason {
            UnreadableReason::Session => &mut self.session,
            UnreadableReason::EventType => &mut self.event_type,
            UnreadableReason::Other => &mut self.other,
        };
        *slot = slot.saturating_add(1);
    }
}

/// Why one row of an audit query could not be read. A row with more than
/// one fault is counted once, under the first reason the reader meets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnreadableReason {
    /// The session field names no session: it is neither a session key nor
    /// a session id an earlier release recorded.
    Session,
    /// The event type is not one this release knows.
    EventType,
    /// Any other field does not decode.
    Other,
}
