//! The audit concern: the trail failing or shedding.

/// Counters for the audit pipeline.
pub trait AuditMetrics: Send + Sync + 'static {
    /// The audit store rejected an event, so the flow was failed rather
    /// than allowed to proceed unrecorded. Every login is failing while
    /// this fires: it is a page, not a dashboard line.
    fn audit_store_outage(&self) {}

    /// An audit sink deliberately dropped an event under load.
    ///
    /// Distinct from [`audit_store_outage`](Self::audit_store_outage):
    /// nothing is failing, the sink is shedding to protect its storage.
    /// A steady rate means the trail has bounded gaps and the sink's
    /// capacity wants looking at; a spike usually means someone is
    /// driving unauthenticated login attempts at you.
    fn audit_event_shed(&self) {}
}
