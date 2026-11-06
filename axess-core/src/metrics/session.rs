//! The session-layer concern: lifecycle, binding and the `sid` map.

/// Counters for the session layer and the session-adjacent maps.
pub trait SessionMetrics: Send + Sync + 'static {
    /// A new session was created (id cycled after auth or first visit).
    fn session_created(&self) {}

    /// A session was invalidated (logout, suspend, forced logout).
    fn session_invalidated(&self) {}

    /// Session binding mismatch detected (possible hijacking).
    fn session_binding_mismatch(&self) {}

    /// An authenticated session that stored no fingerprint was bound to the
    /// client that presented it. A steady rate after binding was turned on
    /// is the old sessions being adopted; a rate that does not fall is a
    /// path that stores sessions without a fingerprint.
    fn session_fingerprint_backfilled(&self) {}

    /// `count` entries of the back-channel `sid` map were dropped because the
    /// map was at its capacity (see
    /// [`with_sid_map_capacity`](crate::authn::AuthnServiceBuilder::with_sid_map_capacity)).
    /// A dropped entry is a session a later back-channel logout can no longer
    /// find by `sid`; persistent counts mean the capacity is too small.
    fn sid_map_evicted(&self, count: u64) {
        let _ = count;
    }
}
