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

    /// A request presented a session whose stored row is below the current
    /// schema version
    /// ([`SESSION_DATA_VERSION`](crate::session::data::SESSION_DATA_VERSION)),
    /// and the row was not served: the request ran as a guest and the row
    /// was left to expire. The session layer also logs it at `warn`, by the
    /// first eight characters of the session's key.
    ///
    /// No store serves such a row. Every store that hands its version up
    /// is counted here, as the five shipped stores do; a store of your own
    /// whose decoder fails on such a row reports its own error instead, and
    /// the request is a guest all the same. Sessions stored before this
    /// release are not carried over, so after the upgrade window the count
    /// stops rising unless something beside this library writes rows to the
    /// session store; a count that has risen does not fall back.
    fn session_row_refused(&self) {}

    /// `count` entries of the back-channel `sid` map were dropped because the
    /// map was at its capacity (see
    /// [`with_sid_map_capacity`](crate::authn::AuthnServiceBuilder::with_sid_map_capacity)).
    /// A dropped entry is a session a later back-channel logout can no longer
    /// find by `sid`; persistent counts mean the capacity is too small.
    fn sid_map_evicted(&self, count: u64) {
        let _ = count;
    }

    /// A back-channel logout token verified but named no session this
    /// instance could find, so nothing ended. The IdP is answered `200`
    /// either way, as OpenID Connect Back-Channel Logout 1.0 has it for a
    /// session the endpoint does not know. A steady rate is instances that
    /// do not share a `sid` store (the token reached an instance that did not
    /// handle the login), or sessions that already ended.
    fn back_channel_logout_unmatched(&self) {}
}
