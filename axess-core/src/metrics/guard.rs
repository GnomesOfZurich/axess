//! The request-guard concern: rate limiting and CSRF.

/// Why the CSRF layer refused a request. A closed set, so it is safe as a
/// metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CsrfRefusal {
    /// The request carried no session id, so no token could be bound
    /// (the layer is outside the session layer).
    NoSession,
    /// The `Origin` or `Referer` was not an allowed origin.
    OriginMismatch,
    /// A WebSocket upgrade came from an origin that is not allowed.
    WebSocketOrigin,
    /// The token could not be read from the request (oversized or malformed
    /// form body, unusable header).
    TokenUnreadable,
    /// The cookie and the presented token were missing, unequal or not bound
    /// to the session.
    TokenInvalid,
}

impl CsrfRefusal {
    /// A stable snake_case name for use as a label value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoSession => "no_session",
            Self::OriginMismatch => "origin_mismatch",
            Self::WebSocketOrigin => "websocket_origin",
            Self::TokenUnreadable => "token_unreadable",
            Self::TokenInvalid => "token_invalid",
        }
    }
}

/// Counters for the guards that sit in front of a route.
pub trait RequestGuardMetrics: Send + Sync + 'static {
    /// A request was allowed through the rate limiter.
    fn rate_limit_allowed(&self) {}

    /// A request was rejected by the rate limiter (429).
    fn rate_limit_rejected(&self) {}

    /// A state-changing request was refused by the CSRF layer (403).
    fn csrf_rejected(&self, reason: CsrfRefusal) {
        let _ = reason;
    }
}
