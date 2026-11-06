//! The authentication-flow concern: logins and lockouts.

/// Counters for the authentication flow as a whole.
///
/// Every method defaults to a no-op, so an implementation overrides only the
/// ones it exports. A counter added to another concern never lands here.
pub trait AuthFlowMetrics: Send + Sync + 'static {
    /// A login attempt was started (`begin_login` called).
    fn auth_attempt(&self) {}

    /// Authentication completed successfully (all factors passed).
    fn auth_success(&self) {}

    /// Authentication failed (bad credentials, locked, and so on).
    fn auth_failure(&self) {}

    /// An account was locked because of too many failed attempts.
    fn account_locked(&self) {}
}
