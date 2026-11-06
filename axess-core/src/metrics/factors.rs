//! The factor concern: verification attempts and the guards around them.

/// Counters for factor verification (password, TOTP, recovery code, passkey,
/// LDAP bind) and for the guards that sit in front of it.
pub trait FactorMetrics: Send + Sync + 'static {
    /// A factor verification was attempted.
    fn factor_attempt(&self) {}

    /// A factor verification succeeded.
    fn factor_success(&self) {}

    /// A factor verification failed.
    fn factor_failure(&self) {}

    /// The failed-attempt counter store errored on `record_failed_attempt`.
    ///
    /// Distinct from [`factor_failure`](Self::factor_failure): the user did
    /// supply credentials, but the persistent counter that drives lockout
    /// could not be incremented. What the request returns then is
    /// [`LockoutPolicy::on_counter_unavailable`](crate::authn::types::LockoutPolicy),
    /// which defaults to treating the attempt as locked. Alert on this
    /// either way: under `Lock` it explains the support calls, and under
    /// `Allow` it is the only signal that lockout is off.
    fn factor_counter_store_outage(&self) {}

    /// A guess was refused by the throttle: consecutive wrong guesses under
    /// one key (see [`Throttle`](crate::authn::types::Throttle)) had earned a
    /// delay that had not run. No verifier ran and nothing was counted. A
    /// steady rate from one address is a guesser; the same from many is a
    /// distributed one, which the per-account lock still caps.
    fn attempt_throttled(&self) {}

    /// A recovery code matched only under the previous pepper of a rotation.
    ///
    /// The login succeeded, and the set it came from stays sealed under the
    /// retired secret: it should be regenerated, and the previous pepper
    /// dropped once this stops firing.
    fn recovery_codes_under_previous_pepper(&self) {}
}
