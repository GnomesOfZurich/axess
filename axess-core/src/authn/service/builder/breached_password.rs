//! The breached-password check an [`AuthnServiceBuilder`] holds, and the
//! policy for the moment it cannot answer.

use super::AuthnServiceBuilder;
use crate::authn::store::{FactorStore, IdentityStore};
use axess_factors::{BreachCheckUnavailable, BreachedPasswordCheck};
use std::sync::Arc;

impl<I, F> AuthnServiceBuilder<I, F>
where
    I: IdentityStore,
    F: FactorStore,
{
    /// Screen every chosen password against `check`.
    ///
    /// A password reset, and an application's own signup, change or
    /// enrolment through
    /// [`check_chosen_password`](crate::authn::service::AuthnService::check_chosen_password)
    /// or
    /// [`hash_chosen_password`](crate::authn::service::AuthnService::hash_chosen_password),
    /// then refuse a password the check knows (`NewPasswordError::Breached`;
    /// a reset audits `password_breached`) and, until
    /// [`allow_unchecked_when_breach_check_unavailable`](Self::allow_unchecked_when_breach_check_unavailable)
    /// says otherwise, a password the check could not screen
    /// (`NewPasswordError::BreachCheckUnavailable`; a reset audits
    /// `breach_check_unavailable`). A tenant whose
    /// [`PasswordRules::breached_check`](crate::authn::factor::PasswordRules::breached_check)
    /// is `false` is not screened.
    ///
    /// Without this call nothing is screened and
    /// [`build`](Self::build) logs a warning once. `axess_factors` ships
    /// the pure half of the k-anonymity range protocol
    /// (`range_prefix`, `count_in_range`) so an implementation is the HTTP
    /// call alone; `BreachedPasswordList` (under `testing`) is a fixed list
    /// for tests and examples.
    pub fn with_breached_password_check(mut self, check: impl BreachedPasswordCheck) -> Self {
        self.breached_password_check = Some(Arc::new(check));
        self
    }

    /// Accept a chosen password unscreened when the breached-password check
    /// cannot answer, instead of refusing it (the default).
    ///
    /// The acceptance is logged at `warn` with the check's error each time.
    /// This is the named opt-out for a deployment that would rather admit an
    /// unscreened password than turn signups and resets away during an
    /// outage of the check; it changes nothing about a password the check
    /// does answer for.
    pub fn allow_unchecked_when_breach_check_unavailable(mut self) -> Self {
        self.on_breach_check_unavailable = BreachCheckUnavailable::Allow;
        self
    }
}
