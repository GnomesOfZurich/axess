//! Account-level hardening knobs of [`AuthnServiceBuilder`]: the password
//! hashing cost, the password reset lifetime and its cap, and how recently an
//! administrator must have authenticated to impersonate.
//!
//! Each starts at the behaviour the library has always had; the strict
//! security profile (`crate::profile`) names the stricter value of each.

use std::time::Duration;

use axess_factors::Argon2Cost;

use super::AuthnServiceBuilder;
use crate::authn::store::{FactorStore, IdentityStore};

/// The longest a password reset token may live unless
/// [`with_max_password_reset_ttl`](AuthnServiceBuilder::with_max_password_reset_ttl)
/// says otherwise: seven days.
pub const DEFAULT_MAX_PASSWORD_RESET_TTL: Duration = Duration::from_secs(7 * 24 * 3600);

/// The settings this module's builder methods write, with the library's
/// long-standing behaviour as the default.
pub(crate) struct AccountHardening {
    /// Cost of new password hashes.
    pub(crate) argon2_cost: Argon2Cost,
    /// Lifetime `begin_password_reset_with_default_ttl` gives a token; `None`
    /// until configured.
    pub(crate) password_reset_ttl: Option<Duration>,
    /// Longest lifetime `begin_password_reset` accepts.
    pub(crate) max_password_reset_ttl: Duration,
    /// How recent the administrator's authentication must be for an
    /// impersonation; `None` applies no limit.
    pub(crate) impersonation_max_authn_age: Option<Duration>,
    /// A hash of a fixed password under [`argon2_cost`](Self::argon2_cost),
    /// made on first use, that a login with no stored hash verifies against.
    pub(crate) dummy_password_hash: std::sync::Arc<std::sync::OnceLock<String>>,
}

impl Default for AccountHardening {
    fn default() -> Self {
        Self {
            argon2_cost: Argon2Cost::default(),
            password_reset_ttl: None,
            max_password_reset_ttl: DEFAULT_MAX_PASSWORD_RESET_TTL,
            impersonation_max_authn_age: None,
            dummy_password_hash: std::sync::Arc::default(),
        }
    }
}

impl<I, F> AuthnServiceBuilder<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// The Argon2id cost new password hashes are made under (default
    /// [`Argon2Cost::default`]: 19 MiB, two passes, one lane).
    ///
    /// Applies to a password a person chooses, a password reset, the rehash a
    /// successful login performs when the stored hash was made under another
    /// cost, and the dummy hash the unknown-user path verifies against, so
    /// that path costs what a real one does. Stored hashes keep verifying
    /// under the cost they were made with.
    #[must_use]
    pub fn with_argon2_cost(mut self, cost: Argon2Cost) -> Self {
        self.hardening.argon2_cost = cost;
        self
    }

    /// The lifetime `begin_password_reset_with_default_ttl` gives a reset
    /// token. Not set by default: that method refuses until it is, and
    /// `begin_password_reset` keeps taking the lifetime from its caller.
    ///
    /// A value above the cap
    /// ([`with_max_password_reset_ttl`](Self::with_max_password_reset_ttl))
    /// is refused by the call that would use it.
    #[must_use]
    pub fn with_password_reset_ttl(mut self, ttl: Duration) -> Self {
        self.hardening.password_reset_ttl = Some(ttl);
        self
    }

    /// The longest lifetime a password reset token may be given (default
    /// [`DEFAULT_MAX_PASSWORD_RESET_TTL`], seven days). A request for a
    /// longer one is refused before anything is looked up.
    #[must_use]
    pub fn with_max_password_reset_ttl(mut self, cap: Duration) -> Self {
        self.hardening.max_password_reset_ttl = cap;
        self
    }
}
