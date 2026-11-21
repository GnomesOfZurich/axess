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
    /// The cost stored hashes may still carry from before `argon2_cost`;
    /// see [`previous_argon2_cost`](Self::previous_argon2_cost).
    pub(crate) previous_argon2_cost: PreviousArgon2Cost,
    /// As [`dummy_password_hash`](Self::dummy_password_hash), under the
    /// previous cost.
    pub(crate) previous_dummy_password_hash: std::sync::Arc<std::sync::OnceLock<String>>,
    /// Set once a wrong password was checked against a hash under neither
    /// cost, so the operator is told once per service.
    pub(crate) unknown_cost_reported: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// Which earlier Argon2 cost every password refusal also spends; see
/// [`AuthnServiceBuilder::with_previous_argon2_cost`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PreviousArgon2Cost {
    /// The pinned [`Argon2Cost::default`] whenever the current cost is
    /// another: the cost every hash had before a deployment raised it.
    LibraryDefault,
    /// A cost the deployment named.
    Named(Argon2Cost),
    /// None: every stored hash is under the current cost.
    Off,
}

impl AccountHardening {
    /// The earlier cost in force, or `None` when there is none or it is the
    /// current cost.
    pub(crate) fn previous_argon2_cost(&self) -> Option<Argon2Cost> {
        let previous = match self.previous_argon2_cost {
            PreviousArgon2Cost::LibraryDefault => Argon2Cost::default(),
            PreviousArgon2Cost::Named(cost) => cost,
            PreviousArgon2Cost::Off => return None,
        };
        (previous != self.argon2_cost).then_some(previous)
    }
}

impl Default for AccountHardening {
    fn default() -> Self {
        Self {
            argon2_cost: Argon2Cost::default(),
            password_reset_ttl: None,
            max_password_reset_ttl: DEFAULT_MAX_PASSWORD_RESET_TTL,
            impersonation_max_authn_age: None,
            dummy_password_hash: std::sync::Arc::default(),
            previous_argon2_cost: PreviousArgon2Cost::LibraryDefault,
            previous_dummy_password_hash: std::sync::Arc::default(),
            unknown_cost_reported: std::sync::Arc::default(),
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

    /// The Argon2id cost the service will hash new passwords under: what
    /// [`with_argon2_cost`](Self::with_argon2_cost) set, or the default.
    #[must_use]
    pub fn argon2_cost(&self) -> Argon2Cost {
        self.hardening.argon2_cost
    }

    /// The Argon2id cost stored hashes may still carry from before the
    /// current one, which every wrong password and every refusal on the
    /// password form spends a run at as well, so a dormant account whose
    /// hash predates a cost change answers in the same work as any other.
    ///
    /// The default is the pinned [`Argon2Cost::default`] whenever
    /// [`with_argon2_cost`](Self::with_argon2_cost) names another cost (the
    /// cost every hash had before the deployment raised it, a security
    /// profile included), and nothing while the cost is the default. Name
    /// the cost here when the hashes came from another one;
    /// [`without_previous_argon2_cost`](Self::without_previous_argon2_cost)
    /// is the opt-out for a deployment whose hashes are all current.
    ///
    /// With a previous cost every refusal runs Argon2id twice, once at each
    /// cost, in two executor jobs: an unknown identifier, a wrong password
    /// against a current or a previous hash, a locked or throttled account.
    /// A right password against a previous hash spends the same, its check
    /// and the rehash at the current cost. A wrong password against a hash
    /// under a third cost spends both runs after its own check and is
    /// logged once at `warn`, naming this method.
    #[must_use]
    pub fn with_previous_argon2_cost(mut self, cost: Argon2Cost) -> Self {
        self.hardening.previous_argon2_cost = PreviousArgon2Cost::Named(cost);
        self
    }

    /// No previous Argon2id cost: a refusal spends one run at the current
    /// cost. Right for a deployment that hashed at its current cost from
    /// the start; with hashes under an earlier cost still stored, a wrong
    /// password against one costs its own run as well, which tells a caller
    /// that the account exists. See
    /// [`with_previous_argon2_cost`](Self::with_previous_argon2_cost).
    #[must_use]
    pub fn without_previous_argon2_cost(mut self) -> Self {
        self.hardening.previous_argon2_cost = PreviousArgon2Cost::Off;
        self
    }

    /// The lifetime `begin_password_reset_with_default_ttl` gives a reset
    /// token. Not set by default: that method refuses until it is, and
    /// `begin_password_reset` keeps taking the lifetime from its caller.
    ///
    /// A value above the cap
    /// ([`with_max_password_reset_ttl`](Self::with_max_password_reset_ttl))
    /// could never be issued, so the service is not built with one:
    /// [`try_build`](Self::try_build) refuses the pair, naming both
    /// settings.
    #[must_use]
    pub fn with_password_reset_ttl(mut self, ttl: Duration) -> Self {
        self.hardening.password_reset_ttl = Some(ttl);
        self
    }

    /// The lifetime `begin_password_reset_with_default_ttl` will give a
    /// reset token: what
    /// [`with_password_reset_ttl`](Self::with_password_reset_ttl) set, or
    /// `None` while it is not configured.
    #[must_use]
    pub fn password_reset_ttl(&self) -> Option<Duration> {
        self.hardening.password_reset_ttl
    }

    /// The longest lifetime a password reset token may be given (default
    /// [`DEFAULT_MAX_PASSWORD_RESET_TTL`], seven days). A request for a
    /// longer one is refused before anything is looked up.
    #[must_use]
    pub fn with_max_password_reset_ttl(mut self, cap: Duration) -> Self {
        self.hardening.max_password_reset_ttl = cap;
        self
    }

    /// The longest lifetime the service will give a password reset token:
    /// what
    /// [`with_max_password_reset_ttl`](Self::with_max_password_reset_ttl)
    /// set, or the default.
    #[must_use]
    pub fn max_password_reset_ttl(&self) -> Duration {
        self.hardening.max_password_reset_ttl
    }

    /// How recently an administrator must have authenticated to begin an
    /// impersonation: what
    /// [`with_impersonation_max_authn_age`](Self::with_impersonation_max_authn_age)
    /// set, or `None` for no limit.
    #[must_use]
    pub fn impersonation_max_authn_age(&self) -> Option<Duration> {
        self.hardening.impersonation_max_authn_age
    }

    /// Take off the limit
    /// [`with_impersonation_max_authn_age`](Self::with_impersonation_max_authn_age)
    /// set: an impersonation may then begin however long ago the
    /// administrator authenticated, which is the default.
    ///
    /// A builder under a security profile that names a limit is refused at
    /// [`try_build`](Self::try_build) without one, unless
    /// `waive_profile_floor(ProfileSetting::ImpersonationMaxAuthnAge)` is
    /// written out.
    #[must_use]
    pub fn without_impersonation_max_authn_age(mut self) -> Self {
        self.hardening.impersonation_max_authn_age = None;
        self
    }
}
