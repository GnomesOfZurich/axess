//! How long an unverified signup holds its identifier, and how many reset
//! links an account may hold at once.

use super::AuthnServiceBuilder;
use crate::authn::store::{FactorStore, IdentityStore};

/// How long an unverified `Candidate` account holds its identifier, unless
/// [`with_candidate_ttl`](AuthnServiceBuilder::with_candidate_ttl) says
/// otherwise: 24 hours.
pub const DEFAULT_CANDIDATE_TTL: std::time::Duration = std::time::Duration::from_secs(24 * 3600);

/// How many reset tokens an account may hold live at once, unless
/// [`with_max_live_reset_tokens`](AuthnServiceBuilder::with_max_live_reset_tokens)
/// says otherwise: 3.
pub const DEFAULT_MAX_LIVE_RESET_TOKENS: usize = 3;

impl<I, F> AuthnServiceBuilder<I, F>
where
    I: IdentityStore,
    F: FactorStore,
{
    /// How long an unverified `Candidate` account holds its identifier
    /// (default: 24 hours, [`DEFAULT_CANDIDATE_TTL`]).
    ///
    /// `begin_signup` creates the account before anyone has proved control of
    /// the identifier, so without a bound a stranger could reserve any
    /// identifier for good by starting a signup nobody finishes. Once the
    /// account is older than this, a new `begin_signup` for the same
    /// identifier deletes it and starts afresh; the session that began it can
    /// still submit it again. The bound is never shorter than
    /// [`with_signup_verification_ttl`](Self::with_signup_verification_ttl),
    /// so a verification secret that is still good never loses its account.
    pub fn with_candidate_ttl(mut self, ttl: std::time::Duration) -> Self {
        self.candidate_ttl = ttl;
        self
    }

    /// How many reset tokens an account may hold live at once (default
    /// [`DEFAULT_MAX_LIVE_RESET_TOKENS`], 3; at least one).
    ///
    /// A new request never invalidates a live link, so a third party who asks
    /// for a reset cannot kill the link in the owner's inbox. Past this many
    /// live tokens a request is refused as throttled (`begin_password_reset`
    /// answers `None` and audits `live_tokens_full`) until one expires. Using
    /// any one token consumes all of the account's tokens.
    pub fn with_max_live_reset_tokens(mut self, max: usize) -> Self {
        self.max_live_reset_tokens = max.max(1);
        self
    }
}
