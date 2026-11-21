//! The answer of a claim on a passkey credential id.

use crate::authn::ids::UserId;

/// How a claim on a passkey credential id stands: the answer of
/// [`FactorStore::claim_fido2_credential`](super::FactorStore::claim_fido2_credential).
///
/// A refusal carries the holder the claim lost to, read in the step that
/// refused it, so the audit row of a refused registration never waits on a
/// second read that a concurrent claim or release could change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fido2CredentialClaim {
    /// The id is claimed by the user who asked: now, or already.
    Claimed,
    /// Another user of the tenant holds the id: the user named.
    HeldBy(UserId),
    /// The store refuses the claim and names no holder: a store that keeps
    /// no passkeys.
    Refused,
}

impl Fido2CredentialClaim {
    /// Whether the id is claimed by the user who asked.
    pub fn is_claimed(&self) -> bool {
        matches!(self, Self::Claimed)
    }
}
