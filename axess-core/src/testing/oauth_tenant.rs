//! The proof [`OwnershipAssumed`], the
//! tenant OAuth directory's proof of client ownership, taken as given, for a
//! test whose subject is something else (discovery, sealing, the pair rule,
//! logout). Under the `testing` feature
//! only, which a release build refuses: a deployment names the proofs it
//! accepts, [`TokenEndpointProbe`](crate::federation::oauth_tenant::TokenEndpointProbe)
//! and [`OperatorAttestation`](crate::federation::oauth_tenant::OperatorAttestation)
//! among them, and none of them holds for every claim.

use crate::federation::oauth_tenant::{
    ClientOwnershipProof, OwnershipClaim, OwnershipFuture, OwnershipProofs, OwnershipProven,
};

/// A proof that holds for every claim.
#[derive(Debug, Clone, Copy, Default)]
pub struct OwnershipAssumed;

impl ClientOwnershipProof for OwnershipAssumed {
    fn prove<'a>(&'a self, _: &'a OwnershipClaim<'a>) -> OwnershipFuture<'a> {
        Box::pin(std::future::ready(Ok(OwnershipProven::Other {
            proof: "assumed by a test".to_string(),
        })))
    }
}

/// [`OwnershipProofs`] that accept [`OwnershipAssumed`] for every tenant.
pub fn ownership_assumed() -> OwnershipProofs {
    OwnershipProofs::accept(OwnershipAssumed)
}
