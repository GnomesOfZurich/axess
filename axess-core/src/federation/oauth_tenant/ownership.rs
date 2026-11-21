//! Proof that a tenant owns the client it registers.
//!
//! The store gives an `(issuer, client_id)` pair to one record, so whoever
//! registers a pair first holds it, and a tenant that registered another
//! tenant's client would keep the owner out and receive its back-channel
//! logout tokens. A
//! [`StoredTenantOAuthProviders`](super::StoredTenantOAuthProviders) that
//! holds [`OwnershipProofs`] therefore asks them before it stores a record,
//! and refuses the record by name when ownership is not proven. Every
//! directory holds them: its constructors take them, so no record is stored
//! without a proof.
//!
//! Two proofs ship, and a deployment names which it accepts, for every
//! tenant or per tenant, in [`OwnershipProofs`]:
//!
//! - [`TokenEndpointProbe`]: a token request to the identity provider made
//!   as the client, with the record's credential, for a grant the client
//!   does not hold. The provider's refusal says whether it authenticated the
//!   client (RFC 6749 section 5.2), so a confidential client proves itself
//!   with the credential the record carries.
//! - [`OperatorAttestation`]: an operator with the right to change providers
//!   attests that the tenant owns the client, through
//!   [`RequestAuthnService::attest_tenant_oauth_client_as`](crate::authn::service::RequestAuthnService::attest_tenant_oauth_client_as),
//!   which writes an audit row naming the operator, the tenant, the pair and
//!   the write it is for ([`OwnershipPurpose`]) and returns the
//!   [`OwnershipAttestation`] that write carries. The only route for a
//!   public client, which has no credential to prove with. The operator is
//!   a deployment operator who checks ownership out of band (with the
//!   identity provider's administrator, in its console): a user the
//!   identity store places in the operator tenant,
//!   [`TenantId::SYSTEM`](crate::authn::ids::TenantId::SYSTEM). The service
//!   refuses, by name, an attester of any other tenant, the one attested
//!   included.

mod probe;

pub use probe::{DEFAULT_OWNERSHIP_PROBE_TIMEOUT, TokenEndpointProbe};

use super::TenantOAuthProviderRecord;
use crate::authn::ids::{TenantId, UserId};
use axess_clock::Clock;
use axess_factors::egress::EgressPolicy;
use axess_rng::SecureRng;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// What a registration offers a [`ClientOwnershipProof`]: the record about
/// to be stored, its credential opened, the write it is for, the operator's
/// attestation when the registration carries one, and what a proof that
/// makes requests uses.
///
/// It has no `Debug`: it holds the credential in clear text.
pub struct OwnershipClaim<'a> {
    /// The record about to be stored.
    pub record: &'a TenantOAuthProviderRecord,
    /// The record's credential, opened: the client secret, or the private
    /// key's PEM text. Empty for a public client.
    pub credential: &'a str,
    /// The write the record is offered for: a registration, or an
    /// operator's hand-over of a pair another record holds.
    pub purpose: OwnershipPurpose,
    /// The attestation the registration carries, if any.
    pub attestation: Option<&'a OwnershipAttestation>,
    /// The directory's egress policy, which every request a proof makes on
    /// the tenant's behalf goes through.
    pub egress: EgressPolicy,
    /// The directory's clock.
    pub clock: Arc<dyn Clock>,
    /// The directory's RNG.
    pub rng: Arc<dyn SecureRng>,
}

impl OwnershipClaim<'_> {
    /// Whether the record is a public client: a client secret that is
    /// empty, so nothing proves the client but an attestation.
    #[must_use]
    pub fn is_public_client(&self) -> bool {
        matches!(
            self.record.credential,
            super::TenantClientCredential::Secret(_)
        ) && self.credential.is_empty()
    }
}

/// The write an ownership proof is asked for, which an
/// [`OwnershipAttestation`] names: an attestation made for one is refused
/// for the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OwnershipPurpose {
    /// A registration or update of a tenant's record, through
    /// [`upsert`](super::StoredTenantOAuthProviders::upsert) and
    /// [`upsert_attested`](super::StoredTenantOAuthProviders::upsert_attested),
    /// and the check of a stored record by
    /// [`reprove`](super::StoredTenantOAuthProviders::reprove).
    Register,
    /// An operator's hand-over of a pair another record holds, which
    /// removes that record, through
    /// [`RequestAuthnService::reassign_tenant_oauth_pair_as`](crate::authn::service::RequestAuthnService::reassign_tenant_oauth_pair_as).
    HandOver,
}

impl OwnershipPurpose {
    /// The name an audit row's reason carries: `register` or `hand_over`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Register => "register",
            Self::HandOver => "hand_over",
        }
    }
}

impl std::fmt::Display for OwnershipPurpose {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How ownership was proven.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnershipProven {
    /// The identity provider authenticated the client with the record's
    /// credential: the OAuth error it refused the probe's grant with.
    ClientAuthenticated {
        /// The error (`invalid_grant`, `unauthorized_client`, ...).
        answer: String,
    },
    /// An operator attested it.
    Attested {
        /// The operator who attested.
        operator: UserId,
    },
    /// A proof of the deployment's own, as it describes itself.
    Other {
        /// What proved it.
        proof: String,
    },
}

/// Why ownership was not proven.
///
/// The text of a refusal (its `Display`, which the directory's
/// [`OAuthError::Config`](axess_factors::oauth::OAuthError::Config) carries
/// back to the tenant) names its kind only: not authenticated, unproven, a
/// public client, not attested. What the far end answered (its OAuth error
/// code, the HTTP status, a redirect, a transport failure) is in
/// [`Unproven::reason`](Self::Unproven) and on the trace, never in the text:
/// a tenant writes its own issuer, and under an egress policy that does not
/// screen, a registration whose refusal repeated the answer would tell it
/// what answers at any address it named.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OwnershipRefused {
    /// The identity provider answered `invalid_client`: it did not
    /// authenticate the client with the record's credential.
    #[error("the identity provider did not authenticate the client with its credential")]
    ClientNotAuthenticated,
    /// The probe's answer proves nothing either way: another error, a
    /// token, a redirect, a transport failure, a discovery that failed, or
    /// a provider that refuses a credential known to be wrong the same way.
    #[error(
        "ownership is unproven: nothing the identity provider answered shows that it \
         authenticated the client; an operator may attest it"
    )]
    Unproven {
        /// What happened, for the trace and the adopter's own code; not
        /// part of the text.
        reason: String,
    },
    /// A public client has no credential to prove ownership with.
    #[error(
        "a public client has no credential to prove ownership with; an operator must attest it"
    )]
    PublicClient,
    /// No attestation was offered, or the one offered names another tenant,
    /// provider name, issuer or client id.
    #[error("no operator attestation names this tenant, provider and client")]
    NotAttested,
    /// The attestation offered names this record, but was made for another
    /// write: one for a registration does not hand a pair over, and one for
    /// a hand-over does not register.
    #[error("the operator attested this client for a {attested} write, not for a {write} write")]
    AttestedForAnotherPurpose {
        /// The write the attestation was made for.
        attested: OwnershipPurpose,
        /// The write it was offered for.
        write: OwnershipPurpose,
    },
    /// A proof of the deployment's own refused. Its text is both fields, as
    /// the proof wrote them: a proof that asks a party the tenant names keeps
    /// that party's answer out of `reason`.
    #[error("{proof}: {reason}")]
    Other {
        /// The proof that refused.
        proof: String,
        /// Why.
        reason: String,
    },
    /// Every accepted proof refused; each refusal, in the order the proofs
    /// were named.
    #[error("no accepted proof holds: {}", join(.0))]
    NoneHeld(Vec<OwnershipRefused>),
}

fn join(refusals: &[OwnershipRefused]) -> String {
    refusals
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

/// What [`ClientOwnershipProof::prove`] returns.
pub type OwnershipFuture<'a> =
    Pin<Box<dyn Future<Output = Result<OwnershipProven, OwnershipRefused>> + Send + 'a>>;

/// Proves that the tenant of a record owns its `(issuer, client_id)` pair.
///
/// [`StoredTenantOAuthProviders`](super::StoredTenantOAuthProviders) calls
/// the proofs its [`OwnershipProofs`] names for the record's tenant before
/// every write of a record, and stores nothing when none holds. The shipped
/// proofs are [`TokenEndpointProbe`] and [`OperatorAttestation`]; implement
/// it for a check of the deployment's own (a signed statement from the
/// identity provider, a lookup in its management API).
pub trait ClientOwnershipProof: Send + Sync + 'static {
    /// Whether `claim` proves the tenant owns the record's client.
    fn prove<'a>(&'a self, claim: &'a OwnershipClaim<'a>) -> OwnershipFuture<'a>;
}

/// An operator's statement that a tenant owns a client: the operator, the
/// tenant, the provider name, the `(issuer, client_id)` pair and the write it
/// is for.
///
/// Only
/// [`RequestAuthnService::attest_tenant_oauth_client_as`](crate::authn::service::RequestAuthnService::attest_tenant_oauth_client_as)
/// makes one, after the audit row naming them all is written, so an
/// attestation a registration carries is always on the audit trail. It
/// refuses an operator the identity store places in the tenant being
/// attested: the attester is a deployment operator who checks ownership out
/// of band, never the tenant's own administrator.
///
/// It is not `Clone`, and
/// [`upsert_attested`](super::StoredTenantOAuthProviders::upsert_attested)
/// and
/// [`reassign_tenant_oauth_pair_as`](crate::authn::service::RequestAuthnService::reassign_tenant_oauth_pair_as)
/// take it by value: one attestation is one write, and each further write
/// needs an attestation of its own, with its own audit row. One kept after
/// its write cannot take a pair back once an operator has handed it on.
///
/// ```compile_fail,E0599
/// use axess_core::federation::oauth_tenant::OwnershipAttestation;
/// fn keep(attestation: &OwnershipAttestation) -> OwnershipAttestation {
///     attestation.clone()
/// }
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct OwnershipAttestation {
    operator: UserId,
    tenant: TenantId,
    name: String,
    issuer: String,
    client_id: String,
    purpose: OwnershipPurpose,
}

impl OwnershipAttestation {
    /// An attestation whose audit row has been written.
    pub(crate) fn recorded(
        operator: UserId,
        tenant: TenantId,
        pair: (&str, &str, &str),
        purpose: OwnershipPurpose,
    ) -> Self {
        let (name, issuer, client_id) = pair;
        Self {
            operator,
            tenant,
            name: name.to_string(),
            issuer: issuer.to_string(),
            client_id: client_id.to_string(),
            purpose,
        }
    }

    /// The operator who attested.
    #[must_use]
    pub fn operator(&self) -> &UserId {
        &self.operator
    }

    /// The tenant the client was attested to.
    #[must_use]
    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// The provider name within the tenant.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The issuer.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The client id.
    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// The write it was made for.
    #[must_use]
    pub fn purpose(&self) -> OwnershipPurpose {
        self.purpose
    }

    /// Whether this attests `record`: the same tenant, provider name,
    /// issuer and client id.
    #[must_use]
    pub fn attests(&self, record: &TenantOAuthProviderRecord) -> bool {
        self.tenant == record.tenant_id
            && self.name == record.name
            && self.issuer == record.issuer
            && self.client_id == record.client_id
    }
}

/// The proof that holds when the registration carries an
/// [`OwnershipAttestation`] naming the record's tenant, provider name,
/// issuer and client id, made for the write it is offered to
/// ([`OwnershipClaim::purpose`]).
#[derive(Debug, Clone, Copy, Default)]
pub struct OperatorAttestation;

impl ClientOwnershipProof for OperatorAttestation {
    fn prove<'a>(&'a self, claim: &'a OwnershipClaim<'a>) -> OwnershipFuture<'a> {
        let verdict = match claim.attestation {
            Some(attestation) if !attestation.attests(claim.record) => {
                Err(OwnershipRefused::NotAttested)
            }
            Some(attestation) if attestation.purpose != claim.purpose => {
                Err(OwnershipRefused::AttestedForAnotherPurpose {
                    attested: attestation.purpose,
                    write: claim.purpose,
                })
            }
            Some(attestation) => Ok(OwnershipProven::Attested {
                operator: attestation.operator,
            }),
            None => Err(OwnershipRefused::NotAttested),
        };
        Box::pin(std::future::ready(verdict))
    }
}

/// Which proofs of ownership a deployment accepts: one list for every
/// tenant, and a list of its own for each tenant named. A record is stored
/// when one proof of its tenant's list holds, tried in the order named.
///
/// There is no default and no proof that accepts everything. The directory
/// takes the choice at construction.
///
/// ```
/// use axess_core::authn::ids::TenantId;
/// use axess_core::federation::oauth_tenant::{
///     OperatorAttestation, OwnershipProofs, TokenEndpointProbe,
/// };
///
/// // Confidential clients prove themselves; an operator attests the rest.
/// let proofs = OwnershipProofs::accept(TokenEndpointProbe::new()).or_accept(OperatorAttestation);
/// // A tenant whose clients only an operator may register.
/// let restricted = TenantId::SYSTEM;
/// let proofs = proofs.for_tenant(restricted, OperatorAttestation);
/// ```
#[derive(Clone)]
pub struct OwnershipProofs {
    every_tenant: Vec<Arc<dyn ClientOwnershipProof>>,
    by_tenant: HashMap<TenantId, Vec<Arc<dyn ClientOwnershipProof>>>,
}

impl OwnershipProofs {
    /// Every tenant's records need `proof`.
    pub fn accept(proof: impl ClientOwnershipProof) -> Self {
        Self {
            every_tenant: vec![Arc::new(proof)],
            by_tenant: HashMap::new(),
        }
    }

    /// Every tenant without a list of its own also accepts `proof`.
    #[must_use]
    pub fn or_accept(mut self, proof: impl ClientOwnershipProof) -> Self {
        self.every_tenant.push(Arc::new(proof));
        self
    }

    /// `tenant` accepts `proof`, and only the proofs named for it: the first
    /// call replaces the every-tenant list for that tenant, each further call
    /// adds to it.
    #[must_use]
    pub fn for_tenant(mut self, tenant: TenantId, proof: impl ClientOwnershipProof) -> Self {
        self.by_tenant
            .entry(tenant)
            .or_default()
            .push(Arc::new(proof));
        self
    }

    /// The proofs `tenant` accepts.
    fn of(&self, tenant: &TenantId) -> &[Arc<dyn ClientOwnershipProof>] {
        self.by_tenant
            .get(tenant)
            .map_or(self.every_tenant.as_slice(), Vec::as_slice)
    }

    /// The first of the record's tenant's proofs that holds, or every
    /// refusal. Each refusal is traced with its reason, which its text
    /// leaves out.
    pub(super) async fn prove(
        &self,
        claim: &OwnershipClaim<'_>,
    ) -> Result<OwnershipProven, OwnershipRefused> {
        let mut refusals = Vec::new();
        for proof in self.of(&claim.record.tenant_id) {
            match proof.prove(claim).await {
                Ok(proven) => return Ok(proven),
                Err(refused) => {
                    tracing::warn!(
                        target: "axess::federation::oauth_tenant",
                        tenant = %claim.record.tenant_id,
                        name = %crate::authn::service::log_text::logged_request_text(&claim.record.name),
                        refused = ?refused,
                        "a proof of a tenant's ownership of its client refused"
                    );
                    refusals.push(refused);
                }
            }
        }
        match refusals.len() {
            1 => Err(refusals.remove(0)),
            _ => Err(OwnershipRefused::NoneHeld(refusals)),
        }
    }
}

impl std::fmt::Debug for OwnershipProofs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnershipProofs")
            .field("every_tenant", &self.every_tenant.len())
            .field("by_tenant", &self.by_tenant.len())
            .finish()
    }
}
