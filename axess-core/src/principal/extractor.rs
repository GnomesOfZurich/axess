//! Axum extractors for [`Principal`].
//!
//! `AuthPrincipal` resolves whichever principal kind the current request
//! presents; `AuthHumanPrincipal` and `AuthWorkloadPrincipal` narrow to a
//! specific variant and reject the other.
//!
//! # Resolution chain
//!
//! The extractors resolve through the [`PrincipalResolverChain`] the
//! application installs in the request's extensions: session, workload, or
//! both, in the order it states. A request with no chain resolves through
//! [`SessionResolver`] over the request's [`AuthSession`] alone. Every
//! extractor runs every step of the chain the same way: a credential a step
//! refuses refuses the request in each, and so do two credentials that
//! resolve to different principals. The chain's documentation says what
//! each rejection means.
//!
//! # Naming
//!
//! Wrappers are named `Auth*` to parallel
//! [`crate::AuthSession`], the existing extractor pattern.
//! Foreign-type orphan rules forbid implementing
//! [`axum::extract::FromRequestParts`] directly on
//! [`axess_identity::Principal`] from inside axess-core (both types are
//! foreign); the local newtype absorbs that constraint while
//! [`std::ops::Deref`] keeps access ergonomic.

use std::ops::Deref;

use axess_identity::{
    HumanPrincipal, IdentityError, Principal, PrincipalResolver, WorkloadPrincipal,
};
use axum::extract::FromRequestParts;
use axum::http::{StatusCode, request::Parts};
use axum::response::IntoResponse;

use super::chain::{PrincipalResolverChain, Step};
use super::session_resolver::SessionResolver;
use crate::AuthSession;
use crate::session::extractor::SessionMissing;

/// Axum extractor that resolves the calling [`Principal`] (human or
/// workload) for the current request.
///
/// ```ignore
/// async fn handler(principal: AuthPrincipal) -> impl IntoResponse {
///     match &*principal {
///         Principal::Human(h) => format!("hello {}", h.user_id),
///         Principal::Workload(w) => format!("workload {}", w.workload_id),
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct AuthPrincipal(pub Principal);

impl AuthPrincipal {
    /// Consume the wrapper and return the underlying [`Principal`].
    pub fn into_inner(self) -> Principal {
        self.0
    }
}

impl Deref for AuthPrincipal {
    type Target = Principal;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Axum extractor that narrows to a human principal: it runs the
/// [`PrincipalResolverChain`] as [`AuthPrincipal`] does, and admits the
/// principal the request resolves to when it is a human. A request that
/// resolves to a workload is rejected with [`PrincipalRejection::WrongKind`].
#[derive(Debug, Clone)]
pub struct AuthHumanPrincipal(pub HumanPrincipal);

impl AuthHumanPrincipal {
    /// Consume the wrapper and return the underlying [`HumanPrincipal`].
    pub fn into_inner(self) -> HumanPrincipal {
        self.0
    }
}

impl Deref for AuthHumanPrincipal {
    type Target = HumanPrincipal;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Axum extractor that narrows to a workload principal: it runs the
/// [`PrincipalResolverChain`] as [`AuthPrincipal`] does, and admits the
/// principal the request resolves to when it is a workload. A request that
/// resolves to a human is rejected with [`PrincipalRejection::WrongKind`].
#[derive(Debug, Clone)]
pub struct AuthWorkloadPrincipal(pub WorkloadPrincipal);

impl AuthWorkloadPrincipal {
    /// Consume the wrapper and return the underlying [`WorkloadPrincipal`].
    pub fn into_inner(self) -> WorkloadPrincipal {
        self.0
    }
}

impl Deref for AuthWorkloadPrincipal {
    type Target = WorkloadPrincipal;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Reason a principal extractor refused the request.
#[derive(Debug)]
pub enum PrincipalRejection {
    /// The session layer is not installed; adopter wiring error, not a
    /// caller fault. Surfaces as 500 to match
    /// [`crate::session::extractor::SessionMissing`].
    SessionLayerMissing,

    /// No principal could be resolved for this request; typically the
    /// caller is unauthenticated. Surfaces as 401.
    NotAuthenticated,

    /// A principal was resolved but its kind (human vs. workload) does
    /// not match the extractor used, or a workload step's resolver answered
    /// a human. Surfaces as 403.
    WrongKind,

    /// A workload step's resolver refused the credential the request
    /// presented with an [`IdentityError`] other than `NotAuthenticated`
    /// (a malformed SPIFFE ID, a trust domain it does not accept).
    /// Surfaces as 401 to fail closed.
    Identity(IdentityError),

    /// Two steps of the chain resolved the credentials the request
    /// presented to different principals: a signed-in session and a
    /// workload credential, or two workload credentials of different
    /// workloads. The request is not admitted as either. Surfaces as 401.
    ConflictingCredentials,
}

impl IntoResponse for PrincipalRejection {
    fn into_response(self) -> axum::response::Response {
        let (status, msg): (StatusCode, &'static str) = match self {
            Self::SessionLayerMissing => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "session layer not installed",
            ),
            Self::NotAuthenticated => (StatusCode::UNAUTHORIZED, "not authenticated"),
            Self::WrongKind => (StatusCode::FORBIDDEN, "principal kind mismatch"),
            Self::Identity(_) => (StatusCode::UNAUTHORIZED, "identity resolution failed"),
            Self::ConflictingCredentials => (StatusCode::UNAUTHORIZED, "conflicting credentials"),
        };
        (status, msg).into_response()
    }
}

/// Which principals an extractor admits.
#[derive(Clone, Copy)]
enum Wanted {
    /// Either kind.
    Any,
    /// A human.
    Human,
    /// A workload.
    Workload,
}

impl Wanted {
    fn admits(self, principal: &Principal) -> bool {
        match self {
            Self::Any => true,
            Self::Human => matches!(principal, Principal::Human(_)),
            Self::Workload => matches!(principal, Principal::Workload(_)),
        }
    }
}

/// The chain the request carries, or the session alone.
fn chain_of(parts: &Parts) -> PrincipalResolverChain {
    parts
        .extensions
        .get::<PrincipalResolverChain>()
        .cloned()
        .unwrap_or_else(|| PrincipalResolverChain::new().session())
}

/// What one step answers: the principal it resolved, `None` when the
/// request presents nothing it reads, or the refusal that refuses the
/// request.
async fn resolve_step<S>(
    parts: &mut Parts,
    state: &S,
    step: &Step,
) -> Result<Option<Principal>, PrincipalRejection>
where
    S: Send + Sync,
{
    match step {
        Step::Session => {
            let session = AuthSession::from_request_parts(parts, state)
                .await
                .map_err(|_: SessionMissing| PrincipalRejection::SessionLayerMissing)?;
            match SessionResolver::new(session).resolve().await {
                Ok(principal) => Ok(Some(principal)),
                // A session that is not authenticated presents no one; the
                // next step may.
                Err(IdentityError::NotAuthenticated) => Ok(None),
                Err(other) => Err(PrincipalRejection::Identity(other)),
            }
        }
        Step::Workload(source) => {
            let Some(resolution) = source.begin(parts) else {
                return Ok(None);
            };
            // The request presented a credential: the resolver's answer
            // decides, and a refusal is never passed on to a later step.
            match resolution.await {
                Ok(Principal::Workload(workload)) => Ok(Some(Principal::Workload(workload))),
                Ok(Principal::Human(_)) => {
                    tracing::error!(
                        "a workload step of the principal chain resolved a human; refused"
                    );
                    Err(PrincipalRejection::WrongKind)
                }
                Err(IdentityError::NotAuthenticated) => Err(PrincipalRejection::NotAuthenticated),
                Err(other) => Err(PrincipalRejection::Identity(other)),
            }
        }
    }
}

/// Whether two resolved principals are the same principal: the same user
/// of the same tenant, or the same workload of the same tenant. Attributes
/// are not compared, as two resolvers of one workload may read different
/// ones.
fn same_principal(a: &Principal, b: &Principal) -> bool {
    match (a, b) {
        (Principal::Human(a), Principal::Human(b)) => {
            a.user_id == b.user_id && a.tenant_id == b.tenant_id
        }
        (Principal::Workload(a), Principal::Workload(b)) => {
            a.workload_id == b.workload_id && a.tenant_id == b.tenant_id
        }
        _ => false,
    }
}

/// Every step of the chain, in its order, the same for every extractor:
/// each step that reads a credential the request presents runs, whatever
/// an earlier step resolved. A credential a step refuses refuses the
/// request; two steps that resolve different principals refuse it as
/// [`PrincipalRejection::ConflictingCredentials`]. The principal the steps
/// agree on is admitted when `wanted` admits its kind, and
/// [`PrincipalRejection::WrongKind`] otherwise.
async fn resolve_principal<S>(
    parts: &mut Parts,
    state: &S,
    wanted: Wanted,
) -> Result<Principal, PrincipalRejection>
where
    S: Send + Sync,
{
    let chain = chain_of(parts);
    let mut resolved: Option<Principal> = None;
    for step in chain.steps() {
        let Some(principal) = resolve_step(parts, state, step).await? else {
            continue;
        };
        match &resolved {
            None => resolved = Some(principal),
            Some(first) if same_principal(first, &principal) => {}
            Some(_) => {
                tracing::warn!(
                    "two credentials of one request resolved to different principals; refused"
                );
                return Err(PrincipalRejection::ConflictingCredentials);
            }
        }
    }
    match resolved {
        Some(principal) if wanted.admits(&principal) => Ok(principal),
        Some(_) => Err(PrincipalRejection::WrongKind),
        None => Err(PrincipalRejection::NotAuthenticated),
    }
}

impl<S> FromRequestParts<S> for AuthPrincipal
where
    S: Send + Sync,
{
    type Rejection = PrincipalRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        resolve_principal(parts, state, Wanted::Any)
            .await
            .map(AuthPrincipal)
    }
}

impl<S> FromRequestParts<S> for AuthHumanPrincipal
where
    S: Send + Sync,
{
    type Rejection = PrincipalRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match resolve_principal(parts, state, Wanted::Human).await? {
            Principal::Human(h) => Ok(AuthHumanPrincipal(h)),
            Principal::Workload(_) => Err(PrincipalRejection::WrongKind),
        }
    }
}

impl<S> FromRequestParts<S> for AuthWorkloadPrincipal
where
    S: Send + Sync,
{
    type Rejection = PrincipalRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match resolve_principal(parts, state, Wanted::Workload).await? {
            Principal::Workload(w) => Ok(AuthWorkloadPrincipal(w)),
            Principal::Human(_) => Err(PrincipalRejection::WrongKind),
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod chain_tests;
