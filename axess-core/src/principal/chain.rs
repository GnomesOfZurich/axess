//! [`PrincipalResolverChain`]: the resolvers the principal extractors use,
//! in the order the application states.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axess_identity::{IdentityError, Principal, PrincipalResolver};
use axum::http::request::Parts;

/// What a workload step resolves to once the request has shown it a
/// credential.
pub(super) type WorkloadFuture =
    Pin<Box<dyn Future<Output = Result<Principal, IdentityError>> + Send>>;

/// A workload step, with the type of its resolver erased.
pub(super) trait WorkloadSource: Send + Sync {
    /// The resolution of what `parts` presents, or `None` when the request
    /// presents nothing this step reads.
    fn begin(&self, parts: &Parts) -> Option<WorkloadFuture>;
}

/// A workload step made from a function that builds a resolver from the
/// request.
struct FromRequest<F>(F);

impl<F, R> WorkloadSource for FromRequest<F>
where
    F: Fn(&Parts) -> Option<R> + Send + Sync,
    R: PrincipalResolver + 'static,
{
    fn begin(&self, parts: &Parts) -> Option<WorkloadFuture> {
        let resolver = (self.0)(parts)?;
        Some(Box::pin(async move { resolver.resolve().await }))
    }
}

/// One step of a chain.
#[derive(Clone)]
pub(super) enum Step {
    /// The request's authenticated session, through
    /// [`SessionResolver`](super::SessionResolver).
    Session,
    /// A workload resolver built from the request.
    Workload(Arc<dyn WorkloadSource>),
}

/// The resolvers [`AuthPrincipal`](super::AuthPrincipal),
/// [`AuthHumanPrincipal`](super::AuthHumanPrincipal) and
/// [`AuthWorkloadPrincipal`](super::AuthWorkloadPrincipal) use, in the order
/// they run.
///
/// Install it in the request's extensions, once for the router, with
/// `axum::Extension`:
///
/// ```ignore
/// let chain = PrincipalResolverChain::new()
///     .workload(move |parts: &Parts| {
///         let token = bearer_token(&parts.headers)?;
///         Some(
///             JwtSvidResolver::new(verifier.clone(), trust_domain.clone(), token)
///                 .with_tenant_lookup(lookup.clone()),
///         )
///     })
///     .session();
/// let app = Router::new()
///     .route("/reports", get(reports))
///     .layer(axum::Extension(chain));
/// ```
///
/// A request with no chain resolves through the session alone, as
/// `PrincipalResolverChain::new().session()` does.
///
/// Every step runs, in order, for every request:
///
/// - a session step resolves the human of an authenticated session, and
///   passes a session that is not authenticated. It needs the session
///   layer; without it the extractor answers
///   [`PrincipalRejection::SessionLayerMissing`](super::PrincipalRejection::SessionLayerMissing).
/// - a workload step calls its function on the request. `None` means the
///   request presents nothing the step reads (no bearer token, no client
///   certificate), and the step passes. Otherwise the resolver it returned
///   runs: a workload is resolved, and a credential it refuses refuses the
///   request, so a request that presents a bad credential is never
///   admitted, whatever another step resolved.
///
/// The steps that resolve a principal must agree: two that resolve
/// different principals (a signed-in session and a workload credential,
/// or two workloads) refuse the request with
/// [`PrincipalRejection::ConflictingCredentials`](super::PrincipalRejection::ConflictingCredentials).
/// When no step resolves anyone the extractor answers
/// [`PrincipalRejection::NotAuthenticated`](super::PrincipalRejection::NotAuthenticated).
///
/// All three extractors run the chain this way, and differ only in the
/// kind they admit: [`AuthHumanPrincipal`](super::AuthHumanPrincipal) and
/// [`AuthWorkloadPrincipal`](super::AuthWorkloadPrincipal) answer
/// [`PrincipalRejection::WrongKind`](super::PrincipalRejection::WrongKind)
/// when the request resolves to the other kind.
#[derive(Clone, Default)]
pub struct PrincipalResolverChain {
    steps: Vec<Step>,
}

impl PrincipalResolverChain {
    /// A chain with no steps, which resolves no one: add the steps in the
    /// order they are to be tried.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a step that resolves the human of the request's authenticated
    /// session.
    #[must_use]
    pub fn session(mut self) -> Self {
        self.steps.push(Step::Session);
        self
    }

    /// Add a step that resolves a workload: `from_request` builds the
    /// resolver for one request from what the request presents (a bearer
    /// token, a peer certificate), or answers `None` when it presents
    /// nothing this step reads. The resolver runs once per request that
    /// presents a credential to the step, whatever the other steps resolve.
    ///
    /// A resolver that answers a human principal is a wiring mistake, and
    /// the extractors refuse the request with
    /// [`PrincipalRejection::WrongKind`](super::PrincipalRejection::WrongKind).
    #[must_use]
    pub fn workload<F, R>(mut self, from_request: F) -> Self
    where
        F: Fn(&Parts) -> Option<R> + Send + Sync + 'static,
        R: PrincipalResolver + 'static,
    {
        self.steps
            .push(Step::Workload(Arc::new(FromRequest(from_request))));
        self
    }

    /// The steps, in order.
    pub(super) fn steps(&self) -> &[Step] {
        &self.steps
    }
}

impl fmt::Debug for PrincipalResolverChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.steps.iter().map(|step| match step {
                Step::Session => "session",
                Step::Workload(_) => "workload",
            }))
            .finish()
    }
}
