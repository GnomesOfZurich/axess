//! Axum extractors for [`Principal`].
//!
//! `AuthPrincipal` resolves whichever principal kind the current request
//! presents; `AuthHumanPrincipal` and `AuthWorkloadPrincipal` narrow to a
//! specific variant and reject the other.
//!
//! # Resolution chain
//!
//! Today the chain is single-step: [`SessionResolver`] over the request's
//! [`AuthSession`]. When the+ workload resolvers
//! (JWT-SVID / mTLS / SPIRE) land, they'll be wired in by middleware that
//! injects a typed `PrincipalResolverChain` into request extensions; the
//! extractor will read that chain first and fall back to the session
//! resolver. The extractor surface here stays stable through that
//! change. Adopter handlers that write `async fn handler(p: AuthPrincipal, ...)`
//! today pick up new resolver kinds automatically as they land.
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

/// Axum extractor that narrows to a human principal. Resolved workloads
/// are rejected with [`PrincipalRejection::WrongKind`].
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

/// Axum extractor that narrows to a workload principal. Resolved humans
/// are rejected with [`PrincipalRejection::WrongKind`].
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
    /// not match the extractor used. Surfaces as 403.
    WrongKind,

    /// The resolver returned an [`IdentityError`] other than
    /// `NotAuthenticated` (e.g. malformed SPIFFE ID at a future
    /// workload resolver). Surfaces as 401 to fail closed.
    Identity(IdentityError),
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
        };
        (status, msg).into_response()
    }
}

async fn resolve_principal<S>(parts: &mut Parts, state: &S) -> Result<Principal, PrincipalRejection>
where
    S: Send + Sync,
{
    // Today: SessionResolver only.+ will read a registered
    // resolver chain from `parts.extensions` and try those first,
    // falling through to SessionResolver as the human path.
    let session = AuthSession::from_request_parts(parts, state)
        .await
        .map_err(|_: SessionMissing| PrincipalRejection::SessionLayerMissing)?;
    SessionResolver::new(session)
        .resolve()
        .await
        .map_err(|e| match e {
            IdentityError::NotAuthenticated => PrincipalRejection::NotAuthenticated,
            other => PrincipalRejection::Identity(other),
        })
}

impl<S> FromRequestParts<S> for AuthPrincipal
where
    S: Send + Sync,
{
    type Rejection = PrincipalRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        resolve_principal(parts, state).await.map(AuthPrincipal)
    }
}

impl<S> FromRequestParts<S> for AuthHumanPrincipal
where
    S: Send + Sync,
{
    type Rejection = PrincipalRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match resolve_principal(parts, state).await? {
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
        match resolve_principal(parts, state).await? {
            Principal::Workload(w) => Ok(AuthWorkloadPrincipal(w)),
            Principal::Human(_) => Err(PrincipalRejection::WrongKind),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::http::{Request, StatusCode};
    use tokio::sync::RwLock;

    use super::*;
    use crate::session::data::SessionData;
    use crate::session::id::SessionId;
    use crate::session::layer::{SessionHandle, SessionInner};
    use crate::{AuthState, TenantId, UserId};
    use axess_rng::SystemRng;

    fn make_parts_with_session(data: SessionData) -> Parts {
        let inner = SessionInner {
            id: SessionId::new(&SystemRng),
            data,
            modified: false,
            regenerate: false,
            pre_cycle_id: None,
            pending_fingerprint: None,
            max_custom_bytes: 64 * 1024,
        };
        let handle = SessionHandle(Arc::new(RwLock::new(inner)));
        let request = Request::builder()
            .uri("/")
            .extension(handle)
            .body(())
            .expect("build request");
        let (parts, _) = request.into_parts();
        parts
    }

    fn make_parts_without_session() -> Parts {
        let request = Request::builder().uri("/").body(()).expect("build request");
        let (parts, _) = request.into_parts();
        parts
    }

    fn authenticated(user_id: UserId, tenant_id: TenantId) -> SessionData {
        SessionData {
            auth_state: AuthState::Authenticated {
                user_id,
                tenant_id,
                authn_time: chrono::Utc::now(),
                factors_completed: Vec::new(),
            },
            ..SessionData::default()
        }
    }

    /// Authenticated session resolves to a human principal.
    #[tokio::test]
    async fn auth_principal_resolves_human_from_session() {
        let user_id = UserId::new(&SystemRng);
        let tenant_id = TenantId::new(&SystemRng);
        let mut parts = make_parts_with_session(authenticated(user_id, tenant_id));

        let extracted = AuthPrincipal::from_request_parts(&mut parts, &()).await;
        let principal = extracted.expect("authenticated session must resolve").0;
        match principal {
            Principal::Human(h) => {
                assert_eq!(h.user_id, user_id);
                assert_eq!(h.tenant_id, tenant_id);
            }
            Principal::Workload(_) => panic!("session-backed extractor returned workload"),
        }
    }

    /// Guest session rejects with 401.
    #[tokio::test]
    async fn auth_principal_rejects_guest_session() {
        let mut parts = make_parts_with_session(SessionData::default());
        let err = AuthPrincipal::from_request_parts(&mut parts, &())
            .await
            .expect_err("guest session must reject");
        assert!(
            matches!(err, PrincipalRejection::NotAuthenticated),
            "got {err:?}"
        );
        assert_eq!(err.into_response().status(), StatusCode::UNAUTHORIZED);
    }

    /// Missing session layer surfaces 500 (adopter wiring error).
    #[tokio::test]
    async fn auth_principal_rejects_missing_session_layer() {
        let mut parts = make_parts_without_session();
        let err = AuthPrincipal::from_request_parts(&mut parts, &())
            .await
            .expect_err("no session layer must reject");
        assert!(
            matches!(err, PrincipalRejection::SessionLayerMissing),
            "got {err:?}"
        );
        assert_eq!(
            err.into_response().status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    /// Human-narrowing extractor succeeds when a human resolves.
    #[tokio::test]
    async fn auth_human_principal_succeeds_for_session() {
        let user_id = UserId::new(&SystemRng);
        let tenant_id = TenantId::new(&SystemRng);
        let mut parts = make_parts_with_session(authenticated(user_id, tenant_id));

        let human = AuthHumanPrincipal::from_request_parts(&mut parts, &())
            .await
            .expect("human extractor must succeed");
        assert_eq!(human.user_id, user_id);
    }

    /// Workload-narrowing extractor rejects with 403 when only a human
    /// is available (the case today; no workload resolver wired).
    #[tokio::test]
    async fn auth_workload_principal_rejects_human() {
        let user_id = UserId::new(&SystemRng);
        let tenant_id = TenantId::new(&SystemRng);
        let mut parts = make_parts_with_session(authenticated(user_id, tenant_id));

        let err = AuthWorkloadPrincipal::from_request_parts(&mut parts, &())
            .await
            .expect_err("workload extractor over human session must reject");
        assert!(matches!(err, PrincipalRejection::WrongKind), "got {err:?}");
        assert_eq!(err.into_response().status(), StatusCode::FORBIDDEN);
    }
}
