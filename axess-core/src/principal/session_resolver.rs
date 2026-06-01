//! `SessionResolver`: extracts a [`HumanPrincipal`] from an
//! authenticated [`AuthSession`].
//!
//! Lives in axess-core (not in the leaf [`axess_identity`] crate)
//! because it depends on axess-core's session state machine. Implements
//! the [`axess_identity::PrincipalResolver`] trait so call sites can
//! treat `SessionResolver` and `CliResolver` uniformly through the same
//! trait surface.

use std::collections::BTreeMap;

use axess_identity::{HumanPrincipal, IdentityError, Principal, PrincipalResolver};

use crate::AuthSession;

/// Resolver that extracts a [`HumanPrincipal`] from an authenticated
/// [`AuthSession`]. Returns [`IdentityError::NotAuthenticated`] when
/// the session is in any state other than
/// [`Authenticated`](crate::AuthState::Authenticated).
///
/// Cheap to construct; clones the session handle (an `Arc`-backed
/// shared value) so the resolver owns its own view. Per-request
/// construction in an Axum handler is the expected use:
///
/// ```text
/// async fn handler(session: AuthSession) -> Result<…, ApiError> {
///     let principal = SessionResolver::new(session).resolve().await?;
///     // …
/// }
/// ```
#[derive(Clone)]
pub struct SessionResolver {
    session: AuthSession,
}

impl SessionResolver {
    /// Construct a resolver over the given session.
    pub fn new(session: AuthSession) -> Self {
        Self { session }
    }
}

impl PrincipalResolver for SessionResolver {
    async fn resolve(&self) -> Result<Principal, IdentityError> {
        let snap = self
            .session
            .snapshot()
            .await
            .ok_or(IdentityError::NotAuthenticated)?;
        // The prior `from_bytes` conversion
        // between two duplicate `SessionId` types here disappeared
        // when `axess_core::session::id::SessionId` became a
        // re-export of `axess_identity::SessionId`. The snapshot's
        // `session_id` is now type-identical to the field on
        // `HumanPrincipal`; direct assignment, no byte copy.
        Ok(Principal::Human(HumanPrincipal {
            user_id: snap.user_id,
            tenant_id: snap.tenant_id,
            session_id: Some(snap.session_id),
            attributes: BTreeMap::new(),
        }))
    }
}
