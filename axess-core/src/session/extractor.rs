//! Axum request extractor providing typed, mutable session access.
//!
//! [`AuthSession`] is the primary API surface for handlers. Changes are flushed
//! to the session store by the [`SessionLayer`] middleware after the handler returns.

use crate::authn::factor::FactorKind;
use crate::session::{
    data::{AuthState, SessionData, WorkflowState},
    id::SessionId,
    layer::SessionHandle,
};
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use chrono::{DateTime, Utc};
use std::sync::Arc;

/// Axum request extractor providing typed, mutable session access.
///
/// Zero generic parameters — wraps the [`SessionHandle`] inserted by [`SessionLayer`].
/// Obtain one in a handler by listing it as a parameter:
///
/// ```rust,ignore
/// async fn my_handler(session: AuthSession) -> impl IntoResponse { ... }
/// ```
///
/// Changes are committed to the store automatically when the response is sent.
#[derive(Clone)]
pub struct AuthSession(pub(crate) SessionHandle);

impl AuthSession {
    /// Return the authenticated user ID, if any.
    pub async fn user_id(&self) -> Option<Arc<str>> {
        self.0.0.read().await.data.auth_state.user_id().cloned()
    }

    /// Return the tenant ID, if any.
    pub async fn tenant_id(&self) -> Option<Arc<str>> {
        self.0.0.read().await.data.auth_state.tenant_id().cloned()
    }

    /// Return `true` if the session is fully authenticated.
    pub async fn is_authenticated(&self) -> bool {
        self.0.0.read().await.data.auth_state.is_authenticated()
    }

    /// Clone the current authentication state enum (cheap — fields are `Arc<str>`).
    pub async fn auth_state(&self) -> AuthState {
        self.0.0.read().await.data.auth_state.clone()
    }

    /// Return the session ID.
    pub async fn session_id(&self) -> SessionId {
        self.0.0.read().await.id
    }

    /// Return a clone of the full session data.
    pub async fn data(&self) -> SessionData {
        self.0.0.read().await.data.clone()
    }

    // ── State mutation helpers ─────────────────────────────────────────────────

    /// Mark the session as fully authenticated.
    ///
    /// Also marks the session for ID cycling to prevent session fixation.
    pub async fn set_authenticated(
        &self,
        user_id: Arc<str>,
        tenant_id: Arc<str>,
        authn_time: DateTime<Utc>,
    ) {
        let mut guard = self.0.0.write().await;
        guard.data.auth_state = AuthState::Authenticated {
            user_id,
            tenant_id,
            authn_time,
        };
        guard.modified = true;
        guard.regenerate = true;
    }

    /// Begin a multi-factor authentication flow.
    ///
    /// Sets the state to [`AuthState::Authenticating`] with the given factors in order.
    pub async fn begin_authenticating(
        &self,
        user_id: Arc<str>,
        tenant_id: Arc<str>,
        method_name: Arc<str>,
        factors: Vec<FactorKind>,
    ) {
        let mut guard = self.0.0.write().await;
        guard.data.auth_state = AuthState::Authenticating {
            user_id,
            tenant_id,
            method_name,
            remaining: factors,
            attempt_count: 0,
            last_attempt: None,
        };
        guard.modified = true;
    }

    /// Advance a multi-factor flow by removing `kind` from the remaining list.
    ///
    /// If `remaining` becomes empty after removal, transitions to
    /// [`AuthState::Authenticated`] automatically.
    pub async fn advance_factor(&self, kind: &FactorKind, authn_time: DateTime<Utc>) {
        let mut guard = self.0.0.write().await;
        match &mut guard.data.auth_state {
            AuthState::Authenticating {
                user_id,
                tenant_id,
                remaining,
                ..
            } => {
                if let Some(pos) = remaining.iter().position(|k| k == kind) {
                    remaining.remove(pos);
                }
                if remaining.is_empty() {
                    let uid = user_id.clone();
                    let tid = tenant_id.clone();
                    guard.data.auth_state = AuthState::Authenticated {
                        user_id: uid,
                        tenant_id: tid,
                        authn_time,
                    };
                    guard.regenerate = true;
                }
                guard.modified = true;
            }
            _ => {
                // No-op if not in Authenticating state.
            }
        }
    }

    /// Record a failed attempt at the given time (for UI display / rate-limit feedback).
    ///
    /// Callers should supply `clock.now()` rather than `Utc::now()` so that
    /// deterministic simulation tests control the timestamp.
    ///
    /// **This does not enforce lockout** — lockout is based exclusively on the
    /// DB counter returned by `IdentityStore::record_failed_attempt`.
    pub async fn record_attempt_at(&self, now: DateTime<Utc>) {
        let mut guard = self.0.0.write().await;
        if let AuthState::Authenticating {
            attempt_count,
            last_attempt,
            ..
        } = &mut guard.data.auth_state
        {
            *attempt_count += 1;
            *last_attempt = Some(now);
            guard.modified = true;
        }
    }

    /// Return `(user_id, tenant_id)` if the session is fully authenticated, `None` otherwise.
    ///
    /// Acquires the read lock once — more efficient than calling `user_id()` and
    /// `tenant_id()` separately.
    pub async fn authenticated_ids(&self) -> Option<(Arc<str>, Arc<str>)> {
        let guard = self.0.0.read().await;
        match &guard.data.auth_state {
            AuthState::Authenticated {
                user_id, tenant_id, ..
            } => Some((user_id.clone(), tenant_id.clone())),
            _ => None,
        }
    }

    /// Enter the identifying state (user has typed their username).
    pub async fn set_identifying(&self, user_id: Arc<str>, tenant_id: Arc<str>) {
        let mut guard = self.0.0.write().await;
        guard.data.auth_state = AuthState::Identifying { user_id, tenant_id };
        guard.modified = true;
    }

    /// Transition to a pending workflow state.
    pub async fn set_pending_workflow(
        &self,
        user_id: Arc<str>,
        tenant_id: Arc<str>,
        workflow: WorkflowState,
    ) {
        let mut guard = self.0.0.write().await;
        guard.data.auth_state = AuthState::PendingWorkflow {
            user_id,
            tenant_id,
            workflow,
        };
        guard.modified = true;
    }

    /// Clear the session (logout). Resets state to `Guest` and marks as modified.
    ///
    /// The caller should regenerate the session ID separately to prevent session fixation.
    pub async fn clear(&self) {
        let mut guard = self.0.0.write().await;
        guard.data = SessionData::default();
        guard.modified = true;
    }

    /// Mark the session for ID cycling on next save.
    ///
    /// Call after completing authentication to prevent session fixation.
    pub async fn regenerate(&self) {
        let mut guard = self.0.0.write().await;
        guard.regenerate = true;
    }

    /// Read a value from the custom JSON bag.
    pub async fn get_custom(&self, key: &str) -> Option<serde_json::Value> {
        self.0.0.read().await.data.custom.get(key).cloned()
    }

    /// Store a value in the custom JSON bag.
    pub async fn set_custom(&self, key: impl Into<String>, value: serde_json::Value) {
        let mut guard = self.0.0.write().await;
        guard.data.custom[key.into()] = value;
        guard.modified = true;
    }
}

// ── Axum extractor impl ────────────────────────────────────────────────────────

/// Rejection type for when the session layer is not installed.
#[derive(Debug)]
pub struct SessionMissing;

impl axum::response::IntoResponse for SessionMissing {
    fn into_response(self) -> axum::response::Response {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "Internal Server Error",
        )
            .into_response()
    }
}

impl<S> FromRequestParts<S> for AuthSession
where
    S: Send + Sync,
{
    type Rejection = SessionMissing;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<SessionHandle>()
            .cloned()
            .map(AuthSession)
            .ok_or(SessionMissing)
    }
}
