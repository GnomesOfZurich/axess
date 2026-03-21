//! Session payload — the typed data stored in the session store per session.

use crate::authn::factor::FactorKind;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// The complete session payload stored in the session store.
///
/// All authentication state is captured here in a flat, serializable form.
/// Session data is serialized as JSON once per request — not per field access.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SessionData {
    /// Authentication state of the session principal.
    pub auth_state: AuthState,
    /// SHA-256 hash of the browser fingerprint string, for session binding.
    pub fingerprint_hash: Option<String>,
    /// Escape hatch for application-specific data stored alongside the session.
    pub custom: serde_json::Value,
}

/// Authentication state machine — flat enum, no generics, [`Arc<str>`] IDs.
///
/// The state machine follows a strict forward progression:
/// `Guest` → `Identifying` → `Authenticating` → `Authenticated`
/// with `PendingWorkflow` as a post-authentication holding state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(tag = "kind")]
pub enum AuthState {
    /// No authentication started — anonymous visitor.
    #[default]
    Guest,

    /// User identified (username entered), first factor not yet verified.
    Identifying {
        user_id: Arc<str>,
        tenant_id: Arc<str>,
    },

    /// Progressing through a multi-factor method.
    Authenticating {
        user_id: Arc<str>,
        tenant_id: Arc<str>,
        /// Human-readable method name, e.g. `"password+totp"`.
        method_name: Arc<str>,
        /// Ordered list of factor kinds still to be verified.
        remaining: Vec<FactorKind>,
        /// Number of failed attempts on the current factor step.
        attempt_count: u32,
        /// Timestamp of last attempt (for rate limiting / lockout).
        last_attempt: Option<DateTime<Utc>>,
    },

    /// All factors verified — user is fully authenticated.
    Authenticated {
        user_id: Arc<str>,
        tenant_id: Arc<str>,
        /// Wall-clock time when authentication completed (from injectable Clock).
        authn_time: DateTime<Utc>,
    },

    /// Authenticated but blocked on a post-auth workflow (e.g. signup, KYC, password reset).
    PendingWorkflow {
        user_id: Arc<str>,
        tenant_id: Arc<str>,
        workflow: WorkflowState,
    },
}

impl AuthState {
    /// Return the authenticated user ID if one is associated with this state.
    pub fn user_id(&self) -> Option<&Arc<str>> {
        match self {
            AuthState::Guest => None,
            AuthState::Identifying { user_id, .. } => Some(user_id),
            AuthState::Authenticating { user_id, .. } => Some(user_id),
            AuthState::Authenticated { user_id, .. } => Some(user_id),
            AuthState::PendingWorkflow { user_id, .. } => Some(user_id),
        }
    }

    /// Return the tenant ID if one is associated with this state.
    pub fn tenant_id(&self) -> Option<&Arc<str>> {
        match self {
            AuthState::Guest => None,
            AuthState::Identifying { tenant_id, .. } => Some(tenant_id),
            AuthState::Authenticating { tenant_id, .. } => Some(tenant_id),
            AuthState::Authenticated { tenant_id, .. } => Some(tenant_id),
            AuthState::PendingWorkflow { tenant_id, .. } => Some(tenant_id),
        }
    }

    /// Return `true` if this state represents a fully authenticated session.
    pub fn is_authenticated(&self) -> bool {
        matches!(self, AuthState::Authenticated { .. })
    }

    /// Return `true` if this is an unauthenticated guest session.
    pub fn is_guest(&self) -> bool {
        matches!(self, AuthState::Guest)
    }

    /// Return `true` if the session is in progress through a multi-factor flow.
    ///
    /// Use this to guard MFA factor-verification routes.
    pub fn is_authenticating(&self) -> bool {
        matches!(self, AuthState::Authenticating { .. })
    }
}

/// Post-authentication workflow tracking.
///
/// Used when the user is fully authenticated but must complete an additional
/// workflow step before being granted full access (e.g. KYC, password reset).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WorkflowState {
    /// The kind of workflow that must be completed.
    pub kind: WorkflowKind,
    /// Zero-based index of the current step.
    pub current_step: u32,
    /// Total number of steps in this workflow.
    pub total_steps: u32,
    /// When this workflow was initiated.
    pub initiated_at: DateTime<Utc>,
}

/// The classification of a post-authentication workflow.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum WorkflowKind {
    /// New-user registration workflow.
    Signup,
    /// Password reset flow initiated by the user or an admin.
    PasswordReset,
    /// Email verification after account creation or address change.
    EmailVerification,
    /// Application-defined workflow with a custom name.
    Custom(Arc<str>),
}
