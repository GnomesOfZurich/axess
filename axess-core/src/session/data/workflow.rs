//! Post-authentication workflows a session can be held in.

use super::*;

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
    /// Lowercase hex SHA-256 of the secret that completes the workflow, when
    /// it has one (signup). Only the digest is kept in the session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_digest: Option<String>,
    /// When the secret stops being accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_expires_at: Option<DateTime<Utc>>,
}

impl WorkflowState {
    /// Create a new workflow. Pass `clock.now()` as `now` for DST compatibility.
    pub fn new(kind: WorkflowKind, total_steps: u32, now: DateTime<Utc>) -> Self {
        Self {
            kind,
            current_step: 0,
            total_steps,
            initiated_at: now,
            verification_digest: None,
            verification_expires_at: None,
        }
    }

    /// Require a secret to complete this workflow: its hex SHA-256 `digest`,
    /// accepted until `expires_at`.
    pub fn with_verification(mut self, digest: String, expires_at: DateTime<Utc>) -> Self {
        self.verification_digest = Some(digest);
        self.verification_expires_at = Some(expires_at);
        self
    }
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
