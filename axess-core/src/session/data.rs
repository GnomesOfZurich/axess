//! Session payload: the typed data stored in the session store per session.

use crate::authn::{
    factor::FactorKind,
    ids::{DeviceId, TenantId, UserId},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Current session data schema version.
///
/// Increment this when the `SessionData` structure changes in a way that
/// requires migration. The session layer checks this on load and calls
/// [`SessionData::migrate`] if the stored version is older.
///
/// # History
///
/// - `v1`: initial schema (`auth_state`, `fingerprint`, `custom`).
/// - `v2`: added `device_id: Option<DeviceId>`. Existing v1
///   sessions deserialise with `device_id = None` via `serde(default)`;
///   the migration step bumps the version field so a re-save reflects
///   the new schema.
pub const SESSION_DATA_VERSION: u8 = 2;

/// The complete session payload stored in the session store.
///
/// All authentication state is captured here in a flat, serializable form.
/// Session data is serialized as JSON once per request, not per field access.
///
/// # Schema versioning
///
/// The `version` field is persisted with each session. When the library evolves
/// and `SessionData` gains or removes fields, bump [`SESSION_DATA_VERSION`] and
/// add a migration step in [`SessionData::migrate`]. The session layer calls
/// `migrate` automatically on load, so existing sessions are upgraded in-place
/// without requiring a coordinated session wipe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    /// Schema version of this session data. Used for forward-compatible
    /// deserialization: if a newer library version adds fields, older sessions
    /// are migrated transparently on load.
    #[serde(default = "default_version")]
    pub version: u8,
    /// Authentication state of the session principal.
    pub auth_state: AuthState,
    /// Fingerprint identifying the expected client for this session.
    ///
    /// Set automatically by [`SessionBinding`](super::binding::SessionBinding)
    /// when the session first becomes authenticated. Checked on every subsequent
    /// request: a mismatch invalidates the session (possible hijacking).
    pub fingerprint: Option<String>,
    /// Opaque [`DeviceId`] resolved for the request that owns this session.
    ///
    /// `None` when the device subsystem is disabled (the `device` feature is
    /// off) or when the request was handled before the device resolver had
    /// a chance to stamp it (the very first request on a brand-new browser,
    /// before any [`Device`](crate::device::Device) row exists).
    ///
    /// Independent of [`fingerprint`](Self::fingerprint): fingerprint is a
    /// short-lived hijack guard recomputed on every request, whereas
    /// `device_id` references a long-lived row in the device store that may
    /// outlive any single session.
    ///
    /// Carried ungated so the on-the-wire shape of `SessionData` does not
    /// diverge across feature configurations. See
    /// [`docs/identity/device.md`](../../../docs/identity/device.md).
    #[serde(default)]
    pub device_id: Option<DeviceId>,
    /// Escape hatch for application-specific data stored alongside the session.
    pub custom: serde_json::Value,
}

fn default_version() -> u8 {
    1
}

impl Default for SessionData {
    fn default() -> Self {
        Self {
            version: SESSION_DATA_VERSION,
            auth_state: AuthState::default(),
            fingerprint: None,
            device_id: None,
            custom: serde_json::Value::default(),
        }
    }
}

impl SessionData {
    /// Migrate session data from an older schema version to the current version.
    ///
    /// Called automatically by the session layer on load. Each version bump
    /// should add a migration step here. Returns `true` if a migration was
    /// applied (session should be re-saved).
    pub fn migrate(&mut self) -> bool {
        if self.version >= SESSION_DATA_VERSION {
            return false;
        }

        // v1 → v2: added `device_id: Option<DeviceId>`. The
        // serde `default` attribute on the field already supplied `None`
        // during deserialisation, so the in-memory representation is
        // already correct; the only work left is bumping the persisted
        // version field so a re-save reflects the current schema.
        //
        // Each per-version step is responsible for bumping `self.version`
        // to the next number. No unconditional trailing assignment to
        // `SESSION_DATA_VERSION`; that hid the per-step bump from
        // observation (mutation tests couldn't distinguish "this branch
        // ran" from "the trailing line ran"). Future steps follow the
        // same shape: `if self.version == 2 { ...; self.version = 3; }`.
        if self.version == 1 {
            self.version = 2;
        }
        true
    }
}

/// Authentication state machine: flat enum, typed [`UserId`] / [`TenantId`] IDs.
///
/// The state machine follows a strict forward progression with
/// `PendingWorkflow` as a post-authentication holding state.
///
/// # State transition diagram
///
/// ```text
///                     ┌───────────────────────────┐
///                     │ (app-level, optional)      │
///  Guest ─┬──────────►│ Identifying ──► Authenticating ──► Authenticated
///         │           └───────────────────────────┘          ▲
///         │                                                  │
///         └──► Authenticating ──► Authenticated              │
///         │         (begin_login default path)               │
///         │                                                  │
///         └──► PendingWorkflow(Signup) ──────────────────────┘
///    ▲              (begin_signup)           (complete_signup)
///    │                                                       │
///    │              (logout / session clear)                  │
///    └───────────────────────────────────────────────────────-┘
/// ```
///
/// - **Guest**: anonymous visitor, no authentication started.
/// - **Identifying**: optional state for username-first flows. The built-in
///   `AuthnService::begin_login()` skips this and goes directly to
///   `Authenticating`. Available via `session.set_identifying()` for apps
///   that need a two-step identify-then-authenticate UX.
/// - **Authenticating**: progressing through a multi-factor method; `remaining`
///   tracks which factor kinds are still to be verified.
/// - **Authenticated**: all required factors verified; full access granted.
/// - **PendingWorkflow**: blocked on a post-auth step (signup, KYC, password
///   reset, etc.). Reached via `begin_signup()` or app-level workflow initiation.
///
/// Calling [`AuthSession::clear`](super::extractor::AuthSession::clear) from
/// any state resets the session back to `Guest` (logout).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(tag = "kind")]
pub enum AuthState {
    /// No authentication started; anonymous visitor.
    #[default]
    Guest,

    /// User identified (username entered), first factor not yet verified.
    Identifying {
        /// Identifier of the user being authenticated.
        user_id: UserId,
        /// Tenant the user belongs to.
        tenant_id: TenantId,
    },

    /// Progressing through a multi-factor method.
    Authenticating {
        /// Identifier of the user being authenticated.
        user_id: UserId,
        /// Tenant the user belongs to.
        tenant_id: TenantId,
        /// Human-readable method name, e.g. `"password+totp"`.
        method_name: Arc<str>,
        /// Ordered list of factor kinds still to be verified.
        remaining: Vec<FactorKind>,
        /// Factor kinds that have already been verified in this flow,
        /// in the order they were completed. Carried into
        /// [`AuthState::Authenticated::factors_completed`] on transition
        /// so audit events can record the full list.
        #[serde(default)]
        completed: Vec<FactorKind>,
        /// Number of failed attempts on the current factor step.
        attempt_count: u32,
        /// Timestamp of last attempt (for rate limiting / lockout).
        last_attempt: Option<DateTime<Utc>>,
    },

    /// All factors verified: user is fully authenticated.
    Authenticated {
        /// Identifier of the authenticated user.
        user_id: UserId,
        /// Tenant the user belongs to.
        tenant_id: TenantId,
        /// Wall-clock time when authentication completed (from injectable Clock).
        authn_time: DateTime<Utc>,
        /// Factor kinds that were verified to reach this state, in
        /// completion order. Used by the audit log to distinguish
        /// "user logged in with password only because the tenant
        /// disables TOTP" (legitimate single-factor) from "user
        /// reached Authenticated without verifying TOTP" (bypass
        /// attack). Empty for sessions whose state predates this
        /// field; `serde(default)` keeps existing serialized
        /// sessions readable.
        #[serde(default)]
        factors_completed: Vec<FactorKind>,
    },

    /// Authenticated but blocked on a post-auth workflow (e.g. signup, KYC, password reset).
    PendingWorkflow {
        /// Identifier of the user awaiting workflow completion.
        user_id: UserId,
        /// Tenant the user belongs to.
        tenant_id: TenantId,
        /// Workflow currently blocking full authentication (e.g. signup, KYC).
        workflow: WorkflowState,
    },
}

impl AuthState {
    /// Return the authenticated user ID if one is associated with this state.
    pub fn user_id(&self) -> Option<&UserId> {
        match self {
            AuthState::Guest => None,
            AuthState::Identifying { user_id, .. } => Some(user_id),
            AuthState::Authenticating { user_id, .. } => Some(user_id),
            AuthState::Authenticated { user_id, .. } => Some(user_id),
            AuthState::PendingWorkflow { user_id, .. } => Some(user_id),
        }
    }

    /// Return the tenant ID if one is associated with this state.
    pub fn tenant_id(&self) -> Option<&TenantId> {
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

    // ── Pure state transitions ────────────────────────────────────
    //
    // These methods own the pure mutation logic for the state machine.
    // They never call out to stores, audit, metrics, or session-level
    // orchestration (RwLock, dirty flag, id rotation, fingerprint
    // binding); those concerns stay on `AuthSession` which delegates
    // here. Visibility is `pub(crate)` because external callers receive
    // `&AuthState` (read-only) via `AuthSession::auth_state` and cannot
    // construct a `&mut AuthState`; the session is the only mutation
    // path and that's enforced at the type level.

    /// Replace the state with `Identifying { user_id, tenant_id }`.
    ///
    /// Valid from any prior state; this is the "user has typed their
    /// username, factor not yet selected" entry point and may interrupt
    /// an in-flight ceremony if the application chooses to re-identify.
    pub(crate) fn set_identifying(&mut self, user_id: UserId, tenant_id: TenantId) {
        *self = AuthState::Identifying { user_id, tenant_id };
    }

    /// Replace the state with `Authenticating { … }`: begin a multi-factor flow.
    pub(crate) fn begin_authenticating(
        &mut self,
        user_id: UserId,
        tenant_id: TenantId,
        method_name: Arc<str>,
        factors: Vec<FactorKind>,
    ) {
        *self = AuthState::Authenticating {
            user_id,
            tenant_id,
            method_name,
            remaining: factors,
            completed: Vec::new(),
            attempt_count: 0,
            last_attempt: None,
        };
    }

    /// Replace the state with `Authenticated { … }`.
    ///
    /// Used for direct-to-authenticated transitions where there isn't a
    /// factor sequence to record (e.g. impersonation, OAuth callback
    /// where the IdP already enforced MFA). For MFA flows that complete
    /// through `advance_factor`, the `factors_completed` list is built
    /// from the prior `Authenticating` state's `completed` field.
    pub(crate) fn set_authenticated(
        &mut self,
        user_id: UserId,
        tenant_id: TenantId,
        authn_time: DateTime<Utc>,
    ) {
        *self = AuthState::Authenticated {
            user_id,
            tenant_id,
            authn_time,
            factors_completed: Vec::new(),
        };
    }

    /// Replace the state with `PendingWorkflow { … }`.
    pub(crate) fn set_pending_workflow(
        &mut self,
        user_id: UserId,
        tenant_id: TenantId,
        workflow: WorkflowState,
    ) {
        *self = AuthState::PendingWorkflow {
            user_id,
            tenant_id,
            workflow,
        };
    }

    /// Advance through a multi-factor flow.
    ///
    /// Removes `kind` from `remaining` (if present) and pushes it to
    /// `completed`. When `remaining` becomes empty, transitions to
    /// `Authenticated` carrying the `completed` list as
    /// `factors_completed`. Returns the [`AdvanceOutcome`] describing
    /// what happened so the caller (`AuthSession::advance_factor`) can
    /// run the right post-mutation orchestration (id rotation,
    /// fingerprint binding, dirty flag).
    ///
    /// `NotApplicable` from any non-`Authenticating` state: the state
    /// machine is defensive: calling `advance_factor` on `Guest` is a
    /// no-op rather than an error so partial-attribution audit emits
    /// can fire before reaching here without a panic risk.
    pub(crate) fn advance_factor(
        &mut self,
        kind: &FactorKind,
        authn_time: DateTime<Utc>,
    ) -> AdvanceOutcome {
        match self {
            AuthState::Authenticating {
                user_id,
                tenant_id,
                remaining,
                completed,
                ..
            } => {
                if let Some(pos) = remaining.iter().position(|k| k == kind) {
                    let removed = remaining.remove(pos);
                    completed.push(removed);
                }
                if remaining.is_empty() {
                    let uid = *user_id;
                    let tid = *tenant_id;
                    let factors = std::mem::take(completed);
                    *self = AuthState::Authenticated {
                        user_id: uid,
                        tenant_id: tid,
                        authn_time,
                        factors_completed: factors,
                    };
                    AdvanceOutcome::Completed
                } else {
                    AdvanceOutcome::StillAuthenticating
                }
            }
            _ => AdvanceOutcome::NotApplicable,
        }
    }

    /// Record a failed factor attempt against the `Authenticating`
    /// state: increment counter, capture timestamp.
    ///
    /// No-op on any other variant. **The session-level dirty flag is
    /// not the caller's concern here**: we deliberately do NOT
    /// persist on every wrong attempt because that scales DB writes
    /// with brute-force traffic. `AuthSession::record_attempt_at`
    /// preserves that property by not setting `modified = true`.
    pub(crate) fn record_attempt_at(&mut self, now: DateTime<Utc>) {
        if let AuthState::Authenticating {
            attempt_count,
            last_attempt,
            ..
        } = self
        {
            *attempt_count += 1;
            *last_attempt = Some(now);
        }
    }
}

/// Result of [`AuthState::advance_factor`].
///
/// The session-level orchestration in `AuthSession::advance_factor`
/// branches on this to run the right side effects: `Completed` requires
/// fingerprint binding + id rotation + dirty flag; `StillAuthenticating`
/// requires only the dirty flag; `NotApplicable` is a no-op.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AdvanceOutcome {
    /// The state was not `Authenticating`; nothing was changed.
    NotApplicable,
    /// The factor was applied (or absent: defensive no-op on the
    /// kind itself); the flow still has remaining factors.
    StillAuthenticating,
    /// The last remaining factor was applied; transitioned to
    /// `Authenticated`.
    Completed,
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

impl WorkflowState {
    /// Create a new workflow. Pass `clock.now()` as `now` for DST compatibility.
    pub fn new(kind: WorkflowKind, total_steps: u32, now: DateTime<Utc>) -> Self {
        Self {
            kind,
            current_step: 0,
            total_steps,
            initiated_at: now,
        }
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

#[cfg(test)]
mod tests;
