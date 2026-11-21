//! Session payload: the typed data stored in the session store per session.

use crate::authn::{
    assurance::{FactorAssurance, record_proof},
    factor::{FactorKind, FactorStep},
    ids::{DeviceId, TenantId, UserId},
};
use axess_clock::Timestamp;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Current session data schema version.
///
/// Raise it when the stored shape of [`SessionData`] changes. A stored row
/// below it is no session of this release and is not served: the session
/// layer runs the request as a guest, counts the row
/// ([`SessionMetrics::session_row_refused`](crate::metrics::SessionMetrics::session_row_refused))
/// and logs it, and leaves it to expire.
///
/// # History
///
/// - `v1`: initial schema (`auth_state`, `fingerprint`, `custom`).
/// - `v2`: added `device_id: Option<DeviceId>`.
/// - `v3`: `Authenticating` gained `flow` and `Authenticated` gained
///   `signed_in_at`; the same version added `key_binding`, the device key
///   a session is bound to.
pub const SESSION_DATA_VERSION: u8 = 3;

/// The complete session payload stored in the session store.
///
/// All authentication state is captured here in a flat, serializable form.
/// The stores serialize it as MessagePack, whole, when the session is written, not per field access.
///
/// # Schema versioning
///
/// The `version` field is persisted with each session. When the stored shape
/// of `SessionData` changes, [`SESSION_DATA_VERSION`] is raised, and a row
/// below the current version is not served: sessions stored by an earlier
/// release are not carried over, and their holders sign in again.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    /// Schema version of this session data, written on every save. A row
    /// with no `version` member reads as 1. The session layer serves no row
    /// below [`SESSION_DATA_VERSION`]; a row above it, written by a later
    /// release during a rolling upgrade, is served.
    #[serde(default = "default_version")]
    pub version: u8,
    /// Authentication state of the session principal.
    pub auth_state: AuthState,
    /// Fingerprint identifying the expected client for this session.
    ///
    /// Set automatically from the
    /// [`SessionBinding`](super::binding::SessionBinding) at the session's
    /// first step out of `Guest` (identifying, the start of a login, a
    /// workflow step, or authentication itself). Checked on every subsequent
    /// request: on a mismatch the request runs as a guest (possible
    /// hijacking).
    pub fingerprint: Option<String>,
    /// Opaque [`DeviceId`] resolved for the request that owns this session.
    ///
    /// It holds for the person it was resolved for: the person at the
    /// session's browser when the request began (the administrator of an
    /// impersonation, else the signed-in user), while that person is at the
    /// browser or, with nobody signed in, is the one a login in progress
    /// names; or for nobody, for a guest's request and one inside a login,
    /// whose device holds for whoever signs in. When another person signs in on the session within a request,
    /// this field, as [`AuthSession::data`](super::extractor::AuthSession::data)
    /// shows it, still names the first person's device for the rest of that
    /// request;
    /// [`AuthSession::device_id`](super::extractor::AuthSession::device_id)
    /// answers `None`, and the row is written without it.
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
    /// Whether the request this session is serving proved `device_id`: its
    /// device resolver answered
    /// [`BoundDevice::Proven`](crate::device::BoundDevice::Proven), which the
    /// library's resolver does for a request that presents the device's
    /// secret cookie token and for the device it creates on that request,
    /// and not for a device found by other means or kept from an earlier
    /// request of the session.
    ///
    /// The answer is the request's own and is never read from a store: the
    /// serialised form does not carry it, the session layer clears it on
    /// every row it loads (a store that keeps the value as it was handed
    /// over may return it), and sets it on every request from what the
    /// resolver reports. A lockout exemption reads the device through
    /// [`AuthSession::proven_device`](super::extractor::AuthSession::proven_device),
    /// which answers only when this is `true`.
    #[serde(skip)]
    pub device_proven: bool,
    /// The key the request this session is serving proved its device by,
    /// when it did, with the tenant and device the proof names: set beside
    /// [`device_proven`](Self::device_proven) from what the device resolver
    /// reports, for a device proven by a signature of its key and not by
    /// its token. The request's own answer, never stored, like
    /// `device_proven`.
    #[serde(skip)]
    pub device_key: Option<crate::device_key::ProvenKey>,
    /// Whether the request this session is serving proved the key the
    /// session is bound to ([`key_binding`](Self::key_binding)): the
    /// session layer's own verdict, from a proof cookie or a request proof,
    /// whether or not the request also presented the device's token. The
    /// request's own answer, never stored, like `device_proven`. What
    /// [`AuthSession::key_bound`](super::extractor::AuthSession::key_bound)
    /// answers.
    #[serde(skip)]
    pub key_proven: bool,
    /// The device key this session is bound to, when it is, and the person
    /// the binding was made for
    /// ([`SessionKeyBinding::owner`](crate::device_key::SessionKeyBinding::owner)).
    ///
    /// The raw field: a binding holds only while its owner is the person at
    /// the session's browser, and every reader that asks whether the session
    /// is bound reads [`key_binding_in_force`](Self::key_binding_in_force).
    /// When another person signs in, or a new login begins, the binding is
    /// no longer in force, and the session layer drops it from the row at
    /// the next write.
    ///
    /// Set when a factor verification completes on a request that proved
    /// its device by key and the device is the signed-in user's (owned by
    /// that user, or unowned and claimed for them); when a key registration
    /// succeeds on a freshly authenticated session; and on the session a
    /// refresh token builds after a proof by the key of the token's device.
    /// A bound session is served only to a request that proves the same
    /// key; see [`device_key`](crate::device_key).
    /// Carried whatever the features so a stored session has one shape.
    /// Absent from the row of a session that is not bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_binding: Option<crate::device_key::SessionKeyBinding>,
    /// Escape hatch for application-specific data stored alongside the session.
    pub custom: serde_json::Value,
    /// Write counter: the session layer raises it on every write to the
    /// store. A store's compare-and-swap
    /// ([`SessionStore::update_if_revision`](super::store::SessionStore::update_if_revision))
    /// compares it, which is what makes a one-shot custom value single-use
    /// across concurrent requests. Sessions stored before the field existed
    /// read as `0`.
    #[serde(default)]
    pub revision: u64,
    /// When the layer last re-armed the stored row's lifetime: set by every
    /// write and by the idle-expiry refresh of a read-only request. `None`
    /// for a session stored before the field existed, which is refreshed on
    /// its next request.
    #[serde(default)]
    pub touched_at: Option<Timestamp>,
    /// The session layer's claim on this session while it ends it. `None`
    /// on every session the load hands to a handler.
    ///
    /// The layer ends a session it finds past an age cap, or gone from the
    /// registry, in three steps: it writes this claim as a compare-and-swap
    /// on the revision (which exactly one of several requests carrying the
    /// same cookie wins), writes the audit row, and deletes the row. The
    /// claim is the decision to end the session. A request that loads a row
    /// claimed less than [`ENDING_CLAIM_LEASE`] ago is refused the session
    /// and ends nothing, so one ending leaves one audit row. A request that
    /// loads an older claim, left by a request that did not finish,
    /// finishes the ending for the reason the claim holds: a claimed
    /// session is never served again. Only the request that made a claim
    /// takes it back, and only when the audit row could not be written.
    ///
    /// A request that was already running when the claim was made, and
    /// writes the session afterwards, writes onto the claimed row and
    /// leaves the claim in place; a rotation of the id is not carried out
    /// for a claimed session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ending: Option<EndingClaim>,
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
            device_proven: false,
            device_key: None,
            key_proven: false,
            key_binding: None,
            custom: serde_json::Value::default(),
            revision: 0,
            touched_at: None,
            ending: None,
        }
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
///   `RequestAuthnService::begin_login()` skips this and goes directly to
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
        /// The method's steps still to be completed, in order. A step may
        /// offer a choice ([`FactorStep::AnyOf`]).
        remaining: Vec<FactorStep>,
        /// Factor kinds that have already been verified in this flow, each
        /// with the time it was verified, in the order they were completed.
        /// Carried into [`AuthState::Authenticated::factors_completed`] on
        /// transition so audit events can record the full list.
        completed: Vec<(FactorKind, Timestamp)>,
        /// Number of failed attempts on the current factor step.
        attempt_count: u32,
        /// Timestamp of last attempt (for rate limiting / lockout).
        last_attempt: Option<Timestamp>,
        /// The groups the directory returned when an LDAP bind step of this
        /// login verified, carried into
        /// [`AuthState::Authenticated::ldap_groups`]; `None` until then.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ldap_groups: Option<Vec<String>>,
        /// The impersonation of the `Authenticated` state a step-up began
        /// from, kept so the state the step-up completes into is still the
        /// administrator's; `None` for a login and for a step-up of the
        /// user's own session.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        impersonator: Option<Impersonation>,
        /// What each factor verified so far proved, the most recent proof
        /// of each kind; carried into
        /// [`AuthState::Authenticated::assurance`]. A step-up begins with
        /// the record of the state it began from.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        assurance: Vec<FactorAssurance>,
        /// What the pending step is for: a login, or a step-up of a session
        /// that was signed in. Set by the transition that opened it, and
        /// always stored: a pending state is read only with its flow, so no
        /// stored row is taken for a login that does not say it is one.
        flow: AuthFlow,
    },

    /// All factors verified: user is fully authenticated.
    Authenticated {
        /// Identifier of the authenticated user.
        user_id: UserId,
        /// Tenant the user belongs to.
        tenant_id: TenantId,
        /// When the person last proved presence (from the injectable
        /// Clock): the moment the most recent factor completed, the login's
        /// or a later step-up's. Recency checks read it
        /// (`AuthSession::authenticated_within`, a FIDO2 `max_authn_age`).
        /// The factors of the original login keep their own times in
        /// `factors_completed`.
        authn_time: Timestamp,
        /// When the login that created the session completed: what the
        /// absolute age cap counts from. A step-up and an id rotation keep
        /// it; only a new login sets it.
        signed_in_at: Timestamp,
        /// Factor kinds that were verified to reach this state, each with
        /// the time it was verified, in completion order. Used by the audit log to distinguish
        /// "user logged in with password only because the tenant
        /// disables TOTP" (legitimate single-factor) from "user
        /// reached Authenticated without verifying TOTP" (bypass
        /// attack). Empty for a session that reached this state without
        /// verifying a factor (impersonation, signup).
        factors_completed: Vec<(FactorKind, Timestamp)>,
        /// The administrator acting in `user_id`'s name and when the
        /// impersonation began, for a session `begin_impersonation` made;
        /// `None` for the user's own session. Part of the authenticated
        /// state, so nothing done to the custom data can remove it; it
        /// ends with the state (`end_impersonation`, logout, a new login).
        /// Stored as an object (`{"admin": .., "since": ..}`), and not at
        /// all when `None`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        impersonator: Option<Impersonation>,
        /// The groups the directory returned when this login's LDAP bind
        /// factor verified (empty when the provider searches no groups);
        /// `None` for a login without an LDAP bind. Part of the
        /// authenticated state for the same reasons as `impersonator`: a
        /// handler cannot overwrite them, the custom-data cap cannot drop
        /// them, and they end with the state. Read with
        /// `AuthSession::ldap_groups`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ldap_groups: Option<Vec<String>>,
        /// What each verified factor proved, and when: the most recent
        /// proof of each factor kind (see
        /// [`FactorAssurance`]). Part of the authenticated state for the
        /// same reasons as `impersonator`. Empty for a session that reached
        /// this state without verifying a factor (impersonation, signup),
        /// and an empty record satisfies no policy that asks for assurance.
        /// Read with [`AuthState::assurance`].
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        assurance: Vec<FactorAssurance>,
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
    /// The user ID this state names, whatever its progress: also for
    /// `Identifying`, `Authenticating` and `PendingWorkflow`, where it is
    /// only a claim the login has not yet proven.
    ///
    /// **Not an authorization principal.** Use it for audit attribution and
    /// for driving the login pipeline. For a principal use
    /// [`authenticated_user_id`](Self::authenticated_user_id).
    pub fn pending_user_id(&self) -> Option<&UserId> {
        match self {
            AuthState::Guest => None,
            AuthState::Identifying { user_id, .. } => Some(user_id),
            AuthState::Authenticating { user_id, .. } => Some(user_id),
            AuthState::Authenticated { user_id, .. } => Some(user_id),
            AuthState::PendingWorkflow { user_id, .. } => Some(user_id),
        }
    }

    /// The user ID of a fully authenticated state, `None` for every other
    /// (guest, identifying, authenticating, pending a workflow). The one to
    /// use as an authorization principal.
    pub fn authenticated_user_id(&self) -> Option<&UserId> {
        match self {
            AuthState::Authenticated { user_id, .. } => Some(user_id),
            _ => None,
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

    /// When `kind` was last verified in this authenticated state, or `None`
    /// from any other state or when it was not. A step-up that verifies a
    /// kind again moves its time forward; earlier factors keep theirs.
    pub fn factor_completed_at(&self, kind: &FactorKind) -> Option<Timestamp> {
        match self {
            AuthState::Authenticated {
                factors_completed, ..
            } => factors_completed
                .iter()
                .filter(|(k, _)| k == kind)
                .map(|(_, at)| *at)
                .max(),
            _ => None,
        }
    }

    /// Return `true` if this state represents a fully authenticated session.
    pub fn is_authenticated(&self) -> bool {
        matches!(self, AuthState::Authenticated { .. })
    }

    /// The administrator impersonating the authenticated user and when the
    /// impersonation began, or `None` for every other session.
    pub fn impersonation(&self) -> Option<Impersonation> {
        match self {
            AuthState::Authenticated { impersonator, .. } => *impersonator,
            _ => None,
        }
    }

    /// The groups the directory returned for the LDAP bind of an
    /// authenticated session, or `None` for every other session.
    pub fn ldap_groups(&self) -> Option<&[String]> {
        match self {
            AuthState::Authenticated { ldap_groups, .. } => ldap_groups.as_deref(),
            _ => None,
        }
    }

    /// What each factor of an authenticated session proved, the most recent
    /// proof of each kind; empty for every other session and for a session
    /// that recorded none.
    pub fn assurance(&self) -> &[FactorAssurance] {
        match self {
            AuthState::Authenticated { assurance, .. } => assurance,
            _ => &[],
        }
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
        steps: Vec<FactorStep>,
    ) {
        *self = AuthState::Authenticating {
            user_id,
            tenant_id,
            method_name,
            remaining: steps,
            completed: Vec::new(),
            attempt_count: 0,
            last_attempt: None,
            ldap_groups: None,
            impersonator: None,
            assurance: Vec::new(),
            flow: AuthFlow::Login,
        };
    }

    /// Turn an `Authenticated` state back into `Authenticating` for a
    /// step-up: the user and tenant are kept, `steps` become the remaining
    /// steps, and the factors already completed are carried over so the
    /// state that results from finishing the step holds them all.
    ///
    /// Returns `false`, changing nothing, from any state but `Authenticated`.
    pub(crate) fn begin_step_up(&mut self, steps: Vec<FactorStep>) -> bool {
        let AuthState::Authenticated {
            user_id,
            tenant_id,
            signed_in_at,
            factors_completed,
            ldap_groups,
            impersonator,
            assurance,
            ..
        } = self
        else {
            return false;
        };
        *self = AuthState::Authenticating {
            user_id: *user_id,
            tenant_id: *tenant_id,
            method_name: Arc::from(STEP_UP_LABEL),
            remaining: steps,
            completed: std::mem::take(factors_completed),
            attempt_count: 0,
            last_attempt: None,
            // The groups of the login stay with the session; an LDAP bind
            // in the step-up replaces them.
            ldap_groups: ldap_groups.take(),
            impersonator: impersonator.take(),
            assurance: std::mem::take(assurance),
            flow: AuthFlow::StepUp {
                signed_in_at: *signed_in_at,
            },
        };
        true
    }

    /// Replace the state with `Authenticated { … }`.
    ///
    /// Used for direct-to-authenticated transitions where there isn't a
    /// factor sequence to record (e.g. impersonation, OAuth callback
    /// where the IdP already enforced MFA). For MFA flows that complete
    /// through `advance_factor`, the `factors_completed` list is built
    /// from the prior `Authenticating` state's `completed` field.
    ///
    /// Records no assurance, which satisfies no assurance policy; the
    /// shorthand the tests use for
    /// [`set_authenticated_with`](Self::set_authenticated_with) without a
    /// proof.
    #[cfg(test)]
    pub(crate) fn set_authenticated(
        &mut self,
        user_id: UserId,
        tenant_id: TenantId,
        authn_time: Timestamp,
    ) {
        self.set_authenticated_with(user_id, tenant_id, authn_time, None);
    }

    /// [`set_authenticated`](Self::set_authenticated) recording `proof`,
    /// what the transition itself verified (a federated login).
    pub(crate) fn set_authenticated_with(
        &mut self,
        user_id: UserId,
        tenant_id: TenantId,
        authn_time: Timestamp,
        proof: Option<FactorAssurance>,
    ) {
        *self = AuthState::Authenticated {
            user_id,
            tenant_id,
            authn_time,
            signed_in_at: authn_time,
            factors_completed: Vec::new(),
            impersonator: None,
            ldap_groups: None,
            assurance: proof.into_iter().collect(),
        };
    }

    /// Mark an `Authenticated` state as an impersonation by `admin` begun
    /// at `since`. Returns `false`, changing nothing, from any other state.
    pub(crate) fn set_impersonator(&mut self, admin: UserId, since: Timestamp) -> bool {
        let AuthState::Authenticated { impersonator, .. } = self else {
            return false;
        };
        *impersonator = Some(Impersonation { admin, since });
        true
    }

    /// Record the groups the directory returned for an LDAP bind step of
    /// the login in flight; the transition to `Authenticated` carries them.
    /// Each bind replaces the list, so a login after a group change sees
    /// the new one. Does nothing outside `Authenticating`, as
    /// [`advance_factor`](Self::advance_factor) does.
    #[cfg(feature = "ldap")]
    pub(crate) fn set_ldap_groups(&mut self, groups: Vec<String>) {
        if let AuthState::Authenticating { ldap_groups, .. } = self {
            *ldap_groups = Some(groups);
        }
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
    /// Removes the first step `proof.kind` satisfies from `remaining` (if
    /// any), pushes the kind to `completed` and records `proof` in
    /// `assurance`, both at `proof.at`. When `remaining` becomes empty, transitions to
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
    pub(crate) fn advance_factor(&mut self, proof: FactorAssurance) -> AdvanceOutcome {
        match self {
            AuthState::Authenticating {
                user_id,
                tenant_id,
                remaining,
                completed,
                ldap_groups,
                impersonator,
                assurance,
                flow,
                ..
            } => {
                let authn_time = proof.at;
                // A step-up keeps the session's login; a login is its own.
                let signed_in_at = match flow {
                    AuthFlow::StepUp { signed_in_at } => *signed_in_at,
                    AuthFlow::Login => authn_time,
                };
                // The step this factor satisfies is done; the factor itself
                // (not the step's other choices) is what was completed, and
                // what it proved is recorded beside it.
                if let Some(pos) = remaining.iter().position(|step| step.accepts(&proof.kind)) {
                    remaining.remove(pos);
                    completed.push((proof.kind.clone(), authn_time));
                    record_proof(assurance, proof);
                }
                if remaining.is_empty() {
                    let uid = *user_id;
                    let tid = *tenant_id;
                    let factors = std::mem::take(completed);
                    let ldap_groups = ldap_groups.take();
                    let impersonator = impersonator.take();
                    let assurance = std::mem::take(assurance);
                    *self = AuthState::Authenticated {
                        user_id: uid,
                        tenant_id: tid,
                        authn_time,
                        signed_in_at,
                        factors_completed: factors,
                        impersonator,
                        ldap_groups,
                        assurance,
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
    pub(crate) fn record_attempt_at(&mut self, now: Timestamp) {
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

mod flow;
pub use flow::AuthFlow;
pub(crate) use flow::{STEP_UP_LABEL, SignedIn};
mod device;
mod impersonation;
pub use impersonation::Impersonation;
mod workflow;
pub use workflow::{WorkflowKind, WorkflowState};
mod version;
#[cfg(any(
    feature = "sqlite",
    feature = "sqlite-unbundled",
    feature = "postgres",
    feature = "mysql",
    feature = "valkey"
))]
pub(crate) use version::stored_version;
mod merge;
pub(crate) use merge::{merge_concurrent, merge_rotating};
mod claim;
pub use claim::{ENDING_CLAIM_LEASE, EndingClaim};
mod custom;
pub(crate) use custom::{
    LOGIN_FLOW_KEY, STEP_UP_CEREMONY_KEY, cap_custom, json_byte_len, retain_across_login,
};

#[cfg(test)]
mod assurance_tests;
#[cfg(test)]
pub(crate) mod assured_fixture;
#[cfg(test)]
mod flow_tests;
#[cfg(test)]
mod signed_in_tests;
#[cfg(test)]
mod tests;
