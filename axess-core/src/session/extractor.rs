//! Axum request extractor providing typed, mutable session access.
//!
//! [`AuthSession`] is the primary API surface for handlers. Changes are flushed
//! to the session store by the [`SessionLayer`](super::layer::SessionLayer) middleware after the handler returns.

use crate::authn::factor::FactorStep;
use crate::authn::ids::{TenantId, UserId};
use crate::session::{
    data::{AdvanceOutcome, AuthState, Impersonation, SessionData, WorkflowState},
    id::SessionId,
    layer::SessionHandle,
};
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use chrono::{DateTime, Utc};
use std::sync::Arc;

/// Axum request extractor providing typed, mutable session access.
///
/// Zero generic parameters: wraps the `SessionHandle` inserted by [`SessionLayer`](super::layer::SessionLayer).
/// Obtain one in a handler by listing it as a parameter:
///
/// ```text
/// async fn my_handler(session: AuthSession) -> impl IntoResponse { ... }
/// ```
///
/// Changes are committed to the store automatically when the response is sent.
///
/// A handler cannot mark a session authenticated: the transition out of the
/// anonymous state belongs to [`AuthnService`](crate::authn::service::AuthnService),
/// which checks the account, the tenant and the registry first. The method
/// that does it is crate-private.
///
/// ```compile_fail,E0624
/// use axess_core::authn::ids::{TenantId, UserId};
/// use axess_core::session::extractor::AuthSession;
///
/// async fn handler(session: AuthSession, user: UserId, tenant: TenantId) {
///     session.set_authenticated(user, tenant, chrono::Utc::now()).await;
/// }
/// ```
#[derive(Clone)]
pub struct AuthSession(pub(crate) SessionHandle);

/// Identity bundle returned by [`AuthSession::snapshot`]. All
/// fields are read under a single `RwLock::read()` acquisition.
#[derive(Clone, Debug)]
pub struct AuthSnapshot {
    /// Identifier of the authenticated user.
    pub user_id: UserId,
    /// Tenant the user belongs to.
    pub tenant_id: TenantId,
    /// Stable session identifier for this snapshot.
    pub session_id: SessionId,
    /// Wall-clock time at which authentication completed.
    pub authn_time: DateTime<Utc>,
    /// The administrator acting in the user's name, and since when; `None`
    /// for the user's own session. See [`AuthSession::impersonation`].
    pub impersonation: Option<Impersonation>,
}

impl AuthSession {
    /// Return the user ID of an authenticated session, `None` for every other
    /// state.
    ///
    /// A session in the middle of a login (identified, awaiting a factor, or
    /// blocked on a workflow) answers `None`, so the value is safe to use as
    /// an authorization principal. The login pipeline reads the user of a
    /// partly logged-in session with
    /// [`pending_user_id`](Self::pending_user_id).
    ///
    /// **Prefer [`snapshot`](Self::snapshot)** when the handler needs more
    /// than one identity field; a single `snapshot().await` acquires the
    /// read lock once and returns `user_id` + `tenant_id` + `session_id` +
    /// `authn_time` together.
    #[doc(hidden)]
    pub async fn user_id(&self) -> Option<UserId> {
        let guard = self.0.0.read().await;
        match &guard.data.auth_state {
            AuthState::Authenticated { user_id, .. } => Some(*user_id),
            _ => None,
        }
    }

    /// Return the tenant ID of an authenticated session, `None` for every
    /// other state. See [`user_id`](Self::user_id).
    #[doc(hidden)]
    pub async fn tenant_id(&self) -> Option<TenantId> {
        let guard = self.0.0.read().await;
        match &guard.data.auth_state {
            AuthState::Authenticated { tenant_id, .. } => Some(*tenant_id),
            _ => None,
        }
    }

    /// Return the user ID the session is in the middle of logging in as, if
    /// any (identified, authenticating, pending a workflow or authenticated).
    ///
    /// The value is a claim until the login completes: use it for audit
    /// attribution and for driving the login pipeline, never as an
    /// authorization principal.
    pub async fn pending_user_id(&self) -> Option<UserId> {
        self.0
            .0
            .read()
            .await
            .data
            .auth_state
            .pending_user_id()
            .cloned()
    }

    /// Return the tenant ID of the login in flight, if any. See
    /// [`pending_user_id`](Self::pending_user_id).
    pub async fn pending_tenant_id(&self) -> Option<TenantId> {
        self.0.0.read().await.data.auth_state.tenant_id().cloned()
    }

    /// Return `true` if the session is fully authenticated.
    pub async fn is_authenticated(&self) -> bool {
        self.0.0.read().await.data.auth_state.is_authenticated()
    }

    /// The administrator who is impersonating the user this session is
    /// authenticated as, or `None` for an ordinary session.
    ///
    /// Set by `begin_impersonation` as part of the authenticated state, so
    /// it survives anything done to the custom data and ends only with the
    /// state (`end_impersonation`, logout, a new login). The library refuses
    /// refresh token issuance and factor enrolment or deletion for such a
    /// session unless the service was built with
    /// `with_impersonated_credential_changes_allowed`, and every audit row a
    /// request under impersonation writes names the administrator as
    /// actor. Check it before anything else an administrator should not do
    /// in a user's name. The session's authentication time is the
    /// administrator's, not a fresh login's. [`impersonation`](Self::impersonation)
    /// also says since when.
    pub async fn impersonator(&self) -> Option<UserId> {
        self.impersonation().await.map(|i| i.admin)
    }

    /// The impersonating administrator and when the impersonation began, or
    /// `None` for an ordinary session. See [`impersonator`](Self::impersonator).
    pub async fn impersonation(&self) -> Option<Impersonation> {
        self.0.0.read().await.data.auth_state.impersonation()
    }

    /// What each factor of the authenticated session proved, and when: the
    /// most recent proof of each kind. Empty for a session that is not
    /// authenticated, one that verified no factor (impersonation, signup) and
    /// one stored before the record existed. Build the Cedar `assurance`
    /// attribute from it with
    /// [`AssuranceContext::from_session`](crate::authz::assurance::AssuranceContext::from_session).
    pub async fn assurance(&self) -> Vec<crate::authn::assurance::FactorAssurance> {
        self.0.0.read().await.data.auth_state.assurance().to_vec()
    }

    /// Mark the authenticated session as `admin`'s impersonation begun at
    /// `since`. Returns `false`, changing nothing, when the session is not
    /// authenticated.
    pub(crate) async fn set_impersonator(&self, admin: UserId, since: DateTime<Utc>) -> bool {
        let mut guard = self.0.0.write().await;
        let marked = guard.data.auth_state.set_impersonator(admin, since);
        if marked {
            guard.modified = true;
        }
        marked
    }

    /// Clone the current authentication state enum (cheap; fields are `Arc<str>`).
    pub async fn auth_state(&self) -> AuthState {
        self.0.0.read().await.data.auth_state.clone()
    }

    /// Destructure an [`AuthState::Authenticating`] session into its
    /// `(user_id, tenant_id, remaining_factors)` triple. Returns `None`
    /// for any other [`AuthState`] variant (Guest / Identifying /
    /// Authenticated / PendingWorkflow).
    ///
    /// Service-side callers in the multi-factor pipeline (`begin_login`,
    /// `prepare_factor`, `verify_factor`) all need this triple to make
    /// progress and treat any other state as the canonical
    /// [`AuthnError::NoFlow`](crate::authn::error::AuthnError::NoFlow),
    /// typically `session.authenticating_state().await.ok_or(AuthnError::NoFlow)?`.
    /// This destructuring was lifted out of `AuthnService` because it
    /// has no service dependency; it belongs alongside the other
    /// session-state accessors here.
    ///
    /// Single-acquisition: the read lock is taken once and the entire
    /// triple is built under it, matching [`snapshot`](Self::snapshot)'s
    /// shape rather than the older "`auth_state().await` then match"
    /// pattern that incurred two lock acquisitions and an extra
    /// `AuthState::clone`.
    pub async fn authenticating_state(&self) -> Option<(UserId, TenantId, Vec<FactorStep>)> {
        let guard = self.0.0.read().await;
        match &guard.data.auth_state {
            AuthState::Authenticating {
                user_id,
                tenant_id,
                remaining,
                ..
            } => Some((*user_id, *tenant_id, remaining.clone())),
            _ => None,
        }
    }

    /// Return the session ID.
    ///
    /// Reading the id marks the session as needed beyond this request, so a
    /// cookieless request that keys something on the id still gets a stored
    /// session and a cookie.
    pub async fn session_id(&self) -> SessionId {
        let mut guard = self.0.0.write().await;
        guard.needs_persist = true;
        guard.id
    }

    /// Read the session id without marking the session as needed beyond
    /// this request. For observers (audit context, logging) that record the
    /// id but key nothing durable on it: calling
    /// [`session_id`](Self::session_id) there would make every cookieless
    /// request that merely passes through them store a session.
    pub(crate) async fn peek_session_id(&self) -> SessionId {
        self.0.0.read().await.id
    }

    /// Return the resolved [`crate::authn::ids::DeviceId`] for this session, if the device
    /// subsystem populated it. `None` when the `device` feature is
    /// disabled, when the resolver did not run for this request, or when
    /// the request did not match a known device.
    ///
    /// Single-acquisition read; cheap when the device subsystem is in
    /// use because `DeviceId` is a 16-byte `Copy` UUID newtype.
    pub async fn device_id(&self) -> Option<crate::authn::ids::DeviceId> {
        self.0.0.read().await.data.device_id
    }

    /// The session's device when the client proved it holds it, `None`
    /// otherwise (no device, or one a resolver found by fingerprint alone).
    ///
    /// The only reading of the session's device that a lockout exemption
    /// accepts: the per-account lockout lets an account's own device through
    /// only as a [`ProvenDevice`](crate::device::ProvenDevice), which the
    /// session layer records when the device resolver reports one (the
    /// library's [`LifecycleDeviceResolver`](crate::device::LifecycleDeviceResolver)
    /// does, on the secret token of the device cookie).
    #[cfg(feature = "device")]
    pub async fn proven_device(&self) -> Option<crate::device::ProvenDevice> {
        let inner = self.0.0.read().await;
        if inner.data.device_proven {
            inner.data.device_id.map(crate::device::ProvenDevice::new)
        } else {
            None
        }
    }

    /// Return a clone of the full session data.
    pub async fn data(&self) -> SessionData {
        self.0.0.read().await.data.clone()
    }

    /// Invoke `f` against a borrow of the current [`AuthState`]
    /// without cloning. Use this when the caller only needs to read a
    /// few fields. Avoids the full `AuthState::clone()` that
    /// [`auth_state`](Self::auth_state) performs (which clones every
    /// `Arc<str>` plus the workflow state). For `AuthState::Authenticated`
    /// in particular this halves the per-request lock-held work in
    /// authenticated handlers that just need the user id.
    ///
    /// The closure runs while the session read lock is held, so do not
    /// `await` inside it on something that needs the same lock.
    pub async fn with_auth_state<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&AuthState) -> T,
    {
        let guard = self.0.0.read().await;
        f(&guard.data.auth_state)
    }

    /// Invoke `f` against a borrow of the full [`SessionData`]
    /// without cloning. Useful when reading several fields together,
    /// where `data()` would copy more than necessary. Same lock-held
    /// caveat as [`with_auth_state`](Self::with_auth_state).
    pub async fn with_data<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&SessionData) -> T,
    {
        let guard = self.0.0.read().await;
        f(&guard.data)
    }

    /// Read all the common identity fields under a *single*
    /// read-lock acquisition. The previous pattern of calling
    /// `is_authenticated()` then `user_id()` then `tenant_id()` then
    /// `session_id()` from a typical authenticated handler took four
    /// `RwLock` reads per request: most contention-free, but each is a
    /// cross-await synchronization point. `snapshot()` collapses them
    /// into one acquisition.
    ///
    /// Returns `None` when the session is not authenticated.
    pub async fn snapshot(&self) -> Option<AuthSnapshot> {
        let guard = self.0.0.read().await;
        match &guard.data.auth_state {
            AuthState::Authenticated {
                user_id,
                tenant_id,
                authn_time,
                impersonator,
                ..
            } => Some(AuthSnapshot {
                user_id: *user_id,
                tenant_id: *tenant_id,
                session_id: guard.id,
                authn_time: *authn_time,
                impersonation: *impersonator,
            }),
            _ => None,
        }
    }

    // ── State mutation helpers ─────────────────────────────────────────────────

    /// Mark the session as fully authenticated.
    ///
    /// Cycles the session id eagerly so handler code that subsequently calls
    /// `session.session_id().await` (e.g. to register against a
    /// `SessionRegistry`) reads the post-rotation id, the same id the
    /// cookie will carry on the next request.
    ///
    /// Clears the custom data the session held before the login, so state an
    /// anonymous visitor could plant does not ride into the authenticated
    /// session. Only the key the login service owns for the flow in flight
    /// survives; the keys an application registered with
    /// `AuthnServiceBuilder::with_preserved_custom_keys` survive when the
    /// transition goes through the authentication service.
    pub(crate) async fn set_authenticated(
        &self,
        user_id: UserId,
        tenant_id: TenantId,
        authn_time: DateTime<Utc>,
    ) {
        self.set_authenticated_keeping(user_id, tenant_id, authn_time, None, &[])
            .await;
    }

    /// [`set_authenticated`](Self::set_authenticated) that records `proof`,
    /// what the transition itself verified (a federated login), and carries
    /// the custom keys in `preserved` across the transition.
    pub(crate) async fn set_authenticated_keeping(
        &self,
        user_id: UserId,
        tenant_id: TenantId,
        authn_time: DateTime<Utc>,
        proof: Option<crate::authn::assurance::FactorAssurance>,
        preserved: &[String],
    ) {
        let mut guard = self.0.0.write().await;
        // Pure state mutation lives on AuthState. Direct
        // authenticated transition (impersonation, OAuth callback, etc.)
        // (no specific factor sequence to record).
        guard
            .data
            .auth_state
            .set_authenticated_with(user_id, tenant_id, authn_time, proof);
        crate::session::data::retain_across_login(&mut guard.data.custom, preserved);
        // Bind the session fingerprint immediately so it's set before the
        // response leaves the server (prevents hijack-before-binding window).
        if guard.data.fingerprint.is_none()
            && let Some(fp) = guard.pending_fingerprint.take()
        {
            guard.data.fingerprint = Some(fp);
        }
        guard.modified = true;
        guard.rotate_id();
    }

    /// Begin a multi-factor authentication flow.
    ///
    /// Sets the state to [`AuthState::Authenticating`] with the method's steps in order.
    pub(crate) async fn begin_authenticating(
        &self,
        user_id: UserId,
        tenant_id: TenantId,
        method_name: Arc<str>,
        steps: Vec<FactorStep>,
    ) {
        let mut guard = self.0.0.write().await;
        // Pure state mutation lives on AuthState.
        guard
            .data
            .auth_state
            .begin_authenticating(user_id, tenant_id, method_name, steps);
        // A ceremony an abandoned step-up chose is not this login's.
        if let Some(custom) = guard.data.custom.as_object_mut() {
            custom.remove(crate::session::data::STEP_UP_CEREMONY_KEY);
        }
        // The id the visitor arrived with may have been planted: the partial
        // login lives under a fresh one.
        guard.rotate_id();
        // Bind fingerprint early; during Authenticating state; so that
        // mid-MFA sessions are also protected against hijacking.
        if guard.data.fingerprint.is_none()
            && let Some(fp) = guard.pending_fingerprint.take()
        {
            guard.data.fingerprint = Some(fp);
        }
        guard.modified = true;
    }

    /// Advance a multi-factor flow by removing `proof.kind` from the
    /// remaining list and recording what it proved.
    ///
    /// If `remaining` becomes empty after removal, transitions to
    /// [`AuthState::Authenticated`] automatically.
    pub(crate) async fn advance_factor(
        &self,
        proof: crate::authn::assurance::FactorAssurance,
        preserved: &[String],
    ) {
        let mut guard = self.0.0.write().await;
        // Pure state transition lives on AuthState; session-level
        // orchestration (fingerprint binding, id rotation, dirty flag) is
        // dispatched on the outcome.
        match guard.data.auth_state.advance_factor(proof) {
            AdvanceOutcome::Completed => {
                crate::session::data::retain_across_login(&mut guard.data.custom, preserved);
                // Bind fingerprint immediately on auth completion.
                if guard.data.fingerprint.is_none()
                    && let Some(fp) = guard.pending_fingerprint.take()
                {
                    guard.data.fingerprint = Some(fp);
                }
                // Cycle the id NOW so handler code that runs after
                // advance_factor (e.g. `complete_factor_step` →
                // `reg.register(user, sid)`) sees the post-rotation id.
                guard.rotate_id();
                guard.modified = true;
            }
            AdvanceOutcome::StillAuthenticating => {
                guard.modified = true;
            }
            AdvanceOutcome::NotApplicable => {
                // No-op if not in Authenticating state.
            }
        }
    }

    /// Record a failed attempt at the given time (for UI display / rate-limit feedback).
    ///
    /// Callers should supply `clock.now()` rather than `Utc::now()` so that
    /// deterministic simulation tests control the timestamp.
    ///
    /// **This does not enforce lockout**; lockout is based exclusively on the
    /// DB counter returned by `IdentityStore::record_failed_attempt`.
    ///
    /// The in-memory state is updated so the *current* response can
    /// surface attempt count / last-attempt to the UI, but we deliberately
    /// do NOT mark the session as modified. Persisting on every wrong
    /// password forces a full SessionStore save per failed login; net
    /// load on Valkey/Postgres scales with brute-force traffic, exactly
    /// the worst time to add round-trips. Applications that need
    /// cross-request "attempts remaining" UX should read the
    /// authoritative counter via `IdentityStore::account_status` /
    /// `record_failed_attempt`'s return value, not session state.
    pub(crate) async fn record_attempt_at(&self, now: DateTime<Utc>) {
        let mut guard = self.0.0.write().await;
        // Pure state mutation lives on AuthState.
        // Intentionally do NOT set `guard.modified = true`.
        guard.data.auth_state.record_attempt_at(now);
    }

    /// Return `(user_id, tenant_id)` if the session is fully authenticated, `None` otherwise.
    ///
    /// **Prefer [`snapshot`](Self::snapshot)**; it returns the full
    /// identity bundle (`user_id` + `tenant_id` + `session_id` +
    /// `authn_time`) under one lock acquisition. `authenticated_ids` is
    /// retained for the narrow case where the caller really only wants
    /// the pair.
    #[doc(hidden)]
    pub async fn authenticated_ids(&self) -> Option<(UserId, TenantId)> {
        let guard = self.0.0.read().await;
        match &guard.data.auth_state {
            AuthState::Authenticated {
                user_id, tenant_id, ..
            } => Some((*user_id, *tenant_id)),
            _ => None,
        }
    }

    /// Enter the identifying state (user has typed their username).
    ///
    /// Binds the session fingerprint early so that even pre-MFA sessions
    /// are protected against cross-device replay.
    pub async fn set_identifying(&self, user_id: UserId, tenant_id: TenantId) {
        let mut guard = self.0.0.write().await;
        // Pure state mutation lives on AuthState.
        guard.data.auth_state.set_identifying(user_id, tenant_id);
        // A planted session id must not carry the login that begins here.
        guard.rotate_id();
        // Bind fingerprint as early as possible (during Identifying state)
        // so a stolen session cookie cannot be replayed from a different device.
        if guard.data.fingerprint.is_none()
            && let Some(fp) = guard.pending_fingerprint.take()
        {
            guard.data.fingerprint = Some(fp);
        }
        guard.modified = true;
    }

    /// Transition to a pending workflow state.
    pub async fn set_pending_workflow(
        &self,
        user_id: UserId,
        tenant_id: TenantId,
        workflow: WorkflowState,
    ) {
        let mut guard = self.0.0.write().await;
        // Pure state mutation lives on AuthState.
        guard
            .data
            .auth_state
            .set_pending_workflow(user_id, tenant_id, workflow);
        // A planted session id must not carry the workflow that begins here.
        guard.rotate_id();
        // Bind the fingerprint, as the other partial-login setters do, so the
        // pending-workflow cookie cannot be replayed from another client.
        if guard.data.fingerprint.is_none()
            && let Some(fp) = guard.pending_fingerprint.take()
        {
            guard.data.fingerprint = Some(fp);
        }
        guard.modified = true;
    }

    /// Clear the session (logout). Resets state to `Guest`, marks it as
    /// modified and cycles the session id, so the identifier that carried the
    /// authenticated session is retired with it and cannot be replayed or
    /// fixed by an attacker who knew it.
    pub async fn clear(&self) {
        let mut guard = self.0.0.write().await;
        guard.data = SessionData::default();
        guard.modified = true;
        guard.rotate_id();
    }

    /// Cycle the session ID immediately.
    ///
    /// Mints a new id, swaps it in, and stashes the old id for the layer to
    /// `store.cycle` on the way out. Idempotent within a single request;
    /// calling twice still rotates only once.
    ///
    /// Call at any **privilege boundary**; i.e. any change to the
    /// session's authentication context, scope, or subject identity.
    /// Login (`RequestAuthnService::verify_factor` completing a factor chain
    /// with `FactorOutcome::Authenticated`) and OAuth callback finish
    /// are cycled inside the library; every other boundary listed below
    /// is the app's call. Canonical list (OWASP ASVS V3, OWASP Session
    /// Management Cheat Sheet, NIST SP 800-63B AAL transitions):
    ///
    /// - MFA factor added (TOTP, WebAuthn, recovery codes, …)
    /// - MFA factor removed or disabled (AAL drops)
    /// - Password / primary-credential change
    /// - Step-up to a higher assurance level
    /// - Account-recovery flow completion
    /// - Impersonation start / stop
    /// - Role grant / revoke or scope change
    /// - Tenant switch in a multi-tenant deployment
    ///
    /// Do *not* call on routine writes (profile edit, factor config
    /// tuning, theme change); rotating churns the cookie and the
    /// store without any security benefit.
    ///
    /// On credential changes (password change, recovery completion)
    /// consider also revoking sibling sessions via
    /// [`SessionRegistry::invalidate_user`](crate::session::store::SessionRegistry::invalidate_user);
    /// that is a strictly
    /// stronger statement than rotation and cuts off other devices
    /// still holding a stale credential-derived cookie.
    ///
    /// See `docs/sessions/lifecycle.md` for the full rationale and
    /// the "library can't hook this for you" discussion.
    pub async fn regenerate(&self) {
        let mut guard = self.0.0.write().await;
        guard.rotate_id();
        guard.modified = true;
    }

    /// Read a value from the custom JSON bag.
    pub async fn get_custom(&self, key: &str) -> Option<serde_json::Value> {
        self.0.0.read().await.data.custom.get(key).cloned()
    }

    /// Wipe the entire custom JSON bag in one shot. Used at privilege
    /// boundaries (e.g., admin impersonation) where the previous session's
    /// app-controlled custom data must not leak into the assumed identity:
    /// pre-seeded OAuth ceremony state in `custom` could otherwise be used
    /// to hijack a subsequent OAuth flow under the new principal.
    pub async fn clear_custom(&self) {
        let mut guard = self.0.0.write().await;
        guard.data.custom = serde_json::Value::Object(serde_json::Map::new());
        guard.modified = true;
    }

    /// Remove a key from the custom JSON bag. Returns `true` if a key was
    /// removed. Use this rather than `set_custom(k, Value::Null)` so the
    /// JSON object stays compact; repeated nulled-out keys would otherwise
    /// monotonically grow until the size cap clears the whole bag.
    pub async fn remove_custom(&self, key: &str) -> bool {
        let mut guard = self.0.0.write().await;
        let removed = guard
            .data
            .custom
            .as_object_mut()
            .is_some_and(|obj| obj.remove(key).is_some());
        if removed {
            guard.modified = true;
        }
        removed
    }

    /// Run `f` against a mutable borrow of the custom-bag JSON
    /// object under a single write-lock acquisition. Returns the value
    /// produced by `f`. Marks the session modified if `f` actually
    /// mutated the bag (judged by JSON-byte-length comparison).
    ///
    /// Use this in place of a series of `remove_custom`/`set_custom`
    /// calls when several edits must appear atomic to a concurrent
    /// reader. The original sequence in `clear_oauth_state` issued six
    /// independent `remove_custom` calls; a parallel `set_custom` racing
    /// in between could re-introduce a key after it had already been
    /// removed.
    ///
    /// `f` runs while the write lock is held; do not `await` inside it
    /// on something that needs the same lock.
    pub async fn mutate_custom<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&mut serde_json::Map<String, serde_json::Value>) -> T,
    {
        let mut guard = self.0.0.write().await;
        // Ensure `custom` is an object so callers can rely on the borrow.
        if !guard.data.custom.is_object() {
            guard.data.custom = serde_json::Value::Object(serde_json::Map::new());
        }
        // Compared by VALUE, not by serialized length: a nonce rotated to one
        // of the same length, or an OAuth state swapped for another, changes
        // nothing in the length and everything in the bag.
        let before = guard.data.custom.clone();
        let obj = guard
            .data
            .custom
            .as_object_mut()
            .expect("custom forced to object above");
        let result = f(obj);
        if guard.data.custom != before {
            guard.modified = true;
        }
        result
    }

    /// Atomically read **and remove** a key from the custom JSON bag.
    ///
    /// Returns the removed value, or `None` if the key was absent. Of any
    /// number of requests, in this process or on other nodes, that hold the
    /// same stored session, exactly one gets the value: the removal is first
    /// written to the session store as a compare-and-swap on the session's
    /// revision, and a request that loses it gets `None`. Use this in
    /// preference to `get_custom(k).await` followed by `remove_custom(k)`
    /// for any one-shot ceremony state (FIDO2 `auth_state`, OAuth PKCE
    /// verifier, password-reset token, etc.).
    ///
    /// A store that cannot answer, or a session that was ended meanwhile,
    /// also gives `None`: the ceremony has to be started again, it never
    /// runs twice. Every write of a stored session is a compare-and-swap on
    /// its revision, so an unrelated request that loaded the session before
    /// the value was taken does not put it back when it saves: its write
    /// finds the row changed and merges its own changes onto the stored row,
    /// in which the value is gone.
    pub async fn take_custom(&self, key: &str) -> Option<serde_json::Value> {
        self.0.0.write().await.consume_custom(key).await
    }

    /// Store a value in the custom JSON bag.
    ///
    /// Returns `false` if the write would exceed the configured
    /// `max_custom_bytes` limit; the value is not stored in that case.
    pub async fn set_custom(&self, key: impl Into<String>, value: serde_json::Value) -> bool {
        let mut guard = self.0.0.write().await;
        guard.set_custom_value(key.into(), value)
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

    // `_state: &S` is the single documented carve-out from the workspace's
    // "no `_`-prefixed names" rule. `FromRequestParts<S>` is axum's trait,
    // so the parameter shape is fixed; `S` is unconstrained (only `Send +
    // Sync` auto-traits) so no method can be called on it, no `tracing` use
    // is possible, and `drop(state)` triggers `drop_ref` on the `&S` borrow.
    // Renaming to `_state` is the language-idiomatic way to express "trait
    // requires this; this impl genuinely cannot use it" without resorting
    // to `#[allow(unused_variables)]` or `core::hint::black_box`.
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<SessionHandle>()
            .cloned()
            .map(AuthSession)
            .ok_or(SessionMissing)
    }
}

#[cfg(test)]
mod tests;
