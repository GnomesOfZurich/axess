//! Axum request extractor providing typed, mutable session access.
//!
//! [`AuthSession`] is the primary API surface for handlers. Changes are flushed
//! to the session store by the [`SessionLayer`](super::layer::SessionLayer) middleware after the handler returns.

use crate::authn::factor::FactorStep;
use crate::authn::ids::{TenantId, UserId};
use crate::session::{
    data::{AdvanceOutcome, AuthState, Impersonation, SessionData, WorkflowState},
    id::SessionKey,
    layer::SessionHandle,
};
use axess_clock::Timestamp;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
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
/// async fn handler(
///     session: AuthSession,
///     user: UserId,
///     tenant: TenantId,
///     now: axess_clock::Timestamp,
/// ) {
///     session.set_authenticated(user, tenant, now).await;
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
    /// The key of the session: the name its store row, its registry entry
    /// and its audit records carry. The session's id, the value its cookie
    /// carries, is held by the session layer alone.
    pub session_key: SessionKey,
    /// When the person last proved presence: the login, or the latest
    /// step-up. What recency checks read.
    pub authn_time: Timestamp,
    /// When the login that created the session completed: what the
    /// absolute age cap counts from. A step-up does not move it.
    pub signed_in_at: Timestamp,
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
    /// read lock once and returns `user_id` + `tenant_id` + `session_key` +
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
    /// in a user's name. The session's authentication time and its login
    /// time are the administrator's, not a fresh login's, and so is its
    /// device: the browser is the administrator's, and nothing about it is
    /// recorded for the user. [`impersonation`](Self::impersonation) also
    /// says since when.
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
    pub(crate) async fn set_impersonator(&self, admin: UserId, since: Timestamp) -> bool {
        let mut guard = self.0.0.write().await;
        let marked = guard.data.auth_state.set_impersonator(admin, since);
        if marked {
            guard.modified = true;
        }
        marked
    }

    /// Keep `at` as the login time of the authenticated session (see
    /// `AuthState::keep_signed_in_at`). Returns `false`, changing nothing,
    /// when the session is not authenticated.
    pub(crate) async fn keep_signed_in_at(&self, at: Timestamp) -> bool {
        let mut guard = self.0.0.write().await;
        let kept = guard.data.auth_state.keep_signed_in_at(at);
        if kept {
            guard.modified = true;
        }
        kept
    }

    /// Clone the current authentication state enum. The ids in it are
    /// `Copy` and the method name is an `Arc<str>`; a login in flight also
    /// clones its lists of remaining and completed factors.
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

    /// The key this session is stored, registered and recorded under, and
    /// the one name of the session a handler can read: the session's id,
    /// the value its cookie carries, never leaves the session layer.
    ///
    /// Reading the key marks the session as needed beyond this request, so
    /// a cookieless request that keys something on it still gets a stored
    /// session and a cookie.
    pub async fn session_key(&self) -> SessionKey {
        let mut guard = self.0.0.write().await;
        guard.needs_persist = true;
        *guard.session.key()
    }

    /// The key without the mark, for observers (the audit context) that
    /// record the session but key nothing durable on it: calling
    /// [`session_key`](Self::session_key) there would make every cookieless
    /// request that merely passes through them store a session.
    pub(crate) async fn peek_session_key(&self) -> SessionKey {
        *self.0.0.read().await.session.key()
    }

    /// Return the resolved [`crate::authn::ids::DeviceId`] for this session, if the device
    /// subsystem populated it and it holds for the person at the session's
    /// browser. `None` when the `device` feature is disabled, when the
    /// resolver did not run for this request, when the request did not
    /// match a known device, and for the rest of a request in which another
    /// person signed in on a signed-in session: the device was resolved for
    /// the first person. [`data`](Self::data) shows the raw field.
    ///
    /// Single-acquisition read; cheap when the device subsystem is in
    /// use because `DeviceId` is a 16-byte `Copy` UUID newtype.
    pub async fn device_id(&self) -> Option<crate::authn::ids::DeviceId> {
        self.0.0.read().await.device_in_force()
    }

    /// Whether this request runs as a session bound to a device key and
    /// proved that key: the session's
    /// [`key_binding`](crate::session::SessionData::key_binding) names the
    /// tenant, the device and the key, and the session layer verified a
    /// proof by exactly that key on this request (a proof cookie, or a
    /// request proof), whether or not the request also presented the
    /// device's token. Only a binding in force counts
    /// ([`SessionData::key_binding_in_force`]): `false` from the moment
    /// another person signs in or a new login begins on the session, in the
    /// same request. `false` for a session that is not bound, and for a
    /// bound one served without a proof, which happens only under
    /// [`KeyBindingPolicy::Off`](crate::device_key::KeyBindingPolicy). On
    /// the request that registers a key it is still `false`: the binding is
    /// made by that request, and proven from the next. What a Cedar policy
    /// reads through
    /// [`StandardRequestContext::with_key_bound`](crate::authz::StandardRequestContext::with_key_bound).
    pub async fn key_bound(&self) -> bool {
        let inner = self.0.0.read().await;
        let data = &inner.data;
        data.key_binding_in_force().is_some() && data.key_proven
    }

    /// Return a clone of the full session data: the row as the request
    /// holds it, before the judgements the readers above make. A key
    /// binding or a device that does not hold for the person at the browser
    /// still shows here until the row is written; ask
    /// [`key_bound`](Self::key_bound) and [`device_id`](Self::device_id).
    pub async fn data(&self) -> SessionData {
        self.0.0.read().await.data.clone()
    }

    /// Invoke `f` against a borrow of the current [`AuthState`]
    /// without cloning. Use this when the caller only needs to read a
    /// few fields. Avoids the full `AuthState::clone()` that
    /// [`auth_state`](Self::auth_state) performs (which clones the method
    /// name, the factor lists and the workflow state). For `AuthState::Authenticated`
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
    /// caveat as [`with_auth_state`](Self::with_auth_state). The data is the
    /// raw row, as [`data`](Self::data) says.
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
    /// `session_key()` from a typical authenticated handler took four
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
                signed_in_at,
                impersonator,
                ..
            } => Some(AuthSnapshot {
                user_id: *user_id,
                tenant_id: *tenant_id,
                session_key: *guard.session.key(),
                authn_time: *authn_time,
                signed_in_at: *signed_in_at,
                impersonation: *impersonator,
            }),
            _ => None,
        }
    }

    // ── State mutation helpers ─────────────────────────────────────────────────

    /// Mark the session as fully authenticated.
    ///
    /// Cycles the session id eagerly so handler code that subsequently calls
    /// `session.session_key().await` (e.g. to register against a
    /// `SessionRegistry`) reads the post-rotation key, the key of the id the
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
        authn_time: Timestamp,
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
        authn_time: Timestamp,
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
    /// Callers should supply `clock.now()` rather than a read of the system
    /// clock so that deterministic simulation tests control the timestamp.
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
    pub(crate) async fn record_attempt_at(&self, now: Timestamp) {
        let mut guard = self.0.0.write().await;
        // Pure state mutation lives on AuthState.
        // Intentionally do NOT set `guard.modified = true`.
        guard.data.auth_state.record_attempt_at(now);
    }

    /// Return `(user_id, tenant_id)` if the session is fully authenticated, `None` otherwise.
    ///
    /// **Prefer [`snapshot`](Self::snapshot)**; it returns the full
    /// identity bundle (`user_id` + `tenant_id` + `session_key` +
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
    /// `store.cycle` on the way out. A second call in the same request
    /// mints another id, and the response still makes one move in the
    /// store, from the id the request arrived with to the last one minted.
    ///
    /// Call at any **privilege boundary**; i.e. any change to the
    /// session's authentication context, scope, or subject identity.
    /// The library cycles the id itself at every state transition of the
    /// session (the start of a login, each completed factor chain, which
    /// is how a login and a step-up through `verify_factor` end, a
    /// workflow step, `clear`), at the OAuth callback finish, and when an
    /// impersonation begins and ends. Every other boundary listed below
    /// is the app's call. Canonical list (OWASP ASVS V3, OWASP Session
    /// Management Cheat Sheet, NIST SP 800-63B AAL transitions):
    ///
    /// - MFA factor added (TOTP, WebAuthn, recovery codes, …)
    /// - MFA factor removed or disabled (AAL drops)
    /// - Password / primary-credential change
    /// - Step-up to a higher assurance level by a path of your own
    /// - Account-recovery flow completion
    /// - Role grant / revoke or scope change
    /// - Tenant switch in a multi-tenant deployment
    ///
    /// Do *not* call on routine writes (profile edit, factor config
    /// tuning, theme change); rotating churns the cookie and the
    /// store without any security benefit.
    ///
    /// On credential changes (password change, recovery completion)
    /// consider also revoking sibling sessions via
    /// [`RequestAuthnService::invalidate_other_sessions`](crate::authn::RequestAuthnService::invalidate_other_sessions),
    /// which keeps the caller's session, or
    /// [`SessionRegistry::invalidate_user`](crate::session::store::SessionRegistry::invalidate_user),
    /// which ends it with the rest; either is a strictly
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
    /// mutated the bag (the bag is compared with a copy taken before `f`
    /// ran).
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

    // The trait fixes the state parameter and this extractor reads none of
    // it, so it is taken as `_`.
    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<SessionHandle>()
            .cloned()
            .map(AuthSession)
            .ok_or(SessionMissing)
    }
}

#[cfg(feature = "device")]
mod device;
mod registered;
#[cfg(test)]
mod tests;
