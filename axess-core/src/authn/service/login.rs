//! Login flow: begin_login, prepare_factor, verify_factor, check_session, logout.

use super::factor_pipeline::GuessSlot;
use super::outcomes::{FactorOutcome, LoginOutcome, PrepareOutcome};
use crate::authn::types::{Tenant, User};
use crate::authn::{
    error::AuthnError,
    event::{AuthEventBuilder, AuthEventType, AuthFailureReason},
    factor::{FactorCredential, FactorKind, FactorStep},
    store::{FactorStore, IdentityStore},
    types::EntityState,
};
#[cfg(feature = "fido2")]
use crate::authn::{factor::FactorConfig, types::AuthnScope};
use crate::session::extractor::AuthSession;
use crate::session::store::note_revocation;
use std::ops::ControlFlow;
use std::sync::Arc;

/// The method and steps a login begins with.
struct FirstFactor {
    method_name: Arc<str>,
    steps: Vec<FactorStep>,
    first_kind: FactorKind,
}

impl<I, F> super::RequestAuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Begin the login flow for an identifier (username/email) within a tenant.
    ///
    /// Looks up the user, checks account status, and begins the first factor.
    /// Updates the session to `Authenticating`.
    ///
    /// Returns a [`LoginOutcome`] describing what the UI should do next.
    #[tracing::instrument(skip(self, identifier, session), fields(tenant = %tenant_identifier))]
    pub async fn begin_login(
        &self,
        identifier: &str,
        tenant_identifier: &str,
        session: &AuthSession,
    ) -> Result<LoginOutcome, AuthnError<I::Error>> {
        use crate::validation::MAX_IDENTIFIER_BYTES;

        self.inner.metrics.auth_attempt();

        // 0. Reject oversized identifiers before hitting the database.
        if identifier.is_empty()
            || identifier.len() > MAX_IDENTIFIER_BYTES
            || tenant_identifier.is_empty()
            || tenant_identifier.len() > MAX_IDENTIFIER_BYTES
        {
            self.inner.metrics.auth_failure();
            return Ok(LoginOutcome::InvalidCredentials);
        }

        let tenant = match self.admit_tenant(identifier, tenant_identifier).await? {
            ControlFlow::Continue(tenant) => tenant,
            ControlFlow::Break(outcome) => return Ok(outcome),
        };
        let user = match self
            .find_loginnable_user(identifier, &tenant, session)
            .await?
        {
            ControlFlow::Continue(user) => user,
            ControlFlow::Break(outcome) => return Ok(outcome),
        };
        let first = match self.select_first_factor(&user, &tenant).await? {
            ControlFlow::Continue(first) => first,
            ControlFlow::Break(outcome) => return Ok(outcome),
        };

        // The epoch the flow is begun against, read before anything moves.
        let epoch = self
            .credential_epoch(&user.id, &tenant.id, &first.method_name)
            .await?;

        // 5. Record the login attempt BEFORE the session moves: a failed
        // audit write fails the call with the session untouched, where the
        // other order left it in `Authenticating` and the flow could carry
        // on with no audit row.
        self.emit_audit(
            AuthEventBuilder::success(AuthEventType::LoginAttempt)
                .attributed_to(&user.id, &tenant.id)
                .with_factor(first.first_kind.clone()),
        )
        .await?;

        // 6. Begin the authentication flow in the session.
        self.stamp_flow(session, &first.method_name, epoch).await;
        session
            .begin_authenticating(user.id, tenant.id, first.method_name, first.steps)
            .await;

        Ok(LoginOutcome::FactorRequired(first.first_kind))
    }

    /// Look the user up and require an account status that allows login.
    ///
    /// Breaks with the outcome for an unknown identifier
    /// ([`LoginOutcome::InvalidCredentials`]), for a non-active account
    /// (the same outcome, so the account's state is not observable) and for
    /// a locked account, whether the lock is a suspension the store reports
    /// or one derived from the failure counter: the same outcome again by
    /// default, so the lock is not observable either, or
    /// [`LoginOutcome::Locked`] when the service was built with
    /// [`with_lockout_revealed_on_begin`](super::AuthnServiceBuilder::with_lockout_revealed_on_begin).
    /// Each refusal emits its audit row, a lockout's with status `Locked`.
    async fn find_loginnable_user(
        &self,
        identifier: &str,
        tenant: &Tenant,
        session: &AuthSession,
    ) -> Result<ControlFlow<LoginOutcome, User>, AuthnError<I::Error>> {
        // 2. Find user with timing equalization; when the identifier is
        // unknown OR the returned User fails validation, the helper
        // still runs the same store queries the happy path would,
        // against a fresh-UUID dummy id, so DB latency doesn't leak
        // whether the identifier exists. See helper for the full
        // security argument.
        let user = match self
            .find_user_with_timing_equalization(identifier, &tenant.id)
            .await?
        {
            Some(u) => u,
            None => {
                self.inner.metrics.auth_failure();
                // Tenant-attributed but userless: the tenant is real and
                // the identifier is not. See the unknown-tenant branch
                // above for why this emits rather than returning quietly.
                self.emit_audit(
                    AuthEventBuilder::failure(AuthEventType::LoginAttempt)
                        .maybe_attributed_to(None, Some(&tenant.id))
                        .with_error(AuthFailureReason::UnknownIdentifier),
                )
                .await?;
                return Ok(ControlFlow::Break(LoginOutcome::InvalidCredentials));
            }
        };

        // 3. Check account status, then the lockout the failure counter
        // imposes. Both are read for every known user, in the order the
        // unknown-identifier path reads its dummies, so a barred account
        // costs the same store calls as a permitted one.
        let status = self.current_account_status(&user.id).await?;
        let derived = if status.allows_login() {
            self.derived_lockout_for(&user.id, &tenant.id, session)
                .await?
        } else {
            let _ = self.inner.identity.failed_attempts(&user.id).await;
            None
        };

        if !status.allows_login() || derived.is_some() {
            // Same fourth call the unknown path makes.
            let _ = self
                .inner
                .factors
                .available_methods(&user.id, &tenant.id)
                .await;
            self.inner.metrics.auth_failure();
            // Emit a `Failure(LoginAttempt)` audit row before returning so
            // a fresh session probing a known-locked account leaves a SOC
            // trail. A lockout carries `Locked` rather than `Failure`, so a
            // dashboard separates brute-force probes from
            // administrative-state mismatches on the status column instead
            // of on a free-text tag. The other non-active states keep the
            // tag, having no status of their own.
            let locked = status.is_suspended() || derived.is_some();
            let builder = if locked {
                AuthEventBuilder::locked(AuthEventType::LoginAttempt)
            } else {
                AuthEventBuilder::failure(AuthEventType::LoginAttempt)
                    .with_error(AuthFailureReason::NotActive)
            };
            self.emit_audit(builder.attributed_to(&user.id, &tenant.id))
                .await?;
            if locked {
                self.inner.metrics.account_locked();
                if !self.inner.reveal_lockout_on_begin {
                    // The caller has proved nothing yet; `Locked` would tell
                    // them the account exists and is being guessed at. The
                    // audit row above carries the lockout.
                    return Ok(ControlFlow::Break(LoginOutcome::InvalidCredentials));
                }
                // Surface the lockout expiry so UIs can render
                // "locked until X" on the begin path.
                let until = match (&status, derived) {
                    (EntityState::Suspended(detail), _) => detail.until,
                    (_, Some(lock)) => lock.until,
                    _ => None,
                };
                return Ok(ControlFlow::Break(LoginOutcome::Locked { until }));
            }
            // A suspended-for-other-reasons, pending or terminated account
            // answers like an unknown identifier: a distinct 403 here made
            // account existence and state observable from the first
            // request. The audit row above carries the real reason.
            return Ok(ControlFlow::Break(LoginOutcome::InvalidCredentials));
        }
        Ok(ControlFlow::Continue(user))
    }

    /// Pick the user's first available authentication method and its steps.
    ///
    /// Breaks with [`LoginOutcome::InvalidCredentials`] when the user has no
    /// method, or none with a usable step, after emitting the audit row.
    async fn select_first_factor(
        &self,
        user: &User,
        tenant: &Tenant,
    ) -> Result<ControlFlow<LoginOutcome, FirstFactor>, AuthnError<I::Error>> {
        // 4. Load available authentication methods.
        let methods = self
            .inner
            .factors
            .available_methods(&user.id, &tenant.id)
            .await
            .map_err(AuthnError::Store)?;

        // The first method whose every step has a primary factor. A method
        // with a step that has none (an empty `AnyOf`, say) is skipped whole,
        // rather than ending the login while a later method is usable: dropping
        // only that step would let the login pass with fewer steps than the
        // method requires.
        let usable = methods
            .into_iter()
            .find(crate::authn::store::AuthMethod::is_complete)
            .map(|method| (method.name, method.steps));

        // No method, or none with a usable step, has to emit, for the same
        // reason every other branch here does. A known account with no
        // usable method would otherwise be the one outcome that leaves no
        // audit row, and during an audit-store outage the one that still
        // succeeds while every other path fails, which is an enumeration
        // signal, narrow but of exactly the shape this flow was rewritten
        // to remove.
        let Some((method_name, steps)) = usable else {
            self.inner.metrics.auth_failure();
            self.emit_audit(
                AuthEventBuilder::failure(AuthEventType::LoginAttempt)
                    .attributed_to(&user.id, &tenant.id)
                    .with_error(AuthFailureReason::NoFactorsConfigured),
            )
            .await?;
            // Same answer as an unknown identifier. `NoFlow` here told a
            // caller that the account exists and has nothing configured.
            return Ok(ControlFlow::Break(LoginOutcome::InvalidCredentials));
        };

        let first_kind = steps[0].primary().cloned().ok_or(AuthnError::NoFlow)?;
        Ok(ControlFlow::Continue(FirstFactor {
            method_name,
            steps,
            first_kind,
        }))
    }

    /// Refuse a login attempt that is turned away before any user is known.
    ///
    /// Every such refusal, whatever its cause, makes the same store calls in
    /// the same order as a permitted request naming an identifier that does
    /// not exist, and answers with the same [`LoginOutcome::InvalidCredentials`]:
    ///
    /// 1. `ip_policy_for_tenant`, against the real tenant earlier in the flow
    ///    when `policy_read` is true, and otherwise here against a throwaway
    ///    tenant id (the unknown, malformed and suspended tenant refusals
    ///    never reach the real read);
    /// 2. the user lookup, `account_status` and `available_methods` against
    ///    throwaway ids (see [`find_user_with_timing_equalization`](Self::find_user_with_timing_equalization));
    /// 3. the metric, then one audit row carrying `reason`.
    ///
    /// A caller who can tell these refusals apart by latency, or by whether an
    /// audit row was written, learns whether a tenant exists, is suspended, or
    /// has an IP allowlist. Lookup errors are discarded for the same reason: a
    /// store hiccup on the throwaway ids must not show as a different answer.
    /// No password hash runs on any of these paths, so there is nothing to
    /// equalize there.
    ///
    /// `attributed_tenant` names the tenant on the audit row when there is
    /// one; an unknown tenant has none.
    async fn reject_pre_user(
        &self,
        identifier: &str,
        attributed_tenant: Option<&crate::authn::ids::TenantId>,
        reason: AuthFailureReason,
        policy_read: bool,
    ) -> Result<LoginOutcome, AuthnError<I::Error>> {
        let dummy_tenant = self.dummy_tenant_id();
        if !policy_read {
            let _ = self
                .inner
                .identity
                .ip_policy_for_tenant(&dummy_tenant)
                .await;
        }
        let _ = self
            .find_user_with_timing_equalization(identifier, &dummy_tenant)
            .await;
        self.inner.metrics.auth_failure();
        self.emit_audit(
            AuthEventBuilder::failure(AuthEventType::LoginAttempt)
                .maybe_attributed_to(None, attributed_tenant)
                .with_error(reason),
        )
        .await?;
        Ok(LoginOutcome::InvalidCredentials)
    }

    /// Prepare the current factor challenge, if the factor kind requires it.
    ///
    /// Call this after `begin_login` (or after a successful `verify_factor`
    /// that returns `FactorRequired`) to set up the next factor step.
    ///
    /// - **Password / TOTP / HOTP** → returns [`PrepareOutcome::Ready`].
    ///   The UI can show the input form immediately.
    /// - **EmailOtp** → generates a random code, hashes it with Argon2id,
    ///   persists it in the factor store, and returns
    ///   [`PrepareOutcome::SendOtp`] with the plaintext code and the
    ///   destination email. The application is responsible for delivering the
    ///   code (via SMTP, SendGrid, etc.).
    /// - **Fido2** → placeholder, currently returns `Ready`.
    ///
    /// The session must be in [`AuthState::Authenticating`](crate::session::data::AuthState::Authenticating).
    #[tracing::instrument(skip(self, session))]
    pub async fn prepare_factor(
        &self,
        session: &AuthSession,
    ) -> Result<PrepareOutcome, AuthnError<I::Error>> {
        self.prepare_factor_for(session, None).await
    }

    /// Prepare the factor the user picked at the current step.
    ///
    /// Like [`prepare_factor`](Self::prepare_factor), but for a step the
    /// user may satisfy in several ways ([`FactorStep::AnyOf`]): `choice`
    /// is the factor to prepare, so an email code or a passkey challenge
    /// can be issued even when it is not the step's first choice. A
    /// `choice` the current step does not accept is refused with
    /// [`AuthnError::NoFlow`].
    #[tracing::instrument(skip(self, session))]
    pub async fn prepare_factor_choice(
        &self,
        session: &AuthSession,
        choice: FactorKind,
    ) -> Result<PrepareOutcome, AuthnError<I::Error>> {
        self.prepare_factor_for(session, Some(choice)).await
    }

    async fn prepare_factor_for(
        &self,
        session: &AuthSession,
        choice: Option<FactorKind>,
    ) -> Result<PrepareOutcome, AuthnError<I::Error>> {
        use super::factor_pipeline::AccountStatusEnforcement;

        let (user_id, tenant_id, remaining) = session
            .authenticating_state()
            .await
            .ok_or(AuthnError::NoFlow)?;
        self.require_current_flow(session, &user_id, &tenant_id)
            .await?;

        // A locked/suspended (or otherwise non-Active) account must not
        // trigger challenge delivery (e.g. OTP email sends). The
        // The audit row on `Locked` is emitted by
        // `enforce_account_status` itself.
        match self
            .enforce_account_status(
                &user_id,
                &tenant_id,
                remaining.first().and_then(FactorStep::primary).cloned(),
                session,
            )
            .await?
        {
            AccountStatusEnforcement::Ok => {}
            // Distinguish locked (suspension) from other
            // non-Active states. UIs can render the lockout expiry
            // for `Locked` and a generic "account not active" for
            // the rest. The earlier behaviour collapsed both into
            // `NotActive(status)`, forcing UIs to deep-pattern-match
            // `EntityState::Suspended(StatusDetail { until, .. })`
            // to render the expiry; the new shape exposes `until`
            // at the top level.
            AccountStatusEnforcement::Locked { until, .. } => {
                return Err(AuthnError::Locked { until });
            }
            // A throttled guesser does not get a challenge delivered either.
            AccountStatusEnforcement::Throttled { retry_after } => {
                return Err(AuthnError::Throttled { retry_after });
            }
            AccountStatusEnforcement::NotActive(status) => {
                return Err(AuthnError::NotActive(status));
            }
        }

        let step = remaining.first().ok_or(AuthnError::NoFlow)?;
        let picked_by_person = choice.is_some();
        let current_kind = match choice {
            Some(kind) if step.accepts(&kind) => kind,
            Some(_) => return Err(AuthnError::NoFlow),
            None => step.primary().ok_or(AuthnError::NoFlow)?.clone(),
        };

        // What the person picks is remembered for `verify_factor`; asking for
        // the step's default forgets an earlier pick.
        let picked = picked_by_person.then_some(&current_kind);
        if !Self::record_chosen_factor(session, &user_id, remaining.len(), picked).await {
            return Err(AuthnError::NoFlow);
        }

        match current_kind {
            FactorKind::Password
            | FactorKind::Totp
            | FactorKind::Hotp
            | FactorKind::LdapBind
            | FactorKind::RecoveryCode => Ok(PrepareOutcome::Ready),

            FactorKind::EmailOtp => self.prepare_email_otp(&tenant_id, &user_id).await,

            FactorKind::Fido2 => {
                #[cfg(feature = "fido2")]
                {
                    self.prepare_fido2(session, &tenant_id, &user_id).await
                }

                #[cfg(not(feature = "fido2"))]
                {
                    Ok(PrepareOutcome::Ready)
                }
            }

            FactorKind::Federated(_) => {
                // Federated auth is handled externally (OAuth redirect flow).
                Ok(PrepareOutcome::Ready)
            }
        }
    }

    /// Start a WebAuthn authentication ceremony for the current `Fido2` step.
    ///
    /// Without a configured relying party the step is `Ready`; otherwise the
    /// ceremony state and its start time go into the session and the
    /// challenge is returned for the browser.
    #[cfg(feature = "fido2")]
    async fn prepare_fido2(
        &self,
        session: &AuthSession,
        tenant_id: &crate::authn::ids::TenantId,
        user_id: &crate::authn::ids::UserId,
    ) -> Result<PrepareOutcome, AuthnError<I::Error>> {
        let webauthn = match &self.inner.fido2 {
            Some(w) => w,
            None => return Ok(PrepareOutcome::Ready),
        };

        // Load stored credentials.
        let user_scope = AuthnScope::User {
            tenant_id: *tenant_id,
            user_id: *user_id,
        };
        let config = self
            .inner
            .factors
            .resolve_factor(&user_scope, FactorKind::Fido2)
            .await
            .map_err(AuthnError::Store)?
            .ok_or(AuthnError::NoFlow)?
            .config;

        let FactorConfig::Fido2(cfg) = &config else {
            return Err(AuthnError::NoFlow);
        };

        if cfg.credentials.is_empty() {
            return Err(AuthnError::NoFlow);
        }

        // Extract raw passkeys for the ceremony.
        let passkeys: Vec<_> = cfg.credentials.iter().map(|c| c.passkey.clone()).collect();

        // Start the authentication ceremony.
        let (challenge, auth_state) = webauthn.start_authentication(&passkeys).map_err(|e| {
            tracing::warn!("FIDO2 start_passkey_authentication failed: {e:?}");
            AuthnError::NoFlow
        })?;

        // Store the ceremony state and timestamp in the session.
        let state_json = serde_json::to_value(&auth_state).map_err(|_| AuthnError::NoFlow)?;
        if !session.set_custom(fido2_keys::AUTH_STATE, state_json).await {
            // The ceremony state did not fit; a challenge handed out without
            // it could never be finished.
            return Err(AuthnError::NoFlow);
        }
        self.stamp_ceremony_start(session, fido2_keys::AUTH_STATE)
            .await?;

        let challenge_json = serde_json::to_value(&challenge).map_err(|_| AuthnError::NoFlow)?;
        Ok(PrepareOutcome::Fido2Challenge {
            challenge: challenge_json,
        })
    }

    /// Verify a factor credential during an in-progress authentication flow.
    ///
    /// The session must be in [`AuthState::Authenticating`](crate::session::data::AuthState::Authenticating).
    /// Returns a [`FactorOutcome`] describing the next step.
    #[tracing::instrument(skip(self, credential, session))]
    pub async fn verify_factor(
        &self,
        credential: &FactorCredential,
        session: &AuthSession,
    ) -> Result<FactorOutcome, AuthnError<I::Error>> {
        let (user_id, tenant_id, remaining) = session
            .authenticating_state()
            .await
            .ok_or(AuthnError::NoFlow)?;
        self.require_current_flow(session, &user_id, &tenant_id)
            .await?;

        let prepared = match self
            .prepare_factor_step(credential, &user_id, &tenant_id, &remaining, session)
            .await?
        {
            Ok(prepared) => prepared,
            Err(outcome) => return Ok(outcome),
        };

        // FIDO2 + LDAP have their own verification methods (different
        // ceremony shape, network call) and short-circuit with their
        // own FactorOutcome. The local-hash factors continue below.
        #[cfg(feature = "fido2")]
        if prepared.current_kind == FactorKind::Fido2 {
            return self
                .verify_fido2_factor(
                    credential,
                    &prepared.config,
                    &prepared.user_scope,
                    &user_id,
                    &tenant_id,
                    session,
                )
                .await;
        }
        // The guess is counted before the verifier runs, so parallel guesses
        // cannot all pass the limit (a passkey assertion is not a guess and
        // is not metered).
        let reserved = match self
            .reserve_guess(&user_id, &tenant_id, &prepared.current_kind, session)
            .await?
        {
            GuessSlot::Reserved(count) => Some(count),
            GuessSlot::Unmetered => None,
            GuessSlot::Refused(outcome) => return Ok(outcome),
        };
        #[cfg(feature = "ldap")]
        if prepared.current_kind == FactorKind::LdapBind {
            return self
                .verify_ldap_factor(
                    credential,
                    &prepared.config,
                    &user_id,
                    &tenant_id,
                    session,
                    reserved,
                )
                .await;
        }

        let outcome = self
            .verify_local_factor(
                credential, session, &user_id, &tenant_id, prepared, reserved,
            )
            .await?;
        // The step is passed: the pick belonged to it, not to the next one.
        if matches!(
            outcome,
            FactorOutcome::Authenticated | FactorOutcome::FactorRequired(_)
        ) {
            session.remove_custom(prepare::CHOSEN_FACTOR).await;
        }
        Ok(outcome)
    }

    /// Log out the current session: clear it and invalidate it in the registry.
    ///
    /// Only this session ends. The user's other sessions (another browser, a
    /// phone) stay signed in; use
    /// [`invalidate_user_sessions`](crate::authn::service::RequestAuthnService::invalidate_user_sessions)
    /// to end all of them.
    ///
    /// The session is cleared and its id rotated **whatever the audit store
    /// does**: the registry entry is dropped, the session is cleared, and
    /// only then is the audit event written, so a caller that gives up on a
    /// slow audit store (a timeout, a client that hangs up) has still logged
    /// the user out. When the audit write fails the call returns the store
    /// error so the failure is not hidden, but the user is logged out: a
    /// degraded audit store never leaves a session authenticated.
    #[tracing::instrument(skip(self, session))]
    pub async fn logout(&self, session: &AuthSession) -> Result<(), AuthnError<I::Error>> {
        let Some(user_id) = session.pending_user_id().await else {
            // `clear` also cycles the session id, which prevents session
            // fixation after logout.
            session.clear().await;
            return Ok(());
        };
        self.inner.metrics.session_invalidated();
        let sid = session.session_id().await;
        let tenant_id = session.pending_tenant_id().await;
        if let Some(reg) = &self.inner.registry {
            note_revocation(
                reg.invalidate_session(&user_id, &sid).await,
                "logout or a refused login",
            );
        }
        // Cleared before the audit write is awaited: everything the row needs
        // was captured above, and nothing that can wait on a store stands
        // between the user and being logged out.
        session.clear().await;

        // When the session is authenticated (user_id exists) but the tenant
        // is somehow missing, record the logout event with `tenant_id = None`
        // rather than inventing an attribution. Logged at WARN because it
        // should never happen in practice: authenticated sessions always
        // carry a tenant_id.
        if tenant_id.is_none() {
            tracing::warn!(
                user_id = %user_id,
                "logout: authenticated session missing tenant_id; audit event will have no tenant attribution",
            );
        }
        self.emit_audit(
            AuthEventBuilder::success(AuthEventType::LogoutAttempt)
                .maybe_attributed_to(Some(&user_id), tenant_id.as_ref())
                .with_session(sid),
        )
        .await
    }

    /// Rotate the session id of an authenticated session and keep the
    /// registry in step.
    ///
    /// [`AuthSession::regenerate`] alone changes the id the client carries
    /// but leaves the registry holding the old one, so a registry check would
    /// then find the session revoked. This registers the new id, drops the
    /// old one, and fails closed: when the registry cannot register the new
    /// id the session is cleared and the call returns
    /// [`AuthnError::NoFlow`]. Without a registry it is just a rotation. Use
    /// it at the privilege boundaries `regenerate` documents (factor added,
    /// password changed, tenant switched).
    ///
    /// A session layer built with a registry moves the entry itself when a
    /// handler calls `regenerate`; this method does it without relying on
    /// that, and works with the validator middleware alone.
    #[tracing::instrument(skip(self, session))]
    pub async fn rotate_session(&self, session: &AuthSession) -> Result<(), AuthnError<I::Error>> {
        let user = if session.is_authenticated().await {
            session.user_id().await
        } else {
            None
        };
        let old = session.session_id().await;
        session.regenerate().await;
        if let (Some(user_id), Some(reg)) = (user, &self.inner.registry) {
            let new = session.session_id().await;
            if !reg.register(&user_id, &new).await {
                tracing::error!(
                    user_id = %user_id,
                    "rotate_session: registering the new session id failed; clearing the session"
                );
                note_revocation(
                    reg.invalidate_session(&user_id, &old).await,
                    "logout or a refused login",
                );
                session.clear().await;
                return Err(AuthnError::NoFlow);
            }
            note_revocation(
                reg.invalidate_session(&user_id, &old).await,
                "logout or a refused login",
            );
        }
        Ok(())
    }
}

// Re-export fido2_keys for use in prepare_factor when fido2 feature is enabled.
#[cfg(feature = "fido2")]
pub(crate) use super::fido2_service::fido2_keys;

mod email_otp;
#[cfg(test)]
mod equalization_tests;
pub(crate) mod flow;
mod local_factor;
#[cfg(test)]
mod login_tests;
mod password_entry;
mod prepare;
use prepare::PreparedFactorStep;
mod reauth;
pub(crate) mod rehash;
#[cfg(test)]
mod security_tests;
mod tenant_admission;
mod timing;
