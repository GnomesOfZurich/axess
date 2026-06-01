//! Login flow: begin_login, prepare_factor, verify_factor, check_session, logout.

use super::outcomes::{FactorOutcome, LoginOutcome, PrepareOutcome};
use super::verification::{VerifyOutcome, generate_otp_code, verify_credential};
use crate::authn::{
    error::AuthnError,
    event::{AuthEventBuilder, AuthEventType},
    factor::{FactorConfig, FactorCredential, FactorKind},
    store::{FactorStore, IdentityStore},
    types::{AuthnScope, EntityState},
};
use crate::session::extractor::AuthSession;
impl<I, F> super::AuthnService<I, F>
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
    #[tracing::instrument(skip(self, session, client_ip), fields(tenant = %tenant_identifier))]
    pub async fn begin_login(
        &self,
        identifier: &str,
        tenant_identifier: &str,
        session: &AuthSession,
        client_ip: Option<std::net::IpAddr>,
    ) -> Result<LoginOutcome, AuthnError<I::Error>> {
        use crate::validation::MAX_IDENTIFIER_BYTES;

        self.metrics.auth_attempt();

        // 0. Reject oversized identifiers before hitting the database.
        if identifier.is_empty()
            || identifier.len() > MAX_IDENTIFIER_BYTES
            || tenant_identifier.is_empty()
            || tenant_identifier.len() > MAX_IDENTIFIER_BYTES
        {
            self.metrics.auth_failure();
            return Ok(LoginOutcome::InvalidCredentials);
        }

        // 1. Find tenant.
        let tenant = self
            .identity
            .find_tenant(tenant_identifier)
            .await
            .map_err(AuthnError::Store)?
            .ok_or(AuthnError::NotActive(EntityState::Guest))?;

        if let Err(e) = tenant.validate() {
            tracing::error!(error = %e, "IdentityStore returned invalid Tenant");
            self.metrics.auth_failure();
            return Ok(LoginOutcome::InvalidCredentials);
        }

        // 1a. Enforce tenant-level status. A Suspended or Terminated
        // tenant rejects all logins before we reveal anything
        // user-specific; this is the operator lever for "lock everyone
        // out of tenant X" (see `docs/identity/tenancy.md`).
        if !tenant.status.allows_login() {
            tracing::warn!(
                tenant = %tenant.id,
                status = ?tenant.status,
                "login rejected: tenant status does not allow login"
            );
            self.metrics.auth_failure();
            return Err(AuthnError::NotActive(tenant.status.clone()));
        }

        // 1b. Enforce tenant IP policy if a client IP was provided.
        if let Some(ip) = client_ip {
            let policy = self
                .identity
                .ip_policy_for_tenant(&tenant.id)
                .await
                .map_err(AuthnError::Store)?;
            if !policy.is_allowed(ip) {
                tracing::warn!(
                    tenant = %tenant.id,
                    client_ip = %ip,
                    "login rejected by tenant IP policy"
                );
                self.metrics.auth_failure();
                return Ok(LoginOutcome::InvalidCredentials);
            }
        }

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
                self.metrics.auth_failure();
                return Ok(LoginOutcome::InvalidCredentials);
            }
        };

        // 3. Check account status.
        let status = self
            .identity
            .account_status(&user.id)
            .await
            .map_err(AuthnError::Store)?;

        if !status.allows_login() {
            self.metrics.auth_failure();
            // Emit a `Failure(LoginAttempt)` audit row before returning so
            // a fresh session probing a known-locked account leaves a SOC
            // trail. `begin_login` does not go through
            // `enforce_account_status`, so the audit emit must happen
            // here explicitly. The error tag distinguishes locked from
            // other non-active states so dashboards can separate
            // brute-force probes from administrative-state mismatches.
            let error_tag = if status.is_locked() {
                "locked"
            } else {
                "not_active"
            };
            self.emit_audit(
                AuthEventBuilder::failure(AuthEventType::LoginAttempt)
                    .attributed_to(&user.id, &tenant.id)
                    .with_error(error_tag),
            )
            .await;
            if status.is_locked() {
                self.metrics.account_locked();
                // Surface the lockout expiry so UIs can render
                // "locked until X" on the begin path. Mirrors
                // `prepare_factor`: read `until` off
                // `Suspended(StatusDetail{until,..})` when the store
                // carries it.
                let until = if let EntityState::Suspended(detail) = &status {
                    detail.until
                } else {
                    None
                };
                return Ok(LoginOutcome::Locked { until });
            }
            return Err(AuthnError::NotActive(status));
        }

        // 4. Load available authentication methods.
        let methods = self
            .factors
            .available_methods(&user.id, &tenant.id)
            .await
            .map_err(AuthnError::Store)?;

        let method = methods.into_iter().next().ok_or(AuthnError::NoFlow)?;

        let resolved_factors = method.factors();
        if resolved_factors.is_empty() {
            self.metrics.auth_failure();
            return Ok(LoginOutcome::InvalidCredentials);
        }

        let first_kind = resolved_factors[0].clone();

        // 5. Begin the authentication flow in the session.
        session
            .begin_authenticating(user.id, tenant.id, method.name.clone(), resolved_factors)
            .await;

        // Record login attempt event.
        self.emit_audit(
            AuthEventBuilder::success(AuthEventType::LoginAttempt)
                .attributed_to(&user.id, &tenant.id)
                .with_factor(first_kind.clone()),
        )
        .await;

        Ok(LoginOutcome::FactorRequired(first_kind))
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
        use super::factor_pipeline::AccountStatusEnforcement;

        let (user_id, tenant_id, remaining) = session
            .authenticating_state()
            .await
            .ok_or(AuthnError::NoFlow)?;

        // A locked/suspended (or otherwise non-Active) account must not
        // trigger challenge delivery (e.g. OTP email sends). The
        // The audit row on `Locked` is emitted by
        // `enforce_account_status` itself.
        match self
            .enforce_account_status(&user_id, &tenant_id, remaining.first().cloned(), session)
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
            AccountStatusEnforcement::NotActive(status) => {
                return Err(AuthnError::NotActive(status));
            }
        }

        let current_kind = remaining.first().ok_or(AuthnError::NoFlow)?.clone();

        match current_kind {
            FactorKind::Password | FactorKind::Totp | FactorKind::Hotp | FactorKind::LdapBind => {
                Ok(PrepareOutcome::Ready)
            }

            FactorKind::EmailOtp => {
                // Load the EmailOtp config to get the destination and parameters.
                let user_scope = AuthnScope::User { tenant_id, user_id };
                let config = self
                    .load_factor_with_fallback(&user_scope, &tenant_id, FactorKind::EmailOtp)
                    .await?;

                // Take ownership of the inner cfg up front so we don't
                // need a second destructure (which used to require an
                // unreachable arm for "config changed kind mid-function").
                let FactorConfig::EmailOtp(mut cfg) = config else {
                    return Err(AuthnError::NoFlow);
                };

                // Cooldown: reject if a pending code hasn't expired yet.
                // This prevents email bombing; the application can only trigger
                // one send per TTL window.
                let now = self.clock.now();
                if cfg.pending_until.is_some_and(|until| now < until) {
                    return Ok(PrepareOutcome::AlreadySent {
                        destination: cfg.email.clone(),
                    });
                }

                let email = cfg.email.clone();
                let code_length = cfg.code_length as usize;
                let ttl_secs = cfg.ttl_secs;

                // Reject unreasonable code lengths to prevent DoS via
                // misconfigured factor config.
                if !(4..=8).contains(&code_length) {
                    tracing::error!(code_length, "email OTP code_length out of bounds (4–8)");
                    return Err(AuthnError::NoFlow);
                }

                // Generate a random numeric code using the injectable RNG.
                // Wrap in ZeroizedString so it's cleared from memory after use.
                let code = crate::authn::factor::ZeroizedString::new(generate_otp_code(
                    &self.rng,
                    code_length,
                ));

                // Hash the code with Argon2id for storage.
                let hash = axess_factors::generate_password_hash(&*code);

                // Compute expiry from config TTL.
                let expires = now + chrono::Duration::seconds(ttl_secs as i64);

                cfg.pending_hash = Some(crate::authn::factor::ZeroizedString::new(hash));
                cfg.pending_until = Some(expires);

                // Save to user scope (per-user pending state).
                self.factors
                    .save_factor(&user_scope, FactorConfig::EmailOtp(cfg))
                    .await
                    .map_err(AuthnError::Store)?;

                Ok(PrepareOutcome::SendOtp {
                    code,
                    destination: email,
                })
            }

            FactorKind::Fido2 => {
                #[cfg(feature = "fido2")]
                {
                    let webauthn = match &self.fido2 {
                        Some(w) => w,
                        None => return Ok(PrepareOutcome::Ready),
                    };

                    // Load stored credentials.
                    let user_scope = AuthnScope::User { tenant_id, user_id };
                    let config = self
                        .load_factor_with_fallback(&user_scope, &tenant_id, FactorKind::Fido2)
                        .await?;

                    let FactorConfig::Fido2(cfg) = &config else {
                        return Err(AuthnError::NoFlow);
                    };

                    if cfg.credentials.is_empty() {
                        return Err(AuthnError::NoFlow);
                    }

                    // Extract raw passkeys for the ceremony.
                    let passkeys: Vec<_> =
                        cfg.credentials.iter().map(|c| c.passkey.clone()).collect();

                    // Start the authentication ceremony.
                    let (challenge, auth_state) =
                        webauthn.start_authentication(&passkeys).map_err(|e| {
                            tracing::warn!("FIDO2 start_passkey_authentication failed: {e:?}");
                            AuthnError::NoFlow
                        })?;

                    // Store the ceremony state and timestamp in the session.
                    let state_json =
                        serde_json::to_value(&auth_state).map_err(|_| AuthnError::NoFlow)?;
                    session.set_custom(fido2_keys::AUTH_STATE, state_json).await;
                    self.stamp_ceremony_start(session).await;

                    let challenge_json =
                        serde_json::to_value(&challenge).map_err(|_| AuthnError::NoFlow)?;
                    Ok(PrepareOutcome::Fido2Challenge {
                        challenge: challenge_json,
                    })
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
        use super::factor_pipeline::AccountStatusEnforcement;

        let (user_id, tenant_id, remaining) = session
            .authenticating_state()
            .await
            .ok_or(AuthnError::NoFlow)?;

        match self
            .enforce_account_status(&user_id, &tenant_id, remaining.first().cloned(), session)
            .await?
        {
            AccountStatusEnforcement::Ok => {}
            AccountStatusEnforcement::Locked { until, .. } => {
                return Ok(FactorOutcome::Locked { until });
            }
            AccountStatusEnforcement::NotActive(status) => {
                return Err(AuthnError::NotActive(status));
            }
        }

        let current_kind = remaining.first().ok_or(AuthnError::NoFlow)?.clone();

        // Load factor config; try User → Tenant → Global scope in order.
        let user_scope = AuthnScope::User { tenant_id, user_id };
        let config = self
            .load_factor_with_fallback(&user_scope, &tenant_id, current_kind.clone())
            .await?;

        // FIDO2 + LDAP have their own verification methods (different
        // ceremony shape, network call) and short-circuit with their
        // own FactorOutcome. The local-hash factors continue below.
        #[cfg(feature = "fido2")]
        if current_kind == FactorKind::Fido2 {
            return self
                .verify_fido2_factor(
                    credential,
                    &config,
                    &user_scope,
                    &user_id,
                    &tenant_id,
                    session,
                )
                .await;
        }
        #[cfg(feature = "ldap")]
        if current_kind == FactorKind::LdapBind {
            return self
                .verify_ldap_factor(credential, &config, &user_id, &tenant_id, session)
                .await;
        }

        self.metrics.factor_attempt();
        let outcome = verify_credential(credential, &config, &current_kind, self.clock.now());

        if let VerifyOutcome::FailWithUpdate(updated_config) = &outcome {
            self.persist_fail_with_update(&user_scope, current_kind.clone(), updated_config)
                .await?;
        }

        if matches!(
            outcome,
            VerifyOutcome::Fail | VerifyOutcome::FailWithUpdate(_)
        ) {
            return self
                .record_factor_failure(&user_id, &tenant_id, &current_kind, session)
                .await;
        }

        self.metrics.factor_success();

        if let VerifyOutcome::PassWithUpdate(updated_config) = outcome {
            let swapped = self
                .persist_pass_with_update(&user_scope, current_kind.clone(), updated_config)
                .await?;
            if !swapped {
                // Concurrent verification spent the same step/counter
                // first; treat as a replay and reject.
                self.metrics.factor_failure();
                return Ok(FactorOutcome::InvalidCredential);
            }
        }

        session
            .advance_factor(&current_kind, self.clock.now())
            .await;
        self.complete_factor_step(&user_id, &tenant_id, session)
            .await
    }

    /// Check whether the current session is valid (consults the registry if installed).
    #[tracing::instrument(skip(self, session))]
    pub async fn check_session(&self, session: &AuthSession) -> bool {
        if !session.is_authenticated().await {
            return false;
        }
        let user_id = match session.user_id().await {
            Some(id) => id,
            None => return false,
        };
        let sid = session.session_id().await;
        if let Some(reg) = &self.registry {
            reg.is_valid(&user_id, &sid).await
        } else {
            true
        }
    }

    /// Log out the current user: clear the session and invalidate in the registry.
    #[tracing::instrument(skip(self, session))]
    pub async fn logout(&self, session: &AuthSession) -> Result<(), AuthnError<I::Error>> {
        if let Some(user_id) = session.user_id().await {
            self.metrics.session_invalidated();
            let sid = session.session_id().await;
            if let Some(reg) = &self.registry {
                reg.invalidate_user(&user_id).await;
            }
            // When the session is authenticated (user_id exists) but the
            // tenant is somehow missing, record the logout event with
            // `tenant_id = None` rather than inventing an attribution.
            // Logged at WARN because it should never happen in practice:
            // authenticated sessions always carry a tenant_id.
            let tenant_id = session.tenant_id().await;
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
            .await;
        }
        session.clear().await;
        // Cycle the session ID to prevent session fixation after logout.
        session.regenerate().await;
        Ok(())
    }

    /// Look up a user by identifier with timing-equalization on miss.
    ///
    /// Returns `Ok(Some(user))` on a clean find + `validate()`,
    /// `Ok(None)` when the identifier is unknown OR the returned
    /// `User` failed validation. The caller maps `None` to
    /// `LoginOutcome::InvalidCredentials`.
    ///
    /// **Security invariant, do not change this without thinking
    /// carefully:** the `None` paths MUST run the same store queries
    /// the found-user path would (against a fresh-UUID dummy id) so
    /// the response time does not leak whether the identifier
    /// exists. Two-step MFA flows (identify → verify) inherently
    /// reveal whether an identifier maps to a valid account through
    /// the response *shape*, but timing must not be a second
    /// side-channel on top of that. This is the same trade-off
    /// Gmail, Microsoft, and most banks accept.
    ///
    /// The dummy UUID is generated per request so it cannot collide
    /// with any real user (including the reserved
    /// [`UserId::system()`](crate::authn::ids::UserId::system)),
    /// preserving timing-equalization semantics regardless of which
    /// principals the application has installed.
    ///
    /// **Scope of equalisation:** DB queries only. LDAP network
    /// latency is NOT equalised because LDAP bind only happens in
    /// `verify_factor` (after the user is already known to exist);
    /// user enumeration via LDAP timing is not reachable from
    /// `begin_login`. Re-evaluate this comment if any LDAP call
    /// migrates earlier in the flow.
    async fn find_user_with_timing_equalization(
        &self,
        identifier: &str,
        tenant_id: &crate::authn::ids::TenantId,
    ) -> Result<Option<crate::authn::types::User>, AuthnError<I::Error>> {
        let user_opt = self
            .identity
            .find_user(identifier, tenant_id)
            .await
            .map_err(AuthnError::Store)?;

        if let Some(u) = user_opt {
            return match u.validate() {
                Ok(()) => Ok(Some(u)),
                Err(e) => {
                    tracing::error!(error = %e, "IdentityStore returned invalid User");
                    // Validate-fail returns `None` *without* running
                    // the dummy queries below: the user exists (find_user
                    // already paid that cost), the observable response
                    // matches the unknown-user path, and a validate
                    // failure on a stored row indicates internal data
                    // corruption, not an attacker-driven enumeration
                    // probe. Re-evaluate if the threat model changes.
                    Ok(None)
                }
            };
        }

        // Unknown identifier; run the same store queries the
        // happy path would, against a fresh-UUID dummy, to keep
        // response time independent of identifier existence.
        let dummy_id = crate::authn::ids::UserId::try_new(uuid::Uuid::new_v4().to_string())
            .expect("fresh v4 UUID is a valid UserId");
        let _ = self.identity.account_status(&dummy_id).await;
        let _ = self.factors.available_methods(&dummy_id, tenant_id).await;
        Ok(None)
    }
}

// Re-export fido2_keys for use in prepare_factor when fido2 feature is enabled.
#[cfg(feature = "fido2")]
pub(crate) use super::fido2_service::fido2_keys;

#[cfg(test)]
mod login_tests {
    //! Pin the cheap, observable surfaces of `login.rs`:
    //! `check_session` (all branches), `logout` (registry invalidation),
    //! `find_user_with_timing_equalization` (real-user lookup).
    //!
    //! Mutations in `prepare_factor` (line 303 temporal `+`) and
    //! `verify_factor` (lines 431/444/473 dispatch + replay-prevention)
    //! require a full factor-pipeline harness with active `MockClock` and
    //! a per-factor verification fixture; those are deferred until the
    //! larger sweep across login flows lands.
    use super::super::AuthnService;
    use super::*;
    use crate::authn::ids::{TenantId, UserId};
    use crate::authn::types::{EntityState, LockoutPolicy, Tenant, User};
    use crate::session::data::SessionData;
    use crate::session::extractor::AuthSession;
    use crate::session::layer::{SessionHandle, SessionInner};
    use crate::session::store::MemorySessionRegistry;
    use crate::testing::mock_authn::{MockFactorStore, MockIdentityStore};
    use std::sync::Arc;
    use tokio::sync::RwLock;

    fn fixture_user_id() -> UserId {
        axess_identity::testing::user("u-login")
    }

    fn fixture_tenant_id() -> TenantId {
        axess_identity::testing::tenant("t-login")
    }

    fn make_session() -> AuthSession {
        let inner = SessionInner {
            id: crate::session::id::SessionId::new(&axess_rng::SystemRng),
            data: SessionData::default(),
            modified: false,
            regenerate: false,
            pre_cycle_id: None,
            pending_fingerprint: None,
            max_custom_bytes: 64 * 1024,
        };
        AuthSession(SessionHandle(Arc::new(RwLock::new(inner))))
    }

    async fn authenticated_session() -> AuthSession {
        let session = make_session();
        session
            .set_authenticated(fixture_user_id(), fixture_tenant_id(), chrono::Utc::now())
            .await;
        session
    }

    fn build_user(user_id: &UserId, tenant_id: &TenantId, identifier: &str) -> User {
        let now = chrono::Utc::now();
        User {
            id: *user_id,
            tenant_id: *tenant_id,
            identifier: identifier.into(),
            display_name: identifier.into(),
            status: EntityState::Active,
            webauthn_id: None,
            created_by: UserId::system(),
            created_at: now,
            updated_by: UserId::system(),
            updated_at: now,
        }
    }

    fn build_tenant(tenant_id: TenantId, identifier: &str) -> Tenant {
        let now = chrono::Utc::now();
        Tenant {
            id: tenant_id,
            identifier: identifier.into(),
            display_name: identifier.into(),
            status: EntityState::Active,
            created_by: UserId::system(),
            created_at: now,
            updated_by: UserId::system(),
            updated_at: now,
        }
    }

    fn build_service_with_identity(
        identity: MockIdentityStore,
    ) -> AuthnService<MockIdentityStore, MockFactorStore> {
        AuthnService::new(identity, MockFactorStore::new())
    }

    // ── check_session (line 491) ─────────────────────────────────────

    /// Kills line 491 body `-> true` / `delete !`: unauthenticated
    /// session must return `false`.
    #[tokio::test]
    async fn check_session_unauthenticated_returns_false() {
        let service = build_service_with_identity(MockIdentityStore::new());
        let session = make_session();
        assert!(!service.check_session(&session).await);
    }

    /// Kills line 491 `-> false`: authenticated session with no
    /// registry must return `true`.
    #[tokio::test]
    async fn check_session_authenticated_no_registry_returns_true() {
        let service = build_service_with_identity(MockIdentityStore::new());
        let session = authenticated_session().await;
        assert!(service.check_session(&session).await);
    }

    /// Authenticated session + registry rejection → false. Pins the
    /// `reg.is_valid` propagation.
    #[tokio::test]
    async fn check_session_registry_rejection_returns_false() {
        let service = build_service_with_identity(MockIdentityStore::new())
            .with_registry(MemorySessionRegistry::new());
        let session = authenticated_session().await;
        assert!(
            !service.check_session(&session).await,
            "registry rejection must invalidate the session"
        );
    }

    /// Authenticated session + registry acceptance → true.
    #[tokio::test]
    async fn check_session_registry_acceptance_returns_true() {
        let registry = MemorySessionRegistry::new();
        let session = authenticated_session().await;
        let sid = session.session_id().await;
        crate::session::store::SessionRegistry::register(&registry, &fixture_user_id(), &sid)
            .await
            .unwrap();

        let service = build_service_with_identity(MockIdentityStore::new()).with_registry(registry);
        assert!(service.check_session(&session).await);
    }

    // ── logout (line 509) ────────────────────────────────────────────

    /// Kills line 509 `-> Ok(())`: `logout` must (a) succeed for an
    /// authenticated session and (b) actually invalidate the user's
    /// sessions in the registry. The mutation returns `Ok(())` without
    /// touching the registry; observable via `registry.is_valid`
    /// flipping from `true` (before) to `false` (after).
    #[tokio::test]
    async fn logout_invalidates_user_in_registry() {
        use crate::session::store::SessionRegistry;

        let identity = MockIdentityStore::new()
            .with_tenant(build_tenant(fixture_tenant_id(), "t-login"))
            .with_user(build_user(
                &fixture_user_id(),
                &fixture_tenant_id(),
                "u-login",
            ))
            .with_lockout_policy(LockoutPolicy::default());

        let registry = MemorySessionRegistry::new();
        let session = authenticated_session().await;
        let sid = session.session_id().await;
        registry.register(&fixture_user_id(), &sid).await.unwrap();
        assert!(registry.is_valid(&fixture_user_id(), &sid).await.unwrap());

        let service = build_service_with_identity(identity).with_registry(registry.clone());
        service.logout(&session).await.expect("logout must succeed");

        assert!(
            !registry.is_valid(&fixture_user_id(), &sid).await.unwrap(),
            "logout must invalidate the user in the registry; \
             the `Ok(())` mutation skips this side effect"
        );
    }

    // ── find_user_with_timing_equalization (line 575) ────────────────

    // ── begin_login input guard (line 41-48) ─────────────────────────

    /// Kills the line-42 `||` / `>` mutations: an oversized identifier
    /// or oversized tenant_identifier must reject as
    /// `InvalidCredentials` *before* hitting the database. Every
    /// mutation in the early-reject chain (`|| → &&`, `> → ==`,
    /// `> → >=`) flips the outcome on either an empty input (admitted
    /// when it should reject) or a one-byte-over input (rejected
    /// when it should still admit / vice versa).
    #[tokio::test]
    async fn begin_login_rejects_oversized_identifier() {
        use crate::validation::MAX_IDENTIFIER_BYTES;
        let service = build_service_with_identity(MockIdentityStore::new());
        let session = make_session();
        let huge_identifier = "x".repeat(MAX_IDENTIFIER_BYTES + 1);

        let outcome = service
            .begin_login(&huge_identifier, "t-login", &session, None)
            .await
            .expect("oversized identifier must reject cleanly");
        assert!(
            matches!(outcome, LoginOutcome::InvalidCredentials),
            "identifier longer than MAX_IDENTIFIER_BYTES must reject; \
             `> → ==/>=` mutants would admit at the boundary. got: {outcome:?}"
        );
    }

    /// Empty identifier must reject. Discriminates `|| → &&`: with
    /// `&&` the guard requires *all* conditions, so an empty
    /// identifier alone wouldn't trip the guard.
    #[tokio::test]
    async fn begin_login_rejects_empty_identifier() {
        let service = build_service_with_identity(MockIdentityStore::new());
        let session = make_session();
        let outcome = service
            .begin_login("", "t-login", &session, None)
            .await
            .expect("empty identifier must reject cleanly");
        assert!(
            matches!(outcome, LoginOutcome::InvalidCredentials),
            "empty identifier must reject; `|| → &&` mutant would admit"
        );
    }

    /// Oversized tenant_identifier must reject. Discriminates the
    /// second `>` mutation at line 44.
    #[tokio::test]
    async fn begin_login_rejects_oversized_tenant_identifier() {
        use crate::validation::MAX_IDENTIFIER_BYTES;
        let service = build_service_with_identity(MockIdentityStore::new());
        let session = make_session();
        let huge_tenant = "y".repeat(MAX_IDENTIFIER_BYTES + 1);
        let outcome = service
            .begin_login("alice", &huge_tenant, &session, None)
            .await
            .expect("oversized tenant must reject cleanly");
        assert!(
            matches!(outcome, LoginOutcome::InvalidCredentials),
            "tenant_identifier longer than MAX_IDENTIFIER_BYTES must reject"
        );
    }

    /// Empty tenant_identifier must reject. Companion to the empty
    /// identifier test.
    #[tokio::test]
    async fn begin_login_rejects_empty_tenant_identifier() {
        let service = build_service_with_identity(MockIdentityStore::new());
        let session = make_session();
        let outcome = service
            .begin_login("alice", "", &session, None)
            .await
            .expect("empty tenant must reject cleanly");
        assert!(
            matches!(outcome, LoginOutcome::InvalidCredentials),
            "empty tenant_identifier must reject"
        );
    }

    /// Kills line 575 `-> Ok(None)`: when the user EXISTS, the
    /// helper must surface `Some(user)`. The mutation always returns
    /// `None`, which collapses `begin_login` to
    /// `Ok(LoginOutcome::InvalidCredentials)` via the user-not-found
    /// arm (line 109). With the original body and a configured user
    /// (but no factor methods registered), `begin_login` continues
    /// past the lookup and fails at the no-methods gate (line 166)
    /// with `Err(AuthnError::NoFlow)`: observably distinct from the
    /// `InvalidCredentials` produced by the mutation.
    #[tokio::test]
    async fn begin_login_finds_existing_user_via_timing_equalized_path() {
        let user_id = fixture_user_id();
        let tenant_id = fixture_tenant_id();
        let tenant_identifier = "t-login";
        let user_identifier = "alice@example.test";
        let identity = MockIdentityStore::new()
            .with_tenant(build_tenant(tenant_id, tenant_identifier))
            .with_user(build_user(&user_id, &tenant_id, user_identifier))
            .with_lockout_policy(LockoutPolicy::default());

        let service = build_service_with_identity(identity);
        let session = make_session();

        let result = service
            .begin_login(user_identifier, tenant_identifier, &session, None)
            .await;

        // With the mutation: result is Ok(InvalidCredentials).
        // With the original: result is Err(NoFlow) (no methods
        // registered for this user).
        assert!(
            !matches!(result, Ok(LoginOutcome::InvalidCredentials)),
            "real user must NOT collapse to InvalidCredentials; \
             `find_user → Ok(None)` mutation would invert this. got: {result:?}"
        );
        assert!(
            matches!(result, Err(AuthnError::NoFlow)),
            "with no methods registered, begin_login must reach the \
             NoFlow gate past the user-lookup. got: {result:?}"
        );
    }
}
