//! Login flow: begin_login, prepare_factor, verify_factor, check_session, logout.

use super::outcomes::{FactorOutcome, LoginOutcome, PrepareOutcome};
use super::verification::{VerifyOutcome, generate_otp_code, verify_credential_blocking};
use crate::authn::types::{Tenant, User};
use crate::authn::{
    error::AuthnError,
    event::{AuthEventBuilder, AuthEventType, AuthFailureReason},
    factor::{FactorConfig, FactorCredential, FactorKind, FactorStep},
    store::{FactorStore, IdentityStore},
    types::{AuthnScope, EntityState},
};
use crate::session::extractor::AuthSession;
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
    #[tracing::instrument(skip(self, session), fields(tenant = %tenant_identifier))]
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
        let user = match self.find_loginnable_user(identifier, &tenant).await? {
            ControlFlow::Continue(user) => user,
            ControlFlow::Break(outcome) => return Ok(outcome),
        };
        let first = match self.select_first_factor(&user, &tenant).await? {
            ControlFlow::Continue(first) => first,
            ControlFlow::Break(outcome) => return Ok(outcome),
        };

        // 5. Begin the authentication flow in the session.
        session
            .begin_authenticating(user.id, tenant.id, first.method_name, first.steps)
            .await;

        // Record login attempt event.
        self.emit_audit(
            AuthEventBuilder::success(AuthEventType::LoginAttempt)
                .attributed_to(&user.id, &tenant.id)
                .with_factor(first.first_kind.clone()),
        )
        .await?;

        Ok(LoginOutcome::FactorRequired(first.first_kind))
    }

    /// Resolve the tenant a login names and admit the request against it.
    ///
    /// Breaks with [`LoginOutcome::InvalidCredentials`] for an unknown
    /// tenant, an invalid tenant row, a tenant whose status bars logins and
    /// a request the tenant IP policy refuses. Every one of those goes
    /// through [`reject_pre_user`](Self::reject_pre_user) so their store
    /// calls and audit rows are indistinguishable from one another.
    async fn admit_tenant(
        &self,
        identifier: &str,
        tenant_identifier: &str,
    ) -> Result<ControlFlow<LoginOutcome, Tenant>, AuthnError<I::Error>> {
        // 1. Find tenant. An unknown tenant is a credential failure like
        // any other, not a distinct error: returning `NotActive` here made
        // tenant existence observable, because that variant maps to 403
        // "account not active" while a wrong password yields
        // `InvalidCredentials`. An attacker could separate "no such tenant"
        // from "wrong password" on the status code alone, which is the
        // enumeration the identifier path below is careful to prevent.
        //
        // Response shape alone is not enough: bailing out here would skip
        // the user lookup entirely and answer measurably sooner, so the
        // same dummy store queries run against a throwaway tenant id to
        // keep the timing of an unknown tenant in line with a known one.
        let tenant = match self
            .inner
            .identity
            .find_tenant(tenant_identifier)
            .await
            .map_err(AuthnError::Store)?
        {
            Some(t) => t,
            None => {
                // Unattributed: there is no tenant and so no user to name.
                // Emitting anyway is what keeps the audit failure mode from
                // becoming an enumeration oracle, because an audit-store
                // outage must fail this path exactly as it fails a known
                // user's wrong password. It also closes a SOC blind spot: a
                // credential-stuffing run against identifiers that do not
                // exist used to leave no audit row at all.
                return self
                    .reject_pre_user(identifier, None, AuthFailureReason::UnknownTenant, false)
                    .await
                    .map(ControlFlow::Break);
            }
        };

        if let Err(e) = tenant.validate() {
            tracing::error!(error = %e, "IdentityStore returned invalid Tenant");
            return self
                .reject_pre_user(identifier, None, AuthFailureReason::InvalidTenantRow, false)
                .await
                .map(ControlFlow::Break);
        }

        // 1a. Enforce tenant-level status. A Suspended or Terminated
        // tenant rejects all logins before we reveal anything
        // user-specific; this is the operator lever for "lock everyone
        // out of tenant X" (see `docs/identity/tenancy.md`).
        //
        // The caller sees the same `InvalidCredentials` as for an unknown
        // tenant, after the same dummy user lookup. A distinct answer here
        // (it was `NotActive`, a 403) let anyone probing tenant slugs tell
        // a suspended tenant from a missing one, and either from a live
        // one. The audit row carries the real reason.
        if !tenant
            .status
            .clone()
            .effective_at(self.inner.clock.now())
            .allows_login()
        {
            tracing::warn!(
                tenant = %tenant.id,
                status = ?tenant.status,
                "login rejected: tenant status does not allow login"
            );
            return self
                .reject_pre_user(
                    identifier,
                    Some(&tenant.id),
                    AuthFailureReason::NotActive,
                    false,
                )
                .await
                .map(ControlFlow::Break);
        }

        if let ControlFlow::Break(outcome) =
            self.enforce_tenant_ip_policy(identifier, &tenant).await?
        {
            return Ok(ControlFlow::Break(outcome));
        }
        Ok(ControlFlow::Continue(tenant))
    }

    /// Enforce the tenant IP policy against the address of this request.
    ///
    /// Breaks with [`LoginOutcome::InvalidCredentials`] when the address is
    /// barred, or when the policy restricts and no address was resolved.
    async fn enforce_tenant_ip_policy(
        &self,
        identifier: &str,
        tenant: &Tenant,
    ) -> Result<ControlFlow<LoginOutcome>, AuthnError<I::Error>> {
        // 1b. Enforce the tenant IP policy against the address this handle
        // was derived with. Until 0.7.0 the address was a parameter and the
        // check ran only `if let Some(ip)`, so a caller passing `None`
        // skipped the policy entirely: an allowlist a caller could switch
        // off by omitting an argument, and 51 of the 52 call sites in this
        // repository omitted it. The address now comes from the client-IP
        // layer by way of the audit context, which the caller does not
        // choose.
        let policy = self
            .inner
            .identity
            .ip_policy_for_tenant(&tenant.id)
            .await
            .map_err(AuthnError::Store)?;
        // Both refusals are answered by `reject_pre_user`, exactly as an
        // unknown identifier is, so a request from a barred address makes the
        // same store calls, in the same order, as one from a permitted
        // address naming a user who does not exist.
        match self.audit.ip_address {
            Some(ip) if !policy.is_allowed(ip) => {
                tracing::warn!(
                    tenant = %tenant.id,
                    client_ip = %ip,
                    "login rejected by tenant IP policy"
                );
                return self
                    .reject_pre_user(
                        identifier,
                        Some(&tenant.id),
                        AuthFailureReason::IpPolicy,
                        true,
                    )
                    .await
                    .map(ControlFlow::Break);
            }
            // A policy that restricts, and no address to test against it:
            // the only safe reading is that it is not satisfied. An empty
            // policy permits everything, so an unknown address is no less
            // compliant with it than a known one, and those deployments are
            // unaffected.
            //
            // `ip_source` separates the two ways to get here. `Unknown`
            // means `client_ip::layer` is not installed, which is a
            // deployment fault and the likely cause. Any other source means
            // the transport genuinely has no address to offer.
            None if policy.restricts() => {
                tracing::error!(
                    tenant = %tenant.id,
                    ip_source = self.audit.ip_source.as_str(),
                    "tenant has an IP policy and this request has no resolved \
                     client address, so the policy cannot be satisfied; install \
                     axess::client_ip::layer on the router"
                );
                return self
                    .reject_pre_user(
                        identifier,
                        Some(&tenant.id),
                        AuthFailureReason::IpPolicy,
                        true,
                    )
                    .await
                    .map(ControlFlow::Break);
            }
            _ => {}
        }
        Ok(ControlFlow::Continue(()))
    }

    /// Look the user up and require an account status that allows login.
    ///
    /// Breaks with the outcome for an unknown identifier
    /// ([`LoginOutcome::InvalidCredentials`]) and for a locked account
    /// ([`LoginOutcome::Locked`]); a non-active, non-locked account is an
    /// [`AuthnError::NotActive`] error. Each refusal emits its audit row.
    async fn find_loginnable_user(
        &self,
        identifier: &str,
        tenant: &Tenant,
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

        // 3. Check account status.
        let status = self.current_account_status(&user.id).await?;

        if !status.allows_login() {
            self.inner.metrics.auth_failure();
            // Emit a `Failure(LoginAttempt)` audit row before returning so
            // a fresh session probing a known-locked account leaves a SOC
            // trail. `begin_login` does not go through
            // `enforce_account_status`, so the audit emit must happen
            // here explicitly. A lockout carries `Locked` rather than
            // `Failure`, so a dashboard separates brute-force probes from
            // administrative-state mismatches on the status column instead
            // of on a free-text tag. The other non-active states keep the
            // tag, having no status of their own.
            let builder = if status.is_locked() {
                AuthEventBuilder::locked(AuthEventType::LoginAttempt)
            } else {
                AuthEventBuilder::failure(AuthEventType::LoginAttempt)
                    .with_error(AuthFailureReason::NotActive)
            };
            self.emit_audit(builder.attributed_to(&user.id, &tenant.id))
                .await?;
            if status.is_locked() {
                self.inner.metrics.account_locked();
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
                return Ok(ControlFlow::Break(LoginOutcome::Locked { until }));
            }
            return Err(AuthnError::NotActive(status));
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

        // Both of the next two rejections have to emit, for the same
        // reason every other branch here does. A known account with no
        // usable method would otherwise be the one outcome that leaves no
        // audit row, and during an audit-store outage the one that still
        // succeeds while every other path fails, which is an enumeration
        // signal, narrow but of exactly the shape this flow was rewritten
        // to remove.
        let Some(method) = methods.into_iter().next() else {
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

        // The method's own steps, choices included: a step offering
        // `AnyOf([Totp, RecoveryCode])` stays a choice for the whole flow.
        let steps: Vec<FactorStep> = method
            .steps
            .iter()
            .filter(|step| step.primary().is_some())
            .cloned()
            .collect();
        if steps.is_empty() {
            self.inner.metrics.auth_failure();
            self.emit_audit(
                AuthEventBuilder::failure(AuthEventType::LoginAttempt)
                    .attributed_to(&user.id, &tenant.id)
                    .with_error(AuthFailureReason::NoFactorsConfigured),
            )
            .await?;
            return Ok(ControlFlow::Break(LoginOutcome::InvalidCredentials));
        }

        let first_kind = steps[0].primary().cloned().ok_or(AuthnError::NoFlow)?;
        Ok(ControlFlow::Continue(FirstFactor {
            method_name: method.name.clone(),
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
            AccountStatusEnforcement::NotActive(status) => {
                return Err(AuthnError::NotActive(status));
            }
        }

        let current_kind = remaining
            .first()
            .and_then(FactorStep::primary)
            .ok_or(AuthnError::NoFlow)?
            .clone();

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

    /// Issue an email one-time code for the current `EmailOtp` step.
    ///
    /// Refuses while a pending code is still live, draws and hashes a fresh
    /// code, stores the hash and expiry in the user's factor config and
    /// hands the plaintext back for the caller to deliver.
    async fn prepare_email_otp(
        &self,
        tenant_id: &crate::authn::ids::TenantId,
        user_id: &crate::authn::ids::UserId,
    ) -> Result<PrepareOutcome, AuthnError<I::Error>> {
        // Load the EmailOtp config to get the destination and parameters.
        let user_scope = AuthnScope::User {
            tenant_id: *tenant_id,
            user_id: *user_id,
        };
        let config = self
            .inner
            .factors
            .resolve_factor(&user_scope, FactorKind::EmailOtp)
            .await
            .map_err(AuthnError::Store)?
            .ok_or(AuthnError::NoFlow)?
            .config;

        // Take ownership of the inner cfg up front so we don't
        // need a second destructure (which used to require an
        // unreachable arm for "config changed kind mid-function").
        let FactorConfig::EmailOtp(mut cfg) = config else {
            return Err(AuthnError::NoFlow);
        };

        // Cooldown: reject if a pending code hasn't expired yet.
        // This prevents email bombing; the application can only trigger
        // one send per TTL window.
        let now = self.inner.clock.now();
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
            &self.inner.rng,
            code_length,
        ));

        // Hash the code with Argon2id for storage, off the executor.
        // The salt is drawn here, from the injected RNG, so a
        // deterministic RNG pins the stored hash; only owned bytes
        // move into the blocking task.
        let salt = axess_factors::generate_password_salt(&self.inner.rng);
        let to_hash = zeroize::Zeroizing::new(code.to_string());
        let hash = self
            .inner
            .kdf
            .run(move || axess_factors::hash_password_with_salt(to_hash.as_str(), &salt))
            .await?;

        // Compute expiry from config TTL.
        let expires = now + chrono::Duration::seconds(ttl_secs as i64);

        cfg.pending_hash = Some(crate::authn::factor::ZeroizedString::new(hash));
        cfg.pending_until = Some(expires);

        // Save to user scope (per-user pending state).
        self.inner
            .factors
            .save_factor(&user_scope, FactorConfig::EmailOtp(cfg))
            .await
            .map_err(AuthnError::Store)?;

        Ok(PrepareOutcome::SendOtp {
            code,
            destination: email,
        })
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
        session.set_custom(fido2_keys::AUTH_STATE, state_json).await;
        self.stamp_ceremony_start(session).await;

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
        use super::factor_pipeline::AccountStatusEnforcement;

        let (user_id, tenant_id, remaining) = session
            .authenticating_state()
            .await
            .ok_or(AuthnError::NoFlow)?;

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
            AccountStatusEnforcement::Locked { until, .. } => {
                return Ok(FactorOutcome::Locked { until });
            }
            AccountStatusEnforcement::NotActive(status) => {
                return Err(AuthnError::NotActive(status));
            }
        }

        // The step's factor the credential is for: the required one, or the
        // choice its shape fits (a recovery code at an `AnyOf([Totp,
        // RecoveryCode])` step). A credential no choice fits is wrong for
        // this step, and fails like a wrong code.
        let step = remaining.first().ok_or(AuthnError::NoFlow)?;
        let current_kind = match step.kind_for(credential) {
            Some(kind) => kind,
            None => step.primary().cloned().ok_or(AuthnError::NoFlow)?,
        };

        // Runtime resolution: User → Tenant → System, single-query in the store.
        let user_scope = AuthnScope::User { tenant_id, user_id };
        let resolved = self
            .inner
            .factors
            .resolve_factor(&user_scope, current_kind.clone())
            .await
            .map_err(AuthnError::Store)?
            .ok_or(AuthnError::NoFlow)?;
        let resolved_from = resolved.resolved_from;
        let config = resolved.config;

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

        self.inner.metrics.factor_attempt();
        let outcome = verify_credential_blocking(
            &self.inner.kdf,
            credential,
            &config,
            &current_kind,
            self.inner.clock.now(),
            self.inner.recovery_pepper.as_ref(),
        )
        .await?;

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

        self.inner.metrics.factor_success();

        if let VerifyOutcome::PassWithUpdate(updated_config) = outcome {
            let swapped = self
                .persist_pass_with_update(&user_scope, &config, &resolved_from, updated_config)
                .await?;
            if !swapped {
                // Concurrent verification spent the same step/counter
                // first; treat as a replay and reject.
                self.inner.metrics.factor_failure();
                return Ok(FactorOutcome::InvalidCredential);
            }
        }

        session
            .advance_factor(&current_kind, self.inner.clock.now())
            .await;
        self.complete_factor_step(&user_id, &tenant_id, session)
            .await
    }

    /// Log out the current session: clear it and invalidate it in the registry.
    ///
    /// Only this session ends. The user's other sessions (another browser, a
    /// phone) stay signed in; use
    /// [`invalidate_user_sessions`](crate::authn::service::AuthnService::invalidate_user_sessions)
    /// to end all of them.
    #[tracing::instrument(skip(self, session))]
    pub async fn logout(&self, session: &AuthSession) -> Result<(), AuthnError<I::Error>> {
        if let Some(user_id) = session.user_id().await {
            self.inner.metrics.session_invalidated();
            let sid = session.session_id().await;
            if let Some(reg) = &self.inner.registry {
                reg.invalidate_session(&user_id, &sid).await;
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
            .await?;
        }
        session.clear().await;
        // Cycle the session ID to prevent session fixation after logout.
        session.regenerate().await;
        Ok(())
    }
}

// Re-export fido2_keys for use in prepare_factor when fido2 feature is enabled.
#[cfg(feature = "fido2")]
pub(crate) use super::fido2_service::fido2_keys;

#[cfg(test)]
mod equalization_tests;
#[cfg(test)]
mod login_tests;
#[cfg(test)]
mod security_tests;

impl<I, F> super::AuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
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
        if let Some(reg) = &self.inner.registry {
            reg.is_valid(&user_id, &sid).await
        } else {
            true
        }
    }

    /// A random v4 UUID drawn from the service's RNG, so a deterministic
    /// RNG pins the throwaway ids the equalization lookups run against.
    fn dummy_uuid(&self) -> uuid::Uuid {
        let mut bytes = [0u8; 16];
        self.inner.rng.fill_bytes(&mut bytes);
        uuid::Builder::from_random_bytes(bytes).into_uuid()
    }

    fn dummy_tenant_id(&self) -> crate::authn::ids::TenantId {
        crate::authn::ids::TenantId::try_new(self.dummy_uuid().to_string())
            .expect("a UUID is a valid TenantId")
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
    /// The dummy UUID is drawn from the service's RNG per request so it cannot collide
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
            .inner
            .identity
            .find_user(identifier, tenant_id)
            .await
            .map_err(AuthnError::Store)?;

        if let Some(u) = user_opt {
            match u.validate() {
                Ok(()) => return Ok(Some(u)),
                // A stored row that fails validation is answered like an
                // unknown identifier, including the dummy queries below, so
                // it costs the same store calls as one.
                Err(e) => tracing::error!(error = %e, "IdentityStore returned invalid User"),
            }
        }

        // Unknown identifier, or a row that failed validation; run the same
        // store queries the happy path would, against a fresh-UUID dummy, to
        // keep response time independent of identifier existence.
        let dummy_id = crate::authn::ids::UserId::try_new(self.dummy_uuid().to_string())
            .expect("a UUID is a valid UserId");
        let _ = self.inner.identity.account_status(&dummy_id).await;
        let _ = self
            .inner
            .factors
            .available_methods(&dummy_id, tenant_id)
            .await;
        Ok(None)
    }
}
