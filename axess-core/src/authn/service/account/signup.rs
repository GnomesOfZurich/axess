//! Signup flow: `begin_signup` + `complete_signup`.
//!
//! Two-step ceremony: `begin_signup` creates a `Candidate` user and
//! transitions the session to `PendingWorkflow(Signup)`; the application
//! sends the verification secret `begin_signup` minted by email (or any
//! other channel only the person reads), then calls `complete_signup` with
//! it to activate the user and transition the session to `Authenticated`.

use crate::authn::service::RequestAuthnService;
use crate::authn::service::outcomes::{SignupOutcome, SignupVerification};
use crate::authn::{
    error::AuthnError,
    event::{AuthEventBuilder, AuthEventType, AuthFailureReason},
    store::{FactorStore, IdentityStore},
};
use crate::session::{
    data::{WorkflowKind, WorkflowState},
    extractor::AuthSession,
};

impl<I, F> RequestAuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Begin a signup flow: create a new user and transition the session to
    /// [`PendingWorkflow(Signup)`](WorkflowKind::Signup).
    ///
    /// The user is created in whatever [`EntityState`](crate::authn::types::EntityState) the caller provides
    /// (typically [`Candidate`](crate::authn::types::EntityState::Candidate)).
    /// The answer carries a single-use verification secret
    /// ([`SignupVerification`]), valid for
    /// [`DEFAULT_SIGNUP_VERIFICATION_TTL`](crate::authn::service::DEFAULT_SIGNUP_VERIFICATION_TTL)
    /// unless the service says otherwise; the session keeps only its digest.
    /// The application mails it to the address the person gave and calls
    /// [`complete_signup`](Self::complete_signup) with it when they return.
    /// Without that proof of control the session that began the signup cannot
    /// activate itself.
    ///
    /// `tenant_identifier` is the tenant slug/domain (looked up via
    /// [`IdentityLookup::find_tenant`](crate::authn::IdentityLookup::find_tenant)).
    ///
    /// An identifier that is already taken answers [`SignupOutcome::Started`]
    /// like a free one, creating nothing and leaving the session anonymous,
    /// so the answer does not say who has an account; the refusal is audited
    /// with reason `already_exists`. A service built with
    /// [`with_signup_conflicts_revealed`](crate::authn::service::AuthnServiceBuilder::with_signup_conflicts_revealed)
    /// answers [`SignupOutcome::AlreadyExists`] instead; see that method for
    /// how the application tells the two apart privately. The session that
    /// began a signup may submit it again and gets `Started` once more, with
    /// a success row carrying reason `resumed`.
    ///
    /// An account that is still `Candidate` holds its identifier only for
    /// [`DEFAULT_CANDIDATE_TTL`](crate::authn::service::DEFAULT_CANDIDATE_TTL)
    /// (`with_candidate_ttl` changes it): past that, a `begin_signup` for the
    /// same identifier from another session deletes it, audits the deletion
    /// and goes on as for a free identifier.
    ///
    /// Because `Started` covers both, the handler tells them apart with
    /// [`AuthSession::pending_user_id`](crate::session::AuthSession::pending_user_id)
    /// after the call: `Some` means an account is in flight, `None` means the
    /// identifier was taken. Send the verification mail only for `Some`, and
    /// never let the response differ between the two.
    ///
    /// # Errors
    ///
    /// Returns [`AuthnError::Store`] if the store operation fails.
    #[tracing::instrument(skip(self, user, session), fields(tenant = %tenant_identifier))]
    pub async fn begin_signup(
        &self,
        user: crate::authn::types::User,
        tenant_identifier: &str,
        session: &AuthSession,
    ) -> Result<SignupOutcome, AuthnError<I::Error>> {
        use crate::validation::{MAX_DISPLAY_NAME_BYTES, MAX_IDENTIFIER_BYTES, is_printable};

        // 0. Reject oversized or invalid inputs before hitting the database.
        if user.identifier.is_empty()
            || user.identifier.len() > MAX_IDENTIFIER_BYTES
            || user.display_name.len() > MAX_DISPLAY_NAME_BYTES
            || tenant_identifier.is_empty()
            || tenant_identifier.len() > MAX_IDENTIFIER_BYTES
            || !is_printable(&user.identifier)
            || !is_printable(&user.display_name)
            || !crate::validation::is_acceptable_new_identifier(&user.identifier)
        {
            self.refuse_signup(None, None, "invalid_input").await?;
            return Err(AuthnError::InvalidAssertion);
        }

        // 1. Validate tenant exists and is active.
        let tenant = self
            .inner
            .identity
            .find_tenant(tenant_identifier)
            .await
            .map_err(AuthnError::Store)?;

        let tenant = match tenant {
            Some(t)
                if t.status
                    .clone()
                    .effective_at(self.inner.clock.now())
                    .allows_login() =>
            {
                t
            }
            Some(t) => {
                self.refuse_signup(None, Some(&t.id), "tenant_not_active")
                    .await?;
                return Ok(SignupOutcome::TenantNotActive);
            }
            None => {
                self.refuse_signup(None, None, "unknown_tenant").await?;
                return Ok(SignupOutcome::TenantNotActive);
            }
        };

        // 2. Check if user already exists.
        let existing = self
            .inner
            .identity
            .find_user(&user.identifier, &tenant.id)
            .await
            .map_err(AuthnError::Store)?;

        // An existing account is never handed to the caller. An earlier
        // release resumed any `Candidate` row for whoever typed its
        // identifier, which let a stranger attach the half-created account
        // of a person who had not finished signing up (and set its
        // password, in a flow that saves one). The only resumption left is
        // the idempotent one: this session is already pending signup for
        // that very user, so a repeated submit answers `Started` again.
        // A `Candidate` holds its identifier only for `candidate_ttl`: nobody
        // has proved control of it, so a stranger who started a signup and
        // walked away must not keep the identifier from the person it
        // belongs to. Once it is older than that and not this session's own
        // it is deleted here and the signup goes on as for a free identifier.
        let existing = match existing {
            Some(candidate) if self.candidate_expired(&candidate, session).await => {
                self.purge_expired_candidate(&candidate).await?;
                None
            }
            other => other,
        };
        if let Some(existing_user) = existing {
            let resuming_own = matches!(
                session.auth_state().await,
                crate::session::data::AuthState::PendingWorkflow { user_id, workflow, .. }
                    if user_id == existing_user.id && workflow.kind == WorkflowKind::Signup
            );
            if matches!(
                existing_user.status,
                crate::authn::types::EntityState::Candidate
            ) && resuming_own
            {
                return self.resume_signup(&existing_user, session).await;
            }
            self.refuse_signup(
                Some(&existing_user.id),
                Some(&existing_user.tenant_id),
                "already_exists",
            )
            .await?;
            // Hidden conflicts (the default) answer as a free identifier
            // does, so the response is not a way to learn who has an account.
            // Nothing is created and the session stays as it was; the
            // application reads that from the session (no user) where the
            // caller cannot.
            if self.inner.reveal_signup_conflicts {
                return Ok(SignupOutcome::AlreadyExists);
            }
            return Ok(SignupOutcome::Started(None));
        }

        // 3. Create the user in the tenant that was just validated. The
        // caller names the tenant by slug and cannot know its id, so the
        // `tenant_id` on the record they built is a placeholder at best;
        // trusting it would store the row in one tenant while the session's
        // pending workflow (and the existence check above) named another.
        let mut user = user;
        user.tenant_id = tenant.id;
        // The age of a candidate is the service's clock at creation, not
        // whatever time the record the caller built carries.
        user.created_at = self.inner.clock.now();
        let user_id = user.id;
        let tenant_id = tenant.id;

        self.inner
            .identity
            .create_user(user)
            .await
            .map_err(AuthnError::Store)?;

        // 4. Transition session to PendingWorkflow(Signup).
        let now = self.inner.clock.now();
        let verification = self
            .arm_signup_verification(
                session,
                &user_id,
                &tenant_id,
                WorkflowState::new(WorkflowKind::Signup, 1, now),
            )
            .await;

        // 5. Record audit event.
        self.emit_audit_at(
            AuthEventBuilder::success(AuthEventType::SignupStarted)
                .attributed_to(&user_id, &tenant_id),
            now,
        )
        .await?;

        Ok(SignupOutcome::Started(Some(verification)))
    }

    /// Delete the unverified signups that have outlived their lifetime and
    /// that nobody asked for again, up to `limit` per call, and return how
    /// many were deleted.
    ///
    /// An expired `Candidate` stops reserving its identifier on its own (the
    /// next [`begin_signup`](Self::begin_signup) for it takes the row over),
    /// but a row nobody asks for again would stay for ever, holding the
    /// address. Call this on a schedule (a timer task, a cron job) with a
    /// `limit` that bounds one pass, for example 1000, and call it again while
    /// it returns `limit`. The lifetime is the one `begin_signup` applies:
    /// [`with_candidate_ttl`](crate::authn::service::AuthnServiceBuilder::with_candidate_ttl),
    /// never shorter than the verification secret's.
    ///
    /// Each deletion writes an `AccountDeleted` audit row naming the user, as
    /// the take-over does. Only accounts still `Candidate` are touched.
    ///
    /// # Errors
    ///
    /// [`AuthnError::Store`] when the store fails, or the audit error when a
    /// row cannot be written; the users deleted before it stay deleted.
    pub async fn purge_expired_candidates(
        &self,
        limit: usize,
    ) -> Result<usize, AuthnError<I::Error>> {
        let ttl = self
            .inner
            .candidate_ttl
            .max(self.inner.signup_verification_ttl);
        let ttl = chrono::Duration::from_std(ttl).unwrap_or(chrono::Duration::MAX / 4);
        let before = self
            .inner
            .clock
            .now()
            .checked_sub_signed(ttl)
            .unwrap_or(chrono::DateTime::<chrono::Utc>::MIN_UTC);
        let deleted = self
            .inner
            .identity
            .delete_candidates_created_before(before, limit)
            .await
            .map_err(AuthnError::Store)?;
        for user in &deleted {
            if let Some(reg) = &self.inner.registry {
                // A candidate holds no session, but a stray entry is cheap
                // to end and costs nothing to be sure of.
                crate::session::store::note_revocation(
                    reg.invalidate_user(&user.id).await,
                    "purging an expired candidate",
                );
            }
            self.emit_audit(
                AuthEventBuilder::success(AuthEventType::AccountDeleted)
                    .attributed_to(&user.id, &user.tenant_id),
            )
            .await?;
        }
        Ok(deleted.len())
    }

    /// Whether `user` is a `Candidate` past `candidate_ttl` that `session` is
    /// not the one resuming.
    async fn candidate_expired(
        &self,
        user: &crate::authn::types::User,
        session: &AuthSession,
    ) -> bool {
        if !matches!(user.status, crate::authn::types::EntityState::Candidate) {
            return false;
        }
        let resuming_own = matches!(
            session.auth_state().await,
            crate::session::data::AuthState::PendingWorkflow { user_id, workflow, .. }
                if user_id == user.id && workflow.kind == WorkflowKind::Signup
        );
        // Never shorter than the verification secret's life.
        let ttl = self
            .inner
            .candidate_ttl
            .max(self.inner.signup_verification_ttl);
        let ttl = chrono::Duration::from_std(ttl).unwrap_or(chrono::Duration::MAX / 4);
        !resuming_own && self.inner.clock.now() - user.created_at > ttl
    }

    /// Delete an expired candidate so its identifier is free, and leave the
    /// row that says so.
    async fn purge_expired_candidate(
        &self,
        user: &crate::authn::types::User,
    ) -> Result<(), AuthnError<I::Error>> {
        self.inner
            .identity
            .delete_user(&user.id)
            .await
            .map_err(AuthnError::Store)?;
        tracing::info!(tenant = %user.tenant_id, "an expired unverified signup released its identifier");
        self.emit_audit(
            AuthEventBuilder::success(AuthEventType::AccountDeleted)
                .attributed_to(&user.id, &user.tenant_id),
        )
        .await
    }

    /// The session submits its own pending signup again: a row for the
    /// resubmit, so the log shows every submit and not only the first (its
    /// type says nothing was created), and a fresh secret that replaces the
    /// earlier one, which cannot be recovered from its digest and so cannot
    /// be sent again.
    async fn resume_signup(
        &self,
        existing_user: &crate::authn::types::User,
        session: &AuthSession,
    ) -> Result<SignupOutcome, AuthnError<I::Error>> {
        self.emit_audit(
            AuthEventBuilder::success(AuthEventType::SignupResumed)
                .attributed_to(&existing_user.id, &existing_user.tenant_id)
                .with_session(session.session_id().await),
        )
        .await?;
        let verification = self
            .arm_signup_verification(
                session,
                &existing_user.id,
                &existing_user.tenant_id,
                WorkflowState::new(WorkflowKind::Signup, 1, self.inner.clock.now()),
            )
            .await;
        Ok(SignupOutcome::Started(Some(verification)))
    }

    /// Mint the secret that completes this signup, store its digest and
    /// expiry in the pending workflow, and return the secret.
    async fn arm_signup_verification(
        &self,
        session: &AuthSession,
        user_id: &crate::authn::ids::UserId,
        tenant_id: &crate::authn::ids::TenantId,
        workflow: WorkflowState,
    ) -> SignupVerification {
        use base64::Engine as _;
        use zeroize::Zeroizing;
        let mut raw = Zeroizing::new([0u8; 32]);
        self.inner.rng.fill_bytes(&mut *raw);
        let secret =
            Zeroizing::new(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw.as_slice()));
        let now = self.inner.clock.now();
        let expires_at = now
            + chrono::Duration::from_std(self.inner.signup_verification_ttl)
                .unwrap_or(chrono::Duration::MAX / 4);
        session
            .set_pending_workflow(
                *user_id,
                *tenant_id,
                workflow.with_verification(secret_digest(&secret), expires_at),
            )
            .await;
        SignupVerification { secret, expires_at }
    }

    /// Leave a failed `SignupStarted` row for a refused signup, with the
    /// user and tenant it concerns when known.
    async fn refuse_signup(
        &self,
        user_id: Option<&crate::authn::ids::UserId>,
        tenant_id: Option<&crate::authn::ids::TenantId>,
        reason: &'static str,
    ) -> Result<(), AuthnError<I::Error>> {
        self.emit_audit(
            AuthEventBuilder::failure(AuthEventType::SignupStarted)
                .maybe_attributed_to(user_id, tenant_id)
                .with_error(AuthFailureReason::from(reason)),
        )
        .await
    }

    /// Complete a signup flow: activate the user and transition the session
    /// to [`AuthState::Authenticated`](crate::session::data::AuthState::Authenticated).
    ///
    /// Call this when the person returns with the secret
    /// [`begin_signup`](Self::begin_signup) minted and the application mailed
    /// to them (a link, a code). The session must be in
    /// [`PendingWorkflow`](crate::session::data::AuthState::PendingWorkflow)
    /// state with a [`Signup`](WorkflowKind::Signup) workflow, and `secret`
    /// must match the digest stored with it, compared in constant time, before
    /// the secret's expiry. The secret is single use: completing the signup
    /// ends the workflow, and submitting the signup again replaces it.
    ///
    /// # Errors
    ///
    /// [`AuthnError::NoFlow`] when the session is not pending a signup;
    /// [`AuthnError::InvalidAssertion`] when `secret` is wrong or expired, or
    /// the pending signup holds no digest (one begun by an older release:
    /// submit the signup again for a new secret).
    #[tracing::instrument(skip_all)]
    pub async fn complete_signup(
        &self,
        session: &AuthSession,
        secret: &str,
    ) -> Result<(), AuthnError<I::Error>> {
        let state = session.auth_state().await;

        let (user_id, tenant_id, workflow) = match &state {
            crate::session::data::AuthState::PendingWorkflow {
                user_id,
                tenant_id,
                workflow,
            } if workflow.kind == WorkflowKind::Signup => (*user_id, *tenant_id, workflow),
            _ => return Err(AuthnError::NoFlow),
        };

        // The proof of control: a secret only the address's owner was sent.
        let fresh = workflow
            .verification_expires_at
            .is_some_and(|at| self.inner.clock.now() < at);
        let matches = workflow
            .verification_digest
            .as_deref()
            .is_some_and(|stored| {
                crate::validation::compare_secrets(
                    stored.as_bytes(),
                    secret_digest(secret).as_bytes(),
                )
            });
        if !(fresh && matches) {
            self.refuse_signup(Some(&user_id), Some(&tenant_id), "verification_failed")
                .await?;
            return Err(AuthnError::InvalidAssertion);
        }

        // Only a user still waiting to be activated is activated. The
        // workflow state in the session is a snapshot; between
        // `begin_signup` and now an administrator may have suspended the
        // account, and activating it here would undo that.
        let status = self.current_account_status(&user_id).await?;
        if !matches!(
            status,
            crate::authn::types::EntityState::Candidate
                | crate::authn::types::EntityState::Pending(_)
        ) {
            session.clear().await;
            self.refuse_signup(Some(&user_id), Some(&tenant_id), "not_awaiting_activation")
                .await?;
            return Err(AuthnError::NotActive(status));
        }

        // The tenant may have been suspended since `begin_signup`: its status is
        // read again, as every login reads it, and a tenant that does not load
        // refuses (fail closed).
        if let Err(refusal) = self.require_active_tenant(&tenant_id).await {
            if !matches!(refusal, AuthnError::Store(_)) {
                session.clear().await;
                self.refuse_signup(Some(&user_id), Some(&tenant_id), "tenant_not_active")
                    .await?;
            }
            return Err(refusal);
        }

        // Activate the user.
        self.inner
            .identity
            .activate_user(&user_id)
            .await
            .map_err(AuthnError::Store)?;

        // Transition to Authenticated.
        let now = self.inner.clock.now();
        session.set_authenticated(user_id, tenant_id, now).await;

        // Register in session registry if configured.
        // React to register-failure by clearing the session and
        // returning Err. Without this the user would walk away with an
        // Authenticated cookie that no `invalidate_user` call could ever
        // evict, because the registry never learnt about it.
        let sid = session.session_id().await;
        if let Some(reg) = &self.inner.registry
            && !reg.register(&user_id, &sid).await
        {
            tracing::error!(
                user_id = %user_id,
                tenant_id = %tenant_id,
                "complete_signup register failed; clearing session and refusing"
            );
            session.clear().await;
            return Err(AuthnError::NoFlow);
        }

        // Record audit event. A signup that cannot be recorded does not
        // leave an authenticated session behind.
        if let Err(e) = self
            .emit_audit_at(
                AuthEventBuilder::success(AuthEventType::SignupCompleted)
                    .attributed_to(&user_id, &tenant_id)
                    .with_session(sid),
                now,
            )
            .await
        {
            self.end_session_after_audit_failure(&user_id, session)
                .await;
            return Err(e);
        }

        Ok(())
    }
}

/// Lowercase hex SHA-256 of a verification secret: what the pending workflow
/// stores in its place.
fn secret_digest(secret: &str) -> String {
    use sha2::Digest as _;
    sha2::Sha256::digest(secret.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
