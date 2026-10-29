//! Signup flow: `begin_signup` + `complete_signup`.
//!
//! Two-step ceremony: `begin_signup` creates a `Candidate` user and
//! transitions the session to `PendingWorkflow(Signup)`; the application
//! sends a verification email (or any other proof-of-control step), then
//! calls `complete_signup` to activate the user and transition the
//! session to `Authenticated`.

use crate::authn::service::RequestAuthnService;
use crate::authn::service::outcomes::SignupOutcome;
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
    /// (typically [`Candidate`](crate::authn::types::EntityState::Candidate)). The application
    /// is responsible for what happens next: typically sending a verification
    /// email and calling [`complete_signup`](Self::complete_signup) after the
    /// user confirms.
    ///
    /// `tenant_identifier` is the tenant slug/domain (looked up via
    /// [`IdentityLookup::find_tenant`](crate::authn::IdentityLookup::find_tenant)).
    ///
    /// An identifier that is already taken answers
    /// [`SignupOutcome::AlreadyExists`], which tells the caller who has an
    /// account. [`with_hidden_signup_conflicts`](crate::authn::service::AuthnServiceBuilder::with_hidden_signup_conflicts)
    /// makes it answer [`SignupOutcome::Started`] instead, creating nothing
    /// and leaving the session anonymous; see that method for how the
    /// application tells the two apart privately. Either way the refusal is
    /// audited with its reason.
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
            || !crate::validation::is_acceptable_identifier(&user.identifier)
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
            Some(t) if t.status.is_active() => t,
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
        // A stale `Candidate` that nobody is resuming is the application's
        // to purge (`delete_user`), after whatever proof of control its
        // verification step gives.
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
                return Ok(SignupOutcome::Started);
            }
            self.refuse_signup(
                Some(&existing_user.id),
                Some(&existing_user.tenant_id),
                "already_exists",
            )
            .await?;
            // Hidden conflicts answer as a free identifier does, so the
            // response is not a way to learn who has an account. Nothing is
            // created and the session stays as it was; the application
            // reads that from the session (no user) where the caller cannot.
            if self.inner.hide_signup_conflicts {
                return Ok(SignupOutcome::Started);
            }
            return Ok(SignupOutcome::AlreadyExists);
        }

        // 3. Create the user in the tenant that was just validated. The
        // caller names the tenant by slug and cannot know its id, so the
        // `tenant_id` on the record they built is a placeholder at best;
        // trusting it would store the row in one tenant while the session's
        // pending workflow (and the existence check above) named another.
        let mut user = user;
        user.tenant_id = tenant.id;
        let user_id = user.id;
        let tenant_id = tenant.id;

        self.inner
            .identity
            .create_user(user)
            .await
            .map_err(AuthnError::Store)?;

        // 4. Transition session to PendingWorkflow(Signup).
        let now = self.inner.clock.now();
        let workflow = WorkflowState::new(WorkflowKind::Signup, 1, now);
        session
            .set_pending_workflow(user_id, tenant_id, workflow)
            .await;

        // 5. Record audit event.
        self.emit_audit_at(
            AuthEventBuilder::success(AuthEventType::SignupStarted)
                .attributed_to(&user_id, &tenant_id),
            now,
        )
        .await?;

        Ok(SignupOutcome::Started)
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
                .with_error(AuthFailureReason::Other(reason.into())),
        )
        .await
    }

    /// Complete a signup flow: activate the user and transition the session
    /// to [`AuthState::Authenticated`](crate::session::data::AuthState::Authenticated).
    ///
    /// Call this after the user has completed whatever verification the
    /// application requires (e.g. email confirmation). The session must be
    /// in [`PendingWorkflow`](crate::session::data::AuthState::PendingWorkflow)
    /// state with a [`Signup`](WorkflowKind::Signup) workflow.
    #[tracing::instrument(skip(self, session))]
    pub async fn complete_signup(&self, session: &AuthSession) -> Result<(), AuthnError<I::Error>> {
        let state = session.auth_state().await;

        let (user_id, tenant_id) = match &state {
            crate::session::data::AuthState::PendingWorkflow {
                user_id,
                tenant_id,
                workflow,
            } if workflow.kind == WorkflowKind::Signup => (*user_id, *tenant_id),
            _ => return Err(AuthnError::NoFlow),
        };

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
