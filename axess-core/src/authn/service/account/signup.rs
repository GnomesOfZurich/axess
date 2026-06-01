//! Signup flow: `begin_signup` + `complete_signup`.
//!
//! Two-step ceremony: `begin_signup` creates a `Candidate` user and
//! transitions the session to `PendingWorkflow(Signup)`; the application
//! sends a verification email (or any other proof-of-control step), then
//! calls `complete_signup` to activate the user and transition the
//! session to `Authenticated`.

use crate::authn::service::AuthnService;
use crate::authn::service::outcomes::SignupOutcome;
use crate::authn::{
    error::AuthnError,
    event::{AuthEventBuilder, AuthEventType},
    store::{FactorStore, IdentityStore},
};
use crate::session::{
    data::{WorkflowKind, WorkflowState},
    extractor::AuthSession,
};

impl<I, F> AuthnService<I, F>
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
        {
            return Err(AuthnError::InvalidAssertion);
        }

        // 1. Validate tenant exists and is active.
        let tenant = self
            .identity
            .find_tenant(tenant_identifier)
            .await
            .map_err(AuthnError::Store)?;

        let tenant = match tenant {
            Some(t) if t.status.is_active() => t,
            Some(_) => return Ok(SignupOutcome::TenantNotActive),
            None => return Ok(SignupOutcome::TenantNotActive),
        };

        // 2. Check if user already exists.
        let existing = self
            .identity
            .find_user(&user.identifier, &tenant.id)
            .await
            .map_err(AuthnError::Store)?;

        // Orphan-Candidate recovery. If a previous `begin_signup`
        // created a `User` row but the application never finished the
        // workflow (the user closed the tab, the verification email was
        // dropped, etc.), the user is stuck in `Candidate` state and a
        // retry would hit `AlreadyExists` indefinitely. Treat an existing
        // `Candidate` row on the same identifier as a *resumption* of the
        // signup: re-attach the in-progress workflow state to the same
        // user_id, skip `create_user`, and let the application continue.
        // Any other status (`Active`, `Suspended`, etc.) still returns
        // `AlreadyExists`; those represent real, completed accounts and
        // must not be silently overwritten.
        if let Some(existing_user) = existing {
            if matches!(
                existing_user.status,
                crate::authn::types::EntityState::Candidate
            ) {
                let now = self.clock.now();
                let workflow = WorkflowState::new(WorkflowKind::Signup, 1, now);
                session
                    .set_pending_workflow(existing_user.id, existing_user.tenant_id, workflow)
                    .await;
                tracing::info!(
                    user_id = %existing_user.id,
                    tenant_id = %existing_user.tenant_id,
                    "resumed orphan Candidate signup"
                );
                return Ok(SignupOutcome::Started);
            }
            return Ok(SignupOutcome::AlreadyExists);
        }

        // 3. Create the user.
        let user_id = user.id;
        let tenant_id = tenant.id;

        self.identity
            .create_user(user)
            .await
            .map_err(AuthnError::Store)?;

        // 4. Transition session to PendingWorkflow(Signup).
        let now = self.clock.now();
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
        .await;

        Ok(SignupOutcome::Started)
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

        // Activate the user.
        self.identity
            .activate_user(&user_id)
            .await
            .map_err(AuthnError::Store)?;

        // Transition to Authenticated.
        let now = self.clock.now();
        session.set_authenticated(user_id, tenant_id, now).await;

        // Register in session registry if configured.
        // React to register-failure by clearing the session and
        // returning Err. Without this the user would walk away with an
        // Authenticated cookie that no `invalidate_user` call could ever
        // evict, because the registry never learnt about it.
        let sid = session.session_id().await;
        if let Some(reg) = &self.registry
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

        // Record audit event.
        self.emit_audit_at(
            AuthEventBuilder::success(AuthEventType::SignupCompleted)
                .attributed_to(&user_id, &tenant_id)
                .with_session(sid),
            now,
        )
        .await;

        Ok(())
    }
}
