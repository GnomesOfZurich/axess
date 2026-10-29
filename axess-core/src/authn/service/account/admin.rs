//! Admin actions: `suspend_user` / `activate_user`.
//!
//! Each operation has two exposed variants, and both name who acted:
//!
//! - `suspend_user` / `activate_user`: tenant-scoped. The target must belong
//!   to `expected_tenant`, or the call refuses with
//!   [`AuthnError::CrossTenant`](crate::authn::AuthnError) and writes a
//!   failed audit row naming the actor. The canonical path for the handler
//!   of one tenant's administrators.
//! - `*_across_tenants`: no tenant rail, for a platform operator whose reach
//!   is every tenant.
//!
//! Both delegate to a private `*_inner` helper that holds the tenant-rail
//! check, the registry invalidation (suspend only; activate doesn't touch
//! live sessions), and the audit-event emission.

use crate::authn::service::{Actor, RequestAuthnService};
use crate::authn::{
    error::AuthnError,
    event::{AuthEventBuilder, AuthEventType},
    store::{FactorStore, IdentityStore},
    types::StatusDetail,
};

impl<I, F> RequestAuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Suspend a user account of `expected_tenant` on behalf of `actor`.
    ///
    /// Updates the user's status in the identity store and invalidates all
    /// active sessions for the user via the session registry (if configured),
    /// removing the stored rows too when the service was given the session
    /// store. The audit event records `actor` as its `actor_id`
    /// (none for [`Actor::System`]).
    ///
    /// **Tenant boundary**: refuses with [`AuthnError::CrossTenant`] when the
    /// target user does not belong to `expected_tenant`, and a user that does
    /// not exist gets the same refusal, so the answer does not say which ids
    /// exist elsewhere. Use [`suspend_user_across_tenants`](Self::suspend_user_across_tenants)
    /// only for a platform-operator console where cross-tenant access is the
    /// intent.
    #[tracing::instrument(skip(self, detail))]
    pub async fn suspend_user(
        &self,
        actor: Actor<'_>,
        user_id: &crate::authn::ids::UserId,
        expected_tenant: &crate::authn::ids::TenantId,
        detail: StatusDetail,
    ) -> Result<(), AuthnError<I::Error>> {
        self.suspend_user_inner(actor, Some(*expected_tenant), user_id, detail)
            .await
    }

    /// Suspend a user account in any tenant, on behalf of `actor`.
    ///
    /// Like [`suspend_user`](Self::suspend_user) without the tenant rail: for
    /// system-tenant administrative paths (a platform-operator console).
    #[tracing::instrument(skip(self, detail))]
    pub async fn suspend_user_across_tenants(
        &self,
        actor: Actor<'_>,
        user_id: &crate::authn::ids::UserId,
        detail: StatusDetail,
    ) -> Result<(), AuthnError<I::Error>> {
        self.suspend_user_inner(actor, None, user_id, detail).await
    }

    async fn suspend_user_inner(
        &self,
        actor: Actor<'_>,
        expected_tenant: Option<crate::authn::ids::TenantId>,
        user_id: &crate::authn::ids::UserId,
        detail: StatusDetail,
    ) -> Result<(), AuthnError<I::Error>> {
        let user = self
            .verify_admin_target_in_tenant(user_id, actor.id(), expected_tenant.as_ref(), "suspend")
            .await?;

        self.inner
            .identity
            .suspend_user(user_id, detail)
            .await
            .map_err(AuthnError::Store)?;

        // Drop every session from the registry. A session is refused on its
        // next request only where the registry is consulted: behind
        // `require_valid_session`, or everywhere when the session layer was
        // built with a registry. Behind `require_authn!` alone the stored
        // session keeps working until its TTL.
        // A registry that fails is reported after the audit row below, like a
        // refresh-token revocation that fails.
        let sessions_ended = self.end_user_sessions(user_id).await;

        // Refresh tokens are a separate credential: a suspended account's
        // holder could otherwise refresh into a new session the moment the
        // suspension lapsed, or through a path that does not check status.
        // The failure is returned after the audit row is written.
        let revoked = self.revoke_refresh_tokens(user_id).await;

        let mut builder = AuthEventBuilder::success(AuthEventType::AccountSuspended)
            .attributed_to(&user.id, &user.tenant_id);
        if let Some(actor_id) = actor.id() {
            builder = builder.with_actor(*actor_id);
        }

        self.emit_audit(builder).await?;

        sessions_ended?;
        revoked?;
        Ok(())
    }

    /// Activate a user account of `expected_tenant` (e.g. unsuspend, or
    /// complete a manual review) on behalf of `actor`.
    ///
    /// Transitions the user to [`EntityState::Active`](crate::authn::types::EntityState::Active) regardless of current state.
    /// **Tenant boundary**: refuses with [`AuthnError::CrossTenant`] when the
    /// target user does not belong to `expected_tenant`; see
    /// [`activate_user_across_tenants`](Self::activate_user_across_tenants)
    /// for the platform-operator form.
    #[tracing::instrument(skip(self))]
    pub async fn activate_user(
        &self,
        actor: Actor<'_>,
        user_id: &crate::authn::ids::UserId,
        expected_tenant: &crate::authn::ids::TenantId,
    ) -> Result<(), AuthnError<I::Error>> {
        self.activate_user_inner(actor, Some(*expected_tenant), user_id)
            .await
    }

    /// Activate a user account in any tenant, on behalf of `actor`.
    ///
    /// Like [`activate_user`](Self::activate_user) without the tenant rail:
    /// for system-tenant administrative paths only.
    #[tracing::instrument(skip(self))]
    pub async fn activate_user_across_tenants(
        &self,
        actor: Actor<'_>,
        user_id: &crate::authn::ids::UserId,
    ) -> Result<(), AuthnError<I::Error>> {
        self.activate_user_inner(actor, None, user_id).await
    }

    async fn activate_user_inner(
        &self,
        actor: Actor<'_>,
        expected_tenant: Option<crate::authn::ids::TenantId>,
        user_id: &crate::authn::ids::UserId,
    ) -> Result<(), AuthnError<I::Error>> {
        let user = self
            .verify_admin_target_in_tenant(
                user_id,
                actor.id(),
                expected_tenant.as_ref(),
                "activate",
            )
            .await?;

        self.inner
            .identity
            .activate_user(user_id)
            .await
            .map_err(AuthnError::Store)?;

        let mut builder = AuthEventBuilder::success(AuthEventType::AccountActivated)
            .attributed_to(&user.id, &user.tenant_id);
        if let Some(actor_id) = actor.id() {
            builder = builder.with_actor(*actor_id);
        }

        self.emit_audit(builder).await?;

        Ok(())
    }
}

impl<I, F> RequestAuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Resolve `user_id` to a [`User`](crate::authn::types::User) and
    /// enforce the expected-tenant rail.
    ///
    /// Returns the resolved user on success. Returns
    /// `Err(AuthnError::NoFlow)` if the user does not exist (admin
    /// targeting a deleted/never-existed id) or
    /// `Err(AuthnError::CrossTenant)` when `expected_tenant` is `Some`
    /// and the resolved user's tenant doesn't match. The
    /// `action_label` parameter is only used in the warn-log
    /// message ("cross-tenant {action} refused") so SOC
    /// dashboards can distinguish suspend vs activate vs any future
    /// admin action; **it is not user-controlled**: call sites pass
    /// short literal strings.
    ///
    /// This converged helper replaced duplicated bodies in
    /// `suspend_user_inner` and `activate_user_inner`. A future
    /// admin action (e.g. `delete_user_inner`,
    /// `force_password_reset_inner`) can adopt the same fail-closed
    /// rail with a single call rather than re-implementing it.
    async fn verify_admin_target_in_tenant(
        &self,
        user_id: &crate::authn::ids::UserId,
        actor: Option<&crate::authn::ids::UserId>,
        expected_tenant: Option<&crate::authn::ids::TenantId>,
        action_label: &'static str,
    ) -> Result<crate::authn::types::User, AuthnError<I::Error>> {
        // With a tenant named, resolve within it. A user of another tenant
        // and a user that does not exist are then the same `CrossTenant`
        // refusal, so the answer does not say which ids exist elsewhere,
        // and both write the same failed audit row naming the actor.
        let user = match expected_tenant {
            Some(expected) => {
                let found = self
                    .inner
                    .identity
                    .get_user_in_tenant(user_id, expected)
                    .await
                    .map_err(AuthnError::Store)?;
                match found {
                    Some(user) => user,
                    None => {
                        tracing::warn!(
                            user_id = %user_id,
                            expected_tenant = %expected,
                            actor = ?actor,
                            action = %action_label,
                            "cross-tenant admin action refused"
                        );
                        let event_type = match action_label {
                            "suspend" => AuthEventType::AccountSuspended,
                            _ => AuthEventType::AccountActivated,
                        };
                        let mut builder = AuthEventBuilder::failure(event_type)
                            .maybe_attributed_to(None, Some(expected))
                            .with_error(crate::authn::event::AuthFailureReason::Other(
                                "cross_tenant_admin_action".into(),
                            ));
                        if let Some(actor_id) = actor {
                            builder = builder.with_actor(*actor_id);
                        }
                        self.emit_audit(builder).await?;
                        return Err(AuthnError::CrossTenant);
                    }
                }
            }
            None => self
                .inner
                .identity
                .get_user(user_id)
                .await
                .map_err(AuthnError::Store)?
                .ok_or(AuthnError::NoFlow)?,
        };
        Ok(user)
    }
}
