//! Admin actions: `suspend_user` / `activate_user` plus their `_by`,
//! `_in_tenant`, and combined `_by_in_tenant` variants.
//!
//! Each operation has four exposed variants:
//!
//! - bare (`suspend_user`): no actor recorded, no tenant rail.
//!   System-tenant admin paths only.
//! - `_by`: records the admin actor on the audit event.
//! - `_in_tenant`: refuses cross-tenant access via
//!   [`AuthnError::CrossTenant`](crate::authn::AuthnError).
//! - `_by_in_tenant`: both, the canonical path for tenant-scoped admin
//!   handlers.
//!
//! Each public variant delegates to a private `*_inner` helper that
//! holds the tenant-rail check, the registry invalidation (suspend
//! only; activate doesn't touch live sessions), and the audit-event
//! emission.

use crate::authn::service::AuthnService;
use crate::authn::{
    error::AuthnError,
    event::{AuthEventBuilder, AuthEventType},
    store::{FactorStore, IdentityStore},
    types::StatusDetail,
};

impl<I, F> AuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Suspend a user account.
    ///
    /// Updates the user's status in the identity store and invalidates all
    /// active sessions for the user via the session registry (if configured).
    /// The audit event records no `actor_id`.
    ///
    /// **Tenant boundary**: this method does NOT check that the target user
    /// belongs to any particular tenant; use [`suspend_user_in_tenant`](Self::suspend_user_in_tenant)
    /// or [`suspend_user_by_in_tenant`](Self::suspend_user_by_in_tenant)
    /// from any handler whose authorisation scope is a single tenant.
    /// The unscoped variant exists for system-tenant administrative paths
    /// (e.g. platform-operator console) where cross-tenant access is the
    /// intent.
    #[tracing::instrument(skip(self, detail))]
    pub async fn suspend_user(
        &self,
        user_id: &crate::authn::ids::UserId,
        detail: StatusDetail,
    ) -> Result<(), AuthnError<I::Error>> {
        self.suspend_user_inner(None, None, user_id, detail).await
    }

    /// Suspend a user account on behalf of an admin.
    ///
    /// Same as [`suspend_user`](Self::suspend_user), but records `actor` as
    /// the [`AuthEvent::actor_id`](crate::authn::event::AuthEvent::actor_id)
    /// so the audit event chain links the action to the admin who took it.
    pub async fn suspend_user_by(
        &self,
        actor: &crate::authn::ids::UserId,
        user_id: &crate::authn::ids::UserId,
        detail: StatusDetail,
    ) -> Result<(), AuthnError<I::Error>> {
        self.suspend_user_inner(Some(*actor), None, user_id, detail)
            .await
    }

    /// Suspend a user account, refusing if the target user's `tenant_id`
    /// does not match `expected_tenant`. Returns
    /// [`AuthnError::CrossTenant`]
    /// on mismatch so the audit log captures the attempt.
    ///
    /// Prefer this variant in any tenant-scoped admin path. Cedar policy
    /// can still enforce per-action allow/deny on top, but this is the
    /// structural rail that prevents tenant A's admin endpoint from
    /// affecting tenant B's users via parameter tampering.
    pub async fn suspend_user_in_tenant(
        &self,
        user_id: &crate::authn::ids::UserId,
        expected_tenant: &crate::authn::ids::TenantId,
        detail: StatusDetail,
    ) -> Result<(), AuthnError<I::Error>> {
        self.suspend_user_inner(None, Some(*expected_tenant), user_id, detail)
            .await
    }

    /// Combined `_by` + `_in_tenant`: records the admin actor and enforces
    /// the tenant rail.
    pub async fn suspend_user_by_in_tenant(
        &self,
        actor: &crate::authn::ids::UserId,
        user_id: &crate::authn::ids::UserId,
        expected_tenant: &crate::authn::ids::TenantId,
        detail: StatusDetail,
    ) -> Result<(), AuthnError<I::Error>> {
        self.suspend_user_inner(Some(*actor), Some(*expected_tenant), user_id, detail)
            .await
    }

    async fn suspend_user_inner(
        &self,
        actor: Option<crate::authn::ids::UserId>,
        expected_tenant: Option<crate::authn::ids::TenantId>,
        user_id: &crate::authn::ids::UserId,
        detail: StatusDetail,
    ) -> Result<(), AuthnError<I::Error>> {
        let user = self
            .verify_admin_target_in_tenant(
                user_id,
                actor.as_ref(),
                expected_tenant.as_ref(),
                "suspend",
            )
            .await?;

        self.identity
            .suspend_user(user_id, detail)
            .await
            .map_err(AuthnError::Store)?;

        // Invalidate all active sessions so suspended users are forced out
        // immediately, rather than staying logged in until their next request
        // happens to check account status.
        if let Some(reg) = &self.registry {
            reg.invalidate_user(user_id).await;
        }

        let mut builder = AuthEventBuilder::success(AuthEventType::AccountSuspended)
            .attributed_to(&user.id, &user.tenant_id);
        if let Some(actor_id) = actor {
            builder = builder.with_actor(actor_id);
        }

        self.emit_audit(builder).await;

        Ok(())
    }

    /// Activate a user account (e.g. unsuspend, or complete a manual review).
    ///
    /// Transitions the user to [`EntityState::Active`](crate::authn::types::EntityState::Active) regardless of current state.
    /// Use [`activate_user_by`](Self::activate_user_by) when an admin
    /// initiated the activation and the audit event should link to them.
    /// **Tenant boundary**: see [`activate_user_in_tenant`](Self::activate_user_in_tenant)
    /// for the tenant-scoped variant; this unscoped form is for
    /// system-tenant administrative paths only.
    #[tracing::instrument(skip(self))]
    pub async fn activate_user(
        &self,
        user_id: &crate::authn::ids::UserId,
    ) -> Result<(), AuthnError<I::Error>> {
        self.activate_user_inner(None, None, user_id).await
    }

    /// Activate a user account on behalf of an admin.
    ///
    /// Same as [`activate_user`](Self::activate_user) but records `actor` as
    /// the audit event's actor.
    pub async fn activate_user_by(
        &self,
        actor: &crate::authn::ids::UserId,
        user_id: &crate::authn::ids::UserId,
    ) -> Result<(), AuthnError<I::Error>> {
        self.activate_user_inner(Some(*actor), None, user_id).await
    }

    /// Activate a user account, refusing if the target user's `tenant_id`
    /// does not match `expected_tenant`. Returns
    /// [`AuthnError::CrossTenant`]
    /// on mismatch.
    pub async fn activate_user_in_tenant(
        &self,
        user_id: &crate::authn::ids::UserId,
        expected_tenant: &crate::authn::ids::TenantId,
    ) -> Result<(), AuthnError<I::Error>> {
        self.activate_user_inner(None, Some(*expected_tenant), user_id)
            .await
    }

    /// Combined `_by` + `_in_tenant`.
    pub async fn activate_user_by_in_tenant(
        &self,
        actor: &crate::authn::ids::UserId,
        user_id: &crate::authn::ids::UserId,
        expected_tenant: &crate::authn::ids::TenantId,
    ) -> Result<(), AuthnError<I::Error>> {
        self.activate_user_inner(Some(*actor), Some(*expected_tenant), user_id)
            .await
    }

    async fn activate_user_inner(
        &self,
        actor: Option<crate::authn::ids::UserId>,
        expected_tenant: Option<crate::authn::ids::TenantId>,
        user_id: &crate::authn::ids::UserId,
    ) -> Result<(), AuthnError<I::Error>> {
        let user = self
            .verify_admin_target_in_tenant(
                user_id,
                actor.as_ref(),
                expected_tenant.as_ref(),
                "activate",
            )
            .await?;

        self.identity
            .activate_user(user_id)
            .await
            .map_err(AuthnError::Store)?;

        let mut builder = AuthEventBuilder::success(AuthEventType::AccountActivated)
            .attributed_to(&user.id, &user.tenant_id);
        if let Some(actor_id) = actor {
            builder = builder.with_actor(actor_id);
        }

        self.emit_audit(builder).await;

        Ok(())
    }

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
        let user = self
            .identity
            .get_user(user_id)
            .await
            .map_err(AuthnError::Store)?
            .ok_or(AuthnError::NoFlow)?;

        if let Some(expected) = expected_tenant
            && user.tenant_id != *expected
        {
            tracing::warn!(
                user_id = %user_id,
                user_tenant = %user.tenant_id,
                expected_tenant = %expected,
                actor = ?actor,
                action = %action_label,
                "cross-tenant admin action refused"
            );
            return Err(AuthnError::CrossTenant);
        }
        Ok(user)
    }
}
