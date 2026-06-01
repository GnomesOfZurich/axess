//! Admin impersonation: assume the identity of another user.
//!
//! Two variants:
//!
//! - `AuthnService::begin_impersonation`: bare. Does not check that
//!   admin and target share a tenant; the caller is responsible (e.g.
//!   via a Cedar policy that scopes the action).
//! - `AuthnService::begin_impersonation_in_tenant`: refuses with
//!   [`AuthnError::CrossTenant`] when `admin.tenant_id != target.tenant_id`,
//!   closing the cross-tenant pivot vector that the unscoped form leaves
//!   to the application's policy layer.
//!
//! Both record an `Impersonation` audit event with the target as
//! `user_id` and the admin as `actor_id`, so forensic queries like
//! `SELECT * FROM auth_events WHERE actor_id = ? AND event_type = 'impersonation'`
//! reconstruct the admin's full session-take history.

use crate::authn::service::AuthnService;
use crate::authn::{
    error::AuthnError,
    event::{AuthEventBuilder, AuthEventType},
    store::{FactorStore, IdentityStore},
};
use crate::session::extractor::AuthSession;

impl<I, F> AuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Assume the identity of another user (admin impersonation).
    ///
    /// Creates a fully authenticated session as `target_user`. An
    /// `Impersonation` audit event is recorded with `target_user.id` as the
    /// subject (`user_id`) and the admin as the actor (`actor_id`), so
    /// forensic queries like
    /// `SELECT * FROM auth_events WHERE actor_id = ? AND event_type = 'impersonation'`
    /// list everything an admin did via impersonation.
    ///
    /// # Arguments
    ///
    /// * `admin_user_id`: the admin performing the impersonation (must be authenticated).
    /// * `target_user`: the user to impersonate.
    /// * `session`: the admin's current session (will be replaced with the target's identity).
    ///
    /// # Security
    ///
    /// This method does NOT check authorization; the caller must verify
    /// that the admin has permission to impersonate (e.g., via Cedar
    /// policy) before calling.
    ///
    /// **Tenant boundary**: this method does NOT check that admin and target
    /// share a tenant. For tenant-scoped impersonation (the common case),
    /// use [`begin_impersonation_in_tenant`](Self::begin_impersonation_in_tenant)
    /// which refuses with [`AuthnError::CrossTenant`] if `admin_user.tenant_id`
    /// and `target_user.tenant_id` differ.
    #[tracing::instrument(skip(self, target_user, session))]
    pub async fn begin_impersonation(
        &self,
        admin_user_id: &crate::authn::ids::UserId,
        target_user: &crate::authn::types::User,
        session: &AuthSession,
    ) -> Result<(), AuthnError<I::Error>> {
        let now = self.clock.now();

        // Wipe any custom JSON the admin's session was carrying. Without
        // this, attacker-pre-seeded keys (OAuth PKCE_VERIFIER, CSRF_STATE,
        // app-specific flags) would persist into the impersonated identity
        // and could be used to hijack a subsequent OAuth login or bypass
        // app-level checks performed under the assumed user.
        session.clear_custom().await;

        // Set the session to the target user's identity.
        session
            .set_authenticated(target_user.id, target_user.tenant_id, now)
            .await;

        // Force a session-ID rotation so the impersonating session never
        // shares its ID with the prior admin session; relevant for any
        // downstream code that keys things by session ID.
        session.regenerate().await;

        let sid = session.session_id().await;
        // Same as complete_signup; refuse to leave an admin in
        // an Authenticated-but-untracked impersonation session.
        if let Some(reg) = &self.registry
            && !reg.register(&target_user.id, &sid).await
        {
            tracing::error!(
                admin_user_id = %admin_user_id,
                target_user_id = %target_user.id,
                "begin_impersonation register failed; clearing session and refusing"
            );
            session.clear().await;
            return Err(AuthnError::NoFlow);
        }

        // Record the impersonation event with both principals: the target
        // is the subject, the admin is the actor.
        self.emit_audit_at(
            AuthEventBuilder::success(AuthEventType::Impersonation)
                .attributed_to(&target_user.id, &target_user.tenant_id)
                .with_session(sid)
                .with_actor(*admin_user_id),
            now,
        )
        .await;

        tracing::warn!(
            admin = %admin_user_id,
            target = %target_user.id,
            "admin impersonation: session assumed target identity"
        );

        Ok(())
    }

    /// Tenant-scoped variant of [`begin_impersonation`](Self::begin_impersonation).
    /// Refuses with [`AuthnError::CrossTenant`] when `admin_user.tenant_id`
    /// does not equal `target_user.tenant_id`, closing the cross-tenant
    /// pivot vector that the unscoped form leaves to the application's
    /// Cedar policy.
    ///
    /// Pass `admin_user` (not just the id) so the rail can be enforced
    /// without an extra `get_user` round-trip in the common case where the
    /// caller already has the admin record loaded.
    pub async fn begin_impersonation_in_tenant(
        &self,
        admin_user: &crate::authn::types::User,
        target_user: &crate::authn::types::User,
        session: &AuthSession,
    ) -> Result<(), AuthnError<I::Error>> {
        if admin_user.tenant_id != target_user.tenant_id {
            tracing::warn!(
                admin = %admin_user.id,
                admin_tenant = %admin_user.tenant_id,
                target = %target_user.id,
                target_tenant = %target_user.tenant_id,
                "cross-tenant impersonation refused"
            );
            // Audit-record the refused attempt; security-relevant signal.
            self.emit_audit(
                AuthEventBuilder::failure(AuthEventType::Impersonation)
                    .attributed_to(&target_user.id, &target_user.tenant_id)
                    .with_actor(admin_user.id)
                    .with_error("cross-tenant impersonation refused"),
            )
            .await;
            return Err(AuthnError::CrossTenant);
        }
        self.begin_impersonation(&admin_user.id, target_user, session)
            .await
    }
}
