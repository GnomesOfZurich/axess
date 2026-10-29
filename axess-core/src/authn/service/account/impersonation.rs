//! Admin impersonation: assume the identity of another user.
//!
//! Two variants:
//!
//! - `RequestAuthnService::begin_impersonation`: refuses with
//!   [`AuthnError::CrossTenant`] when `admin.tenant_id != target.tenant_id`,
//!   closing the cross-tenant pivot vector. The default.
//! - `RequestAuthnService::begin_impersonation_across_tenants`: does not
//!   check that admin and target share a tenant; the caller is responsible
//!   (e.g. via a Cedar policy that scopes the action). For a platform
//!   operator.
//!
//! Both record an `Impersonation` audit event with the target as
//! `user_id` and the admin as `actor_id`, so forensic queries like
//! `SELECT * FROM auth_events WHERE actor_id = ? AND event_type = 'impersonation'`
//! reconstruct the admin's full session-take history.

use crate::authn::service::RequestAuthnService;
use crate::authn::{
    error::AuthnError,
    event::{AuthEventBuilder, AuthEventType, AuthFailureReason},
    store::{FactorStore, IdentityStore},
};
use crate::session::extractor::AuthSession;
use crate::session::store::note_revocation;

impl<I, F> RequestAuthnService<I, F>
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
    /// share a tenant, so it is for a platform operator whose reach is every
    /// tenant. A handler scoped to one tenant uses
    /// [`begin_impersonation`](Self::begin_impersonation), which refuses with
    /// [`AuthnError::CrossTenant`] if `admin_user.tenant_id` and
    /// `target_user.tenant_id` differ.
    #[tracing::instrument(skip(self, target_user, session))]
    pub async fn begin_impersonation_across_tenants(
        &self,
        admin_user_id: &crate::authn::ids::UserId,
        target_user: &crate::authn::types::User,
        session: &AuthSession,
    ) -> Result<(), AuthnError<I::Error>> {
        self.impersonate(admin_user_id, None, target_user, session)
            .await
    }

    /// Refuse an impersonation and leave the failed audit row naming the
    /// admin as actor.
    async fn refuse_impersonation(
        &self,
        admin: &crate::authn::ids::UserId,
        target: Option<&crate::authn::types::User>,
        reason: &'static str,
        error: AuthnError<I::Error>,
    ) -> AuthnError<I::Error> {
        tracing::warn!(admin = %admin, reason, "impersonation refused");
        let builder = AuthEventBuilder::failure(AuthEventType::Impersonation)
            .maybe_attributed_to(target.map(|t| &t.id), target.map(|t| &t.tenant_id))
            .with_actor(*admin)
            .with_error(AuthFailureReason::Other(reason.into()));
        match self.emit_audit(builder).await {
            Ok(()) => error,
            Err(audit_error) => audit_error,
        }
    }

    /// The checks that come before the admin's session is touched: it is
    /// the admin's, and the target (reloaded from the store) is inside the
    /// tenant rail. Returns the admin's snapshot and the stored target.
    async fn admit_impersonation(
        &self,
        admin_user_id: &crate::authn::ids::UserId,
        expected_tenant: Option<&crate::authn::ids::TenantId>,
        target_user: &crate::authn::types::User,
        session: &AuthSession,
    ) -> Result<
        (
            crate::session::extractor::AuthSnapshot,
            crate::authn::types::User,
        ),
        AuthnError<I::Error>,
    > {
        // The session must BE the admin: authenticated as `admin_user_id`.
        // The caller names the admin as an argument, and nothing else tied
        // that name to the session, so any session could assume any
        // identity under an admin's name in the audit trail.
        let Some(admin_snapshot) = session.snapshot().await else {
            return Err(self
                .refuse_impersonation(
                    admin_user_id,
                    Some(target_user),
                    "admin_not_authenticated",
                    AuthnError::NoFlow,
                )
                .await);
        };
        if &admin_snapshot.user_id != admin_user_id {
            return Err(self
                .refuse_impersonation(
                    admin_user_id,
                    Some(target_user),
                    "session_is_not_admin",
                    AuthnError::NoFlow,
                )
                .await);
        }

        // The target is the store's, not the caller's record of it: a
        // `User` struct is whatever the caller built, and its `tenant_id`
        // is what the tenant rail compares. Reloaded by id; the tenant
        // rail uses the stored tenants of both principals.
        let target = self
            .inner
            .identity
            .get_user(&target_user.id)
            .await
            .map_err(AuthnError::Store)?;
        let Some(target) = target else {
            return Err(self
                .refuse_impersonation(
                    admin_user_id,
                    Some(target_user),
                    "unknown_target",
                    AuthnError::NoFlow,
                )
                .await);
        };
        if let Some(expected) = expected_tenant
            && (&target.tenant_id != expected || admin_snapshot.tenant_id != *expected)
        {
            return Err(self
                .refuse_impersonation(
                    admin_user_id,
                    Some(&target),
                    "cross_tenant_impersonation",
                    AuthnError::CrossTenant,
                )
                .await);
        }
        Ok((admin_snapshot, target))
    }

    async fn impersonate(
        &self,
        admin_user_id: &crate::authn::ids::UserId,
        expected_tenant: Option<&crate::authn::ids::TenantId>,
        target_user: &crate::authn::types::User,
        session: &AuthSession,
    ) -> Result<(), AuthnError<I::Error>> {
        let now = self.inner.clock.now();

        let (admin_snapshot, target) = self
            .admit_impersonation(admin_user_id, expected_tenant, target_user, session)
            .await?;
        let target_user = &target;

        // A suspended, terminated or otherwise non-active target cannot be
        // assumed: impersonation would hand the admin a session the account's
        // own owner is barred from holding. Checked before the admin's
        // session is touched.
        let status = self.current_account_status(&target_user.id).await?;
        if !status.allows_login() {
            tracing::warn!(
                admin = %admin_user_id,
                target = %target_user.id,
                status = ?status,
                "impersonation refused: target account is not active"
            );
            self.emit_audit_at(
                AuthEventBuilder::failure(AuthEventType::Impersonation)
                    .attributed_to(&target_user.id, &target_user.tenant_id)
                    .with_actor(*admin_user_id)
                    .with_error(AuthFailureReason::NotActive),
                now,
            )
            .await?;
            return Err(AuthnError::NotActive(status));
        }

        // The admin's own session ends with this call: its cookie is about
        // to carry the target's identity. Leaving the admin's sid in the
        // registry would keep a session alive that nobody can reach.
        let admin_sid = session.session_id().await;

        // Wipe any custom JSON the admin's session was carrying. Without
        // this, attacker-pre-seeded keys (OAuth PKCE_VERIFIER, CSRF_STATE,
        // app-specific flags) would persist into the impersonated identity
        // and could be used to hijack a subsequent OAuth login or bypass
        // app-level checks performed under the assumed user.
        session.clear_custom().await;

        // Set the session to the target user's identity, with the ADMIN's
        // authentication time. Stamping `now` made an impersonated session
        // look like a fresh login of the target and satisfied every
        // recent-authentication check on the strength of nothing the target
        // did.
        session
            .set_authenticated(
                target_user.id,
                target_user.tenant_id,
                admin_snapshot.authn_time,
            )
            .await;
        // The marker `AuthSession::impersonator` reads. It lives in the
        // session's custom data, which only server code writes.
        session
            .set_custom(
                IMPERSONATOR_KEY,
                serde_json::json!({
                    "actor": admin_user_id.to_string(),
                    "since": now.to_rfc3339(),
                }),
            )
            .await;

        // Force a session-ID rotation so the impersonating session never
        // shares its ID with the prior admin session; relevant for any
        // downstream code that keys things by session ID.
        session.regenerate().await;

        let sid = session.session_id().await;
        // Same as complete_signup; refuse to leave an admin in
        // an Authenticated-but-untracked impersonation session.
        if let Some(reg) = &self.inner.registry {
            if !reg.register(&target_user.id, &sid).await {
                tracing::error!(
                    admin_user_id = %admin_user_id,
                    target_user_id = %target_user.id,
                    "begin_impersonation register failed; clearing session and refusing"
                );
                session.clear().await;
                return Err(AuthnError::NoFlow);
            }
            note_revocation(
                reg.invalidate_session(admin_user_id, &admin_sid).await,
                "ending an impersonation",
            );
        }

        // Record the impersonation event with both principals: the target
        // is the subject, the admin is the actor. An impersonation that
        // cannot be recorded does not stand: the session is ended.
        if let Err(e) = self
            .emit_audit_at(
                AuthEventBuilder::success(AuthEventType::Impersonation)
                    .attributed_to(&target_user.id, &target_user.tenant_id)
                    .with_session(sid)
                    .with_actor(*admin_user_id),
                now,
            )
            .await
        {
            self.end_session_after_audit_failure(&target_user.id, session)
                .await;
            return Err(e);
        }

        tracing::warn!(
            admin = %admin_user_id,
            target = %target_user.id,
            "admin impersonation: session assumed target identity"
        );

        Ok(())
    }

    /// End an impersonation: the session and its registry entry are
    /// cleared and the id rotated, so nothing of the target's identity
    /// stays on the cookie. The admin signs in again.
    ///
    /// Returns [`AuthnError::NoFlow`] for a session that is not
    /// impersonating. Writes a logout audit row attributed to the target
    /// with the admin as actor.
    pub async fn end_impersonation(
        &self,
        session: &AuthSession,
    ) -> Result<(), AuthnError<I::Error>> {
        let Some(actor) = session.impersonator().await else {
            return Err(AuthnError::NoFlow);
        };
        let target = session.user_id().await;
        let tenant = session.tenant_id().await;
        let sid = session.session_id().await;
        if let (Some(reg), Some(target)) = (&self.inner.registry, &target) {
            note_revocation(
                reg.invalidate_session(target, &sid).await,
                "ending an impersonation",
            );
        }
        session.clear().await;
        session.regenerate().await;
        let mut builder = AuthEventBuilder::success(AuthEventType::LogoutAttempt)
            .maybe_attributed_to(target.as_ref(), tenant.as_ref())
            .with_actor(actor);
        builder = builder.with_session(sid);
        self.emit_audit(builder).await
    }

    /// Assume the identity of another user of the admin's own tenant.
    ///
    /// The same operation as
    /// [`begin_impersonation_across_tenants`](Self::begin_impersonation_across_tenants),
    /// which it is the safe default for: it refuses with
    /// [`AuthnError::CrossTenant`] when `admin_user.tenant_id` does not equal
    /// `target_user.tenant_id`, closing the cross-tenant pivot vector that the
    /// other form leaves to the application's Cedar policy.
    ///
    /// Pass `admin_user` (not just the id) so the rail can be enforced
    /// without an extra `get_user` round-trip in the common case where the
    /// caller already has the admin record loaded.
    pub async fn begin_impersonation(
        &self,
        admin_user: &crate::authn::types::User,
        target_user: &crate::authn::types::User,
        session: &AuthSession,
    ) -> Result<(), AuthnError<I::Error>> {
        // The admin's tenant is the store's, as the target's is: the
        // supplied records only name the principals.
        let stored_admin_tenant = self
            .inner
            .identity
            .get_user_tenant(&admin_user.id)
            .await
            .map_err(AuthnError::Store)?;
        let Some(admin_tenant) = stored_admin_tenant else {
            return Err(self
                .refuse_impersonation(
                    &admin_user.id,
                    Some(target_user),
                    "unknown_admin",
                    AuthnError::NoFlow,
                )
                .await);
        };
        self.impersonate(&admin_user.id, Some(&admin_tenant), target_user, session)
            .await
    }
}

/// Session custom key that marks an impersonated session.
pub(crate) const IMPERSONATOR_KEY: &str = "axess.impersonation";

impl AuthSession {
    /// The administrator who is impersonating the user this session is
    /// authenticated as, or `None` for an ordinary session.
    ///
    /// Set by `begin_impersonation`. Check it before allowing anything an
    /// administrator should not do in a user's name: changing credentials,
    /// enrolling factors, issuing refresh tokens. The session's
    /// authentication time is the administrator's, not a fresh login's.
    pub async fn impersonator(&self) -> Option<crate::authn::ids::UserId> {
        let marker = self.get_custom(IMPERSONATOR_KEY).await?;
        let actor = marker.get("actor")?.as_str()?;
        crate::authn::ids::UserId::try_new(actor).ok()
    }
}
