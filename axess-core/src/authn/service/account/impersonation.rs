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
//!
//! The impersonated session carries the administrator and the start time in
//! its authenticated state (`AuthSession::impersonation`). While it is set
//! the service refuses refresh token issuance and factor enrolment or
//! deletion unless built with
//! `AuthnServiceBuilder::with_impersonated_credential_changes_allowed`, the
//! audit context of a request under impersonation names the administrator
//! as actor on every row, and `SessionLayer::with_max_impersonation_age`
//! ends the session once the impersonation is older than the cap (1 hour by
//! default; `None` lifts it).

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
    /// [`AuthnError::CrossTenant`] unless the stored target is a user of the
    /// admin's stored tenant. Here a target id that does not exist is
    /// refused with [`AuthnError::NoFlow`]; a session that is already an
    /// impersonation is refused with [`AuthnError::Impersonated`]. An
    /// administrator whose own
    /// account is not active is refused with [`AuthnError::NotActive`],
    /// as a target that is not active is. Every refusal, and a target
    /// lookup the store could not make, leaves a failed `Impersonation`
    /// row naming the administrator as actor; the row names the target
    /// only once it was read from the store.
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
    /// admin as actor. `target` is the stored target when it was read and
    /// is inside the rail, and `None` otherwise: a refusal made before, or
    /// without, a stored target names none, since the caller's `User`
    /// value is whatever the caller built and a row carrying its ids would
    /// put a chosen user and tenant on the trail.
    async fn refuse_impersonation(
        &self,
        admin: &crate::authn::ids::UserId,
        target: Option<&crate::authn::types::User>,
        reason: AuthFailureReason,
        error: AuthnError<I::Error>,
    ) -> AuthnError<I::Error> {
        tracing::warn!(admin = %admin, reason = reason.as_str(), "impersonation refused");
        let builder = AuthEventBuilder::failure(AuthEventType::Impersonation)
            .maybe_attributed_to(target.map(|t| &t.id), target.map(|t| &t.tenant_id))
            .with_actor(*admin)
            .with_error(reason);
        match self.emit_audit(builder).await {
            Ok(()) => error,
            Err(audit_error) => audit_error,
        }
    }

    /// The checks that come before the admin's session is touched: it is
    /// the admin's own (not already an impersonation), and the target
    /// (reloaded from the store) is inside the tenant rail. Returns the
    /// admin's snapshot and the stored target.
    ///
    /// `expected_tenant` is the rail. `Some(tenant)` is the tenant-scoped
    /// form: the target must be a stored user of that tenant, and so must
    /// the admin's session. A target that is missing and one that exists in
    /// another tenant are refused with the same error after the same work
    /// (one read, one audit write), so the answer does not say which ids
    /// exist elsewhere; the audit row names which it was. `None` is the
    /// across-tenants form: no rail is applied here, the caller's policy
    /// is the rail, and only a target that does not exist at all is refused.
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
        // A session that is already an impersonation is the administrator's
        // in the impersonated user's name: letting it impersonate again
        // would record the second take, and everything after it, as the
        // first target's act. The row names the administrator who really
        // holds the session and, like every refusal made before the target
        // is read, no target. `end_impersonation` is the way back. Asked
        // first, so the answer does not depend on which administrator id
        // the caller names.
        if let Some(holder) = session.impersonator().await {
            return Err(self
                .refuse_impersonation(
                    &holder,
                    None,
                    AuthFailureReason::NestedImpersonation,
                    AuthnError::Impersonated,
                )
                .await);
        }

        // The session must BE the admin: authenticated as `admin_user_id`.
        // The caller names the admin as an argument, and nothing else tied
        // that name to the session, so any session could assume any
        // identity under an admin's name in the audit trail.
        let Some(admin_snapshot) = session.snapshot().await else {
            return Err(self
                .refuse_impersonation(
                    admin_user_id,
                    None,
                    AuthFailureReason::AdminNotAuthenticated,
                    AuthnError::NoFlow,
                )
                .await);
        };
        if &admin_snapshot.user_id != admin_user_id {
            return Err(self
                .refuse_impersonation(
                    admin_user_id,
                    None,
                    AuthFailureReason::SessionIsNotAdmin,
                    AuthnError::NoFlow,
                )
                .await);
        }
        // The target is the store's, not the caller's record of it: a
        // `User` struct is whatever the caller built, and its `tenant_id`
        // is what the tenant rail compares. Reloaded by id; the tenant
        // rail uses the stored tenants of both principals.
        // A lookup the store cannot make fails the impersonation with a row
        // saying so; it names no target, since none was read.
        let target = match self.inner.identity.get_user(&target_user.id).await {
            Ok(target) => target,
            Err(e) => {
                return Err(self
                    .refuse_impersonation(
                        admin_user_id,
                        None,
                        AuthFailureReason::TargetLookupFailed,
                        AuthnError::Store(e),
                    )
                    .await);
            }
        };
        // Inside the rail, or why not. The two refusals the rail can give
        // share one error and one audit write, so a tenant administrator
        // learns nothing about ids outside the tenant from either. The row
        // of a missing target names none: there is no stored user to name,
        // and the caller's record is not one.
        let Some(target) = target else {
            let error = match expected_tenant {
                None => AuthnError::NoFlow,
                Some(_) => AuthnError::CrossTenant,
            };
            return Err(self
                .refuse_impersonation(admin_user_id, None, AuthFailureReason::UnknownTarget, error)
                .await);
        };
        if let Some(expected) = expected_tenant
            && (&target.tenant_id != expected || admin_snapshot.tenant_id != *expected)
        {
            return Err(self
                .refuse_impersonation(
                    admin_user_id,
                    Some(&target),
                    AuthFailureReason::CrossTenantImpersonation,
                    AuthnError::CrossTenant,
                )
                .await);
        }
        Ok((admin_snapshot, target))
    }

    /// Refuse an impersonation unless the standing of every party allows it.
    ///
    /// In order: the administrator's account must be active, the target's
    /// account must be active, and the target's tenant and the
    /// administrator's own tenant (read from the store) must both be
    /// active. Each refusal writes its audit row at `now` and returns the
    /// error; a store failure on the way returns without a row. Nothing of
    /// the session is touched here.
    async fn require_impersonation_standing(
        &self,
        admin_user_id: &crate::authn::ids::UserId,
        target_user: &crate::authn::types::User,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), AuthnError<I::Error>> {
        // A suspended administrator with a session still open cannot take
        // another identity through it: the session outlived the account's
        // standing, and the impersonation would hand it a fresh one.
        let admin_status = self.current_account_status(admin_user_id).await?;
        if !admin_status.allows_login() {
            tracing::warn!(
                admin = %admin_user_id,
                status = ?admin_status,
                "impersonation refused: the administrator's account is not active"
            );
            return Err(self
                .refuse_impersonation(
                    admin_user_id,
                    Some(target_user),
                    AuthFailureReason::AdminNotActive,
                    AuthnError::NotActive(admin_status),
                )
                .await);
        }

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

        // The tenant's status gates impersonation as it gates a login: the
        // target's tenant (the one being entered) and the admin's own (the
        // store's record of the administrator, not the tenant the session
        // names) must both be active. A tenant that does not load refuses
        // (fail closed).
        let admin_tenant = self
            .inner
            .identity
            .get_user_tenant(admin_user_id)
            .await
            .map_err(AuthnError::Store)?;
        for tenant_id in std::iter::once(target_user.tenant_id).chain(admin_tenant) {
            if let Err(refusal) = self.require_active_tenant(&tenant_id).await {
                if matches!(refusal, AuthnError::Store(_)) {
                    return Err(refusal);
                }
                tracing::warn!(
                    admin = %admin_user_id,
                    target = %target_user.id,
                    tenant = %tenant_id,
                    "impersonation refused: tenant is not active"
                );
                self.emit_audit_at(
                    AuthEventBuilder::failure(AuthEventType::Impersonation)
                        .attributed_to(&target_user.id, &target_user.tenant_id)
                        .with_actor(*admin_user_id)
                        .with_error(AuthFailureReason::NotActive),
                    now,
                )
                .await?;
                return Err(refusal);
            }
        }

        Ok(())
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

        self.require_impersonation_standing(admin_user_id, target_user, now)
            .await?;

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
        // The marker `AuthSession::impersonator` reads, part of the
        // authenticated state: the custom-data cap and `clear_custom` cannot
        // reach it, and it ends with the state.
        session.set_impersonator(*admin_user_id, now).await;

        // Force a session-ID rotation so the impersonating session never
        // shares its ID with the prior admin session; relevant for any
        // downstream code that keys things by session ID.
        session.regenerate().await;

        let sid = session.session_id().await;
        // Same as complete_signup; refuse to leave an admin in
        // an Authenticated-but-untracked impersonation session.
        if let Some(reg) = &self.inner.registry {
            // The administrator's old id ends first: the cookie carries the
            // new identity whether or not the registry takes the new id, so
            // the old entry must not outlive this call on a refusal.
            note_revocation(
                reg.invalidate_session(admin_user_id, &admin_sid).await,
                "ending an impersonation",
            );
            // The administrator's standing is the impersonation's: an entry
            // under the administrator that the session layer reads on every
            // request, so ending the administrator's sessions ends this one.
            let anchored = match session.impersonation().await {
                Some(imp) => {
                    reg.register(admin_user_id, &imp.registry_anchor(&target_user.id))
                        .await
                }
                None => false,
            };
            if !anchored || !reg.register(&target_user.id, &sid).await {
                tracing::error!(
                    admin_user_id = %admin_user_id,
                    target_user_id = %target_user.id,
                    "begin_impersonation register failed; clearing session and refusing"
                );
                session.clear().await;
                return Err(self
                    .refuse_impersonation(
                        admin_user_id,
                        Some(target_user),
                        AuthFailureReason::SessionNotRegistered,
                        AuthnError::NoFlow,
                    )
                    .await);
            }
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
            if let Some(imp) = session.impersonation().await {
                note_revocation(
                    reg.invalidate_session(&imp.admin, &imp.registry_anchor(target))
                        .await,
                    "ending an impersonation",
                );
            }
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
    /// [`AuthnError::CrossTenant`] when the stored target is not a user of
    /// the admin's stored tenant, closing the cross-tenant pivot vector that
    /// the other form leaves to the application's Cedar policy. A target id
    /// that does not exist is refused with the same error after the same
    /// work, so the answer does not say which ids exist in other tenants;
    /// the audit row names which it was.
    ///
    /// A session that is already an impersonation is refused with
    /// [`AuthnError::Impersonated`] and a failed row naming the administrator
    /// who holds it; [`end_impersonation`](Self::end_impersonation) first.
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
        // An administrator the store does not hold is refused before the
        // target is read; the row names no target, as every refusal made
        // before that read does.
        let Some(admin_tenant) = stored_admin_tenant else {
            return Err(self
                .refuse_impersonation(
                    &admin_user.id,
                    None,
                    AuthFailureReason::UnknownAdmin,
                    AuthnError::NoFlow,
                )
                .await);
        };
        self.impersonate(&admin_user.id, Some(&admin_tenant), target_user, session)
            .await
    }
}
