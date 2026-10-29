//! The passwordless (discoverable) passkey login.

use super::{RequestAuthnService, fido2_keys};
use crate::authn::{
    error::AuthnError,
    event::{AuthEventBuilder, AuthEventType, AuthFailureReason},
    factor::FactorKind,
    service::outcomes::FactorOutcome,
    store::{FactorStore, IdentityStore},
    types::AuthnScope,
};
use crate::session::extractor::AuthSession;

impl<I, F> RequestAuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Retire a failed discoverable ceremony and name the failure.
    ///
    /// The ceremony state is cleared BEFORE the failure is recorded, so a
    /// store error while recording cannot leave it behind. The failure goes
    /// through the canonical helper so counter-store errors are muted (no
    /// lockout-evading side channel) and the audit row precedes the counter.
    /// A lockout passes its `until` to the caller; every other verdict is
    /// `InvalidAssertion`. A store error from the helper is returned as is.
    async fn discoverable_failure(
        &self,
        user: &crate::authn::types::User,
        session: &AuthSession,
    ) -> AuthnError<I::Error> {
        self.clear_ceremony_state(session, fido2_keys::DISC_STATE)
            .await;
        match self
            .record_factor_failure(&user.id, &user.tenant_id, &FactorKind::Fido2, session)
            .await
        {
            Ok(FactorOutcome::Locked { until }) => AuthnError::Locked { until },
            Ok(_) => AuthnError::InvalidAssertion,
            Err(e) => e,
        }
    }

    /// Complete a passwordless/discoverable FIDO2 authentication.
    ///
    /// The passkey proves the user holds a registered credential; it does
    /// not by itself decide how far the login goes. The user's own
    /// authentication methods do: the first method whose first step accepts
    /// a passkey is begun and that step is marked complete.
    ///
    /// * A method that is a passkey alone (or offers one among alternatives)
    ///   ends the login: [`FactorOutcome::Authenticated`], with
    ///   `factors_completed == [Fido2]`.
    /// * A method that begins with a passkey and goes on to require more
    ///   (a passkey then a TOTP code) continues: [`FactorOutcome::FactorRequired`]
    ///   names the next factor, and the session is `Authenticating`.
    /// * A user none of whose methods accepts a passkey first (password
    ///   then a hardware key, or no passkey method at all) is refused with
    ///   [`AuthnError::NoFlow`] and a failed audit row. Their passkey is a
    ///   step-up factor, not a way in.
    ///
    /// The tenant rail: when the ceremony began with
    /// [`begin_discoverable_login_in_tenant`](crate::authn::service::AuthnService::begin_discoverable_login_in_tenant)
    /// a user of another tenant is refused with [`AuthnError::CrossTenant`].
    /// The user's tenant is also re-read from the identity store, whatever
    /// the caller-supplied record says.
    #[tracing::instrument(skip(self, assertion, user, credentials, session))]
    pub async fn finish_discoverable_login(
        &self,
        assertion: &webauthn_rs::prelude::PublicKeyCredential,
        user: &crate::authn::types::User,
        credentials: &[crate::authn::factor::Fido2Credential],
        session: &AuthSession,
    ) -> Result<FactorOutcome, AuthnError<I::Error>> {
        let webauthn = match &self.inner.fido2 {
            Some(w) => w,
            None => return Err(AuthnError::NoFlow),
        };

        let status = self.current_account_status(&user.id).await?;
        if !status.allows_login() {
            self.clear_ceremony_state(session, fido2_keys::DISC_STATE)
                .await;
            return Err(self
                .refuse_inactive_account(user, status, AuthEventType::FactorVerified, Some(session))
                .await);
        }
        // The tenant's own gates, as `begin_login` runs them: its status
        // and its IP policy. The passkey path used to skip both, so a
        // suspended tenant, or an allowlisted one, still logged in here.
        if let std::ops::ControlFlow::Break(_) = self
            .admit_tenant_by_id(&user.identifier, &user.tenant_id)
            .await?
        {
            self.clear_ceremony_state(session, fido2_keys::DISC_STATE)
                .await;
            return Err(AuthnError::InvalidAssertion);
        }
        // The lockout the failure counter imposes, before any assertion is
        // verified: a locked account answers `Locked` to a valid passkey
        // as to an invalid one.
        if let Some(lock) = self.derived_lockout(&user.id, &user.tenant_id).await? {
            self.clear_ceremony_state(session, fido2_keys::DISC_STATE)
                .await;
            self.inner.metrics.account_locked();
            self.emit_audit(
                AuthEventBuilder::locked(AuthEventType::FactorVerified)
                    .attributed_to(&user.id, &user.tenant_id)
                    .with_factor(FactorKind::Fido2)
                    .with_session(session.session_id().await),
            )
            .await?;
            return Err(AuthnError::Locked { until: lock.until });
        }

        if self
            .is_ceremony_expired(session, fido2_keys::DISC_STATE)
            .await
        {
            self.clear_ceremony_state(session, fido2_keys::DISC_STATE)
                .await;
            return Err(AuthnError::NoFlow);
        }

        // Take the discoverable auth state atomically. Same threat
        // model as the regular `verify_fido2_factor` path; two parallel
        // submissions of the same valid assertion must not both consume
        // the same ceremony state. The timestamp is retired the moment the
        // state is consumed (or found absent), so no later exit leaves a
        // stamp behind for the next request to read as a ceremony in
        // progress.
        let state_json = session.take_custom(fido2_keys::DISC_STATE).await;
        let expected_tenant = session.take_custom(fido2_keys::DISC_TENANT).await;
        self.clear_ceremony_timestamp(session, fido2_keys::DISC_STATE)
            .await;
        let state_json = match state_json {
            Some(v) if !v.is_null() => v,
            _ => return Err(AuthnError::NoFlow),
        };

        let Ok(auth_state) =
            serde_json::from_value::<webauthn_rs::prelude::DiscoverableAuthentication>(state_json)
        else {
            return Err(AuthnError::NoFlow);
        };

        // The tenant rail. The caller resolved `user` from the credential's
        // user handle, which names a user and carries no tenant; the tenant
        // of record is the store's.
        let stored_tenant = self
            .inner
            .identity
            .get_user_tenant(&user.id)
            .await
            .map_err(AuthnError::Store)?;
        if stored_tenant.as_ref() != Some(&user.tenant_id) {
            return Err(AuthnError::CrossTenant);
        }
        if let Some(expected) = expected_tenant.as_ref().and_then(|v| v.as_str())
            && expected != user.tenant_id.to_string()
        {
            tracing::warn!(
                user_id = %user.id,
                "discoverable login refused: the user is not in the tenant the ceremony began for"
            );
            return Err(AuthnError::CrossTenant);
        }

        let discoverable_keys: Vec<webauthn_rs::prelude::DiscoverableKey> =
            credentials.iter().map(|c| (&c.passkey).into()).collect();

        let auth_result = match webauthn.finish_discoverable_authentication(
            assertion,
            auth_state,
            &discoverable_keys,
        ) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("FIDO2 finish_discoverable_authentication failed: {e:?}");
                return Err(self.discoverable_failure(user, session).await);
            }
        };

        let user_scope = AuthnScope::User {
            tenant_id: user.tenant_id,
            user_id: user.id,
        };
        // A passkey deleted after the ceremony began is no longer a
        // credential of this user, however valid the assertion was against
        // the caller's list.
        if !self
            .save_fido2_credentials(&user_scope, &auth_result)
            .await?
        {
            return Err(self.discoverable_failure(user, session).await);
        }

        self.continue_after_passkey(user, &auth_result, session)
            .await
    }

    /// The passkey verified and its use is recorded: let the user's own
    /// method decide what it is worth, begin that method and complete its
    /// first step.
    async fn continue_after_passkey(
        &self,
        user: &crate::authn::types::User,
        auth_result: &webauthn_rs::prelude::AuthenticationResult,
        session: &AuthSession,
    ) -> Result<FactorOutcome, AuthnError<I::Error>> {
        let Some(webauthn) = &self.inner.fido2 else {
            return Err(AuthnError::NoFlow);
        };
        // The user's own method decides what the passkey is worth.
        let methods = self
            .inner
            .factors
            .available_methods(&user.id, &user.tenant_id)
            .await
            .map_err(AuthnError::Store)?;
        let Some(method) = methods.into_iter().find(|m| {
            m.steps
                .first()
                .is_some_and(|step| step.accepts(&FactorKind::Fido2))
        }) else {
            self.emit_audit(
                AuthEventBuilder::failure(AuthEventType::FactorVerified)
                    .attributed_to(&user.id, &user.tenant_id)
                    .with_factor(FactorKind::Fido2)
                    .with_session(session.session_id().await)
                    .with_error(AuthFailureReason::Other("method_not_passkey_first".into())),
            )
            .await?;
            return Err(AuthnError::NoFlow);
        };
        let steps: Vec<_> = method
            .steps
            .iter()
            .filter(|step| step.primary().is_some())
            .cloned()
            .collect();
        let epoch = self
            .credential_epoch(&user.id, &user.tenant_id, &method.name)
            .await?;
        self.stamp_flow(session, &method.name, epoch).await;
        session
            .begin_authenticating(user.id, user.tenant_id, method.name.clone(), steps)
            .await;

        let now = self.inner.clock.now();
        session
            .advance_factor(&FactorKind::Fido2, now, &self.inner.preserved_custom_keys)
            .await;

        // `complete_factor_step` registers the session, re-checks the
        // account status and, on the last step, clears the failure counter;
        // a failure in any of them reaches the caller, and the session goes
        // back to Guest so it does not hold an Authenticated cookie outside
        // the registry's view (the fail-closed contract).
        let outcome = match self
            .complete_factor_step(&user.id, &user.tenant_id, session)
            .await
        {
            Ok(outcome) => outcome,
            Err(e) => {
                session.clear().await;
                return Err(e);
            }
        };

        // Device-binding hook for the credential that just satisfied this
        // assertion, after the step completed: see `verify_fido2_factor`.
        if let Some(device_id) = session.device_id().await {
            webauthn.on_credential_used(auth_result.cred_id(), &device_id);
        }
        Ok(outcome)
    }
}
