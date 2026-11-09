//! The passwordless (discoverable) passkey login.

use super::{RequestAuthnService, fido2_keys};
use crate::authn::{
    error::AuthnError,
    event::{AuthEventBuilder, AuthEventType, AuthFailureReason},
    factor::{FactorConfig, FactorKind},
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
        self.clear_discoverable_ceremony(session).await;
        match self
            .record_factor_failure(&user.id, &user.tenant_id, &FactorKind::Fido2, session)
            .await
        {
            Ok(FactorOutcome::Locked { until }) => AuthnError::Locked { until },
            Ok(_) => AuthnError::InvalidAssertion,
            Err(e) => e,
        }
    }

    /// Count and record a discoverable login refused on the tenant rail,
    /// and name the refusal. `known` is the user and the tenant of record
    /// when the store holds the user; the row is attributed to them, and
    /// to nobody otherwise. A failed audit write is returned in its place.
    async fn refuse_cross_tenant(
        &self,
        known: Option<(&crate::authn::ids::UserId, &crate::authn::ids::TenantId)>,
        session: &AuthSession,
    ) -> AuthnError<I::Error> {
        self.inner.metrics.auth_flow.auth_failure();
        let builder = AuthEventBuilder::failure(AuthEventType::FactorVerified)
            .maybe_attributed_to(known.map(|(u, _)| u), known.map(|(_, t)| t))
            .with_factor(FactorKind::Fido2)
            .with_session(session.session_id().await)
            .with_error(AuthFailureReason::CrossTenant);
        match self.emit_audit(builder).await {
            Ok(()) => AuthnError::CrossTenant,
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
    /// The tenant rail: the user's tenant is re-read from the identity store
    /// before any gate runs, and a record whose tenant differs is refused
    /// with [`AuthnError::CrossTenant`] without the tenant, lockout or audit
    /// paths ever seeing the caller-supplied tenant. When the ceremony began
    /// with
    /// [`begin_discoverable_login_in_tenant`](crate::authn::service::AuthnService::begin_discoverable_login_in_tenant)
    /// a user of another tenant is refused the same way. Either refusal is
    /// a login failure like the others: counted, and recorded as a failed
    /// `FactorVerified` row (`cross_tenant`) against the user's tenant of
    /// record, never against the tenant the caller supplied.
    ///
    /// `credentials` is the list the caller verifies the assertion against,
    /// and only the entries the store holds for `user`, with the same
    /// credential id and the same public key, are used. A passkey that
    /// merely carries a stored id (one registered by another account under a
    /// copied credential id) therefore cannot log in as `user`. The match is
    /// on credential id and public key against the user's stored
    /// credentials, never on the id alone. The lookup that turns the
    /// assertion's credential id or user handle into `user` is the
    /// adopter's, and it must be tenant-scoped: a credential id is not
    /// unique across tenants, so an unscoped lookup can name another
    /// tenant's user.
    ///
    /// Whichever way the call ends, the ceremony's state, its stamp and the
    /// tenant it began for are gone from the session.
    #[tracing::instrument(skip(self, assertion, user, credentials, session))]
    pub async fn finish_discoverable_login(
        &self,
        assertion: &webauthn_rs::prelude::PublicKeyCredential,
        user: &crate::authn::types::User,
        credentials: &[crate::authn::factor::Fido2Credential],
        session: &AuthSession,
    ) -> Result<FactorOutcome, AuthnError<I::Error>> {
        let result = self
            .finish_discoverable_login_gated(assertion, user, credentials, session)
            .await;
        // Whichever way the call ended, including a store error at one of
        // the gates, no ceremony state is left to a later request.
        if result.is_err() {
            self.clear_discoverable_ceremony(session).await;
        }
        result
    }

    /// The body of [`finish_discoverable_login`](Self::finish_discoverable_login):
    /// the gates, then the assertion.
    async fn finish_discoverable_login_gated(
        &self,
        assertion: &webauthn_rs::prelude::PublicKeyCredential,
        user: &crate::authn::types::User,
        credentials: &[crate::authn::factor::Fido2Credential],
        session: &AuthSession,
    ) -> Result<FactorOutcome, AuthnError<I::Error>> {
        let fido2 = self.inner.fido2.load_full();
        let webauthn = match &fido2 {
            Some(w) => w,
            None => return Err(AuthnError::NoFlow),
        };

        // The tenant rail first. The caller resolved `user` from the
        // credential's user handle, which names a user and carries no
        // tenant; the tenant of record is the store's, and every gate below
        // (the tenant's status and IP policy, the lockout policy, the audit
        // rows) must run against it rather than against whatever the caller
        // put on the record. A mismatch ends the ceremony here.
        let stored_tenant = self
            .inner
            .identity
            .get_user_tenant(&user.id)
            .await
            .map_err(AuthnError::Store)?;
        if stored_tenant.as_ref() != Some(&user.tenant_id) {
            self.clear_discoverable_ceremony(session).await;
            // Named only when the store knows the user: an id the store
            // does not hold is the caller's word alone.
            let known = stored_tenant.as_ref().map(|tenant| (&user.id, tenant));
            return Err(self.refuse_cross_tenant(known, session).await);
        }

        let status = self.current_account_status(&user.id).await?;
        if !status.allows_login() {
            self.clear_discoverable_ceremony(session).await;
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
            self.clear_discoverable_ceremony(session).await;
            return Err(AuthnError::InvalidAssertion);
        }
        // The lockout the failure counter imposes, before any assertion is
        // verified: a locked account answers `Locked` to a valid passkey
        // as to an invalid one.
        if let Some(lock) = self.derived_lockout(&user.id, &user.tenant_id).await? {
            self.clear_discoverable_ceremony(session).await;
            self.inner.metrics.auth_flow.account_locked();
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
            self.clear_discoverable_ceremony(session).await;
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

        // The ceremony's own tenant rail: a ceremony begun for one tenant
        // does not finish a user of another. The store's tenant was settled
        // above, before any gate ran.
        if let Some(expected) = expected_tenant.as_ref().and_then(|v| v.as_str())
            && expected != user.tenant_id.to_string()
        {
            tracing::warn!(
                user_id = %user.id,
                "discoverable login refused: the user is not in the tenant the ceremony began for"
            );
            return Err(self
                .refuse_cross_tenant(Some((&user.id, &user.tenant_id)), session)
                .await);
        }

        let user_scope = AuthnScope::User {
            tenant_id: user.tenant_id,
            user_id: user.id,
        };
        let discoverable_keys = self
            .stored_discoverable_keys(&user_scope, credentials)
            .await?;

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

    /// The keys the assertion may be verified against: the caller's
    /// `credentials` narrowed to those the store holds for the user in
    /// `user_scope`, matched on credential id and public key together.
    /// A user with no stored passkey yields no keys.
    async fn stored_discoverable_keys(
        &self,
        user_scope: &AuthnScope,
        credentials: &[crate::authn::factor::Fido2Credential],
    ) -> Result<Vec<webauthn_rs::prelude::DiscoverableKey>, AuthnError<I::Error>> {
        // The assertion is verified against the caller's list, but only the
        // credentials the store holds for this user, with the key it holds,
        // may stand in that list. A second account can register a passkey
        // under a copied credential id; an application that resolves the
        // user from the user handle and the credential by id can then pass
        // that other key here, and the stored id alone would let it in.
        let stored = match self
            .inner
            .factors
            .load_factor(user_scope, FactorKind::Fido2)
            .await
            .map_err(AuthnError::Store)?
        {
            Some(FactorConfig::Fido2(cfg)) => cfg.credentials,
            _ => Vec::new(),
        };
        // A security key is not a discoverable credential `webauthn-rs`
        // verifies here; passkeys and attested passkeys are.
        let keys = credentials
            .iter()
            .filter_map(|c| {
                let offered = c.key.passkey()?;
                stored
                    .iter()
                    .filter_map(|s| s.key.passkey())
                    .any(|s| {
                        s.cred_id() == offered.cred_id()
                            && s.get_public_key() == offered.get_public_key()
                    })
                    .then(|| (&offered).into())
            })
            .collect();
        Ok(keys)
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
        let fido2 = self.inner.fido2.load_full();
        let Some(webauthn) = &fido2 else {
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
            m.is_complete()
                && m.steps
                    .first()
                    .is_some_and(|step| step.accepts(&FactorKind::Fido2))
        }) else {
            self.emit_audit(
                AuthEventBuilder::failure(AuthEventType::FactorVerified)
                    .attributed_to(&user.id, &user.tenant_id)
                    .with_factor(FactorKind::Fido2)
                    .with_session(session.session_id().await)
                    .with_error(AuthFailureReason::from("method_not_passkey_first")),
            )
            .await?;
            return Err(AuthnError::NoFlow);
        };
        let epoch = self
            .credential_epoch(&user.id, &user.tenant_id, &method.name)
            .await?;
        self.stamp_flow(session, &method.name, epoch).await;
        session
            .begin_authenticating(user.id, user.tenant_id, method.name.clone(), method.steps)
            .await;

        // The discoverable ceremony is not an attested one: no trust anchor.
        let proof = crate::authn::assurance::FactorAssurance::from_fido2_result(
            auth_result,
            None,
            self.inner.clock.now(),
        );
        session
            .advance_factor(proof, &self.inner.preserved_custom_keys)
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
