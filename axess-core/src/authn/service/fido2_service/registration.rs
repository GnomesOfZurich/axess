//! Passkey registration: beginning and finishing the ceremony.

use super::{CredentialChange, RequestAuthnService, fido2_keys};
use crate::authn::{
    error::AuthnError,
    event::{AuthEventBuilder, AuthEventType, AuthFailureReason},
    factor::{FactorConfig, FactorKind},
    store::{FactorStore, IdentityStore},
    types::AuthnScope,
};
use crate::session::extractor::AuthSession;

impl<I, F> RequestAuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Begin FIDO2 passkey registration.
    ///
    /// `session` must be authenticated as `user`, or pending signup for
    /// them, recently enough for
    /// [`Fido2Options::max_authn_age`](crate::authn::factor::Fido2Options::max_authn_age)
    /// when one is set, and not impersonated; any other session is refused
    /// with [`AuthnError::NoFlow`] and a failed audit row.
    ///
    /// Returns the challenge for the browser and, for a user with no
    /// [`webauthn_id`](crate::authn::types::User::webauthn_id) yet, the id
    /// minted for them: the caller persists it on the user row before the
    /// next ceremony, since WebAuthn needs the same handle for every
    /// credential of the user. `None` means the user already had one.
    #[tracing::instrument(skip(self, user, session))]
    pub async fn begin_fido2_registration(
        &self,
        user: &crate::authn::types::User,
        session: &AuthSession,
    ) -> Result<(serde_json::Value, Option<uuid::Uuid>), AuthnError<I::Error>> {
        let fido2 = self.inner.fido2.load_full();
        let webauthn = match &fido2 {
            Some(w) => w,
            None => return Err(AuthnError::NoFlow),
        };

        self.require_enrolment_context(
            user,
            session,
            AuthEventType::FactorEnabled,
            CredentialChange::Enrolment,
        )
        .await?;
        let status = self.current_account_status(&user.id).await?;
        if !status.allows_login() {
            return Err(self
                .refuse_inactive_account(user, status, AuthEventType::FactorEnabled, Some(session))
                .await);
        }

        let user_scope = AuthnScope::User {
            tenant_id: user.tenant_id,
            user_id: user.id,
        };
        // A failed read must not look like "no passkeys yet": the exclude
        // list would be empty and the user could register a duplicate.
        let existing = match self
            .inner
            .factors
            .load_factor(&user_scope, FactorKind::Fido2)
            .await
        {
            Ok(Some(FactorConfig::Fido2(cfg))) => cfg.credentials,
            Ok(_) => vec![],
            Err(e) => return Err(AuthnError::Store(e)),
        };

        let (user_unique_id, new_id) = match user.webauthn_id {
            Some(id) => (id, None),
            None => {
                let mut bytes = [0u8; 16];
                self.inner.rng.fill_bytes(&mut bytes);
                let id = uuid::Uuid::from_bytes(bytes);
                (id, Some(id))
            }
        };

        let exclude_ids: Vec<_> = existing.iter().map(|pk| pk.cred_id().clone()).collect();

        let (challenge, reg_state) = webauthn
            .start_registration(
                user_unique_id,
                &user.identifier,
                &user.display_name,
                Some(exclude_ids),
            )
            .map_err(|e| {
                tracing::warn!("FIDO2 start_passkey_registration failed: {e:?}");
                AuthnError::NoFlow
            })?;

        let state_json = serde_json::to_value(&reg_state).map_err(|_| AuthnError::NoFlow)?;
        if !session.set_custom(fido2_keys::REG_STATE, state_json).await {
            // The ceremony state did not fit; a challenge handed out without
            // it could never be finished.
            return Err(AuthnError::NoFlow);
        }
        self.stamp_ceremony_start(session, fido2_keys::REG_STATE)
            .await?;

        let challenge_json = serde_json::to_value(&challenge).map_err(|_| AuthnError::NoFlow)?;
        Ok((challenge_json, new_id))
    }

    /// Complete FIDO2 passkey registration.
    ///
    /// Re-checks the session on the terms of
    /// [`begin_fido2_registration`](Self::begin_fido2_registration), so a
    /// session swapped, impersonated or aged out between begin and finish
    /// cannot complete the ceremony.
    ///
    /// A credential id the user already holds is refused with
    /// [`AuthnError::NoFlow`] and nothing is stored. So is an id another user
    /// of the same tenant holds, found through
    /// [`FactorStore::fido2_credential_holder`];
    /// that refusal also leaves a failed `FactorSetup` audit row. A store
    /// that does not implement the lookup admits the id (its default answers
    /// "nobody"), and an application on such a store keeps its own index.
    /// A failed lookup fails the registration.
    #[tracing::instrument(skip(self, user, response, session))]
    pub async fn finish_fido2_registration(
        &self,
        user: &crate::authn::types::User,
        response: &webauthn_rs::prelude::RegisterPublicKeyCredential,
        credential_name: &str,
        session: &AuthSession,
    ) -> Result<(), AuthnError<I::Error>> {
        let fido2 = self.inner.fido2.load_full();
        let webauthn = match &fido2 {
            Some(w) => w,
            None => return Err(AuthnError::NoFlow),
        };

        // A session that is not this user's cannot finish a ceremony it did
        // not begin, and a refusal here leaves any state it holds in place.
        self.require_enrolment_context(
            user,
            session,
            AuthEventType::FactorSetup,
            CredentialChange::Enrolment,
        )
        .await?;

        // Take the state first so two parallel finishes cannot both consume
        // one challenge, and so a failed finish leaves nothing to replay.
        let state_json = session.take_custom(fido2_keys::REG_STATE).await;
        if self
            .is_ceremony_expired(session, fido2_keys::REG_STATE)
            .await
        {
            self.clear_ceremony_timestamp(session, fido2_keys::REG_STATE)
                .await;
            return Err(AuthnError::NoFlow);
        }
        self.clear_ceremony_timestamp(session, fido2_keys::REG_STATE)
            .await;
        let state_json = match state_json {
            Some(v) if !v.is_null() => v,
            _ => return Err(AuthnError::NoFlow),
        };

        let reg_state: webauthn_rs::prelude::PasskeyRegistration =
            serde_json::from_value(state_json).map_err(|_| AuthnError::NoFlow)?;

        // The account may have been suspended or locked since the
        // ceremony began; begin refused it, so finish refuses it too, under
        // the finish's own kind beside its success row.
        let status = self.current_account_status(&user.id).await?;
        if !status.allows_login() {
            return Err(self
                .refuse_inactive_account(user, status, AuthEventType::FactorSetup, Some(session))
                .await);
        }

        let passkey = match webauthn.finish_registration(response, &reg_state) {
            Ok(passkey) => passkey,
            Err(e) => {
                tracing::warn!("FIDO2 finish_passkey_registration failed: {e:?}");
                // A rejected attestation is a security-relevant event, and
                // the success and inactive-account paths both leave a row.
                self.emit_audit(
                    AuthEventBuilder::failure(AuthEventType::FactorSetup)
                        .attributed_to(&user.id, &user.tenant_id)
                        .with_factor(FactorKind::Fido2)
                        .with_session(session.session_id().await)
                        .with_error(AuthFailureReason::from("registration_rejected")),
                )
                .await?;
                return Err(AuthnError::NoFlow);
            }
        };

        // Capture the credential id before `passkey` moves into the
        // factor config below; needed for the post-save device-binding
        // hook so the `Fido2Provider` impl can durably bind this
        // credential to the resolved `DeviceId`.
        let cred_id = passkey.cred_id().clone();

        // A credential id another user of the tenant holds is refused: one
        // authenticator credential belongs to one account. A failed lookup
        // is an error, never "nobody holds it".
        let holder = self
            .inner
            .factors
            .fido2_credential_holder(&user.tenant_id, cred_id.as_ref())
            .await
            .map_err(AuthnError::Store)?;
        if holder.is_some_and(|holder| holder != user.id) {
            self.emit_audit(
                AuthEventBuilder::failure(AuthEventType::FactorSetup)
                    .attributed_to(&user.id, &user.tenant_id)
                    .with_factor(FactorKind::Fido2)
                    .with_session(session.session_id().await)
                    .with_error(AuthFailureReason::from("credential_held_by_another_user")),
            )
            .await?;
            return Err(AuthnError::NoFlow);
        }

        let user_scope = AuthnScope::User {
            tenant_id: user.tenant_id,
            user_id: user.id,
        };
        // Read-modify-write under compare-and-swap: a failed read aborts
        // (never saves just the new passkey over the existing ones), and a
        // concurrent registration or deletion is merged rather than lost.
        let registered_at = self.inner.clock.now();
        let added = self
            .update_fido2_credentials(&user_scope, |credentials| {
                if credentials.iter().any(|c| c.cred_id() == &cred_id) {
                    return None;
                }
                credentials.push(crate::authn::factor::Fido2Credential::new(
                    passkey.clone(),
                    credential_name,
                    registered_at,
                ));
                Some(())
            })
            .await?;
        // `None` is a credential id that is already registered: nothing was
        // stored, so no device binding and no `FactorSetup` audit.
        if added.is_none() {
            return Err(AuthnError::NoFlow);
        }

        // Auto-invoke the device-binding hook. Adopters that wire the
        // `device` subsystem override `Fido2Provider::on_credential_used`
        // to record a `DeviceBinding::WebAuthn` row; the default impl is
        // a no-op so deployments without the subsystem are unaffected.
        // Reads `device_id` from the session payload populated by the
        // device resolver at request entry. `None` (resolver disabled,
        // request did not match a known device, or `device` feature off)
        // skips the call entirely.
        if let Some(device_id) = session.device_id().await {
            webauthn.on_credential_used(&cred_id, &device_id);
        }

        self.emit_audit(
            AuthEventBuilder::success(AuthEventType::FactorSetup)
                .attributed_to(&user.id, &user.tenant_id)
                .with_factor(FactorKind::Fido2)
                .with_session(session.session_id().await),
        )
        .await?;

        Ok(())
    }
}
