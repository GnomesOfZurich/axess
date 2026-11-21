//! FIDO2 registration: beginning and finishing the typed ceremony.

use super::{CredentialChange, RequestAuthnService, fido2_keys};
use crate::authn::{
    error::AuthnError,
    event::{AuthEventBuilder, AuthEventType, AuthFailureReason},
    factor::{FactorConfig, FactorKind},
    store::{FactorStore, Fido2CredentialClaim, IdentityStore},
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
    ///
    /// The ceremony is [`Fido2Options::registration_ceremony`](crate::authn::factor::Fido2Options::registration_ceremony);
    /// [`begin_fido2_registration_with`](Self::begin_fido2_registration_with)
    /// names one for this call. A passkey or attested-passkey registration
    /// asks for a discoverable credential as
    /// [`Fido2Options::discoverable_credential`](crate::authn::factor::Fido2Options::discoverable_credential)
    /// says.
    #[tracing::instrument(skip(self, user, session))]
    pub async fn begin_fido2_registration(
        &self,
        user: &crate::authn::types::User,
        session: &AuthSession,
    ) -> Result<(serde_json::Value, Option<uuid::Uuid>), AuthnError<I::Error>> {
        let ceremony = self.inner.fido2_options.registration_ceremony.clone();
        self.begin_fido2_registration_with(user, session, &ceremony)
            .await
    }

    /// [`begin_fido2_registration`](Self::begin_fido2_registration) running
    /// `ceremony`: a security key for an administrator who enrols hardware
    /// tokens, an attested passkey for a role that must hold one. The
    /// credential is stored typed by the ceremony, and later logins use it
    /// only through a ceremony that accepts that type
    /// ([`Fido2Ceremony::accepts`](crate::authn::factor::Fido2Ceremony::accepts)).
    /// A ceremony the provider cannot run (an attested passkey against a
    /// trust anchor it does not hold) is [`AuthnError::NoFlow`].
    ///
    /// A begin retires the registration the session held before it, whether
    /// or not it succeeds: the earlier challenge can no longer be finished.
    #[tracing::instrument(skip(self, user, session))]
    pub async fn begin_fido2_registration_with(
        &self,
        user: &crate::authn::types::User,
        session: &AuthSession,
        ceremony: &crate::authn::factor::Fido2Ceremony,
    ) -> Result<(serde_json::Value, Option<uuid::Uuid>), AuthnError<I::Error>> {
        // An earlier registration ends here: whatever becomes of this
        // begin, the challenge the browser already holds cannot be finished.
        self.clear_ceremony_state(session, fido2_keys::REG_STATE)
            .await;

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

        let (mut challenge, reg_state) = webauthn
            .start_registration(
                ceremony,
                user_unique_id,
                &user.identifier,
                &user.display_name,
                Some(exclude_ids),
            )
            .map_err(|e| {
                tracing::warn!(%ceremony, "FIDO2 registration could not start: {e:?}");
                AuthnError::NoFlow
            })?;

        // Whether the authenticator stores the credential is the browser's
        // to read; the registration state holds none of it.
        self.inner
            .fido2_options
            .discoverable_credential
            .apply(ceremony, &mut challenge);

        let state_json = serde_json::to_value(&reg_state).map_err(|_| AuthnError::NoFlow)?;
        if !session.set_custom(fido2_keys::REG_STATE, state_json).await {
            // The ceremony state did not fit; a challenge handed out without
            // it could never be finished.
            return Err(AuthnError::NoFlow);
        }
        if let Err(unstamped) = self
            .stamp_ceremony_start(session, fido2_keys::REG_STATE)
            .await
        {
            // A ceremony that cannot be timed does not stay behind.
            self.clear_ceremony_state(session, fido2_keys::REG_STATE)
                .await;
            return Err(unstamped);
        }

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
    /// of the same tenant holds, refused through
    /// [`FactorStore::claim_fido2_credential`];
    /// that refusal also leaves a failed `FactorSetup` audit row naming
    /// `credential_held_by_another_user`; a claim the store refuses with no
    /// other holder to name (a store that keeps no passkeys) names
    /// `credential_id_claim_refused`. The claim is the store's atomic step,
    /// so two registrations racing for one id cannot both pass. A failed
    /// claim fails the registration. A credential write that fails returns
    /// its own error and keeps the claim, which stays with the user.
    #[tracing::instrument(
        skip(self, user, response, credential_name, session),
        fields(credential_name = %crate::authn::service::log_text::logged_request_text(credential_name))
    )]
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

        // The state names the ceremony that began it; state from before the
        // ceremonies were typed does not read and the ceremony begins again.
        let reg_state: axess_factors::fido2::Fido2Registration =
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

        let key = match webauthn.finish_registration(response, &reg_state) {
            Ok(key) => key,
            Err(e) => {
                tracing::warn!(ceremony = %reg_state.ceremony(), "FIDO2 registration refused: {e:?}");
                // A rejected attestation is a security-relevant event, and
                // the success and inactive-account paths both leave a row.
                self.emit_audit(
                    AuthEventBuilder::failure(AuthEventType::FactorSetup)
                        .attributed_to(&user.id, &user.tenant_id)
                        .with_factor(FactorKind::Fido2)
                        .with_session(session.session_key().await)
                        .with_error(AuthFailureReason::from("registration_rejected")),
                )
                .await?;
                return Err(AuthnError::NoFlow);
            }
        };

        // Capture the credential id before `key` moves into the factor
        // config below; needed for the post-save device-binding hook so the
        // `Fido2Provider` impl can durably bind this credential to the
        // resolved `DeviceId`.
        let cred_id = key.cred_id().clone();

        self.claim_credential_id(user, session, &cred_id).await?;

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
                    key.clone(),
                    credential_name,
                    registered_at,
                ));
                Some(())
            })
            .await;
        let added = added.map_err(|error| claim_kept_after_failed_write(user, error))?;
        // `None` is a credential id that is already registered: nothing was
        // stored, so no device binding and no `FactorSetup` audit.
        if added.is_none() {
            return Err(AuthnError::NoFlow);
        }

        // Auto-invoke the device-binding hook. Adopters that wire the
        // `device` subsystem override `Fido2Provider::on_credential_used`
        // to record a `DeviceBinding::WebAuthn` row; the default impl is
        // a no-op so deployments without the subsystem are unaffected.
        // The hook is handed the device this request proved; a request that
        // proved none (no resolver, a device kept from an earlier request,
        // or the `device` feature off) skips the call.
        super::credential_used(webauthn, &cred_id, session).await;

        self.emit_audit(
            AuthEventBuilder::success(AuthEventType::FactorSetup)
                .attributed_to(&user.id, &user.tenant_id)
                .with_factor(FactorKind::Fido2)
                .with_session(session.session_key().await),
        )
        .await?;

        Ok(())
    }

    /// Claim `cred_id` for `user` through the store's atomic step (see
    /// [`FactorStore::claim_fido2_credential`]), so two accounts racing to
    /// register one id cannot both pass. A refused claim is
    /// [`AuthnError::NoFlow`] with a failed `FactorSetup` audit row whose
    /// reason is the claim's own answer and no second read: it names
    /// `credential_held_by_another_user` when the claim says another user of
    /// the tenant holds the id, and `credential_id_claim_refused` when it
    /// names nobody else (a store that keeps no passkeys refuses every
    /// claim). A failed claim is an error, never "nobody holds it".
    async fn claim_credential_id(
        &self,
        user: &crate::authn::types::User,
        session: &AuthSession,
        cred_id: &webauthn_rs::prelude::CredentialID,
    ) -> Result<(), AuthnError<I::Error>> {
        let factors = &self.inner.factors;
        let claim = factors
            .claim_fido2_credential(&user.tenant_id, &user.id, cred_id.as_slice())
            .await
            .map_err(AuthnError::Store)?;
        let reason = match claim {
            Fido2CredentialClaim::Claimed => return Ok(()),
            Fido2CredentialClaim::HeldBy(holder) if holder != user.id => {
                "credential_held_by_another_user"
            }
            Fido2CredentialClaim::HeldBy(_) | Fido2CredentialClaim::Refused => {
                "credential_id_claim_refused"
            }
        };
        self.emit_audit(
            AuthEventBuilder::failure(AuthEventType::FactorSetup)
                .attributed_to(&user.id, &user.tenant_id)
                .with_factor(FactorKind::Fido2)
                .with_session(session.session_key().await)
                .with_error(AuthFailureReason::from(reason)),
        )
        .await?;
        Err(AuthnError::NoFlow)
    }
}

/// Log a registration whose credential write failed, and hand its error back.
///
/// The write's own error is returned and the claim is kept. A concurrent
/// registration by the same user may store this credential after any check
/// made here, and that credential depends on the claim, so giving it back
/// could leave it standing without one for another account to take. The id
/// stays held for this user, who can claim it again; no other account can
/// hold a credential id this user's authenticator produced. The line is at
/// `warn` with the error, so an operator can see why an id is held with no
/// passkey stored.
fn claim_kept_after_failed_write<E: std::fmt::Display>(
    user: &crate::authn::types::User,
    error: E,
) -> E {
    tracing::warn!(
        tenant_id = %user.tenant_id,
        user_id = %user.id,
        %error,
        "passkey registration failed to store the credential; its credential-id \
         claim is kept, so the id stays held by this user with no passkey stored"
    );
    error
}
