//! FIDO2/WebAuthn ceremony methods on [`AuthnService`].

use super::{AuthnService, outcomes::FactorOutcome};
use crate::authn::{
    error::AuthnError,
    event::{AuthEventBuilder, AuthEventType},
    factor::{FactorConfig, FactorCredential, FactorKind},
    ids::{TenantId, UserId},
    store::{FactorStore, IdentityStore},
    types::AuthnScope,
};
use crate::session::extractor::AuthSession;

// ── FIDO2 ceremony session keys ──────────────────────────────────────────────

pub(crate) mod fido2_keys {
    pub const AUTH_STATE: &str = "axess.fido2.auth_state";
    pub const REG_STATE: &str = "axess.fido2.reg_state";
    pub const DISC_STATE: &str = "axess.fido2.disc_state";
    pub const CEREMONY_STARTED: &str = "axess.fido2.ceremony_started";
}

impl<I, F> AuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Save updated FIDO2 credentials after a successful authentication.
    async fn save_fido2_credentials(
        &self,
        user_scope: &AuthnScope,
        credentials: &[crate::authn::factor::Fido2Credential],
        auth_result: &webauthn_rs::prelude::AuthenticationResult,
    ) -> Result<(), AuthnError<I::Error>> {
        let now = self.clock.now();
        let mut updated = credentials.to_vec();
        for cred in &mut updated {
            cred.record_authentication(auth_result, now);
        }
        self.factors
            .save_factor(
                user_scope,
                FactorConfig::Fido2(crate::authn::factor::Fido2Config {
                    credentials: updated,
                }),
            )
            .await
            .map_err(AuthnError::Store)
    }

    /// Store the ceremony-started timestamp in the session.
    pub(super) async fn stamp_ceremony_start(&self, session: &AuthSession) {
        session
            .set_custom(
                fido2_keys::CEREMONY_STARTED,
                serde_json::Value::String(self.clock.now().to_rfc3339()),
            )
            .await;
    }

    /// Clear ceremony state keys from the session.
    pub(super) async fn clear_ceremony_state(&self, session: &AuthSession, state_key: &str) {
        session.set_custom(state_key, serde_json::Value::Null).await;
        session
            .set_custom(fido2_keys::CEREMONY_STARTED, serde_json::Value::Null)
            .await;
    }

    /// Clear ONLY the ceremony timestamp; the state key has already been
    /// consumed via [`AuthSession::take_custom`]. Used by the hardened
    /// paths that take the ceremony state atomically with the read.
    pub(super) async fn clear_ceremony_timestamp(&self, session: &AuthSession) {
        session
            .set_custom(fido2_keys::CEREMONY_STARTED, serde_json::Value::Null)
            .await;
    }

    /// Check if the FIDO2 ceremony has exceeded the configured timeout.
    ///
    /// Fails closed: if the ceremony timestamp is missing or unparseable,
    /// the ceremony is considered expired. This prevents stale or corrupted
    /// sessions from bypassing timeout enforcement.
    pub(super) async fn is_ceremony_expired(&self, session: &AuthSession) -> bool {
        let Some(started) = session.get_custom(fido2_keys::CEREMONY_STARTED).await else {
            // No timestamp → ceremony was never properly started; fail closed.
            tracing::warn!("FIDO2 ceremony timestamp missing; treating as expired (fail closed)");
            return true;
        };
        let Some(ts) = started.as_str() else {
            tracing::warn!("FIDO2 ceremony timestamp not a string; treating as expired");
            return true;
        };
        let Ok(started_at) = chrono::DateTime::parse_from_rfc3339(ts) else {
            tracing::warn!("FIDO2 ceremony timestamp unparseable; treating as expired");
            return true;
        };
        let elapsed = self.clock.now() - started_at.with_timezone(&chrono::Utc);
        match elapsed.to_std() {
            Ok(d) => d > self.fido2_options.ceremony_timeout,
            Err(_) => {
                // Negative duration (clock skew); treat as expired and log.
                tracing::warn!(
                    "FIDO2 ceremony elapsed duration is negative (clock skew?); treating as expired"
                );
                true
            }
        }
    }

    /// Verify a FIDO2/WebAuthn authentication assertion.
    pub(super) async fn verify_fido2_factor(
        &self,
        credential: &FactorCredential,
        config: &FactorConfig,
        user_scope: &AuthnScope,
        user_id: &UserId,
        tenant_id: &TenantId,
        session: &AuthSession,
    ) -> Result<FactorOutcome, AuthnError<I::Error>> {
        let webauthn = match &self.fido2 {
            Some(w) => w,
            None => return Ok(FactorOutcome::InvalidCredential),
        };

        let FactorConfig::Fido2(cfg) = config else {
            return Ok(FactorOutcome::InvalidCredential);
        };

        let assertion = match credential.as_public_key_credential() {
            Some(a) => a,
            None => return Ok(FactorOutcome::InvalidCredential),
        };

        // Take the auth state atomically (read + remove under one
        // write lock) so two parallel POSTs of the same valid assertion
        // cannot both observe and consume the same ceremony state. If the
        // authenticator returns a sign-counter of 0 (common on platform
        // authenticators), webauthn-rs's replay check is a no-op and this
        // is the only thing standing between an attacker with a captured
        // assertion and a successful re-use.
        let state_json = match session.take_custom(fido2_keys::AUTH_STATE).await {
            Some(v) if !v.is_null() => v,
            _ => return Ok(FactorOutcome::InvalidCredential),
        };

        if self.is_ceremony_expired(session).await {
            self.clear_ceremony_timestamp(session).await;
            return Ok(FactorOutcome::InvalidCredential);
        }

        let auth_state: webauthn_rs::prelude::PasskeyAuthentication =
            match serde_json::from_value(state_json) {
                Ok(s) => s,
                Err(_) => {
                    self.clear_ceremony_timestamp(session).await;
                    return Ok(FactorOutcome::InvalidCredential);
                }
            };

        let auth_result = match webauthn.finish_authentication(&assertion, &auth_state) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("FIDO2 finish_passkey_authentication failed: {e:?}");
                self.clear_ceremony_timestamp(session).await;
                // Route through the canonical failure helper so FIDO2
                // matches the canonical audit ordering and store-error muting.
                return self
                    .record_factor_failure(user_id, tenant_id, &FactorKind::Fido2, session)
                    .await;
            }
        };

        // Clear the ceremony timestamp FIRST. The state blob has
        // already been atomically consumed by `take_custom` above, so the
        // ceremony is fully retired in the session by the time we attempt
        // the credential save. If `save_fido2_credentials` then errors,
        // the session is in a clean state; the user can begin a fresh
        // ceremony immediately rather than tripping the
        // `is_ceremony_expired` fast-path on a stale timestamp.
        self.clear_ceremony_timestamp(session).await;

        self.save_fido2_credentials(user_scope, &cfg.credentials, &auth_result)
            .await?;

        // Device-binding hook: when the `device` subsystem is wired in
        // via a custom `Fido2Provider`, this updates
        // `DeviceBinding::WebAuthn.last_used_at` and (if the credential
        // is not yet bound to this device) creates the binding row. The
        // hook must fire on EVERY successful FIDO2 ceremony; including
        // this standard MFA path; so a stolen credential authenticating
        // from a fresh device produces a `DeviceBinding::WebAuthn` row
        // tying that credential to a new `DeviceId`, defeating the
        // cross-check the device subsystem exists to perform. Mirrors
        // the same call in `finish_discoverable_login` and the
        // registration path.
        if let Some(device_id) = session.device_id().await {
            webauthn.on_credential_used(auth_result.cred_id(), &device_id);
        }

        let now = self.clock.now();
        session.advance_factor(&FactorKind::Fido2, now).await;

        self.complete_factor_step(user_id, tenant_id, session).await
    }

    /// Begin FIDO2 passkey registration.
    #[tracing::instrument(skip(self, user, session))]
    pub async fn begin_fido2_registration(
        &self,
        user: &crate::authn::types::User,
        session: &AuthSession,
    ) -> Result<(serde_json::Value, Option<uuid::Uuid>), AuthnError<I::Error>> {
        let webauthn = match &self.fido2 {
            Some(w) => w,
            None => return Err(AuthnError::NoFlow),
        };

        let status = self
            .identity
            .account_status(&user.id)
            .await
            .map_err(AuthnError::Store)?;
        if !status.allows_login() {
            // Emit `Failure(FactorEnabled)` so a registration attempt
            // from a suspended user leaves SOC visibility. Distinguish
            // Locked from other non-active states so dashboards can
            // separate brute-force probes from administrative-state
            // mismatches; preserve `until` for the Locked path. Audit
            // type is `FactorEnabled` rather than `FactorVerified`
            // because this is an account-management action, not a login.
            let error_tag = if status.is_locked() {
                "locked"
            } else {
                "not_active"
            };
            self.emit_audit(
                AuthEventBuilder::failure(AuthEventType::FactorEnabled)
                    .attributed_to(&user.id, &user.tenant_id)
                    .with_factor(FactorKind::Fido2)
                    .with_error(error_tag),
            )
            .await;
            if let crate::authn::types::EntityState::Suspended(detail) = &status {
                self.metrics.account_locked();
                return Err(AuthnError::Locked {
                    until: detail.until,
                });
            }
            return Err(AuthnError::NotActive(status));
        }

        let user_scope = AuthnScope::User {
            tenant_id: user.tenant_id,
            user_id: user.id,
        };
        let existing = match self
            .factors
            .load_factor(&user_scope, FactorKind::Fido2)
            .await
        {
            Ok(Some(FactorConfig::Fido2(cfg))) => cfg.credentials,
            _ => vec![],
        };

        let (user_unique_id, new_id) = match user.webauthn_id {
            Some(id) => (id, None),
            None => {
                let mut bytes = [0u8; 16];
                self.rng.fill_bytes(&mut bytes);
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
        session.set_custom(fido2_keys::REG_STATE, state_json).await;
        self.stamp_ceremony_start(session).await;

        let challenge_json = serde_json::to_value(&challenge).map_err(|_| AuthnError::NoFlow)?;
        Ok((challenge_json, new_id))
    }

    /// Complete FIDO2 passkey registration.
    #[tracing::instrument(skip(self, user, response, session))]
    pub async fn finish_fido2_registration(
        &self,
        user: &crate::authn::types::User,
        response: &webauthn_rs::prelude::RegisterPublicKeyCredential,
        credential_name: &str,
        session: &AuthSession,
    ) -> Result<(), AuthnError<I::Error>> {
        let webauthn = match &self.fido2 {
            Some(w) => w,
            None => return Err(AuthnError::NoFlow),
        };

        if self.is_ceremony_expired(session).await {
            self.clear_ceremony_state(session, fido2_keys::REG_STATE)
                .await;
            return Err(AuthnError::NoFlow);
        }

        let state_json = session
            .get_custom(fido2_keys::REG_STATE)
            .await
            .ok_or(AuthnError::NoFlow)?;

        let reg_state: webauthn_rs::prelude::PasskeyRegistration =
            serde_json::from_value(state_json).map_err(|_| AuthnError::NoFlow)?;

        let passkey = webauthn
            .finish_registration(response, &reg_state)
            .map_err(|e| {
                tracing::warn!("FIDO2 finish_passkey_registration failed: {e:?}");
                AuthnError::NoFlow
            })?;

        // Capture the credential id before `passkey` moves into the
        // factor config below; needed for the post-save device-binding
        // hook so the `Fido2Provider` impl can durably bind this
        // credential to the resolved `DeviceId`.
        let cred_id = passkey.cred_id().clone();

        let user_scope = AuthnScope::User {
            tenant_id: user.tenant_id,
            user_id: user.id,
        };
        let mut credentials = match self
            .factors
            .load_factor(&user_scope, FactorKind::Fido2)
            .await
        {
            Ok(Some(FactorConfig::Fido2(cfg))) => cfg.credentials,
            _ => vec![],
        };
        credentials.push(crate::authn::factor::Fido2Credential::new(
            passkey,
            credential_name,
            self.clock.now(),
        ));

        self.factors
            .save_factor(
                &user_scope,
                FactorConfig::Fido2(crate::authn::factor::Fido2Config { credentials }),
            )
            .await
            .map_err(AuthnError::Store)?;

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

        self.clear_ceremony_state(session, fido2_keys::REG_STATE)
            .await;

        self.emit_audit(
            AuthEventBuilder::success(AuthEventType::FactorSetup)
                .attributed_to(&user.id, &user.tenant_id)
                .with_factor(FactorKind::Fido2),
        )
        .await;

        Ok(())
    }

    /// Begin a passwordless/discoverable FIDO2 authentication.
    #[tracing::instrument(skip(self, session))]
    pub async fn begin_discoverable_login(
        &self,
        session: &AuthSession,
    ) -> Result<serde_json::Value, AuthnError<I::Error>> {
        let webauthn = match &self.fido2 {
            Some(w) => w,
            None => return Err(AuthnError::NoFlow),
        };

        let (challenge, auth_state) =
            webauthn.start_discoverable_authentication().map_err(|e| {
                tracing::warn!("FIDO2 start_discoverable_authentication failed: {e:?}");
                AuthnError::NoFlow
            })?;

        let state_json = serde_json::to_value(&auth_state).map_err(|_| AuthnError::NoFlow)?;
        session.set_custom(fido2_keys::DISC_STATE, state_json).await;
        self.stamp_ceremony_start(session).await;

        serde_json::to_value(&challenge).map_err(|_| AuthnError::NoFlow)
    }

    /// Complete a passwordless/discoverable FIDO2 authentication.
    #[tracing::instrument(skip(self, assertion, user, credentials, session))]
    pub async fn finish_discoverable_login(
        &self,
        assertion: &webauthn_rs::prelude::PublicKeyCredential,
        user: &crate::authn::types::User,
        credentials: &[crate::authn::factor::Fido2Credential],
        session: &AuthSession,
    ) -> Result<(), AuthnError<I::Error>> {
        let webauthn = match &self.fido2 {
            Some(w) => w,
            None => return Err(AuthnError::NoFlow),
        };

        let status = self
            .identity
            .account_status(&user.id)
            .await
            .map_err(AuthnError::Store)?;
        if !status.allows_login() {
            self.clear_ceremony_state(session, fido2_keys::DISC_STATE)
                .await;
            // Emit `Failure(FactorVerified)` audit row and distinguish
            // Locked from other non-active states, preserving `until`
            // for the Locked path by walking the `EntityState::Suspended`
            // deep-nested form. The discoverable path runs OUTSIDE the
            // factor pipeline so it can't piggy-back on
            // `enforce_account_status`'s audit emit; mirror it here.
            let error_tag = if status.is_locked() {
                "locked"
            } else {
                "not_active"
            };
            self.emit_audit(
                AuthEventBuilder::failure(AuthEventType::FactorVerified)
                    .attributed_to(&user.id, &user.tenant_id)
                    .with_factor(FactorKind::Fido2)
                    .with_session(session.session_id().await)
                    .with_error(error_tag),
            )
            .await;
            if let crate::authn::types::EntityState::Suspended(detail) = &status {
                self.metrics.account_locked();
                return Err(AuthnError::Locked {
                    until: detail.until,
                });
            }
            return Err(AuthnError::NotActive(status));
        }

        if self.is_ceremony_expired(session).await {
            self.clear_ceremony_state(session, fido2_keys::DISC_STATE)
                .await;
            return Err(AuthnError::NoFlow);
        }

        // Take the discoverable auth state atomically. Same threat
        // model as the regular `verify_fido2_factor` path; two parallel
        // submissions of the same valid assertion must not both consume
        // the same ceremony state.
        let state_json = match session.take_custom(fido2_keys::DISC_STATE).await {
            Some(v) if !v.is_null() => v,
            _ => return Err(AuthnError::NoFlow),
        };

        let auth_state: webauthn_rs::prelude::DiscoverableAuthentication =
            serde_json::from_value(state_json).map_err(|_| {
                // State already removed; clear timestamp too.
                AuthnError::NoFlow
            })?;

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

                // Route through the canonical failure helper so the
                // two invariants hold here: counter-store errors must
                // NOT propagate as `Err(AuthnError::Store)` (would be a
                // distinguishable timing/error side-channel letting
                // attackers brute-force without tripping lockout), and
                // the audit emit must happen BEFORE the counter
                // increment.
                let outcome = self
                    .record_factor_failure(&user.id, &user.tenant_id, &FactorKind::Fido2, session)
                    .await?;

                self.clear_ceremony_state(session, fido2_keys::DISC_STATE)
                    .await;

                return match outcome {
                    // Pass `until` through to the caller so the
                    // FIDO2 discoverable path matches the same lockout
                    // shape as the cookie/factor path.
                    FactorOutcome::Locked { until } => Err(AuthnError::Locked { until }),
                    // `record_factor_failure` only emits `Locked` or
                    // `InvalidCredential`; the wildcard covers
                    // `InvalidCredential` defensively.
                    _ => Err(AuthnError::InvalidAssertion),
                };
            }
        };

        let user_scope = AuthnScope::User {
            tenant_id: user.tenant_id,
            user_id: user.id,
        };
        self.save_fido2_credentials(&user_scope, credentials, &auth_result)
            .await?;

        // Auto-invoke the device-binding hook for the credential that
        // just satisfied this assertion. Mirrors the call in
        // `finish_fido2_registration`: adopters that wire the `device`
        // subsystem override `Fido2Provider::on_credential_used` to
        // update `last_used_at` on the corresponding
        // `DeviceBinding::WebAuthn` row (or insert one on first sighting);
        // the default impl is a no-op so deployments without the
        // subsystem are unaffected.
        if let Some(device_id) = session.device_id().await {
            webauthn.on_credential_used(auth_result.cred_id(), &device_id);
        }

        // Clear the ceremony timestamp BEFORE flipping the session
        // to Authenticated. The state JSON itself was already taken by the
        // atomic-take above. Doing it now (rather than after
        // `complete_factor_step`) means an early return on the
        // status-recheck or registry-error path inside complete_factor_step
        // does not leave a stale ceremony timestamp
        // that the next request would interpret as "ceremony in progress".
        self.clear_ceremony_timestamp(session).await;

        // Reset the failed-attempt counter BEFORE flipping the session to
        // Authenticated. Same reasoning as the standard
        // verify_factor path: if the counter reset errors after the
        // session is already authenticated, we'd hold an Authenticated
        // session that the registry never saw. Reset first → register-
        // through-complete-step → handle errors before set_authenticated.
        self.identity
            .reset_failed_attempts(&user.id)
            .await
            .map_err(AuthnError::Store)?;

        let now = self.clock.now();
        session
            .set_authenticated(user.id, user.tenant_id, now)
            .await;

        // complete_factor_step here both registers in the SessionRegistry
        // and re-checks account status; propagate any error so
        // a failed registration / mid-flow suspension reaches the caller.
        match self
            .complete_factor_step(&user.id, &user.tenant_id, session)
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => {
                // Roll the session back to Guest on failure so the user
                // does not hold an Authenticated cookie outside the
                // registry's view (fail-closed contract).
                session.clear().await;
                Err(e)
            }
        }
    }

    // ── Credential management ────────────────────────────────────────────────

    /// List all FIDO2 credentials registered for a user.
    #[tracing::instrument(skip(self, user))]
    pub async fn list_fido2_credentials(
        &self,
        user: &crate::authn::types::User,
    ) -> Result<Vec<crate::authn::factor::Fido2Credential>, AuthnError<I::Error>> {
        let user_scope = AuthnScope::User {
            tenant_id: user.tenant_id,
            user_id: user.id,
        };
        match self
            .factors
            .load_factor(&user_scope, FactorKind::Fido2)
            .await
        {
            Ok(Some(FactorConfig::Fido2(cfg))) => Ok(cfg.credentials),
            Ok(_) => Ok(vec![]),
            Err(e) => Err(AuthnError::Store(e)),
        }
    }

    /// Delete a FIDO2 credential by its credential ID.
    #[tracing::instrument(skip(self, user, credential_id))]
    pub async fn delete_fido2_credential(
        &self,
        user: &crate::authn::types::User,
        credential_id: &webauthn_rs::prelude::CredentialID,
        min_remaining: usize,
    ) -> Result<bool, AuthnError<I::Error>> {
        let user_scope = AuthnScope::User {
            tenant_id: user.tenant_id,
            user_id: user.id,
        };
        let mut credentials = match self
            .factors
            .load_factor(&user_scope, FactorKind::Fido2)
            .await
        {
            Ok(Some(FactorConfig::Fido2(cfg))) => cfg.credentials,
            _ => return Ok(false),
        };

        let original_len = credentials.len();
        credentials.retain(|c| c.cred_id() != credential_id);

        if credentials.len() == original_len {
            return Ok(false);
        }
        if credentials.len() < min_remaining {
            return Ok(false);
        }

        self.factors
            .save_factor(
                &user_scope,
                FactorConfig::Fido2(crate::authn::factor::Fido2Config { credentials }),
            )
            .await
            .map_err(AuthnError::Store)?;

        self.emit_audit(
            AuthEventBuilder::success(AuthEventType::FactorDisabled)
                .attributed_to(&user.id, &user.tenant_id)
                .with_factor(FactorKind::Fido2),
        )
        .await;

        Ok(true)
    }
}
