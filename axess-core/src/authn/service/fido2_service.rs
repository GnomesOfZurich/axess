//! FIDO2/WebAuthn ceremony methods on [`AuthnService`].

use super::*;

// ── FIDO2 ceremony session keys ──────────────────────────────────────────────

pub(crate) mod fido2_keys {
    pub const AUTH_STATE: &str = "axess.fido2.auth_state";
    pub const REG_STATE: &str = "axess.fido2.reg_state";
    pub const DISC_STATE: &str = "axess.fido2.disc_state";
    pub const CEREMONY_STARTED: &str = "axess.fido2.ceremony_started";
}

impl<I, F, R, C> AuthnService<I, F, R, C>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
    R: SecureRng,
    C: Clock,
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

    /// Record a FIDO2 authentication failure, check lockout.
    async fn record_fido2_failure(
        &self,
        user_id: &Arc<str>,
        tenant_id: &Arc<str>,
        session: &AuthSession,
    ) -> Result<FactorOutcome, AuthnError<I::Error>> {
        let count = self
            .identity
            .record_failed_attempt(user_id)
            .await
            .map_err(AuthnError::Store)?;

        session.record_attempt_at(self.clock.now()).await;

        let _ = self
            .identity
            .record_event(
                AuthEventBuilder::new(
                    user_id.clone(),
                    tenant_id.clone(),
                    AuthEventType::FactorVerified,
                    AuthEventStatus::Failure,
                )
                .with_factor(FactorKind::Fido2)
                .build_at(self.clock.now()),
            )
            .await;

        let policy = self.identity.lockout_policy();
        if count >= policy.max_attempts {
            Ok(FactorOutcome::Locked { until: None })
        } else {
            Ok(FactorOutcome::InvalidCredential)
        }
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

    /// Check if the FIDO2 ceremony has exceeded the configured timeout.
    pub(super) async fn is_ceremony_expired(&self, session: &AuthSession) -> bool {
        let Some(started) = session.get_custom(fido2_keys::CEREMONY_STARTED).await else {
            return false;
        };
        let Some(ts) = started.as_str() else {
            return false;
        };
        let Ok(started_at) = chrono::DateTime::parse_from_rfc3339(ts) else {
            return false;
        };
        let elapsed = self.clock.now() - started_at.with_timezone(&chrono::Utc);
        elapsed.to_std().unwrap_or_default() > self.fido2_options.ceremony_timeout
    }

    /// Verify a FIDO2/WebAuthn authentication assertion.
    pub(super) async fn verify_fido2_factor(
        &self,
        credential: &FactorCredential,
        config: &FactorConfig,
        user_scope: &AuthnScope,
        user_id: &Arc<str>,
        tenant_id: &Arc<str>,
        session: &AuthSession,
    ) -> Result<FactorOutcome, AuthnError<I::Error>> {
        let webauthn = match &self.fido2 {
            Some(w) => w,
            None => return Ok(FactorOutcome::InvalidCredential),
        };

        let FactorConfig::Fido2(cfg) = config else {
            return Ok(FactorOutcome::InvalidCredential);
        };

        let FactorCredential::Fido2Assertion(assertion) = credential else {
            return Ok(FactorOutcome::InvalidCredential);
        };

        let state_json = match session.get_custom(fido2_keys::AUTH_STATE).await {
            Some(v) if !v.is_null() => v,
            _ => return Ok(FactorOutcome::InvalidCredential),
        };

        if self.is_ceremony_expired(session).await {
            self.clear_ceremony_state(session, fido2_keys::AUTH_STATE)
                .await;
            return Ok(FactorOutcome::InvalidCredential);
        }

        let auth_state: webauthn_rs::prelude::PasskeyAuthentication =
            match serde_json::from_value(state_json) {
                Ok(s) => s,
                Err(_) => return Ok(FactorOutcome::InvalidCredential),
            };

        let auth_result = match webauthn.finish_authentication(assertion, &auth_state) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("FIDO2 finish_passkey_authentication failed: {e:?}");
                return self.record_fido2_failure(user_id, tenant_id, session).await;
            }
        };

        self.save_fido2_credentials(user_scope, &cfg.credentials, &auth_result)
            .await?;

        self.clear_ceremony_state(session, fido2_keys::AUTH_STATE)
            .await;

        let now = self.clock.now();
        session.advance_factor(&FactorKind::Fido2, now).await;

        self.complete_factor_step(user_id, tenant_id, session).await
    }

    /// Begin FIDO2 passkey registration.
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
            return Err(AuthnError::NotActive(status));
        }

        let user_scope = AuthnScope::User {
            tenant_id: user.tenant_id.clone(),
            user_id: user.id.clone(),
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
                let mut rng = self.rng.clone();
                rng.fill_bytes(&mut bytes);
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

        let user_scope = AuthnScope::User {
            tenant_id: user.tenant_id.clone(),
            user_id: user.id.clone(),
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

        self.clear_ceremony_state(session, fido2_keys::REG_STATE)
            .await;

        let _ = self
            .identity
            .record_event(
                AuthEventBuilder::new(
                    user.id.clone(),
                    user.tenant_id.clone(),
                    AuthEventType::FactorSetup,
                    AuthEventStatus::Success,
                )
                .with_factor(FactorKind::Fido2)
                .build_at(self.clock.now()),
            )
            .await;

        Ok(())
    }

    /// Begin a passwordless/discoverable FIDO2 authentication.
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
            return Err(AuthnError::NotActive(status));
        }

        if self.is_ceremony_expired(session).await {
            self.clear_ceremony_state(session, fido2_keys::DISC_STATE)
                .await;
            return Err(AuthnError::NoFlow);
        }

        let state_json = match session.get_custom(fido2_keys::DISC_STATE).await {
            Some(v) if !v.is_null() => v,
            _ => return Err(AuthnError::NoFlow),
        };

        let auth_state: webauthn_rs::prelude::DiscoverableAuthentication =
            serde_json::from_value(state_json).map_err(|_| AuthnError::NoFlow)?;

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
                let count = self
                    .identity
                    .record_failed_attempt(&user.id)
                    .await
                    .map_err(AuthnError::Store)?;

                let _ = self
                    .identity
                    .record_event(
                        AuthEventBuilder::new(
                            user.id.clone(),
                            user.tenant_id.clone(),
                            AuthEventType::FactorVerified,
                            AuthEventStatus::Failure,
                        )
                        .with_factor(FactorKind::Fido2)
                        .build_at(self.clock.now()),
                    )
                    .await;

                self.clear_ceremony_state(session, fido2_keys::DISC_STATE)
                    .await;

                let policy = self.identity.lockout_policy();
                if count >= policy.max_attempts {
                    return Err(AuthnError::Locked);
                }
                return Err(AuthnError::InvalidAssertion);
            }
        };

        let user_scope = AuthnScope::User {
            tenant_id: user.tenant_id.clone(),
            user_id: user.id.clone(),
        };
        self.save_fido2_credentials(&user_scope, credentials, &auth_result)
            .await?;

        let now = self.clock.now();
        session
            .set_authenticated(user.id.clone(), user.tenant_id.clone(), now)
            .await;

        let _ = self
            .complete_factor_step(&user.id, &user.tenant_id, session)
            .await?;

        self.clear_ceremony_state(session, fido2_keys::DISC_STATE)
            .await;

        Ok(())
    }

    // ── Credential management ────────────────────────────────────────────────

    /// List all FIDO2 credentials registered for a user.
    pub async fn list_fido2_credentials(
        &self,
        user: &crate::authn::types::User,
    ) -> Result<Vec<crate::authn::factor::Fido2Credential>, AuthnError<I::Error>> {
        let user_scope = AuthnScope::User {
            tenant_id: user.tenant_id.clone(),
            user_id: user.id.clone(),
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
    pub async fn delete_fido2_credential(
        &self,
        user: &crate::authn::types::User,
        credential_id: &webauthn_rs::prelude::CredentialID,
        min_remaining: usize,
    ) -> Result<bool, AuthnError<I::Error>> {
        let user_scope = AuthnScope::User {
            tenant_id: user.tenant_id.clone(),
            user_id: user.id.clone(),
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

        let _ = self
            .identity
            .record_event(
                AuthEventBuilder::new(
                    user.id.clone(),
                    user.tenant_id.clone(),
                    AuthEventType::FactorDisabled,
                    AuthEventStatus::Success,
                )
                .with_factor(FactorKind::Fido2)
                .build_at(self.clock.now()),
            )
            .await;

        Ok(true)
    }
}
