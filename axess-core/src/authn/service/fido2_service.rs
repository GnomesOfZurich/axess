//! FIDO2/WebAuthn ceremony methods on [`AuthnService`].

use super::{AuthnService, RequestAuthnService, outcomes::FactorOutcome};
use crate::authn::{
    error::AuthnError,
    event::{AuthEventBuilder, AuthEventType, AuthFailureReason},
    factor::{FactorConfig, FactorCredential, FactorKind},
    ids::{TenantId, UserId},
    store::{FactorStore, IdentityStore},
    types::AuthnScope,
};
use crate::session::extractor::AuthSession;

/// Bound on compare-and-swap retries when updating a user's passkey list.
const MAX_PASSKEY_UPDATE_ATTEMPTS: usize = 8;

// ── FIDO2 ceremony session keys ──────────────────────────────────────────────

pub(crate) mod fido2_keys {
    pub const AUTH_STATE: &str = "axess.fido2.auth_state";
    pub const REG_STATE: &str = "axess.fido2.reg_state";
    pub const DISC_STATE: &str = "axess.fido2.disc_state";
    /// When the authentication ceremony began; paired with [`AUTH_STATE`].
    pub const AUTH_STARTED: &str = "axess.fido2.auth_started";
    /// When the registration ceremony began; paired with [`REG_STATE`].
    pub const REG_STARTED: &str = "axess.fido2.reg_started";
    /// When the discoverable ceremony began; paired with [`DISC_STATE`].
    pub const DISC_STARTED: &str = "axess.fido2.disc_started";

    /// The timestamp key that belongs to a ceremony state key. Each ceremony
    /// has its own, so starting one never refreshes the timeout of stale
    /// state another one left behind.
    pub fn started_key(state_key: &str) -> &'static str {
        match state_key {
            AUTH_STATE => AUTH_STARTED,
            REG_STATE => REG_STARTED,
            _ => DISC_STARTED,
        }
    }
}

impl<I, F> AuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Apply `mutate` to the user's stored passkey list and persist the
    /// result with a compare-and-swap, so two concurrent updates (two
    /// registrations, a registration racing a deletion, a counter update
    /// racing either) never overwrite one another. A lost swap reloads and
    /// re-applies `mutate` to the fresh list, up to
    /// [`MAX_PASSKEY_UPDATE_ATTEMPTS`] times.
    ///
    /// `mutate` returns `None` to abandon the update (nothing is written and
    /// `Ok(None)` is returned) or `Some(value)` to commit. A failed read or
    /// write is an error, never an empty list.
    async fn update_fido2_credentials<R>(
        &self,
        user_scope: &AuthnScope,
        mutate: impl Fn(&mut Vec<crate::authn::factor::Fido2Credential>) -> Option<R>,
    ) -> Result<Option<R>, AuthnError<I::Error>> {
        for _ in 0..MAX_PASSKEY_UPDATE_ATTEMPTS {
            let prior = self
                .inner
                .factors
                .load_factor(user_scope, FactorKind::Fido2)
                .await
                .map_err(AuthnError::Store)?;
            let mut credentials = match &prior {
                Some(FactorConfig::Fido2(cfg)) => cfg.credentials.clone(),
                _ => Vec::new(),
            };
            let Some(outcome) = mutate(&mut credentials) else {
                return Ok(None);
            };
            let next = FactorConfig::Fido2(crate::authn::factor::Fido2Config { credentials });
            let swapped = match &prior {
                Some(prior @ FactorConfig::Fido2(_)) => {
                    self.inner
                        .factors
                        .compare_and_save_factor(user_scope, prior, next)
                        .await
                }
                _ => {
                    self.inner
                        .factors
                        .insert_factor_if_absent(user_scope, next)
                        .await
                }
            }
            .map_err(AuthnError::Store)?;
            if swapped {
                return Ok(Some(outcome));
            }
        }
        Err(AuthnError::ExternalService(
            "passkey list kept changing concurrently; retry".to_string(),
        ))
    }

    /// Record a successful authentication on the stored passkey it used.
    ///
    /// Returns `Ok(false)`, writing nothing, when the stored list no longer
    /// holds the credential that produced `auth_result` (the passkey was
    /// deleted after the ceremony began) or the user has no passkeys at all.
    /// The caller must treat that as a failed assertion.
    async fn save_fido2_credentials(
        &self,
        user_scope: &AuthnScope,
        auth_result: &webauthn_rs::prelude::AuthenticationResult,
    ) -> Result<bool, AuthnError<I::Error>> {
        let now = self.inner.clock.now();
        let saved = self
            .update_fido2_credentials(user_scope, |credentials| {
                let used = credentials
                    .iter_mut()
                    .find(|c| c.cred_id() == auth_result.cred_id())?;
                used.record_authentication(auth_result, now);
                Some(())
            })
            .await?;
        Ok(saved.is_some())
    }

    /// Store the ceremony-started timestamp for the ceremony that owns
    /// `state_key`.
    pub(super) async fn stamp_ceremony_start(&self, session: &AuthSession, state_key: &str) {
        session
            .set_custom(
                fido2_keys::started_key(state_key),
                serde_json::Value::String(self.inner.clock.now().to_rfc3339()),
            )
            .await;
    }

    /// Clear a ceremony's state key and its timestamp from the session.
    pub(super) async fn clear_ceremony_state(&self, session: &AuthSession, state_key: &str) {
        session.set_custom(state_key, serde_json::Value::Null).await;
        self.clear_ceremony_timestamp(session, state_key).await;
    }

    /// Clear ONLY the ceremony timestamp; the state key has already been
    /// consumed via [`AuthSession::take_custom`]. Used by the hardened
    /// paths that take the ceremony state atomically with the read.
    pub(super) async fn clear_ceremony_timestamp(&self, session: &AuthSession, state_key: &str) {
        session
            .set_custom(fido2_keys::started_key(state_key), serde_json::Value::Null)
            .await;
    }

    /// Check if the FIDO2 ceremony that owns `state_key` has exceeded the
    /// configured timeout.
    ///
    /// Fails closed: if the ceremony timestamp is missing or unparseable,
    /// the ceremony is considered expired. This prevents stale or corrupted
    /// sessions from bypassing timeout enforcement.
    pub(super) async fn is_ceremony_expired(&self, session: &AuthSession, state_key: &str) -> bool {
        let Some(started) = session.get_custom(fido2_keys::started_key(state_key)).await else {
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
        let elapsed = self.inner.clock.now() - started_at.with_timezone(&chrono::Utc);
        match elapsed.to_std() {
            Ok(d) => d > self.inner.fido2_options.ceremony_timeout,
            Err(_) => {
                // Negative duration (clock skew); treat as expired and log.
                tracing::warn!(
                    "FIDO2 ceremony elapsed duration is negative (clock skew?); treating as expired"
                );
                true
            }
        }
    }

    /// Begin a passwordless/discoverable FIDO2 authentication.
    #[tracing::instrument(skip(self, session))]
    pub async fn begin_discoverable_login(
        &self,
        session: &AuthSession,
    ) -> Result<serde_json::Value, AuthnError<I::Error>> {
        let webauthn = match &self.inner.fido2 {
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
        self.stamp_ceremony_start(session, fido2_keys::DISC_STATE)
            .await;

        serde_json::to_value(&challenge).map_err(|_| AuthnError::NoFlow)
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
            .inner
            .factors
            .load_factor(&user_scope, FactorKind::Fido2)
            .await
        {
            Ok(Some(FactorConfig::Fido2(cfg))) => Ok(cfg.credentials),
            Ok(_) => Ok(vec![]),
            Err(e) => Err(AuthnError::Store(e)),
        }
    }
}

impl<I, F> RequestAuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Audit and name the refusal of a passkey ceremony for an account that
    /// may not log in. A lockout carries `Locked` (with its `until`), the
    /// other non-active states a `Failure` tagged `NotActive`, so a dashboard
    /// separates brute-force probes from administrative-state mismatches.
    /// `event` is `FactorEnabled` for an account-management action and
    /// `FactorVerified` for a login. A failed audit write is returned in
    /// place of the refusal.
    async fn refuse_inactive_account(
        &self,
        user: &crate::authn::types::User,
        status: crate::authn::types::EntityState,
        event: AuthEventType,
        session: Option<&AuthSession>,
    ) -> AuthnError<I::Error> {
        let builder = if status.is_locked() {
            AuthEventBuilder::locked(event)
        } else {
            AuthEventBuilder::failure(event).with_error(AuthFailureReason::NotActive)
        };
        let mut builder = builder
            .attributed_to(&user.id, &user.tenant_id)
            .with_factor(FactorKind::Fido2);
        if let Some(session) = session {
            builder = builder.with_session(session.session_id().await);
        }
        if let Err(e) = self.emit_audit(builder).await {
            return e;
        }
        if let crate::authn::types::EntityState::Suspended(detail) = &status {
            self.inner.metrics.account_locked();
            return AuthnError::Locked {
                until: detail.until,
            };
        }
        AuthnError::NotActive(status)
    }

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
        let webauthn = match &self.inner.fido2 {
            Some(w) => w,
            None => return Ok(FactorOutcome::InvalidCredential),
        };

        let FactorConfig::Fido2(_) = config else {
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

        if self
            .is_ceremony_expired(session, fido2_keys::AUTH_STATE)
            .await
        {
            self.clear_ceremony_timestamp(session, fido2_keys::AUTH_STATE)
                .await;
            return Ok(FactorOutcome::InvalidCredential);
        }

        let auth_state: webauthn_rs::prelude::PasskeyAuthentication =
            match serde_json::from_value(state_json) {
                Ok(s) => s,
                Err(_) => {
                    self.clear_ceremony_timestamp(session, fido2_keys::AUTH_STATE)
                        .await;
                    return Ok(FactorOutcome::InvalidCredential);
                }
            };

        let auth_result = match webauthn.finish_authentication(&assertion, &auth_state) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("FIDO2 finish_passkey_authentication failed: {e:?}");
                self.clear_ceremony_timestamp(session, fido2_keys::AUTH_STATE)
                    .await;
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
        self.clear_ceremony_timestamp(session, fido2_keys::AUTH_STATE)
            .await;

        // A passkey deleted after the ceremony began is no longer a
        // credential of this user: the assertion verified against a stale
        // list, so it counts as a failed attempt and authenticates nothing.
        if !self
            .save_fido2_credentials(user_scope, &auth_result)
            .await?
        {
            return self
                .record_factor_failure(user_id, tenant_id, &FactorKind::Fido2, session)
                .await;
        }

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

        let now = self.inner.clock.now();
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
        let webauthn = match &self.inner.fido2 {
            Some(w) => w,
            None => return Err(AuthnError::NoFlow),
        };

        let status = self.current_account_status(&user.id).await?;
        if !status.allows_login() {
            return Err(self
                .refuse_inactive_account(user, status, AuthEventType::FactorEnabled, None)
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
        session.set_custom(fido2_keys::REG_STATE, state_json).await;
        self.stamp_ceremony_start(session, fido2_keys::REG_STATE)
            .await;

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
        let webauthn = match &self.inner.fido2 {
            Some(w) => w,
            None => return Err(AuthnError::NoFlow),
        };

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
        // ceremony began; begin refused it, so finish refuses it too.
        let status = self.current_account_status(&user.id).await?;
        if !status.allows_login() {
            return Err(self
                .refuse_inactive_account(user, status, AuthEventType::FactorEnabled, None)
                .await);
        }

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
                .with_factor(FactorKind::Fido2),
        )
        .await?;

        Ok(())
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
        // the same ceremony state.
        let state_json = match session.take_custom(fido2_keys::DISC_STATE).await {
            Some(v) if !v.is_null() => v,
            _ => return Err(AuthnError::NoFlow),
        };

        let Ok(auth_state) =
            serde_json::from_value::<webauthn_rs::prelude::DiscoverableAuthentication>(state_json)
        else {
            // The state is already taken; retire the timestamp too.
            self.clear_ceremony_timestamp(session, fido2_keys::DISC_STATE)
                .await;
            return Err(AuthnError::NoFlow);
        };

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
        self.clear_ceremony_timestamp(session, fido2_keys::DISC_STATE)
            .await;

        // Reset the failed-attempt counter BEFORE flipping the session to
        // Authenticated. Same reasoning as the standard
        // verify_factor path: if the counter reset errors after the
        // session is already authenticated, we'd hold an Authenticated
        // session that the registry never saw. Reset first → register-
        // through-complete-step → handle errors before set_authenticated.
        self.inner
            .identity
            .reset_failed_attempts(&user.id)
            .await
            .map_err(AuthnError::Store)?;

        let now = self.inner.clock.now();
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
        // A failed read or write is an error to the caller, and `Ok(true)`
        // is returned only once the swap that removes the credential has
        // been committed.
        let removed = self
            .update_fido2_credentials(&user_scope, |credentials| {
                let original_len = credentials.len();
                credentials.retain(|c| c.cred_id() != credential_id);
                if credentials.len() == original_len || credentials.len() < min_remaining {
                    return None;
                }
                Some(())
            })
            .await?;
        if removed.is_none() {
            return Ok(false);
        }

        self.emit_audit(
            AuthEventBuilder::success(AuthEventType::FactorDisabled)
                .attributed_to(&user.id, &user.tenant_id)
                .with_factor(FactorKind::Fido2),
        )
        .await?;

        Ok(true)
    }
}
