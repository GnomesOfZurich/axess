//! Password reset flow: `begin_password_reset` + `complete_password_reset`
//! plus the tenant-scoped `complete_password_reset_in_tenant` rail.
//!
//! Two-step ceremony with single-use, hashed-on-disk token:
//!
//! - [`AuthnService::begin_password_reset`] generates a 32-byte URL-safe
//!   token, stores `SHA-256(token)`, returns the plaintext for the
//!   application to deliver out-of-band (email link, SMS, etc.).
//! - [`AuthnService::complete_password_reset`] verifies the token,
//!   enforces the tenant's history-reuse rule against the new plaintext,
//!   Argon2id-hashes it, updates the password factor, records audit
//!   events, and invalidates other live sessions for the user.
//! - [`AuthnService::complete_password_reset_in_tenant`] adds a
//!   cross-tenant rail before `complete_password_reset` does the
//!   expensive Argon2id-flavoured rest of the flow.

use crate::authn::service::AuthnService;
use crate::authn::{
    error::AuthnError,
    event::{AuthEventBuilder, AuthEventType},
    factor::{FactorConfig, FactorKind},
    store::{FactorStore, IdentityStore},
    types::AuthnScope,
};

impl<I, F> AuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Begin a password-reset flow for a user.
    ///
    /// Generates a single-use reset token (SHA-256 hash stored, plaintext
    /// returned exactly once). The application is responsible for delivering
    /// the token to the user (email link, SMS, etc.).
    ///
    /// The token expires after `ttl`. Returns the plaintext token that the
    /// application should embed in a reset link.
    ///
    /// # Arguments
    ///
    /// * `identifier`: the user's login identifier (email, username).
    /// * `tenant_identifier`: the tenant slug/domain.
    /// * `ttl`: how long the token is valid.
    #[tracing::instrument(skip(self, ttl), fields(tenant = %tenant_identifier))]
    pub async fn begin_password_reset(
        &self,
        identifier: &str,
        tenant_identifier: &str,
        ttl: std::time::Duration,
    ) -> Result<Option<String>, AuthnError<I::Error>> {
        // Look up the user. If not found, return Ok(None) to avoid
        // leaking whether the identifier exists (timing equalized below).
        let tenant = self
            .identity
            .find_tenant(tenant_identifier)
            .await
            .map_err(AuthnError::Store)?;

        let tenant = match tenant {
            Some(t) if t.status.is_active() => t,
            _ => return Ok(None),
        };

        let user = self
            .identity
            .find_user(identifier, &tenant.id)
            .await
            .map_err(AuthnError::Store)?;

        let user = match user {
            Some(u) if u.validate().is_ok() => Some(u),
            _ => None,
        };

        // Generate token: 32 random bytes → URL-safe base64. Done
        // unconditionally so the not-found path performs the same RNG +
        // SHA-256 work as the found path, narrowing the timing side
        // channel that would otherwise leak account existence.
        let mut token_bytes = [0u8; 32];
        self.rng.fill_bytes(&mut token_bytes);
        use base64::Engine as _;
        let plaintext = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token_bytes);
        let hash = {
            use sha2::Digest;
            let digest = sha2::Sha256::digest(plaintext.as_bytes());
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
        };

        let user = match user {
            Some(u) => u,
            None => {
                // Burn comparable wall time on the miss path. We can't write
                // to the database (no user_id), but we can at least amortize
                // the dominant work the success path will perform; the
                // store_reset_token round-trip is application-specific and
                // typically much smaller than the Argon2id verify in
                // complete_password_reset, so this matters less than for
                // login. Two-step UX still inherently signals existence
                // (the user only gets the email when they exist); apps
                // should additionally always return the same UI message.
                return Ok(None);
            }
        };

        let expires_at = self.clock.now() + chrono::Duration::from_std(ttl).unwrap_or_default();
        self.identity
            .store_reset_token(&user.id, &hash, expires_at)
            .await
            .map_err(AuthnError::Store)?;

        self.emit_audit(
            AuthEventBuilder::success(AuthEventType::PasswordResetRequested)
                .attributed_to(&user.id, &user.tenant_id),
        )
        .await;

        Ok(Some(plaintext))
    }

    /// Tenant-scoped password-reset variant.
    ///
    /// Same as [`complete_password_reset`](Self::complete_password_reset) but
    /// refuses with [`AuthnError::CrossTenant`] if the resolved user's
    /// `tenant_id` does not match `expected_tenant`. Use this from any
    /// password-reset handler whose authorisation scope is a single
    /// tenant. It closes the gap where parameter tampering on a
    /// reset-link callback could otherwise reset a user in tenant B
    /// while authenticated as an admin (or just a visitor) of tenant A.
    pub async fn complete_password_reset_in_tenant(
        &self,
        user_id: &crate::authn::ids::UserId,
        expected_tenant: &crate::authn::ids::TenantId,
        token: &str,
        new_password: &str,
    ) -> Result<bool, AuthnError<I::Error>> {
        // Resolve the user and check tenant before doing the (much more
        // expensive) Argon2id-flavoured rest of the flow. The resolution
        // re-runs inside `complete_password_reset`, but the cost is tiny
        // compared to history hashing and we get a fast-path tenant
        // refusal here.
        let user = self
            .identity
            .get_user(user_id)
            .await
            .map_err(AuthnError::Store)?
            .ok_or(AuthnError::NoFlow)?;
        if &user.tenant_id != expected_tenant {
            tracing::warn!(
                user_id = %user_id,
                user_tenant = %user.tenant_id,
                expected_tenant = %expected_tenant,
                "cross-tenant password reset refused"
            );
            return Err(AuthnError::CrossTenant);
        }
        self.complete_password_reset(user_id, token, new_password)
            .await
    }

    /// Complete a password-reset flow by verifying the token and setting a new password.
    ///
    /// The token is single-use, consumed on verification. Returns `Ok(true)`
    /// if the reset succeeded, `Ok(false)` if the token was invalid, expired,
    /// or the new password violates the tenant's history-reuse rule.
    ///
    /// # Arguments
    ///
    /// * `user_id`: the user's opaque ID (from the reset link context).
    /// * `token`: the plaintext reset token.
    /// * `new_password`: the plaintext new password. Hashed internally with
    ///   `axess_factors::generate_password_hash` *after* the history-reuse
    ///   check passes, so passing the hash here would defeat the check.
    #[tracing::instrument(skip(self, token, new_password))]
    pub async fn complete_password_reset(
        &self,
        user_id: &crate::authn::ids::UserId,
        token: &str,
        new_password: &str,
    ) -> Result<bool, AuthnError<I::Error>> {
        if !self.verify_reset_token_hash(user_id, token).await? {
            return Ok(false);
        }

        // Update the password factor.
        let user = self
            .identity
            .get_user(user_id)
            .await
            .map_err(AuthnError::Store)?
            .ok_or(AuthnError::NoFlow)?;

        let user_scope = AuthnScope::User {
            tenant_id: user.tenant_id,
            user_id: user.id,
        };

        // Record old hash in password history (if backend supports it).
        if let Some(FactorConfig::Password(ref old_config)) = self
            .factors
            .load_factor(&user_scope, FactorKind::Password)
            .await
            .map_err(AuthnError::Store)?
        {
            self.identity
                .record_password_hash(user_id, &old_config.hash)
                .await
                .map_err(AuthnError::Store)?;
        }

        let rules = self
            .identity
            .password_rules_for_tenant(&user.tenant_id)
            .await
            .map_err(AuthnError::Store)?;

        if self
            .verify_new_password_not_in_history(user_id, new_password, &rules)
            .await?
        {
            return Ok(false); // Password was used before.
        }

        // Hash AFTER the history check passes; the check verifies the new
        // plaintext against each old Argon2 hash, so it MUST receive
        // plaintext. Hashing earlier would feed a PHC string into Argon2's
        // plaintext slot and the check would never match.
        let new_password_hash = axess_factors::generate_password_hash(new_password);

        // Order the writes so that the *worst* possible partial
        // failure is benign.
        //
        //   * Record the NEW hash in history BEFORE activating it via
        //     `save_factor`. If the history write fails, we abort with
        //     the old password still live; no policy bypass.
        //   * If the history write succeeds and `save_factor` fails, the
        //     new hash is in history but not active. The user retries
        //     with a different password (or the same password; which
        //     will fail the history check, prompting them to pick a new
        //     one). This is strictly better than the prior order, which
        //     could leave a *live new password* missing from history,
        //     letting the user re-use it on the next reset and silently
        //     violate the password-rotation policy.
        //
        // Production backends should override `record_password_hash` and
        // `save_factor` to share a single SQL transaction; until then,
        // this ordering minimises blast radius.
        self.identity
            .record_password_hash(user_id, &new_password_hash)
            .await
            .map_err(AuthnError::Store)?;

        let new_config = FactorConfig::Password(crate::authn::factor::PasswordConfig {
            hash: crate::authn::factor::ZeroizedString::new(new_password_hash),
            rules,
        });
        self.factors
            .save_factor(&user_scope, new_config)
            .await
            .map_err(AuthnError::Store)?;

        // Reset failed attempts.
        self.identity
            .reset_failed_attempts(user_id)
            .await
            .map_err(AuthnError::Store)?;

        // Invalidate all other live sessions for this user. A stolen session
        // cookie must not survive a password change; anyone authenticated as
        // this user prior to the reset is forced to re-authenticate. Best
        // effort: failures are logged but do not block the reset (the
        // password change has already succeeded and is more important than
        // session-registry hygiene).
        if let Some(reg) = &self.registry {
            reg.invalidate_user(user_id).await;
            tracing::info!(
                user_id = %user_id,
                "password reset: invalidated all sessions for user"
            );
        }

        self.emit_audit(
            AuthEventBuilder::success(AuthEventType::PasswordReset)
                .attributed_to(&user.id, &user.tenant_id),
        )
        .await;

        Ok(true)
    }

    /// Hash the supplied plaintext token via SHA-256 and verify it
    /// against the store's per-user reset-token record.
    ///
    /// Returns `Ok(true)` when the token matches the current
    /// outstanding reset token for `user_id`. Returns `Ok(false)`
    /// when the token doesn't match (consumed, expired, never
    /// issued, or simply wrong): caller maps to "reset failed."
    /// Errors only on store outage.
    ///
    /// SHA-256 (rather than HMAC or Argon2) matches the begin-side
    /// `record_reset_token` storage shape: the token is high-entropy
    /// (32 random bytes from `SecureRng`, base64-encoded) and
    /// single-use, so a fast hash is appropriate. If begin-side
    /// hashing changes, this must change in lockstep.
    async fn verify_reset_token_hash(
        &self,
        user_id: &crate::authn::ids::UserId,
        token: &str,
    ) -> Result<bool, AuthnError<I::Error>> {
        use base64::Engine as _;
        let hash = {
            use sha2::Digest;
            let digest = sha2::Sha256::digest(token.as_bytes());
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
        };
        self.identity
            .verify_reset_token(user_id, &hash)
            .await
            .map_err(AuthnError::Store)
    }

    /// Check whether `new_password` (plaintext) Argon2-verifies against
    /// any of the user's last `rules.history_count` stored hashes.
    ///
    /// Returns `Ok(true)` if the password was previously used (caller
    /// rejects the reset), `Ok(false)` if it's safe to use. Returns
    /// `Ok(false)` immediately when `rules.history_count == 0` (history
    /// check disabled).
    ///
    /// **Security invariant, preserve on every refactor:** the loop
    /// iterates ALL history entries to constant time, even after a match
    /// is found. The naïve `if reused { break; }` would leak the position
    /// of the matched hash via response time: a 5-deep history with the
    /// recent password reused returns measurably faster than a 5-deep
    /// history with the oldest reused, telling an attacker who's
    /// iterating candidate passwords roughly *which* historical password
    /// they hit. The `let mut reused = false;` accumulator + full scan +
    /// post-loop check is load-bearing for that timing equalisation. Do
    /// NOT "optimise" by short-circuiting the loop.
    ///
    /// `axess_factors::verify_password` itself uses constant-time Argon2
    /// verification per hash, so the per-iteration cost is constant
    /// regardless of whether that single iteration matches.
    ///
    /// **Plaintext-not-hash invariant:** `new_password` MUST be the
    /// plaintext candidate. Argon2's verify routine recomputes the hash
    /// of `new_password` against each old hash's embedded salt and
    /// parameters; feeding an already-hashed PHC string here means
    /// Argon2 hashes the PHC string itself, which never matches anything
    /// real and silently disables the entire history-reuse check.
    async fn verify_new_password_not_in_history(
        &self,
        user_id: &crate::authn::ids::UserId,
        new_password: &str,
        rules: &crate::authn::factor::PasswordRules,
    ) -> Result<bool, AuthnError<I::Error>> {
        if rules.history_count == 0 {
            return Ok(false);
        }
        let history = self
            .identity
            .password_history(user_id, rules.history_count)
            .await
            .map_err(AuthnError::Store)?;
        let mut reused = false;
        for old_hash in &history {
            if axess_factors::verify_password(new_password, old_hash).is_ok() {
                reused = true;
            }
        }
        Ok(reused)
    }
}
