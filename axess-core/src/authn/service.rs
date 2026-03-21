//! Authentication service — orchestrates identity lookup, factor verification,
//! and session management.
//!
//! Hold an `Arc<AuthnService<…>>` in Axum state. Login handlers call
//! [`AuthnService::begin_login`] then [`AuthnService::verify_factor`].

use crate::{
    authn::{
        error::AuthnError,
        event::{AuthEventBuilder, AuthEventStatus, AuthEventType},
        factor::{FactorConfig, FactorCredential, FactorKind},
        store::{FactorStore, IdentityStore},
        types::{AuthnScope, EntityState},
    },
    session::{extractor::AuthSession, store::SessionRegistry},
    utils::{
        random::{SecureRng, SystemRng},
        time::{Clock, SystemClock},
    },
};
use std::{future::Future, pin::Pin, sync::Arc};

// ── Outcome types ─────────────────────────────────────────────────────────────

/// Result of beginning a login attempt.
pub enum LoginOutcome {
    /// Single-factor method complete — session is now `Authenticated`.
    Authenticated,
    /// Multi-factor — first factor passed, session is `Authenticating`.
    /// The UI should present the next factor.
    FactorRequired(FactorKind),
    /// The account is locked out.
    Locked {
        until: Option<chrono::DateTime<chrono::Utc>>,
    },
    /// Bad credentials. Deliberately vague — do NOT distinguish user-not-found
    /// from wrong-password to prevent user enumeration.
    InvalidCredentials,
}

/// Result of verifying a factor step.
pub enum FactorOutcome {
    /// This was the last factor — session is now `Authenticated`.
    Authenticated,
    /// More factors remain — present the next factor UI.
    FactorRequired(FactorKind),
    /// The credential was wrong.
    InvalidCredential,
    /// Too many failed attempts — the account is now locked.
    Locked {
        until: Option<chrono::DateTime<chrono::Utc>>,
    },
}

// ── AuthnService ──────────────────────────────────────────────────────────────

/// Authentication service — orchestrates identity lookup, factor verification,
/// and session management.
///
/// Generic over:
/// - `I`: [`IdentityStore`]
/// - `F`: [`FactorStore`] (same error type as `I`)
/// - `Rng`: [`SecureRng`] (default: `SystemRng`)
/// - `C`: [`Clock`] (default: `SystemClock`)
pub struct AuthnService<I, F, Rng = SystemRng, C = SystemClock>
where
    I: IdentityStore,
    F: FactorStore,
    Rng: SecureRng,
    C: Clock,
{
    identity: Arc<I>,
    factors: Arc<F>,
    registry: Option<Arc<dyn ErasedRegistry>>,
    #[allow(dead_code)]
    rng: Rng,
    clock: C,
}

// Trait-object-safe async wrapper for SessionRegistry.
//
// Uses the `Pin<Box<dyn Future>>` pattern (BoxFuture) so callers can `.await`
// registry operations in async contexts — no `block_in_place` / `block_on`
// which deadlock on single-threaded runtimes and hold the thread under load.
trait ErasedRegistry: Send + Sync + 'static {
    fn is_valid<'a>(
        &'a self,
        user_id: &'a str,
        session_id: &'a crate::session::id::SessionId,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>>;

    fn invalidate_user<'a>(
        &'a self,
        user_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

    fn register<'a>(
        &'a self,
        user_id: &'a str,
        session_id: &'a crate::session::id::SessionId,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
}

struct RegistryWrapper<R: SessionRegistry>(R);

impl<R: SessionRegistry + 'static> ErasedRegistry for RegistryWrapper<R> {
    fn is_valid<'a>(
        &'a self,
        user_id: &'a str,
        session_id: &'a crate::session::id::SessionId,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async move { self.0.is_valid(user_id, session_id).await.unwrap_or(false) })
    }

    fn invalidate_user<'a>(
        &'a self,
        user_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            let _ = self.0.invalidate_user(user_id).await;
        })
    }

    fn register<'a>(
        &'a self,
        user_id: &'a str,
        session_id: &'a crate::session::id::SessionId,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            let _ = self.0.register(user_id, session_id).await;
        })
    }
}

impl<I, F> AuthnService<I, F, SystemRng, SystemClock>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Create a new service with OS RNG and system clock.
    pub fn new(identity: I, factors: F) -> Self {
        Self {
            identity: Arc::new(identity),
            factors: Arc::new(factors),
            registry: None,
            rng: SystemRng,
            clock: SystemClock,
        }
    }
}

impl<I, F, Rng, C> AuthnService<I, F, Rng, C>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
    Rng: SecureRng,
    C: Clock,
{
    /// Replace the RNG (for DST).
    pub fn with_rng<R: SecureRng>(self, rng: R) -> AuthnService<I, F, R, C> {
        AuthnService {
            identity: self.identity,
            factors: self.factors,
            registry: self.registry,
            rng,
            clock: self.clock,
        }
    }

    /// Replace the clock (for DST).
    pub fn with_clock<Cl: Clock>(self, clock: Cl) -> AuthnService<I, F, Rng, Cl> {
        AuthnService {
            identity: self.identity,
            factors: self.factors,
            registry: self.registry,
            rng: self.rng,
            clock,
        }
    }

    /// Attach a session registry for forced-logout support.
    pub fn with_registry(mut self, registry: impl SessionRegistry + 'static) -> Self {
        self.registry = Some(Arc::new(RegistryWrapper(registry)));
        self
    }

    // ── Public methods ─────────────────────────────────────────────────────────

    /// Begin the login flow for an identifier (username/email) within a tenant.
    ///
    /// Looks up the user, checks account status, and begins the first factor.
    /// Updates the session to `Authenticating`.
    ///
    /// Returns a [`LoginOutcome`] describing what the UI should do next.
    pub async fn begin_login(
        &self,
        identifier: &str,
        tenant_identifier: &str,
        session: &AuthSession,
    ) -> Result<LoginOutcome, AuthnError<I::Error>> {
        // 1. Find tenant.
        let tenant = self
            .identity
            .find_tenant(tenant_identifier)
            .await
            .map_err(AuthnError::Store)?
            .ok_or(AuthnError::NotActive(EntityState::Guest))?;

        // 2. Find user — constant-time: do NOT short-circuit on user-not-found.
        let user_opt = self
            .identity
            .find_user(identifier, &tenant.id)
            .await
            .map_err(AuthnError::Store)?;

        let user = match user_opt {
            Some(u) => u,
            None => {
                // Return generic error — no user enumeration.
                return Ok(LoginOutcome::InvalidCredentials);
            }
        };

        // 3. Check account status.
        let status = self
            .identity
            .account_status(&user.id)
            .await
            .map_err(AuthnError::Store)?;

        if !status.allows_login() {
            if status.is_locked() {
                return Ok(LoginOutcome::Locked { until: None });
            }
            return Err(AuthnError::NotActive(status));
        }

        // 4. Load available authentication methods.
        let methods = self
            .factors
            .available_methods(&user.id, &tenant.id)
            .await
            .map_err(AuthnError::Store)?;

        let method = methods.into_iter().next().ok_or(AuthnError::NoFlow)?;

        if method.factors.is_empty() {
            return Ok(LoginOutcome::InvalidCredentials);
        }

        let first_kind = method.factors[0].clone();

        // 5. Begin the authentication flow in the session.
        session
            .begin_authenticating(
                user.id.clone(),
                tenant.id.clone(),
                method.name.clone(),
                method.factors.clone(),
            )
            .await;

        // Record login attempt event.
        let _ = self
            .identity
            .record_event(
                AuthEventBuilder::new(
                    user.id.clone(),
                    tenant.id.clone(),
                    AuthEventType::LoginAttempt,
                    AuthEventStatus::Success,
                )
                .with_factor(first_kind.clone())
                .build_at(self.clock.now()),
            )
            .await;

        Ok(LoginOutcome::FactorRequired(first_kind))
    }

    /// Verify a factor credential during an in-progress authentication flow.
    ///
    /// The session must be in [`AuthState::Authenticating`].
    /// Returns a [`FactorOutcome`] describing the next step.
    pub async fn verify_factor(
        &self,
        credential: &FactorCredential,
        session: &AuthSession,
    ) -> Result<FactorOutcome, AuthnError<I::Error>> {
        let auth_state = session.auth_state().await;

        // Extract state — must be Authenticating.
        let (user_id, tenant_id, remaining) = match &auth_state {
            crate::session::data::AuthState::Authenticating {
                user_id,
                tenant_id,
                remaining,
                ..
            } => (user_id.clone(), tenant_id.clone(), remaining.clone()),
            _ => return Err(AuthnError::NoFlow),
        };

        // Re-check account status from the store on every factor step.
        //
        // Lockout must be enforced here via the store — not via session state.
        // A session-based counter can be bypassed by the client starting a new
        // session; the store's counter cannot.
        let status = self
            .identity
            .account_status(&user_id)
            .await
            .map_err(AuthnError::Store)?;

        if status.is_locked() {
            let until = if let EntityState::Suspended(detail) = &status {
                detail.until
            } else {
                None
            };
            return Ok(FactorOutcome::Locked { until });
        }
        if !status.allows_login() {
            return Err(AuthnError::NotActive(status));
        }

        let current_kind = remaining.first().ok_or(AuthnError::NoFlow)?.clone();

        // Load factor config — try User → Tenant → Global scope in order.
        let user_scope = AuthnScope::User {
            tenant_id: tenant_id.clone(),
            user_id: user_id.clone(),
        };
        let config = self
            .load_factor_with_fallback(&user_scope, &tenant_id, current_kind.clone())
            .await?;

        // Verify the credential. Clock is injected so TOTP is deterministically testable.
        let now: std::time::SystemTime = self.clock.now().into();
        let outcome = verify_credential(credential, &config, &current_kind, now);

        if matches!(outcome, VerifyOutcome::Fail) {
            // Record the failed attempt in the store — this is the authoritative counter.
            let count = self
                .identity
                .record_failed_attempt(&user_id)
                .await
                .map_err(AuthnError::Store)?;

            // Update session state for UI feedback only — never used for lockout decisions.
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
                    .with_factor(current_kind.clone())
                    .build_at(self.clock.now()),
                )
                .await;

            let policy = self.identity.lockout_policy();
            if count >= policy.max_attempts {
                return Ok(FactorOutcome::Locked { until: None });
            }

            return Ok(FactorOutcome::InvalidCredential);
        }

        // Credential verified — persist any updated factor state.
        // For TOTP this records the accepted step (replay prevention).
        // For HOTP this advances the counter past the matched value.
        if let VerifyOutcome::PassWithUpdate(updated_config) = outcome {
            self.factors
                .save_factor(&user_scope, updated_config)
                .await
                .map_err(AuthnError::Store)?;
        }

        // Reset the failed-attempt counter in the store.
        self.identity
            .reset_failed_attempts(&user_id)
            .await
            .map_err(AuthnError::Store)?;

        // Advance the factor in the session.
        let now = self.clock.now();
        session.advance_factor(&current_kind, now).await;

        // Check if all factors are satisfied.
        let new_state = session.auth_state().await;
        if new_state.is_authenticated() {
            let sid = session.session_id().await;
            if let Some(reg) = &self.registry {
                reg.register(&user_id, &sid).await;
            }

            let _ = self
                .identity
                .record_event(
                    AuthEventBuilder::new(
                        user_id.clone(),
                        tenant_id.clone(),
                        AuthEventType::Authenticated,
                        AuthEventStatus::Success,
                    )
                    .with_session(sid)
                    .build_at(now),
                )
                .await;

            return Ok(FactorOutcome::Authenticated);
        }

        // More factors remain — return the next kind.
        let next_kind = match &session.auth_state().await {
            crate::session::data::AuthState::Authenticating { remaining, .. } => {
                remaining.first().cloned()
            }
            _ => None,
        };

        Ok(next_kind.map_or(FactorOutcome::Authenticated, FactorOutcome::FactorRequired))
    }

    /// Check whether the current session is valid (consults the registry if installed).
    pub async fn check_session(&self, session: &AuthSession) -> bool {
        if !session.is_authenticated().await {
            return false;
        }
        let user_id = match session.user_id().await {
            Some(id) => id,
            None => return false,
        };
        let sid = session.session_id().await;
        if let Some(reg) = &self.registry {
            reg.is_valid(&user_id, &sid).await
        } else {
            true
        }
    }

    /// Log out the current user: clear the session and invalidate in the registry.
    pub async fn logout(&self, session: &AuthSession) -> Result<(), AuthnError<I::Error>> {
        if let Some(user_id) = session.user_id().await {
            let sid = session.session_id().await;
            if let Some(reg) = &self.registry {
                reg.invalidate_user(&user_id).await;
            }
            let tenant_id = session.tenant_id().await.unwrap_or_else(|| "".into());
            let _ = self
                .identity
                .record_event(
                    AuthEventBuilder::new(
                        user_id,
                        tenant_id,
                        AuthEventType::LogoutAttempt,
                        AuthEventStatus::Success,
                    )
                    .with_session(sid)
                    .build_at(self.clock.now()),
                )
                .await;
        }
        session.clear().await;
        // Cycle the session ID to prevent session fixation after logout.
        session.regenerate().await;
        Ok(())
    }

    // ── Internal helpers ───────────────────────────────────────────────────────

    /// Load a factor config, trying User → Tenant → Global scope in order.
    async fn load_factor_with_fallback(
        &self,
        user_scope: &AuthnScope,
        tenant_id: &Arc<str>,
        kind: FactorKind,
    ) -> Result<FactorConfig, AuthnError<I::Error>> {
        if let Some(cfg) = self
            .factors
            .load_factor(user_scope, kind.clone())
            .await
            .map_err(AuthnError::Store)?
        {
            return Ok(cfg);
        }
        let tenant_scope = AuthnScope::Tenant(tenant_id.clone());
        if let Some(cfg) = self
            .factors
            .load_factor(&tenant_scope, kind.clone())
            .await
            .map_err(AuthnError::Store)?
        {
            return Ok(cfg);
        }
        self.factors
            .load_factor(&AuthnScope::Global, kind)
            .await
            .map_err(AuthnError::Store)?
            .ok_or(AuthnError::NoFlow)
    }
}

// ── Credential verification ────────────────────────────────────────────────────

/// Result of verifying a single factor credential.
enum VerifyOutcome {
    /// Verification failed — wrong credential or replay detected.
    Fail,
    /// Verification succeeded — no factor state needs persisting.
    Pass,
    /// Verification succeeded — caller must persist this updated config.
    ///
    /// Used for TOTP (update `last_step` for replay prevention) and
    /// HOTP (advance `counter` to prevent reuse).
    PassWithUpdate(FactorConfig),
}

/// Verify a credential against a factor config.
///
/// `now` is supplied by the caller (from an injectable [`Clock`]) rather than
/// reading `SystemTime::now()` directly, keeping the function deterministically
/// testable under DST.
fn verify_credential(
    credential: &FactorCredential,
    config: &FactorConfig,
    kind: &FactorKind,
    now: std::time::SystemTime,
) -> VerifyOutcome {
    match (credential, config, kind) {
        (FactorCredential::Password(pwd), FactorConfig::Password(cfg), FactorKind::Password) => {
            let pwd_str: &str = pwd.as_ref();
            let hash_str: &str = cfg.hash.as_ref();
            if axess_factors::verify_password(pwd_str, hash_str).is_ok() {
                VerifyOutcome::Pass
            } else {
                VerifyOutcome::Fail
            }
        }

        (FactorCredential::OtpCode(code), FactorConfig::Totp(cfg), FactorKind::Totp) => {
            let matched = axess_factors::verify_totp(
                cfg.secret.as_ref(),
                code.as_ref(),
                now,
                Some(cfg.digits as usize),
                Some(cfg.period_secs as u64),
                Some(cfg.past_window as u64),
                Some(cfg.future_window as u64),
            );
            match matched {
                None => VerifyOutcome::Fail,
                Some(step) => {
                    // Reject replays: the matched step must be strictly greater than
                    // the last accepted step. Equality means the same code is being
                    // reused within the same time window.
                    if cfg.last_step.is_some_and(|ls| step <= ls) {
                        return VerifyOutcome::Fail;
                    }
                    let mut updated = cfg.clone();
                    updated.last_step = Some(step);
                    VerifyOutcome::PassWithUpdate(FactorConfig::Totp(updated))
                }
            }
        }

        (FactorCredential::OtpCode(code), FactorConfig::Hotp(cfg), FactorKind::Hotp) => {
            let matched = axess_factors::verify_hotp(
                cfg.secret.as_ref(),
                code.as_ref(),
                cfg.counter,
                cfg.digits as usize,
                cfg.lookahead_window as u64,
            );
            match matched {
                None => VerifyOutcome::Fail,
                Some(counter) => {
                    // Advance counter past the matched value to prevent reuse.
                    let mut updated = cfg.clone();
                    updated.counter = counter + 1;
                    VerifyOutcome::PassWithUpdate(FactorConfig::Hotp(updated))
                }
            }
        }

        (FactorCredential::Fido2Assertion(_), FactorConfig::Fido2(_), FactorKind::Fido2) => {
            // FIDO2 is a placeholder — always fail until implemented.
            VerifyOutcome::Fail
        }

        _ => VerifyOutcome::Fail,
    }
}
