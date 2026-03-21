//! Authentication service — orchestrates identity lookup, factor verification,
//! and session management.
//!
//! Hold an `Arc<AuthnService<…>>` in Axum state. The login flow is:
//!
//! 1. [`AuthnService::begin_login`] — identifies the user, starts the MFA chain.
//! 2. [`AuthnService::prepare_factor`] — for challenge-based factors (EmailOtp),
//!    generates and stores the challenge, returns data for the app to deliver.
//!    For simple factors (Password, TOTP, HOTP), returns `Ready` immediately.
//! 3. [`AuthnService::verify_factor`] — verifies the credential the user submits.
//!
//! # Enforcing session validity on protected routes
//!
//! The [`login_required!`] macro checks `is_authenticated()` on the session
//! state, but does **not** consult the session registry. If you use
//! [`AuthnService::with_registry`] for forced-logout support, you should add
//! a middleware layer that calls [`AuthnService::check_session`]:
//!
//! ```rust,ignore
//! use axess::{AuthSession, AuthnService};
//! use axum::{middleware::from_fn, response::IntoResponse, http::StatusCode};
//!
//! let authn: Arc<AuthnService<_, _, _, _>> = /* … */;
//!
//! let app = Router::new()
//!     .route("/api/protected", get(my_handler))
//!     .layer(from_fn(move |session: AuthSession, req, next: axum::middleware::Next| {
//!         let authn = authn.clone();
//!         async move {
//!             if !authn.check_session(&session).await {
//!                 return StatusCode::UNAUTHORIZED.into_response();
//!             }
//!             next.run(req).await
//!         }
//!     }));
//! ```
//!
//! This gives full control over which routes enforce registry checks and what
//! the rejection response looks like, without adding any new types to the library.

use crate::{
    authn::{
        error::AuthnError,
        event::{AuthEventBuilder, AuthEventStatus, AuthEventType},
        factor::{FactorConfig, FactorCredential, FactorKind},
        store::{FactorStore, IdentityStore},
        types::{AuthnScope, EntityState, StatusDetail},
    },
    session::{
        data::{WorkflowKind, WorkflowState},
        extractor::AuthSession,
        store::SessionRegistry,
    },
    utils::{
        random::{SecureRng, SystemRng},
        time::{Clock, SystemClock},
    },
};
use std::{future::Future, pin::Pin, sync::Arc};

// ── Outcome types ─────────────────────────────────────────────────────────────

/// Result of beginning a login attempt.
#[derive(Debug)]
pub enum LoginOutcome {
    /// The first factor is required — session is now `Authenticating`.
    /// Call `prepare_factor` then present the factor UI.
    FactorRequired(FactorKind),
    /// The account is locked out.
    Locked {
        until: Option<chrono::DateTime<chrono::Utc>>,
    },
    /// Bad credentials. Deliberately vague — do NOT distinguish user-not-found
    /// from wrong-password to prevent user enumeration.
    InvalidCredentials,
}

/// Result of preparing a factor challenge.
///
/// Returned by [`AuthnService::prepare_factor`]. Challenge-based factors
/// (EmailOtp, Fido2) return data the application must act on — e.g. sending
/// an email or forwarding a WebAuthn challenge to the browser. Simple factors
/// (Password, TOTP, HOTP) are always [`Ready`](PrepareOutcome::Ready).
pub enum PrepareOutcome {
    /// No preparation needed — the UI can present the input form immediately.
    Ready,
    /// An OTP code was generated and stored. The application must deliver it
    /// to the user via the indicated channel (email address).
    ///
    /// The `code` is plaintext — the hashed version is already persisted in the
    /// factor store. After delivery, the application calls `verify_factor` with
    /// the code the user enters.
    SendOtp {
        /// The plaintext OTP code to deliver.
        code: String,
        /// Where to send it (email address for EmailOtp).
        destination: Arc<str>,
    },
    /// A challenge was already sent and hasn't expired yet (cooldown active).
    /// The application should show a "code already sent" message rather than
    /// sending a new one.
    AlreadySent {
        /// Where the code was sent (email address for EmailOtp).
        destination: Arc<str>,
    },
    /// A FIDO2/WebAuthn challenge was generated (placeholder for future use).
    Fido2Challenge {
        /// Opaque challenge data to forward to the browser's WebAuthn API.
        challenge: serde_json::Value,
    },
}

impl std::fmt::Debug for PrepareOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ready => write!(f, "Ready"),
            Self::SendOtp { destination, .. } => f
                .debug_struct("SendOtp")
                .field("code", &"***")
                .field("destination", destination)
                .finish(),
            Self::AlreadySent { destination } => f
                .debug_struct("AlreadySent")
                .field("destination", destination)
                .finish(),
            Self::Fido2Challenge { .. } => f.debug_struct("Fido2Challenge").finish_non_exhaustive(),
        }
    }
}

/// Result of verifying a factor step.
#[derive(Debug)]
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

/// Result of beginning a signup flow.
#[derive(Debug)]
pub enum SignupOutcome {
    /// User account created, session moved to `PendingWorkflow(Signup)`.
    /// The application should now send a verification email or similar.
    Started,
    /// A user with this identifier already exists in the tenant.
    AlreadyExists,
    /// The target tenant does not exist or is not active.
    TenantNotActive,
}

// ── AuthnService ──────────────────────────────────────────────────────────────

/// Authentication service — orchestrates identity lookup, factor verification,
/// and session management.
///
/// Generic over:
/// - `I`: [`IdentityStore`]
/// - `F`: [`FactorStore`] (same error type as `I`)
/// - `R`: [`SecureRng`] (default: `SystemRng`)
/// - `C`: [`Clock`] (default: `SystemClock`)
pub struct AuthnService<I, F, R = SystemRng, C = SystemClock>
where
    I: IdentityStore,
    F: FactorStore,
    R: SecureRng,
    C: Clock,
{
    identity: Arc<I>,
    factors: Arc<F>,
    registry: Option<Arc<dyn RegistryHandle>>,
    rng: R,
    clock: C,
    #[cfg(feature = "fido2")]
    fido2: Option<Arc<dyn crate::authn::fido2::Fido2Provider>>,
    #[cfg(feature = "fido2")]
    fido2_options: crate::authn::factor::Fido2Options,
    #[cfg(feature = "oauth")]
    oauth_providers: crate::authn::oauth::OAuthProviderRegistry,
}

// Trait-object-safe async wrapper for SessionRegistry.
//
// Uses the `Pin<Box<dyn Future>>` pattern (BoxFuture) so callers can `.await`
// registry operations in async contexts — no `block_in_place` / `block_on`
// which deadlock on single-threaded runtimes and hold the thread under load.
trait RegistryHandle: Send + Sync + 'static {
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

struct RegistryWrapper<T: SessionRegistry>(T);

impl<T: SessionRegistry + 'static> RegistryHandle for RegistryWrapper<T> {
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
            #[cfg(feature = "fido2")]
            fido2: None,
            #[cfg(feature = "fido2")]
            fido2_options: Default::default(),
            #[cfg(feature = "oauth")]
            oauth_providers: Default::default(),
        }
    }
}

impl<I, F, R, C> AuthnService<I, F, R, C>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
    R: SecureRng,
    C: Clock,
{
    /// Replace the RNG (for DST).
    pub fn with_rng<R2: SecureRng>(self, rng: R2) -> AuthnService<I, F, R2, C> {
        AuthnService {
            identity: self.identity,
            factors: self.factors,
            registry: self.registry,
            rng,
            clock: self.clock,
            #[cfg(feature = "fido2")]
            fido2: self.fido2,
            #[cfg(feature = "fido2")]
            fido2_options: self.fido2_options,
            #[cfg(feature = "oauth")]
            oauth_providers: self.oauth_providers,
        }
    }

    /// Replace the clock (for DST).
    pub fn with_clock<Cl: Clock>(self, clock: Cl) -> AuthnService<I, F, R, Cl> {
        AuthnService {
            identity: self.identity,
            factors: self.factors,
            registry: self.registry,
            rng: self.rng,
            clock,
            #[cfg(feature = "fido2")]
            fido2: self.fido2,
            #[cfg(feature = "fido2")]
            fido2_options: self.fido2_options,
            #[cfg(feature = "oauth")]
            oauth_providers: self.oauth_providers,
        }
    }

    /// Attach a FIDO2/WebAuthn provider.
    ///
    /// Use [`DefaultFido2Provider`](crate::authn::fido2::DefaultFido2Provider)
    /// for production or [`MockFido2Provider`](crate::authn::fido2::MockFido2Provider)
    /// for testing.
    ///
    /// ```rust,ignore
    /// use axess::authn::fido2::DefaultFido2Provider;
    /// use axess::authn::factor::Fido2Options;
    ///
    /// let provider = DefaultFido2Provider::new(
    ///     "example.com",
    ///     &url::Url::parse("https://example.com")?,
    ///     Fido2Options::default(),
    /// )?;
    /// let authn = AuthnService::new(identity, factors).with_fido2(provider);
    /// ```
    #[cfg(feature = "fido2")]
    pub fn with_fido2(mut self, provider: impl crate::authn::fido2::Fido2Provider) -> Self {
        self.fido2 = Some(Arc::new(provider));
        self
    }

    /// Configure FIDO2 ceremony timeout and other options stored on the service.
    ///
    /// The UV policy, attestation, and authenticator attachment are configured
    /// on the [`Fido2Provider`](crate::authn::fido2::Fido2Provider) itself
    /// (via [`Fido2Options`](crate::authn::factor::Fido2Options) on
    /// [`DefaultFido2Provider`](crate::authn::fido2::DefaultFido2Provider)).
    /// This method controls the ceremony timeout applied at the service level.
    #[cfg(feature = "fido2")]
    pub fn with_fido2_options(mut self, options: crate::authn::factor::Fido2Options) -> Self {
        self.fido2_options = options;
        self
    }

    /// Register an OAuth/OIDC identity provider.
    ///
    /// Call once per provider at startup. Multiple providers can be registered
    /// (e.g. Google + GitHub + corporate IdP).
    ///
    /// ```rust,ignore
    /// let google = OAuthProviderConfig::discover(
    ///     "google", "https://accounts.google.com",
    ///     "client-id", "client-secret", "https://app.com/auth/callback/google",
    /// ).await?;
    /// let authn = AuthnService::new(identity, factors).with_oauth_provider(google);
    /// ```
    #[cfg(feature = "oauth")]
    pub fn with_oauth_provider(mut self, config: crate::authn::oauth::OAuthProviderConfig) -> Self {
        self.oauth_providers.add(config);
        self
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
        use crate::utils::validation::MAX_IDENTIFIER_BYTES;

        // 0. Reject oversized identifiers before hitting the database.
        if identifier.is_empty()
            || identifier.len() > MAX_IDENTIFIER_BYTES
            || tenant_identifier.is_empty()
            || tenant_identifier.len() > MAX_IDENTIFIER_BYTES
        {
            return Ok(LoginOutcome::InvalidCredentials);
        }

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
                // Two-step MFA flows (identify → verify) inherently reveal
                // whether an identifier maps to a valid account — the response
                // must differ so the UI can show the correct next step.
                // This is the same trade-off Gmail, Microsoft, and most banks
                // accept. A dummy Argon2 hash is NOT used here because no
                // password is verified at this stage — it would create an
                // *inverted* timing channel (not-found slower than found).
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

    /// Prepare the current factor challenge, if the factor kind requires it.
    ///
    /// Call this after `begin_login` (or after a successful `verify_factor`
    /// that returns `FactorRequired`) to set up the next factor step.
    ///
    /// - **Password / TOTP / HOTP** → returns [`PrepareOutcome::Ready`].
    ///   The UI can show the input form immediately.
    /// - **EmailOtp** → generates a random code, hashes it with Argon2id,
    ///   persists it in the factor store, and returns
    ///   [`PrepareOutcome::SendOtp`] with the plaintext code and the
    ///   destination email. The application is responsible for delivering the
    ///   code (via SMTP, SendGrid, etc.).
    /// - **Fido2** → placeholder, currently returns `Ready`.
    ///
    /// The session must be in [`AuthState::Authenticating`].
    pub async fn prepare_factor(
        &self,
        session: &AuthSession,
    ) -> Result<PrepareOutcome, AuthnError<I::Error>> {
        let auth_state = session.auth_state().await;

        let (user_id, tenant_id, remaining) = match &auth_state {
            crate::session::data::AuthState::Authenticating {
                user_id,
                tenant_id,
                remaining,
                ..
            } => (user_id.clone(), tenant_id.clone(), remaining.clone()),
            _ => return Err(AuthnError::NoFlow),
        };

        // Check account status — a locked/suspended account must not trigger
        // challenge delivery (e.g. email sends).
        let status = self
            .identity
            .account_status(&user_id)
            .await
            .map_err(AuthnError::Store)?;

        if status.is_locked() {
            return Err(AuthnError::NotActive(status));
        }
        if !status.allows_login() {
            return Err(AuthnError::NotActive(status));
        }

        let current_kind = remaining.first().ok_or(AuthnError::NoFlow)?.clone();

        match current_kind {
            FactorKind::Password | FactorKind::Totp | FactorKind::Hotp => Ok(PrepareOutcome::Ready),

            FactorKind::EmailOtp => {
                // Load the EmailOtp config to get the destination and parameters.
                let user_scope = AuthnScope::User {
                    tenant_id: tenant_id.clone(),
                    user_id: user_id.clone(),
                };
                let config = self
                    .load_factor_with_fallback(&user_scope, &tenant_id, FactorKind::EmailOtp)
                    .await?;

                let FactorConfig::EmailOtp(ref cfg) = config else {
                    return Err(AuthnError::NoFlow);
                };

                // Cooldown: reject if a pending code hasn't expired yet.
                // This prevents email bombing — the application can only trigger
                // one send per TTL window.
                let now = self.clock.now();
                if cfg.pending_until.is_some_and(|until| now < until) {
                    return Ok(PrepareOutcome::AlreadySent {
                        destination: cfg.email.clone(),
                    });
                }

                let email = cfg.email.clone();
                let code_length = cfg.code_length as usize;
                let ttl_secs = cfg.ttl_secs;

                // Generate a random numeric code using the injectable RNG.
                let mut rng = self.rng.clone();
                let code = generate_otp_code(&mut rng, code_length);

                // Hash the code with Argon2id for storage.
                let hash = axess_factors::generate_password_hash(&code);

                // Compute expiry from config TTL.
                let expires = now + chrono::Duration::seconds(ttl_secs as i64);

                // Build the updated config with the pending hash.
                let FactorConfig::EmailOtp(mut updated_cfg) = config else {
                    unreachable!();
                };
                updated_cfg.pending_hash = Some(crate::authn::factor::ZeroizedString::new(hash));
                updated_cfg.pending_until = Some(expires);

                // Save to user scope (per-user pending state).
                self.factors
                    .save_factor(&user_scope, FactorConfig::EmailOtp(updated_cfg))
                    .await
                    .map_err(AuthnError::Store)?;

                Ok(PrepareOutcome::SendOtp {
                    code,
                    destination: email,
                })
            }

            FactorKind::Fido2 => {
                #[cfg(feature = "fido2")]
                {
                    let webauthn = match &self.fido2 {
                        Some(w) => w,
                        None => return Ok(PrepareOutcome::Ready),
                    };

                    // Load stored credentials.
                    let user_scope = AuthnScope::User {
                        tenant_id: tenant_id.clone(),
                        user_id: user_id.clone(),
                    };
                    let config = self
                        .load_factor_with_fallback(&user_scope, &tenant_id, FactorKind::Fido2)
                        .await?;

                    let FactorConfig::Fido2(cfg) = &config else {
                        return Err(AuthnError::NoFlow);
                    };

                    if cfg.credentials.is_empty() {
                        return Err(AuthnError::NoFlow);
                    }

                    // Extract raw passkeys for the ceremony.
                    let passkeys: Vec<_> =
                        cfg.credentials.iter().map(|c| c.passkey.clone()).collect();

                    // Start the authentication ceremony.
                    let (challenge, auth_state) =
                        webauthn.start_authentication(&passkeys).map_err(|e| {
                            tracing::warn!("FIDO2 start_passkey_authentication failed: {e:?}");
                            AuthnError::NoFlow
                        })?;

                    // Store the ceremony state and timestamp in the session.
                    let state_json =
                        serde_json::to_value(&auth_state).map_err(|_| AuthnError::NoFlow)?;
                    session.set_custom(fido2_keys::AUTH_STATE, state_json).await;
                    self.stamp_ceremony_start(session).await;

                    let challenge_json =
                        serde_json::to_value(&challenge).map_err(|_| AuthnError::NoFlow)?;
                    Ok(PrepareOutcome::Fido2Challenge {
                        challenge: challenge_json,
                    })
                }

                #[cfg(not(feature = "fido2"))]
                {
                    Ok(PrepareOutcome::Ready)
                }
            }

            FactorKind::Federated(_) => {
                // Federated auth is handled externally (OAuth redirect flow).
                Ok(PrepareOutcome::Ready)
            }
        }
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

        // FIDO2 verification is handled separately because it needs:
        // (a) the Webauthn instance, (b) ceremony state from the session.
        #[cfg(feature = "fido2")]
        if current_kind == FactorKind::Fido2 {
            return self
                .verify_fido2_factor(
                    credential,
                    &config,
                    &user_scope,
                    &user_id,
                    &tenant_id,
                    session,
                )
                .await;
        }

        // Verify the credential. Clock is injected so TOTP/expiry are DST-testable.
        let now_utc = self.clock.now();
        let outcome = verify_credential(credential, &config, &current_kind, now_utc);

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
        //
        // The updated config is always saved to the user scope, even when the
        // original config was loaded from a tenant or global scope via fallback.
        // This is intentional: per-user mutable state (TOTP last_step, HOTP
        // counter) must be stored per-user, while the inherited template
        // (secret, digits, period) remains at the higher scope.
        if let VerifyOutcome::PassWithUpdate(updated_config) = outcome {
            self.factors
                .save_factor(&user_scope, updated_config)
                .await
                .map_err(AuthnError::Store)?;
        }

        // Advance the factor in the session.
        let now = self.clock.now();
        session.advance_factor(&current_kind, now).await;

        self.complete_factor_step(&user_id, &tenant_id, session)
            .await
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

    // ── Signup ─────────────────────────────────────────────────────────────────

    /// Begin a signup flow: create a new user and transition the session to
    /// [`PendingWorkflow(Signup)`](WorkflowKind::Signup).
    ///
    /// The user is created in whatever [`EntityState`] the caller provides
    /// (typically [`Candidate`](EntityState::Candidate)). The application
    /// is responsible for what happens next — typically sending a verification
    /// email and calling [`complete_signup`](Self::complete_signup) after the
    /// user confirms.
    ///
    /// `tenant_identifier` is the tenant slug/domain (looked up via
    /// [`IdentityStore::find_tenant`]).
    ///
    /// # Errors
    ///
    /// Returns [`AuthnError::Store`] if the store operation fails.
    pub async fn begin_signup(
        &self,
        user: crate::authn::types::User,
        tenant_identifier: &str,
        session: &AuthSession,
    ) -> Result<SignupOutcome, AuthnError<I::Error>> {
        use crate::utils::validation::{
            MAX_DISPLAY_NAME_BYTES, MAX_IDENTIFIER_BYTES, is_printable,
        };

        // 0. Reject oversized or invalid inputs before hitting the database.
        if user.identifier.is_empty()
            || user.identifier.len() > MAX_IDENTIFIER_BYTES
            || user.display_name.len() > MAX_DISPLAY_NAME_BYTES
            || tenant_identifier.is_empty()
            || tenant_identifier.len() > MAX_IDENTIFIER_BYTES
            || !is_printable(&user.identifier)
            || !is_printable(&user.display_name)
        {
            return Err(AuthnError::InvalidAssertion);
        }

        // 1. Validate tenant exists and is active.
        let tenant = self
            .identity
            .find_tenant(tenant_identifier)
            .await
            .map_err(AuthnError::Store)?;

        let tenant = match tenant {
            Some(t) if t.status.is_active() => t,
            Some(_) => return Ok(SignupOutcome::TenantNotActive),
            None => return Ok(SignupOutcome::TenantNotActive),
        };

        // 2. Check if user already exists.
        let existing = self
            .identity
            .find_user(&user.identifier, &tenant.id)
            .await
            .map_err(AuthnError::Store)?;

        if existing.is_some() {
            return Ok(SignupOutcome::AlreadyExists);
        }

        // 3. Create the user.
        let user_id = user.id.clone();
        let tenant_id = tenant.id.clone();

        self.identity
            .create_user(user)
            .await
            .map_err(AuthnError::Store)?;

        // 4. Transition session to PendingWorkflow(Signup).
        let now = self.clock.now();
        let workflow = WorkflowState::new(WorkflowKind::Signup, 1, now);
        session
            .set_pending_workflow(user_id.clone(), tenant_id.clone(), workflow)
            .await;

        // 5. Record audit event.
        let _ = self
            .identity
            .record_event(
                AuthEventBuilder::new(
                    user_id,
                    tenant_id,
                    AuthEventType::SignupStarted,
                    AuthEventStatus::Success,
                )
                .build_at(now),
            )
            .await;

        Ok(SignupOutcome::Started)
    }

    /// Complete a signup flow: activate the user and transition the session
    /// to [`AuthState::Authenticated`].
    ///
    /// Call this after the user has completed whatever verification the
    /// application requires (e.g. email confirmation). The session must be
    /// in [`PendingWorkflow`](crate::session::data::AuthState::PendingWorkflow)
    /// state with a [`Signup`](WorkflowKind::Signup) workflow.
    pub async fn complete_signup(&self, session: &AuthSession) -> Result<(), AuthnError<I::Error>> {
        let state = session.auth_state().await;

        let (user_id, tenant_id) = match &state {
            crate::session::data::AuthState::PendingWorkflow {
                user_id,
                tenant_id,
                workflow,
            } if workflow.kind == WorkflowKind::Signup => (user_id.clone(), tenant_id.clone()),
            _ => return Err(AuthnError::NoFlow),
        };

        // Activate the user.
        self.identity
            .activate_user(&user_id)
            .await
            .map_err(AuthnError::Store)?;

        // Transition to Authenticated.
        let now = self.clock.now();
        session
            .set_authenticated(user_id.clone(), tenant_id.clone(), now)
            .await;

        // Register in session registry if configured.
        let sid = session.session_id().await;
        if let Some(reg) = &self.registry {
            reg.register(&user_id, &sid).await;
        }

        // Record audit event.
        let _ = self
            .identity
            .record_event(
                AuthEventBuilder::new(
                    user_id,
                    tenant_id,
                    AuthEventType::SignupCompleted,
                    AuthEventStatus::Success,
                )
                .with_session(sid)
                .build_at(now),
            )
            .await;

        Ok(())
    }

    /// Suspend a user account.
    ///
    /// This updates the user's status in the identity store. It does **not**
    /// invalidate existing sessions — use [`SessionRegistry::invalidate_user`]
    /// or a middleware that checks [`account_status`](IdentityStore::account_status)
    /// on each request.
    pub async fn suspend_user(
        &self,
        user_id: &str,
        detail: StatusDetail,
    ) -> Result<(), AuthnError<I::Error>> {
        let user = self
            .identity
            .get_user(user_id)
            .await
            .map_err(AuthnError::Store)?
            .ok_or(AuthnError::NoFlow)?;

        self.identity
            .suspend_user(user_id, detail)
            .await
            .map_err(AuthnError::Store)?;

        let _ = self
            .identity
            .record_event(
                AuthEventBuilder::new(
                    user.id.clone(),
                    user.tenant_id.clone(),
                    AuthEventType::AccountSuspended,
                    AuthEventStatus::Success,
                )
                .build_at(self.clock.now()),
            )
            .await;

        Ok(())
    }

    /// Activate a user account (e.g. unsuspend, or complete a manual review).
    ///
    /// Transitions the user to [`EntityState::Active`] regardless of current state.
    pub async fn activate_user(&self, user_id: &str) -> Result<(), AuthnError<I::Error>> {
        let user = self
            .identity
            .get_user(user_id)
            .await
            .map_err(AuthnError::Store)?
            .ok_or(AuthnError::NoFlow)?;

        self.identity
            .activate_user(user_id)
            .await
            .map_err(AuthnError::Store)?;

        let _ = self
            .identity
            .record_event(
                AuthEventBuilder::new(
                    user.id.clone(),
                    user.tenant_id.clone(),
                    AuthEventType::AccountActivated,
                    AuthEventStatus::Success,
                )
                .build_at(self.clock.now()),
            )
            .await;

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

    /// Shared post-factor-success logic: check if all factors are complete,
    /// and if so, reset the failed-attempt counter, register in the session
    /// registry, and emit an Authenticated audit event.
    ///
    /// Returns `FactorOutcome::Authenticated` or `FactorOutcome::FactorRequired(next)`.
    async fn complete_factor_step(
        &self,
        user_id: &Arc<str>,
        tenant_id: &Arc<str>,
        session: &AuthSession,
    ) -> Result<FactorOutcome, AuthnError<I::Error>> {
        let new_state = session.auth_state().await;
        if new_state.is_authenticated() {
            // Only reset the failed-attempt counter after ALL factors pass.
            self.identity
                .reset_failed_attempts(user_id)
                .await
                .map_err(AuthnError::Store)?;

            let sid = session.session_id().await;
            if let Some(reg) = &self.registry {
                reg.register(user_id, &sid).await;
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
                    .build_at(self.clock.now()),
                )
                .await;

            return Ok(FactorOutcome::Authenticated);
        }

        // More factors remain — return the next kind.
        let next_kind = match &new_state {
            crate::session::data::AuthState::Authenticating { remaining, .. } => {
                remaining.first().cloned()
            }
            _ => None,
        };

        Ok(next_kind.map_or(FactorOutcome::Authenticated, FactorOutcome::FactorRequired))
    }
}

// ── Feature-gated submodules ──────────────────────────────────────────────────
//
// FIDO2 and OAuth impl blocks live in their own files to keep mod.rs focused
// on the core authentication flow.

#[cfg(feature = "fido2")]
mod fido2_service;
#[cfg(feature = "fido2")]
pub(crate) use fido2_service::fido2_keys;

#[cfg(feature = "oauth")]
mod oauth_service;

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
/// reading `Utc::now()` directly, keeping the function deterministically
/// testable under DST. Converted to `SystemTime` only for the TOTP path
/// which requires it.
fn verify_credential(
    credential: &FactorCredential,
    config: &FactorConfig,
    kind: &FactorKind,
    now: chrono::DateTime<chrono::Utc>,
) -> VerifyOutcome {
    use crate::utils::validation::{MAX_OTP_CODE_BYTES, MAX_PASSWORD_BYTES};

    match (credential, config, kind) {
        (FactorCredential::Password(pwd), FactorConfig::Password(cfg), FactorKind::Password) => {
            let pwd_str: &str = pwd.as_ref();
            // Reject oversized passwords before Argon2 — prevents CPU DoS.
            if pwd_str.len() > MAX_PASSWORD_BYTES {
                return VerifyOutcome::Fail;
            }
            let hash_str: &str = cfg.hash.as_ref();
            if axess_factors::verify_password(pwd_str, hash_str).is_ok() {
                VerifyOutcome::Pass
            } else {
                VerifyOutcome::Fail
            }
        }

        (FactorCredential::OtpCode(code), FactorConfig::Totp(cfg), FactorKind::Totp) => {
            if code.as_ref().len() > MAX_OTP_CODE_BYTES {
                return VerifyOutcome::Fail;
            }
            let now_system: std::time::SystemTime = now.into();
            let matched = axess_factors::verify_totp(
                cfg.secret.as_ref(),
                code.as_ref(),
                now_system,
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
            if code.as_ref().len() > MAX_OTP_CODE_BYTES {
                return VerifyOutcome::Fail;
            }
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

        (FactorCredential::OtpCode(code), FactorConfig::EmailOtp(cfg), FactorKind::EmailOtp) => {
            // Reject oversized codes before Argon2 — prevents CPU DoS.
            if code.as_ref().len() > MAX_OTP_CODE_BYTES {
                return VerifyOutcome::Fail;
            }
            // Verify: pending hash must exist and code must not have expired.
            let hash = match &cfg.pending_hash {
                Some(h) => h,
                None => return VerifyOutcome::Fail,
            };

            // Check expiry using the injected clock time.
            if cfg.pending_until.is_some_and(|until| now > until) {
                return VerifyOutcome::Fail;
            }

            // Constant-time hash comparison via Argon2id verify.
            if axess_factors::verify_password(code.as_ref(), hash.as_ref()).is_err() {
                return VerifyOutcome::Fail;
            }

            // Clear the pending state to prevent reuse.
            let mut updated = cfg.clone();
            updated.pending_hash = None;
            updated.pending_until = None;
            VerifyOutcome::PassWithUpdate(FactorConfig::EmailOtp(updated))
        }

        (FactorCredential::Fido2Assertion(_), FactorConfig::Fido2(_), FactorKind::Fido2) => {
            // FIDO2 is a placeholder — always fail until implemented.
            VerifyOutcome::Fail
        }

        _ => VerifyOutcome::Fail,
    }
}

// ── OTP code generation ────────────────────────────────────────────────────────

/// Generate a random numeric OTP code of the given length using the injectable RNG.
///
/// Returns a zero-padded decimal string (e.g. `"042817"` for length 6).
fn generate_otp_code(rng: &mut impl SecureRng, length: usize) -> String {
    let modulus = 10u64.pow(length as u32);
    // Rejection sampling to eliminate modulo bias: discard values from the
    // partial final bucket that would skew the distribution.
    let max_fair = u64::MAX - (u64::MAX % modulus);
    loop {
        let mut bytes = [0u8; 8];
        rng.fill_bytes(&mut bytes);
        let value = u64::from_le_bytes(bytes);
        if value < max_fair {
            return format!("{:0>width$}", value % modulus, width = length);
        }
        // Extremely rare (~5.4e-14 probability per iteration for 6-digit codes).
    }
}
