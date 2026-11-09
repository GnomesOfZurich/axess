//! The builder that configures an [`AuthnService`] and is the collaborator set
//! its handles share.

use super::AuthnService;
use crate::{
    authn::store::{FactorStore, IdentityStore},
    session::store::{SessionRegistry, SessionRegistryAdapter, SessionRegistryHandle},
};
use axess_clock::{Clock, SystemClock};
use axess_rng::{SecureRng, SystemRng};
use std::sync::Arc;

pub use account_limits::{DEFAULT_CANDIDATE_TTL, DEFAULT_MAX_LIVE_RESET_TOKENS};
pub use hardening::DEFAULT_MAX_PASSWORD_RESET_TTL;

mod account_limits;
mod hardening;
pub(crate) use hardening::AccountHardening;
mod breached_password;
mod removers;
use removers::{RefreshStoreRevoker, RowRemover};
pub(crate) use removers::{SessionRowRemover, UserTokenRevoker};
#[cfg(feature = "oauth")]
mod duplicate_providers;
#[cfg(feature = "oauth")]
mod federation;

/// Configures an [`AuthnService`], and is what the built handle shares.
///
/// Customisation happens here rather than on the built service because the
/// collaborators sit behind an `Arc` the moment [`build`](Self::build) is
/// called, where every copy of the handle observes them. After `build` the
/// same value is the shared collaborator set, which is why the handle's
/// field is typed as this.
pub struct AuthnServiceBuilder<I, F>
where
    I: IdentityStore,
    F: FactorStore,
{
    pub(crate) identity: Arc<I>,
    pub(crate) factors: Arc<F>,
    pub(crate) registry: Option<Arc<dyn SessionRegistryHandle>>,
    pub(crate) metrics: crate::metrics::MetricSinks,
    /// Providers registered under a name that was already taken; reported
    /// to the provider-registry sink when the service is built.
    #[cfg(feature = "oauth")]
    pub(crate) duplicate_providers: u32,
    /// Maximum concurrent sessions per user. `None` means unlimited.
    pub(crate) max_sessions_per_user: Option<usize>,
    pub(crate) rng: Arc<dyn SecureRng>,
    pub(crate) clock: Arc<dyn Clock>,
    /// Where password hashing and verification run.
    pub(crate) kdf: Arc<crate::blocking::KdfExecutor>,
    /// Where refresh tokens are revoked when a user's credentials change.
    pub(crate) refresh_revoker: Option<Arc<dyn UserTokenRevoker>>,
    /// How long a half-finished login may sit before it is dropped.
    pub(crate) flow_ttl: std::time::Duration,
    /// Minimum time between password reset requests for one identifier.
    pub(crate) reset_cooldown: Option<std::time::Duration>,
    /// Identifiers inside their cooldown, built by `build` from
    /// [`reset_cooldown`](Self::reset_cooldown) on the service's clock.
    pub(crate) reset_requests: Option<Arc<super::reset_cooldown::ResetCooldowns>>,
    /// Whether `begin_signup` answers an identifier that is already taken
    /// with `AlreadyExists` rather than as it answers a free one (the
    /// default); see
    /// [`with_signup_conflicts_revealed`](Self::with_signup_conflicts_revealed).
    pub(crate) reveal_signup_conflicts: bool,
    /// How long the secret `begin_signup` mints completes the signup; see
    /// [`with_signup_verification_ttl`](Self::with_signup_verification_ttl).
    pub(crate) signup_verification_ttl: std::time::Duration,
    /// How long an unverified `Candidate` account holds its identifier; see
    /// [`with_candidate_ttl`](Self::with_candidate_ttl).
    pub(crate) candidate_ttl: std::time::Duration,
    /// See [`with_max_live_reset_tokens`](Self::with_max_live_reset_tokens).
    pub(crate) max_live_reset_tokens: usize,
    /// Whether an impersonated session may issue refresh tokens and enrol
    /// or delete factors; see
    /// [`with_impersonated_credential_changes_allowed`](Self::with_impersonated_credential_changes_allowed).
    pub(crate) impersonated_credential_changes: bool,
    /// Password hashing cost, password reset lifetime and cap, and the
    /// impersonation recency rule; see the setters in `hardening`.
    pub(crate) hardening: AccountHardening,
    /// Where a locked account's own devices are looked up; see
    /// [`with_device_store`](Self::with_device_store).
    #[cfg(feature = "device")]
    pub(crate) known_devices: Option<Arc<dyn super::known_device::KnownDevices>>,
    /// Whether `begin_login` answers a locked account with
    /// [`LoginOutcome::Locked`](crate::authn::service::LoginOutcome::Locked)
    /// rather than as it answers an unknown identifier (the default); see
    /// [`with_lockout_revealed_on_begin`](Self::with_lockout_revealed_on_begin).
    pub(crate) reveal_lockout_on_begin: bool,
    /// Custom session keys the application asked to carry across the
    /// transition to `Authenticated`; see
    /// [`with_preserved_custom_keys`](Self::with_preserved_custom_keys).
    pub(crate) preserved_custom_keys: Vec<String>,
    /// Set once the throttle has reported a request with no resolved client
    /// address because `client_ip::layer` is not installed, so the fault is
    /// logged once per service and not per guess.
    pub(crate) throttle_address_unknown_reported: std::sync::atomic::AtomicBool,
    /// The session store, when the application handed it over so that a
    /// revocation can delete the rows as well as the registry entries.
    pub(crate) session_rows: Option<Arc<dyn SessionRowRemover>>,
    /// The secrets keyed recovery codes are checked under, when configured:
    /// the current pepper and, during a rotation, the previous one.
    pub(crate) recovery_peppers: super::verification::RecoveryPeppers,
    /// The cipher OTP secrets are sealed and opened with, when configured.
    pub(crate) factor_secret_cipher: Option<Arc<crate::authn::factor_secret::FactorSecretCipher>>,
    /// Whether a one-time-code secret may be written without a cipher; see
    /// [`allow_plaintext_factor_secrets`](Self::allow_plaintext_factor_secrets).
    pub(crate) allow_plaintext_factor_secrets: bool,
    /// What every chosen password is screened against, when configured; see
    /// [`with_breached_password_check`](Self::with_breached_password_check).
    pub(crate) breached_password_check: Option<Arc<dyn axess_factors::BreachedPasswordCheck>>,
    /// What becomes of a chosen password when that check cannot answer;
    /// refuse unless
    /// [`allow_unchecked_when_breach_check_unavailable`](Self::allow_unchecked_when_breach_check_unavailable).
    pub(crate) on_breach_check_unavailable: axess_factors::BreachCheckUnavailable,
    /// Reload settings and the coordinator for live provider changes.
    #[cfg(any(feature = "oauth", feature = "fido2", feature = "ldap"))]
    pub(crate) provider_reload: super::provider_reload::ProviderReloadState,
    #[cfg(feature = "fido2")]
    pub(crate) fido2: arc_swap::ArcSwapOption<Arc<dyn axess_factors::fido2::Fido2Provider>>,
    #[cfg(feature = "fido2")]
    pub(crate) fido2_options: crate::authn::factor::Fido2Options,
    #[cfg(feature = "ldap")]
    pub(crate) ldap: arc_swap::ArcSwapOption<Arc<dyn axess_factors::ldap::LdapProvider>>,
    #[cfg(feature = "oauth")]
    pub(crate) oauth_providers: crate::federation::oauth::OAuthRegistrySlot,
    /// Per-tenant providers resolved at request time, when configured by
    /// [`with_tenant_oauth_providers`](AuthnServiceBuilder::with_tenant_oauth_providers).
    #[cfg(feature = "oauth")]
    pub(crate) tenant_oauth_providers:
        Option<Arc<dyn crate::federation::oauth_tenant::TenantOAuthProviders>>,
    /// Shared OIDC `sid` → `(user_id, session_id, inserted_at)` map for back-channel logout.
    /// The timestamp enables TTL-based eviction of stale entries.
    #[cfg(feature = "oauth")]
    pub(crate) sid_map: crate::federation::sid_map::SidMap,
    /// A store that replaces [`sid_map`](Self::sid_map) for the login path,
    /// set by [`with_sid_store`](AuthnServiceBuilder::with_sid_store).
    #[cfg(feature = "oauth")]
    pub(crate) sid_store: Option<Arc<dyn crate::federation::sid_store::SidStore>>,
    /// Capacity cap for [`sid_map`](Self::sid_map). When at/over this
    /// count, `maintain_oidc_sid_map` evicts a batch of oldest entries.
    /// High-throughput OAuth deployments raise this via
    /// [`with_sid_map_capacity`](AuthnServiceBuilder::with_sid_map_capacity); the
    /// default matches the historical hardcoded value.
    #[cfg(feature = "oauth")]
    pub(crate) sid_map_capacity: usize,
    /// Interval of the JWKS refresh loop started by `build`, if requested.
    #[cfg(feature = "oauth")]
    pub(crate) jwks_refresh_interval: Option<std::time::Duration>,
    /// The running refresh loop; aborted when the last handle to the service
    /// is dropped.
    #[cfg(feature = "oauth")]
    pub(crate) jwks_refresh_task: Option<super::oauth_service::JwksRefreshTask>,
}

/// The password reset cooldown a new builder starts with: a minute. Change it
/// with [`AuthnServiceBuilder::with_password_reset_cooldown`], remove it with
/// [`AuthnServiceBuilder::without_password_reset_cooldown`].
pub const DEFAULT_PASSWORD_RESET_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(60);

/// How many identifiers the password reset cooldown remembers.
pub const RESET_COOLDOWN_CAPACITY: usize = 100_000;

/// How long the secret `begin_signup` mints completes the signup, unless
/// [`with_signup_verification_ttl`](AuthnServiceBuilder::with_signup_verification_ttl)
/// says otherwise: 24 hours.
pub const DEFAULT_SIGNUP_VERIFICATION_TTL: std::time::Duration =
    std::time::Duration::from_secs(24 * 3600);

/// How long a login may sit between `begin_login` and its last factor before
/// the next step answers [`NoFlow`](crate::authn::error::AuthnError::NoFlow):
/// ten minutes. Change it with [`AuthnServiceBuilder::with_flow_ttl`].
pub const DEFAULT_FLOW_TTL: std::time::Duration = std::time::Duration::from_secs(10 * 60);

/// Default interval of the JWKS refresh loop the builder starts: one hour.
/// Well inside the 24 hour maximum age of a cached key set, so a few failed
/// refreshes in a row do not stop verification.
#[cfg(feature = "oauth")]
pub const DEFAULT_JWKS_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3600);

/// Default capacity cap for the OIDC `sid` → local-session map. High-throughput
/// OAuth deployments can override via
/// [`AuthnServiceBuilder::with_sid_map_capacity`].
#[cfg(feature = "oauth")]
pub const DEFAULT_SID_MAP_CAPACITY: usize = 10_000;

impl<I, F> AuthnServiceBuilder<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// The store the login path writes the `sid` mapping and subject record
    /// to: the one set with `with_sid_store`, else the in-process map.
    #[cfg(feature = "oauth")]
    pub(crate) fn sid_store(&self) -> Arc<dyn crate::federation::sid_store::SidStore> {
        match &self.sid_store {
            Some(store) => Arc::clone(store),
            None => Arc::new(self.sid_map.clone()),
        }
    }

    /// Start configuring a service. Finish with [`build`](Self::build).
    pub fn new(identity: I, factors: F) -> Self {
        Self {
            identity: Arc::new(identity),
            factors: Arc::new(factors),
            registry: None,
            metrics: crate::metrics::MetricSinks::noop(),
            #[cfg(feature = "oauth")]
            duplicate_providers: 0,
            max_sessions_per_user: None,
            rng: Arc::new(SystemRng),
            clock: Arc::new(SystemClock),
            kdf: Arc::new(crate::blocking::KdfExecutor::pool()),
            refresh_revoker: None,
            flow_ttl: DEFAULT_FLOW_TTL,
            reset_cooldown: Some(DEFAULT_PASSWORD_RESET_COOLDOWN),
            reset_requests: None,
            reveal_signup_conflicts: false,
            signup_verification_ttl: DEFAULT_SIGNUP_VERIFICATION_TTL,
            candidate_ttl: DEFAULT_CANDIDATE_TTL,
            max_live_reset_tokens: DEFAULT_MAX_LIVE_RESET_TOKENS,
            impersonated_credential_changes: false,
            hardening: AccountHardening::default(),
            reveal_lockout_on_begin: false,
            #[cfg(feature = "device")]
            known_devices: None,
            preserved_custom_keys: Vec::new(),
            throttle_address_unknown_reported: std::sync::atomic::AtomicBool::new(false),
            session_rows: None,
            recovery_peppers: Default::default(),
            factor_secret_cipher: None,
            allow_plaintext_factor_secrets: false,
            breached_password_check: None,
            on_breach_check_unavailable: Default::default(),
            #[cfg(any(feature = "oauth", feature = "fido2", feature = "ldap"))]
            provider_reload: Default::default(),
            #[cfg(feature = "fido2")]
            fido2: arc_swap::ArcSwapOption::empty(),
            #[cfg(feature = "fido2")]
            fido2_options: Default::default(),
            #[cfg(feature = "ldap")]
            ldap: arc_swap::ArcSwapOption::empty(),
            #[cfg(feature = "oauth")]
            oauth_providers: Default::default(),
            #[cfg(feature = "oauth")]
            tenant_oauth_providers: None,
            #[cfg(feature = "oauth")]
            sid_map: Default::default(),
            #[cfg(feature = "oauth")]
            sid_store: None,
            #[cfg(feature = "oauth")]
            sid_map_capacity: DEFAULT_SID_MAP_CAPACITY,
            #[cfg(feature = "oauth")]
            jwks_refresh_interval: None,
            #[cfg(feature = "oauth")]
            jwks_refresh_task: None,
        }
    }
}

impl<I, F> AuthnServiceBuilder<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Replace the RNG (for DST). Type-erased; service shape unchanged.
    pub fn with_rng(mut self, rng: impl SecureRng) -> Self {
        self.rng = Arc::new(rng);
        self
    }

    /// Replace the clock (for DST). Type-erased; service shape unchanged.
    pub fn with_clock(mut self, clock: impl Clock) -> Self {
        self.clock = Arc::new(clock);
        self
    }

    /// Replace the executor password hashing and verification run on.
    ///
    /// The default is the blocking pool, one job per CPU. Deterministic tests
    /// pass [`KdfExecutor::inline`](crate::blocking::KdfExecutor::inline),
    /// keep a clone of the `Arc`, and read
    /// [`jobs_started`](crate::blocking::KdfExecutor::jobs_started) to assert
    /// how many hashes a flow ran.
    pub fn with_kdf_executor(mut self, executor: Arc<crate::blocking::KdfExecutor>) -> Self {
        self.kdf = executor;
        self
    }

    /// Set the secret recovery codes stored in the keyed form are checked
    /// under. Without it only Argon2id recovery codes can verify; a keyed row
    /// then fails closed. See [`axess_factors::RecoveryCodePepper`].
    pub fn with_recovery_code_pepper(mut self, pepper: axess_factors::RecoveryCodePepper) -> Self {
        self.recovery_peppers.current = Some(Arc::new(pepper));
        self
    }

    /// Keep the pepper a rotation retired, so recovery-code sets generated
    /// under it still verify while their owners regenerate them.
    ///
    /// A keyed row cannot be re-keyed without its plaintext, so after
    /// [`with_recovery_code_pepper`](Self::with_recovery_code_pepper) moves
    /// to a new secret every set made under the old one would fail closed.
    /// With the previous pepper set a code matches under either; a match
    /// under the previous one still logs the user in, and is reported so the
    /// application can have them generate a new set: the persisted
    /// [`RecoveryCodesConfig::under_previous_pepper`](crate::authn::factor::RecoveryCodesConfig::under_previous_pepper)
    /// is set, a warning is logged and
    /// [`FactorMetrics::recovery_codes_under_previous_pepper`](crate::metrics::FactorMetrics::recovery_codes_under_previous_pepper)
    /// fires. Drop the previous pepper once no stored set uses it.
    pub fn with_previous_recovery_code_pepper(
        mut self,
        pepper: axess_factors::RecoveryCodePepper,
    ) -> Self {
        self.recovery_peppers.previous = Some(Arc::new(pepper));
        self
    }

    /// Keep TOTP and HOTP secrets encrypted at rest.
    ///
    /// With a cipher the service opens a sealed secret to verify a code and
    /// writes it back sealed, and a plain secret that verifies is sealed in
    /// the same login while the cipher's plain-secret policy still reads it
    /// (see [`FactorSecretCipher`](crate::authn::factor_secret::FactorSecretCipher)).
    /// Seal new enrolments with the same cipher's `seal_config`. Without one
    /// the service refuses to write a TOTP or HOTP secret (see
    /// [`allow_plaintext_factor_secrets`](Self::allow_plaintext_factor_secrets)),
    /// and a sealed secret fails with a clear error.
    pub fn with_factor_secret_cipher(
        mut self,
        cipher: Arc<crate::authn::factor_secret::FactorSecretCipher>,
    ) -> Self {
        self.factor_secret_cipher = Some(cipher);
        self
    }

    /// Let the service write TOTP and HOTP secrets in plain text, with no
    /// cipher.
    ///
    /// **For development and tests only**, like the `plaintext` constructors
    /// of the session and device stores. Without a cipher the service
    /// refuses, with
    /// [`FactorSecretError::PlaintextNotAllowed`](crate::authn::factor_secret::FactorSecretError::PlaintextNotAllowed),
    /// to store a one-time-code secret: a seed in the table in clear text
    /// is a second factor for anyone who can read a backup or a replica.
    /// Production sets
    /// [`with_factor_secret_cipher`](Self::with_factor_secret_cipher).
    pub fn allow_plaintext_factor_secrets(mut self) -> Self {
        self.allow_plaintext_factor_secrets = true;
        self
    }

    /// Configure the FIDO2 ceremony timeout and the recency a credential
    /// change requires of the session
    /// ([`Fido2Options::max_authn_age`](crate::authn::factor::Fido2Options::max_authn_age)).
    #[cfg(feature = "fido2")]
    pub fn with_fido2_options(mut self, options: crate::authn::factor::Fido2Options) -> Self {
        self.fido2_options = options;
        self
    }

    /// Attach a session registry for forced-logout support.
    pub fn with_registry(mut self, registry: impl SessionRegistry + 'static) -> Self {
        self.registry = Some(Arc::new(SessionRegistryAdapter(registry)));
        self
    }

    /// Hand the session store to the service, so that ending a user's
    /// sessions ([`invalidate_user_sessions`](crate::authn::service::RequestAuthnService::invalidate_user_sessions),
    /// suspension, a password reset) deletes the stored rows as well as the
    /// registry entries. Pass the store the session layer uses (a clone).
    ///
    /// Without it only the registry entries go, and the rows are refused on
    /// their next request by a layer built with a registry, or expire with
    /// their TTL.
    pub fn with_session_store(mut self, store: impl crate::session::store::SessionStore) -> Self {
        self.session_rows = Some(Arc::new(RowRemover(store)));
        self
    }

    /// Carry these custom session keys across the transition to
    /// `Authenticated`. Names are matched exactly.
    ///
    /// Becoming authenticated clears the session's custom data, so state a
    /// visitor could plant while anonymous does not ride into the signed-in
    /// session. An application that stashes something deliberately before the
    /// login (a post-login destination, a chosen locale) lists its keys here;
    /// nothing is preserved by default. The keys the login itself owns need
    /// no listing.
    pub fn with_preserved_custom_keys<K: Into<String>>(
        mut self,
        keys: impl IntoIterator<Item = K>,
    ) -> Self {
        self.preserved_custom_keys = keys.into_iter().map(Into::into).collect();
        self
    }

    /// Set the maximum number of concurrent sessions per user.
    ///
    /// When a user authenticates and already has this many active sessions,
    /// the oldest session is evicted. Not calling this (the default) means
    /// unlimited. The cap is a [`NonZeroUsize`](std::num::NonZeroUsize): a cap
    /// of 0 cannot hold a session that has just logged in, and used to behave
    /// as 1 without saying so.
    pub fn with_max_sessions_per_user(mut self, max: std::num::NonZeroUsize) -> Self {
        self.max_sessions_per_user = Some(max.get());
        self
    }

    /// Attach the refresh token store, so that changing a user's credentials
    /// also revokes the user's refresh tokens.
    ///
    /// Session registry invalidation reaches registered cookie sessions
    /// only. A refresh token is a separate credential that mints a new
    /// authenticated session, so without this a refresh token stolen before
    /// a password reset keeps working after it. With it,
    /// `complete_password_reset` and the `suspend_user` family call
    /// [`RefreshTokenStore::revoke_user_tokens`](crate::session::refresh::RefreshTokenStore::revoke_user_tokens)
    /// and return an error when that fails, after the change itself has been
    /// made and audited. Pass the same store the application issues tokens
    /// into (a clone or a shared handle).
    pub fn with_refresh_store(
        mut self,
        store: impl crate::session::refresh::RefreshTokenStore + 'static,
    ) -> Self {
        self.refresh_revoker = Some(Arc::new(RefreshStoreRevoker(store)));
        self
    }

    /// Set how long a half-finished login may sit before the next step
    /// answers `NoFlow` and the session is reset.
    ///
    /// Measured from `begin_login` with the injected clock. The default is
    /// [`DEFAULT_FLOW_TTL`](crate::authn::service::DEFAULT_FLOW_TTL), ten minutes.
    pub fn with_flow_ttl(mut self, ttl: std::time::Duration) -> Self {
        self.flow_ttl = ttl;
        self
    }

    /// Refuse a second password reset request for the same identifier inside
    /// `cooldown`.
    ///
    /// `begin_password_reset` then answers `Ok(None)`, as it does for an
    /// unknown identifier, to a request that follows another for the same
    /// tenant and identifier within the cooldown. The key is the identifier
    /// normalised as the login rate limiter normalises it
    /// ([`normalise_identifier`](crate::validation::normalise_identifier):
    /// NFKC, lowercase, invisible format characters dropped, trimmed), so a
    /// variant spelling of one address does not earn a second token; whether
    /// or not an account has it, so the cooldown cannot tell a caller which
    /// identifiers exist. It stops one inbox being flooded with reset mail
    /// and one account being kept busy; it is not a rate limit on the route,
    /// which still belongs in front of the handler.
    ///
    /// The record lives in this process, on the injected clock, and holds at
    /// most [`RESET_COOLDOWN_CAPACITY`] identifiers, each for the cooldown
    /// and no longer. When that many are live, the oldest is dropped to
    /// make room, so a caller who mints identifiers cannot refuse a real
    /// user's reset: a refusal falls only on an identifier that is itself
    /// cooling down. What bounds the mail an account is sent is the limit on
    /// its live reset tokens
    /// ([`with_max_live_reset_tokens`](Self::with_max_live_reset_tokens)). A
    /// deployment of several instances applies the
    /// cooldown per instance; put the route behind a shared rate limit for a
    /// bound across them. The default is
    /// [`DEFAULT_PASSWORD_RESET_COOLDOWN`], a minute.
    pub fn with_password_reset_cooldown(mut self, cooldown: std::time::Duration) -> Self {
        self.reset_cooldown = Some(cooldown);
        self
    }

    /// Answer every password reset request with a token, however soon the
    /// last one for the identifier was.
    ///
    /// Removes the cooldown a new builder starts with
    /// ([`DEFAULT_PASSWORD_RESET_COOLDOWN`]). Without one, anyone who knows
    /// an address can fill its inbox with reset mail at the speed of the
    /// route, so take this only when the route is behind a rate limit keyed
    /// on the identifier, or in a test that resets the same account twice.
    pub fn without_password_reset_cooldown(mut self) -> Self {
        self.reset_cooldown = None;
        self
    }

    /// How long the secret `begin_signup` mints completes the signup
    /// (default: 24 hours). After that `complete_signup` refuses it; the
    /// session submits the signup again to get a new secret.
    pub fn with_signup_verification_ttl(mut self, ttl: std::time::Duration) -> Self {
        self.signup_verification_ttl = ttl;
        self
    }

    /// Let the account's own devices through a per-account lockout.
    ///
    /// With a device store, a login from a device the locked account has
    /// already used (a row of the tenant owned by the user, at
    /// [`Seen`](crate::device::DeviceTrustLevel::Seen) or
    /// [`Trusted`](crate::device::DeviceTrustLevel::Trusted), as the session
    /// layer's device resolver bound it to the session) still works while the
    /// failure counter has the account locked; every other origin stays
    /// locked out. Without one, or when the store cannot answer, the lock
    /// holds for everyone. See
    /// [`LockoutPolicy`](crate::authn::types::LockoutPolicy). An
    /// administrator's suspension is not affected.
    ///
    /// **The session's device must be one the client proved.** Wire the
    /// session layer with
    /// [`LifecycleDeviceResolver`](crate::device::LifecycleDeviceResolver),
    /// which binds a device only on its secret cookie token. A resolver that
    /// binds by fingerprint alone (for example through
    /// [`DeviceLifecycleService::ensure_device`](crate::device::DeviceLifecycleService::ensure_device)
    /// with no user) lets anyone sharing the victim's address and headers
    /// ride the victim's `Seen` device past the lockout.
    #[cfg(feature = "device")]
    #[must_use]
    pub fn with_device_store<D: crate::device::DeviceStore>(mut self, devices: D) -> Self {
        self.known_devices = Some(Arc::new(super::known_device::StoreKnownDevices(devices)));
        self
    }

    /// Answer `begin_signup` for an identifier that is already taken with
    /// [`SignupOutcome::AlreadyExists`](crate::authn::service::SignupOutcome::AlreadyExists),
    /// for a form that must say so at once.
    ///
    /// By default a taken identifier gets
    /// [`SignupOutcome::Started`](crate::authn::service::SignupOutcome::Started)
    /// like a free one, so the response is not a way to find out who has an
    /// account: nothing is created, the session is left as it was,
    /// anonymous, and the refusal is audited with its reason. The
    /// application tells the two apart where the caller cannot see it: after
    /// `Started`, a session with no user means the identifier was taken, and
    /// the address on file gets a "you already have an account" mail where a
    /// new signup gets the verification link. Answer the client the same
    /// either way, and do the mail off the request path, since creating an
    /// account takes longer than declining to (the hidden answer skips the
    /// `create_user` write, and that difference is measurable by a caller
    /// timing the response). Revealing the conflict trades that away for a
    /// form that can say "taken" on the spot.
    pub fn with_signup_conflicts_revealed(mut self) -> Self {
        self.reveal_signup_conflicts = true;
        self
    }

    /// Let an impersonated session issue refresh tokens and enrol or delete
    /// factors.
    ///
    /// By default a session `begin_impersonation` made is refused these with
    /// [`AuthnError::NoFlow`](crate::authn::error::AuthnError::NoFlow) and a
    /// failed audit row naming the administrator as actor: a refresh token
    /// would outlive the impersonation as a credential of the user, and a
    /// factor the administrator enrols is one the user never saw. A support
    /// desk that enrols a replacement authenticator for a locked-out user on
    /// purpose, and audits it, opts in here.
    pub fn with_impersonated_credential_changes_allowed(mut self) -> Self {
        self.impersonated_credential_changes = true;
        self
    }

    /// Require the administrator to have authenticated within `max_age` to
    /// begin an impersonation.
    ///
    /// An impersonation lets one session act as another user, so a session
    /// left open on a shared machine, or a stolen cookie, should not be able
    /// to begin one hours after the administrator signed in. With this set,
    /// `begin_impersonation` refuses an administrator session whose
    /// authentication is older than `max_age` with
    /// [`AuthnError::NoFlow`](crate::authn::error::AuthnError::NoFlow) and a
    /// failed audit row with the reason `authn_too_old`; the administrator
    /// authenticates again (a step-up) and retries. The default is no limit.
    /// A few minutes is the usual choice.
    pub fn with_impersonation_max_authn_age(mut self, max_age: std::time::Duration) -> Self {
        self.hardening.impersonation_max_authn_age = Some(max_age);
        self
    }

    /// Let `begin_login` answer a locked account with
    /// [`LoginOutcome::Locked`](crate::authn::service::LoginOutcome::Locked)
    /// and the time the lock ends.
    ///
    /// By default a locked account, whether the lock is a suspension the
    /// store reports or one derived from the failure counter, is answered
    /// [`InvalidCredentials`](crate::authn::service::LoginOutcome::InvalidCredentials),
    /// the outcome an unknown identifier gets: a caller who has proved
    /// nothing is otherwise told that the account exists and that it is
    /// being guessed at, from the first request. The audit row carries
    /// `Locked` either way, and the metrics count the lockout either way.
    /// Turn the answer on for a first-party form behind its own abuse
    /// controls, where "locked until" is worth more than the concealment;
    /// [`login_with_password`](crate::authn::RequestAuthnService::login_with_password)
    /// always conceals.
    pub fn with_lockout_revealed_on_begin(mut self) -> Self {
        self.reveal_lockout_on_begin = true;
        self
    }

    /// Attach the metric sinks the service reports to: the authentication
    /// flow, factors, sessions, the provider registry and the audit pipeline.
    /// Concerns left at their no-op default report nothing; see
    /// [`MetricSinks`](crate::metrics::MetricSinks).
    pub fn with_metrics(mut self, metrics: crate::metrics::MetricSinks) -> Self {
        self.metrics = metrics;
        self
    }

    /// Share the collaborators and return the handle.
    ///
    /// Logs a warning when no session registry was attached: without one,
    /// suspending a user, resetting a password and an administrator's kick
    /// end no existing session, which then lives until its TTL. Logs another
    /// when no breached-password check was attached: without one, a reset or
    /// a signup accepts a password from a public breach corpus when it meets
    /// the rules.
    pub fn build(self) -> AuthnService<I, F> {
        let mut this = self;
        #[cfg(feature = "oauth")]
        this.report_duplicate_providers();
        if this.registry.is_none() {
            tracing::warn!(
                "AuthnService built without a session registry: suspending a user, \
                 resetting a password and kicking a session end no existing session; \
                 attach one with with_registry"
            );
        }
        if this.breached_password_check.is_none() {
            tracing::warn!(
                "AuthnService built without a breached-password check: a reset or a signup \
                 accepts a password known from a breach when it meets the rules; \
                 attach one with with_breached_password_check"
            );
        }
        this.reset_requests = this.reset_cooldown.map(|cooldown| {
            Arc::new(super::reset_cooldown::ResetCooldowns::new(
                RESET_COOLDOWN_CAPACITY,
                cooldown,
                this.clock.clone(),
            ))
        });
        #[cfg(feature = "oauth")]
        let this = this.with_jwks_refresh_started();
        AuthnService {
            inner: Arc::new(this),
        }
    }
}
