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
    pub(crate) metrics: Arc<dyn crate::metrics::AuthnMetrics>,
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
    /// Whether an impersonated session may issue refresh tokens and enrol
    /// or delete factors; see
    /// [`with_impersonated_credential_changes_allowed`](Self::with_impersonated_credential_changes_allowed).
    pub(crate) impersonated_credential_changes: bool,
    /// Whether `begin_login` answers a locked account with
    /// [`LoginOutcome::Locked`](crate::authn::service::LoginOutcome::Locked)
    /// rather than as it answers an unknown identifier (the default); see
    /// [`with_lockout_revealed_on_begin`](Self::with_lockout_revealed_on_begin).
    pub(crate) reveal_lockout_on_begin: bool,
    /// Custom session keys the application asked to carry across the
    /// transition to `Authenticated`; see
    /// [`with_preserved_custom_keys`](Self::with_preserved_custom_keys).
    pub(crate) preserved_custom_keys: Vec<String>,
    /// The session store, when the application handed it over so that a
    /// revocation can delete the rows as well as the registry entries.
    pub(crate) session_rows: Option<Arc<dyn SessionRowRemover>>,
    /// The secrets keyed recovery codes are checked under, when configured:
    /// the current pepper and, during a rotation, the previous one.
    pub(crate) recovery_peppers: super::verification::RecoveryPeppers,
    /// The cipher OTP secrets are sealed and opened with, when configured.
    pub(crate) factor_secret_cipher: Option<Arc<crate::authn::factor_secret::FactorSecretCipher>>,
    #[cfg(feature = "fido2")]
    pub(crate) fido2: Option<Arc<dyn axess_factors::fido2::Fido2Provider>>,
    #[cfg(feature = "fido2")]
    pub(crate) fido2_options: crate::authn::factor::Fido2Options,
    #[cfg(feature = "ldap")]
    pub(crate) ldap: Option<Arc<dyn axess_factors::ldap::LdapProvider>>,
    #[cfg(feature = "oauth")]
    pub(crate) oauth_providers: crate::federation::oauth::OAuthProviderRegistry,
    /// Per-tenant providers resolved at request time, when configured by
    /// [`with_tenant_oauth_providers`](AuthnServiceBuilder::with_tenant_oauth_providers).
    #[cfg(feature = "oauth")]
    pub(crate) tenant_oauth_providers:
        Option<Arc<dyn crate::federation::oauth_tenant::TenantOAuthProviders>>,
    /// Shared OIDC `sid` → `(user_id, session_id, inserted_at)` map for back-channel logout.
    /// The timestamp enables TTL-based eviction of stale entries.
    #[cfg(feature = "oauth")]
    pub(crate) sid_map: crate::federation::sid_map::SidMap,
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

/// How many identifiers the password reset cooldown remembers.
pub const RESET_COOLDOWN_CAPACITY: usize = 100_000;

/// How long a login may sit between `begin_login` and its last factor before
/// the next step answers [`NoFlow`](crate::authn::error::AuthnError::NoFlow):
/// ten minutes. Change it with [`AuthnServiceBuilder::with_flow_ttl`].
pub const DEFAULT_FLOW_TTL: std::time::Duration = std::time::Duration::from_secs(10 * 60);

/// Deletes one stored session row, behind a trait object so the service does
/// not take the session store's type as a parameter.
pub(crate) trait SessionRowRemover: Send + Sync {
    /// Delete the row of `id`. The error is its text.
    fn delete_row<'a>(
        &'a self,
        id: &'a crate::session::id::SessionId,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>>;
}

struct RowRemover<S>(S);

impl<S: crate::session::store::SessionStore> SessionRowRemover for RowRemover<S> {
    fn delete_row<'a>(
        &'a self,
        id: &'a crate::session::id::SessionId,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move { self.0.delete(id).await.map_err(|e| e.to_string()) })
    }
}

/// The one refresh-token operation the credential-change paths need, behind a
/// trait object so the service does not take the store's type as a parameter.
pub(crate) trait UserTokenRevoker: Send + Sync {
    /// Revoke every refresh token of `user_id`. The error is its text.
    fn revoke_user_tokens<'a>(
        &'a self,
        user_id: &'a crate::authn::ids::UserId,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>>;
}

struct RefreshStoreRevoker<R>(R);

impl<R> UserTokenRevoker for RefreshStoreRevoker<R>
where
    R: crate::session::refresh::RefreshTokenStore + 'static,
{
    fn revoke_user_tokens<'a>(
        &'a self,
        user_id: &'a crate::authn::ids::UserId,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            self.0
                .revoke_user_tokens(user_id)
                .await
                .map_err(|e| e.to_string())
        })
    }
}

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
    /// Start configuring a service. Finish with [`build`](Self::build).
    pub fn new(identity: I, factors: F) -> Self {
        Self {
            identity: Arc::new(identity),
            factors: Arc::new(factors),
            registry: None,
            metrics: Arc::new(crate::metrics::NoopMetrics),
            max_sessions_per_user: None,
            rng: Arc::new(SystemRng),
            clock: Arc::new(SystemClock),
            kdf: Arc::new(crate::blocking::KdfExecutor::pool()),
            refresh_revoker: None,
            flow_ttl: DEFAULT_FLOW_TTL,
            reset_cooldown: None,
            reset_requests: None,
            reveal_signup_conflicts: false,
            impersonated_credential_changes: false,
            reveal_lockout_on_begin: false,
            preserved_custom_keys: Vec::new(),
            session_rows: None,
            recovery_peppers: Default::default(),
            factor_secret_cipher: None,
            #[cfg(feature = "fido2")]
            fido2: None,
            #[cfg(feature = "fido2")]
            fido2_options: Default::default(),
            #[cfg(feature = "ldap")]
            ldap: None,
            #[cfg(feature = "oauth")]
            oauth_providers: Default::default(),
            #[cfg(feature = "oauth")]
            tenant_oauth_providers: None,
            #[cfg(feature = "oauth")]
            sid_map: Default::default(),
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
    /// [`AuthnMetrics::recovery_codes_under_previous_pepper`](crate::metrics::AuthnMetrics::recovery_codes_under_previous_pepper)
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
    /// nothing changes: secrets are read and written as plain text, and a
    /// sealed secret fails with a clear error.
    pub fn with_factor_secret_cipher(
        mut self,
        cipher: Arc<crate::authn::factor_secret::FactorSecretCipher>,
    ) -> Self {
        self.factor_secret_cipher = Some(cipher);
        self
    }

    /// Attach a FIDO2/WebAuthn provider.
    ///
    /// **Single-instance by design.** Calling `with_fido2` twice replaces
    /// the previously attached provider silently: one deployment, one
    /// relying-party configuration is the assumption. Multi-tenant apps
    /// that need per-tenant relying-party ids (e.g. distinct RP-IDs per
    /// customer domain) must wrap dispatch in the application layer;
    /// axess-core does not maintain a per-tenant FIDO2 registry.
    #[cfg(feature = "fido2")]
    pub fn with_fido2(mut self, provider: impl axess_factors::fido2::Fido2Provider) -> Self {
        self.fido2 = Some(Arc::new(provider));
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

    /// Attach an LDAP provider for directory-based password verification.
    ///
    /// When a user's factor chain includes [`FactorKind::LdapBind`](crate::authn::factor::FactorKind::LdapBind), the
    /// service will verify their password via an LDAP simple bind against
    /// this provider instead of checking a local password hash.
    ///
    /// **Single-instance by design.** Calling `with_ldap` twice replaces
    /// the previously attached provider silently: one deployment, one
    /// directory is the assumption. Multi-tenant apps that need
    /// per-subsidiary directories must wrap dispatch in the application
    /// layer; axess-core does not maintain a per-tenant LDAP registry.
    ///
    /// ```rust,ignore
    /// let ldap = LdapProviderConfig::new(
    ///     "ldaps://ad.corp.example.com",
    ///     "{user}@corp.example.com",
    /// );
    /// let authn = AuthnService::builder(identity, factors).with_ldap(ldap).build();
    /// ```
    #[cfg(feature = "ldap")]
    pub fn with_ldap(mut self, provider: impl axess_factors::ldap::LdapProvider) -> Self {
        self.ldap = Some(Arc::new(provider));
        self
    }

    /// Register an OAuth/OIDC identity provider.
    ///
    /// Call once per provider at startup. Multiple providers can be registered
    /// (e.g. Google + GitHub + corporate IdP), each under a distinct name.
    ///
    /// **Duplicate name safety.** Registering two providers under the same
    /// `provider.name()` is a real security-relevant misconfiguration
    /// (token exchanges for that IdP would then run against whichever
    /// credentials won the race). The registry emits `tracing::warn!` on
    /// overwrite and `debug_assert!`s in debug builds; production builds
    /// keep the new registration and continue, so operators still notice
    /// via logs.
    ///
    /// # Tenancy
    ///
    /// **Providers are registered globally on `AuthnService`, not per-tenant.**
    /// The library does not maintain a per-tenant OAuth registry; that is
    /// out of scope by design. Two supported patterns:
    ///
    /// 1. **Same IdP, multiple tenants (single shared client).** Tenant A
    ///    and tenant B both federate to the same IdP (e.g. one Azure AD
    ///    app serving two SaaS tenants). The callback alone cannot tell
    ///    them apart; the application MUST use
    ///    [`begin_oauth_login_in_tenant`](AuthnService::begin_oauth_login_in_tenant)
    ///    to bind the ceremony to a tenant up-front, and the
    ///    claims→user resolver MUST scope its lookup to the bound tenant.
    /// 2. **Distinct IdPs, one per set of tenants.** Register one provider
    ///    per IdP under a stable name (`"acme-corp-azure"`, `"beta-corp-okta"`,
    ///    etc.); the application maps a tenant → provider-name in its own
    ///    tenant record and calls [`begin_oauth_login`](AuthnService::begin_oauth_login)
    ///    with the resolved name. Provider names are stable identifiers,
    ///    NOT dynamic per-tenant strings: do not derive them from
    ///    `tenant_id` at registration time (would require re-registration
    ///    on every tenant create/delete, would collide with reserved
    ///    identifier characters, and would defeat the introspection story
    ///    on [`oauth_providers`](AuthnService::oauth_providers)).
    ///
    /// If you need genuinely dynamic per-tenant IdP configuration
    /// (each tenant admin uploads their own client_secret through a UI,
    /// changing at runtime), use
    /// [`with_tenant_oauth_providers`](Self::with_tenant_oauth_providers):
    /// the provider is resolved by `(tenant, name)` from a store at request
    /// time and an update is used by the next login.
    #[cfg(feature = "oauth")]
    pub fn with_oauth_provider(
        mut self,
        provider: impl axess_factors::oauth::OAuthProvider,
    ) -> Self {
        self.oauth_providers.add(provider);
        self
    }

    /// Resolve per-tenant OAuth providers (bring your own IdP) from
    /// `providers` at request time.
    ///
    /// A login started with
    /// [`begin_oauth_login_with_tenant_provider`](AuthnService::begin_oauth_login_with_tenant_provider)
    /// asks `providers` for the provider named `(tenant, name)`; the
    /// callback asks again for the same tenant, taken from the session. The
    /// global registrations of
    /// [`with_oauth_provider`](Self::with_oauth_provider) are unaffected and
    /// remain the single-tenant form: a name registered there is reached by
    /// [`begin_oauth_login`](AuthnService::begin_oauth_login), a tenant's by
    /// the tenant method, and the two never shadow each other.
    ///
    /// [`StoredTenantOAuthProviders`](crate::federation::oauth_tenant::StoredTenantOAuthProviders)
    /// is the implementation over a store.
    #[cfg(feature = "oauth")]
    pub fn with_tenant_oauth_providers(
        mut self,
        providers: impl crate::federation::oauth_tenant::TenantOAuthProviders,
    ) -> Self {
        self.tenant_oauth_providers = Some(Arc::new(providers));
        self
    }

    /// Override the capacity cap for the OIDC `sid` → local-session map that
    /// powers back-channel logout by `sid`.
    ///
    /// The map is populated per successful OAuth login that returns an
    /// `oidc_sid` claim; when at/over this cap, the maintenance path
    /// evicts a batch of oldest entries. Default:
    /// [`DEFAULT_SID_MAP_CAPACITY`] (10 000). Raise for high-throughput
    /// deployments where legitimate concurrent OIDC sessions exceed the
    /// default and back-channel logout precision degrades on eviction.
    #[cfg(feature = "oauth")]
    pub fn with_sid_map_capacity(mut self, capacity: usize) -> Self {
        self.sid_map_capacity = capacity;
        self
    }

    /// Have [`build`](Self::build) start a background loop that refreshes the
    /// JWKS of every registered OAuth provider every `interval`.
    ///
    /// Cached key sets have a maximum age (24 hours by default,
    /// `JwksCache::with_max_age`), after which verification with them fails
    /// closed until a refresh succeeds. Without this loop (or an equivalent
    /// started with `AuthnService::spawn_jwks_refresh` or a scheduler calling
    /// `AuthnService::refresh_all_jwks`) the keys expire by that maximum age
    /// and logout-token verification then relies on the refresh a kid miss
    /// triggers. The loop stops when the last clone of the built service is
    /// dropped. It needs a tokio runtime at `build` time: without one it is
    /// not started and a warning is logged.
    #[cfg(feature = "oauth")]
    pub fn with_jwks_refresh(mut self, interval: std::time::Duration) -> Self {
        self.jwks_refresh_interval = Some(interval);
        self
    }

    /// [`with_jwks_refresh`](Self::with_jwks_refresh) at the default
    /// interval, [`DEFAULT_JWKS_REFRESH_INTERVAL`] (one hour).
    #[cfg(feature = "oauth")]
    pub fn with_default_jwks_refresh(self) -> Self {
        self.with_jwks_refresh(DEFAULT_JWKS_REFRESH_INTERVAL)
    }

    /// Start the refresh loop `with_jwks_refresh` asked for, if any.
    #[cfg(feature = "oauth")]
    fn with_jwks_refresh_started(mut self) -> Self {
        if let Some(interval) = self.jwks_refresh_interval {
            self.jwks_refresh_task = super::oauth_service::JwksRefreshTask::start(
                self.oauth_providers.values().cloned().collect(),
                interval,
            );
        }
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
    /// most [`RESET_COOLDOWN_CAPACITY`] identifiers (the least recently
    /// requested are forgotten first). A deployment of several instances
    /// applies the cooldown per instance; put the route behind a shared rate
    /// limit for a bound across them. The default is no cooldown.
    pub fn with_password_reset_cooldown(mut self, cooldown: std::time::Duration) -> Self {
        self.reset_cooldown = Some(cooldown);
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

    /// Attach a metrics hook for observability.
    ///
    /// The [`AuthnMetrics`](crate::metrics::AuthnMetrics) trait has no-op
    /// defaults; implement only the counters you need.
    pub fn with_metrics(mut self, metrics: impl crate::metrics::AuthnMetrics) -> Self {
        self.metrics = Arc::new(metrics);
        self
    }

    /// Share the collaborators and return the handle.
    ///
    /// Logs a warning when no session registry was attached: without one,
    /// suspending a user, resetting a password and an administrator's kick
    /// end no existing session, which then lives until its TTL.
    pub fn build(self) -> AuthnService<I, F> {
        let mut this = self;
        if this.registry.is_none() {
            tracing::warn!(
                "AuthnService built without a session registry: suspending a user, \
                 resetting a password and kicking a session end no existing session; \
                 attach one with with_registry"
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
