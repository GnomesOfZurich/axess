//! The strict security profile: one named value for each setting a
//! high-assurance deployment tightens, readable, overridable, and applied
//! to the configuration types it belongs to.
//!
//! [`SecurityProfile::Standard`](crate::profile::SecurityProfile::Standard) is the library's own defaults, restated as
//! values; [`SecurityProfile::Strict`](crate::profile::SecurityProfile::Strict) is the tightened set. Choosing the
//! profile changes nothing by itself: [`values`](crate::profile::SecurityProfile::values)
//! returns a [`ProfileValues`](crate::profile::ProfileValues) whose public fields an adopter reads, changes
//! and then applies through the `apply`-style methods, each of which takes
//! the configuration it adjusts and hands it back. A setting the adopter
//! overrides stays overridden because the adopter changes the field before
//! applying it, or configures the type afterwards.
//!
//! The profile is additive: it adds no default and removes none. See
//! `docs/production/strict-profile.md` for the value of each setting, why it
//! is that value, and what the profile leaves to the adopter.

use std::time::Duration;

use axess_factors::Argon2Cost;

use crate::authn::service::AuthnServiceBuilder;
use crate::authn::store::{FactorStore, IdentityStore};
use crate::middleware::csrf::CsrfConfig;
use crate::middleware::ratelimit::RateLimitConfigBuilder;
use crate::session::config::{SessionConfig, SessionConfigBuilder};
use crate::session::refresh::RefreshTokenConfig;

/// Which set of values to start from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityProfile {
    /// The library's own defaults, as values. Applying them changes nothing.
    Standard,
    /// The tightened set for a deployment that holds money or regulated
    /// data. See the module documentation.
    Strict,
}

/// Why a profile could not be applied.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProfileError {
    /// The profile requires CSRF origin checking and the caller named no
    /// origin to allow. The profile cannot know the application's own
    /// origins, and an empty list leaves the check off.
    #[error("the profile requires CSRF origin checking: name the application's own origins")]
    CsrfOriginsRequired,
    /// An origin named for CSRF checking is not a scheme, host and optional
    /// port. Every entry is checked, so none is dropped silently.
    #[error("a CSRF origin is not a valid origin (needs scheme and host): {0}")]
    CsrfOriginInvalid(String),
}

/// The value of every setting the profile names.
///
/// Every field is public: read it back to see what the profile sets, assign
/// to it to override, then apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileValues {
    /// Idle lifetime of a session, sliding
    /// ([`SessionConfig::ttl`](crate::session::config::SessionConfig::ttl)).
    pub session_idle_ttl: Duration,
    /// Absolute cap on an authenticated session
    /// ([`SessionConfig::max_authenticated_age`](crate::session::config::SessionConfig::max_authenticated_age)).
    pub session_max_authenticated_age: Option<Duration>,
    /// Sliding lifetime of a refresh token
    /// ([`RefreshTokenConfig::ttl`](crate::session::refresh::RefreshTokenConfig)).
    pub refresh_ttl: chrono::Duration,
    /// Absolute lifetime of a refresh-token family
    /// ([`RefreshTokenConfig::max_lifetime`](crate::session::refresh::RefreshTokenConfig)).
    pub refresh_max_lifetime: Option<chrono::Duration>,
    /// How recently a session must have authenticated to change a passkey
    /// (`Fido2Options::max_authn_age`).
    pub fido2_max_authn_age: Option<Duration>,
    /// Clock-skew tolerance of a JWT verifier
    /// (`JwtVerifier::with_clock_skew`).
    pub jwt_leeway: Duration,
    /// The `typ` header a JWT verifier should require of an access token.
    /// Held for the verifier option that checks it; `None` requires none.
    pub jwt_expected_typ: Option<String>,
    /// Whether a back-channel logout token must carry `typ: logout+jwt`
    /// (`OAuthProviderBuilder::with_required_logout_typ`).
    pub logout_typ_required: bool,
    /// Whether the server screens the URLs it fetches for discovery and key
    /// sets: HTTPS only and no connection to a reserved address. Under a
    /// screened policy the egress client never follows a proxy named in the
    /// environment. `egress_policy` turns it into the
    /// policy to pass to the discovery entry points.
    pub egress_screened: bool,
    /// Time-to-live of a cached device row
    /// (`CachedDeviceStore::with_ttl`): how long another process keeps
    /// honouring a device that was revoked.
    pub device_cache_ttl: Duration,
    /// Lifetime of the device-trust cookie
    /// (`DeviceCookieConfig::with_max_age`).
    pub device_cookie_max_age: Duration,
    /// Whether [`csrf_config`](Self::csrf_config) refuses to run without an
    /// origin allow-list.
    pub csrf_origin_check_required: bool,
    /// Longest a supervised WebSocket stays open
    /// (`WatchOptions::max_lifetime`).
    pub ws_max_lifetime: Option<Duration>,
    /// Argon2id cost of new password hashes.
    pub argon2_cost: Argon2Cost,
    /// Lifetime of a password reset token for
    /// `begin_password_reset_with_default_ttl`; `None` configures none.
    pub password_reset_ttl: Option<Duration>,
    /// Longest lifetime a password reset token may be given.
    pub max_password_reset_ttl: Duration,
    /// How recently an administrator must have authenticated to impersonate;
    /// `None` applies no limit.
    pub impersonation_max_authn_age: Option<Duration>,
    /// Requests per window of the rate limit on authentication routes.
    pub auth_rate_limit_max_requests: u32,
    /// Window of that rate limit.
    pub auth_rate_limit_window: Duration,
}

impl SecurityProfile {
    /// The values this profile names.
    #[must_use]
    pub fn values(self) -> ProfileValues {
        match self {
            Self::Standard => ProfileValues::standard(),
            Self::Strict => ProfileValues::strict(),
        }
    }
}

const MINUTE: u64 = 60;
const HOUR: u64 = 60 * MINUTE;
const DAY: u64 = 24 * HOUR;

impl ProfileValues {
    /// Today's library defaults, one value each.
    fn standard() -> Self {
        Self {
            session_idle_ttl: Duration::from_secs(DAY),
            session_max_authenticated_age: Some(Duration::from_secs(7 * DAY)),
            refresh_ttl: chrono::Duration::days(30),
            refresh_max_lifetime: Some(chrono::Duration::days(90)),
            fido2_max_authn_age: None,
            jwt_leeway: Duration::from_secs(MINUTE),
            jwt_expected_typ: None,
            logout_typ_required: false,
            egress_screened: false,
            device_cache_ttl: Duration::from_secs(MINUTE),
            device_cookie_max_age: Duration::from_secs(400 * DAY),
            csrf_origin_check_required: false,
            ws_max_lifetime: Some(Duration::from_secs(DAY)),
            argon2_cost: Argon2Cost::default(),
            password_reset_ttl: None,
            max_password_reset_ttl: Duration::from_secs(7 * DAY),
            impersonation_max_authn_age: None,
            auth_rate_limit_max_requests: 100,
            auth_rate_limit_window: Duration::from_secs(MINUTE),
        }
    }

    /// The strict set.
    fn strict() -> Self {
        Self {
            session_idle_ttl: Duration::from_secs(15 * MINUTE),
            session_max_authenticated_age: Some(Duration::from_secs(8 * HOUR)),
            refresh_ttl: chrono::Duration::hours(24),
            refresh_max_lifetime: Some(chrono::Duration::days(7)),
            fido2_max_authn_age: Some(Duration::from_secs(5 * MINUTE)),
            jwt_leeway: Duration::from_secs(30),
            jwt_expected_typ: Some("at+jwt".to_owned()),
            logout_typ_required: true,
            egress_screened: true,
            device_cache_ttl: Duration::from_secs(5),
            device_cookie_max_age: Duration::from_secs(90 * DAY),
            csrf_origin_check_required: true,
            ws_max_lifetime: Some(Duration::from_secs(8 * HOUR)),
            argon2_cost: strict_argon2_cost(),
            password_reset_ttl: Some(Duration::from_secs(30 * MINUTE)),
            max_password_reset_ttl: Duration::from_secs(HOUR),
            impersonation_max_authn_age: Some(Duration::from_secs(15 * MINUTE)),
            auth_rate_limit_max_requests: 15,
            auth_rate_limit_window: Duration::from_secs(MINUTE),
        }
    }

    /// A [`SessionConfigBuilder`] with the idle lifetime and the
    /// authenticated-age cap set; the caller continues with its own cookie
    /// name, `SameSite` and the rest, then builds.
    #[must_use]
    pub fn session_config_builder(&self) -> SessionConfigBuilder {
        SessionConfig::builder()
            .ttl(self.session_idle_ttl)
            .max_authenticated_age(self.session_max_authenticated_age)
    }

    /// `base` with the refresh lifetimes set. Peppers, per-user limit and
    /// rotation stay as `base` has them.
    #[must_use]
    pub fn refresh_config(&self, mut base: RefreshTokenConfig) -> RefreshTokenConfig {
        base.ttl = self.refresh_ttl;
        base.max_lifetime = self.refresh_max_lifetime;
        base
    }

    /// `base` with the passkey-change recency set.
    #[cfg(feature = "fido2")]
    #[cfg_attr(docsrs, doc(cfg(feature = "fido2")))]
    #[must_use]
    pub fn fido2_options(
        &self,
        mut base: crate::authn::factor::Fido2Options,
    ) -> crate::authn::factor::Fido2Options {
        base.max_authn_age = self.fido2_max_authn_age;
        base
    }

    /// `verifier` with the clock-skew tolerance set and, when the profile
    /// names one, the JOSE `typ` the verifier requires
    /// ([`jwt_expected_typ`](Self::jwt_expected_typ) through
    /// `JwtVerifier::with_typ`).
    #[cfg(feature = "jwt")]
    #[cfg_attr(docsrs, doc(cfg(feature = "jwt")))]
    #[must_use]
    pub fn jwt_verifier<R>(
        &self,
        verifier: axess_factors::jwt::verifier::JwtVerifier<R>,
    ) -> axess_factors::jwt::verifier::JwtVerifier<R> {
        let verifier = verifier.with_clock_skew(self.jwt_leeway);
        match &self.jwt_expected_typ {
            Some(typ) => verifier.with_typ(typ.clone()),
            None => verifier,
        }
    }

    /// The egress policy to hand to the discovery entry points that take one
    /// (`OAuthProviderConfig::discover_screened` and the OIDC discovery
    /// functions).
    #[cfg(feature = "oauth")]
    #[cfg_attr(docsrs, doc(cfg(feature = "oauth")))]
    #[must_use]
    pub fn egress_policy(&self) -> axess_factors::egress::EgressPolicy {
        if self.egress_screened {
            axess_factors::egress::EgressPolicy::screened()
        } else {
            axess_factors::egress::EgressPolicy::unscreened()
        }
    }

    /// `builder` requiring the logout-token `typ` when the profile does.
    #[cfg(feature = "oauth")]
    #[cfg_attr(docsrs, doc(cfg(feature = "oauth")))]
    #[must_use]
    pub fn oauth_provider(
        &self,
        builder: axess_factors::oauth::OAuthProviderBuilder,
    ) -> axess_factors::oauth::OAuthProviderBuilder {
        if self.logout_typ_required {
            builder.with_required_logout_typ()
        } else {
            builder
        }
    }

    /// `store` wrapped in a cache with the profile's time-to-live.
    #[cfg(feature = "device")]
    #[cfg_attr(docsrs, doc(cfg(feature = "device")))]
    #[must_use]
    pub fn cached_device_store<S: crate::device::DeviceStore>(
        &self,
        store: S,
    ) -> crate::device::CachedDeviceStore<S> {
        crate::device::CachedDeviceStore::new(store).with_ttl(self.device_cache_ttl)
    }

    /// `base` with the device-trust cookie lifetime set.
    #[cfg(feature = "device")]
    #[cfg_attr(docsrs, doc(cfg(feature = "device")))]
    #[must_use]
    pub fn device_cookie_config(
        &self,
        base: crate::device::DeviceCookieConfig,
    ) -> crate::device::DeviceCookieConfig {
        base.with_max_age(self.device_cookie_max_age)
    }

    /// `base` with the application's own origins as the allow-list.
    ///
    /// When the profile requires origin checking, an empty `own_origins`
    /// and any entry that is not an origin are refused; when it does not,
    /// an empty list returns `base` unchanged.
    ///
    /// # Errors
    ///
    /// [`ProfileError::CsrfOriginsRequired`] or
    /// [`ProfileError::CsrfOriginInvalid`].
    pub fn csrf_config<S: AsRef<str>>(
        &self,
        base: CsrfConfig,
        own_origins: &[S],
    ) -> Result<CsrfConfig, ProfileError> {
        if own_origins.is_empty() {
            return if self.csrf_origin_check_required {
                Err(ProfileError::CsrfOriginsRequired)
            } else {
                Ok(base)
            };
        }
        for origin in own_origins {
            let origin = origin.as_ref();
            let valid = url::Url::parse(origin)
                .map(|u| u.origin().is_tuple())
                .unwrap_or(false);
            if !valid {
                return Err(ProfileError::CsrfOriginInvalid(origin.to_owned()));
            }
        }
        Ok(base.require_origin(own_origins))
    }

    /// `base` with the socket lifetime set.
    #[cfg(feature = "ws")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ws")))]
    #[must_use]
    pub fn watch_options(
        &self,
        mut base: crate::middleware::ws::WatchOptions,
    ) -> crate::middleware::ws::WatchOptions {
        base.max_lifetime = self.ws_max_lifetime;
        base
    }

    /// A rate-limit builder with the profile's request budget and window,
    /// for the authentication routes; the caller sets the key and builds.
    #[must_use]
    pub fn auth_rate_limit_builder(&self) -> RateLimitConfigBuilder {
        crate::middleware::ratelimit::RateLimitConfig::builder()
            .max_requests(self.auth_rate_limit_max_requests)
            .window(self.auth_rate_limit_window)
    }

    /// `builder` with the password hashing cost, the password reset
    /// lifetime and cap, the impersonation recency and (with `fido2`) the
    /// passkey-change recency set.
    #[must_use]
    pub fn authn_service_builder<I, F>(
        &self,
        builder: AuthnServiceBuilder<I, F>,
    ) -> AuthnServiceBuilder<I, F>
    where
        I: IdentityStore,
        F: FactorStore<Error = I::Error>,
    {
        let mut builder = builder
            .with_argon2_cost(self.argon2_cost)
            .with_max_password_reset_ttl(self.max_password_reset_ttl);
        if let Some(ttl) = self.password_reset_ttl {
            builder = builder.with_password_reset_ttl(ttl);
        }
        if let Some(age) = self.impersonation_max_authn_age {
            builder = builder.with_impersonation_max_authn_age(age);
        }
        #[cfg(feature = "fido2")]
        {
            builder = builder.with_fido2_options(
                self.fido2_options(crate::authn::factor::Fido2Options::default()),
            );
        }
        builder
    }
}

/// 64 MiB, two passes, one lane: above the OWASP minimum the library pins,
/// within what a login worker pool absorbs.
fn strict_argon2_cost() -> Argon2Cost {
    const STRICT_M_COST_KIB: u32 = 64 * 1024;
    Argon2Cost::new(
        STRICT_M_COST_KIB,
        axess_factors::password::ARGON2_T_COST,
        axess_factors::password::ARGON2_P_COST,
    )
    .unwrap_or_default()
}
