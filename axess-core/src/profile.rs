//! The strict security profile: one named value for each setting a
//! high-assurance deployment tightens, readable, overridable, and applied
//! to the configuration types it belongs to.
//!
//! [`SecurityProfile::Standard`] is the library's own defaults, restated as
//! values; [`SecurityProfile::Strict`] is the tightened set. Choosing the
//! profile changes nothing by itself: [`values`](crate::profile::SecurityProfile::values)
//! returns a [`ProfileValues`] whose public fields an adopter reads, changes
//! and then applies through the `apply`-style methods, each of which takes
//! the configuration it adjusts and hands it back.
//!
//! # Applying a profile never loosens
//!
//! Where a method takes a configuration that already holds a value, and one
//! value of the setting is tighter than another, the result is the tighter
//! of the two: the configuration's own and the profile's. A value the
//! adopter tightened before applying survives the profile, applying a
//! profile twice is applying it once, and the order of "configure" and
//! "apply" does not matter for a tightening. What "tighter" means:
//!
//! - a lifetime, a window or a clock-skew tolerance: the shorter one
//!   (refresh lifetimes, the device-trust cookie, the device-key proof and
//!   challenge lifetimes, the JWT leeway, the password reset lifetime and
//!   its cap);
//! - a limit that may be absent, where `None` means no limit: any limit is
//!   tighter than none, and of two limits the shorter (the refresh family's
//!   absolute lifetime, the passkey-change recency, the socket lifetime,
//!   the impersonation recency);
//! - a requirement that is on or off: on (the logout-token `typ`, the CSRF
//!   origin check);
//! - the Argon2id cost: the larger memory and the larger number of passes
//!   of the two, with the configuration's own lanes, so neither component
//!   comes out lower than either side had it.
//!
//! Two settings have no order and are assigned from the profile: the `typ`
//! an access-token verifier requires (two different types are neither
//! tighter; `access_token_verifier` is named for the retyping) and the CSRF
//! origin list, which the caller names at the call. A default password
//! reset lifetime is a convenience that is either configured or not, so the
//! profile's is taken where the builder has none, and it is never left above
//! the cap in force. The methods that build a configuration from nothing
//! ([`session_config_builder`](crate::profile::ProfileValues::session_config_builder),
//! [`auth_rate_limit_builder`](crate::profile::ProfileValues::auth_rate_limit_builder),
//! `cached_device_store`, `egress_policy`) have no earlier value to compare
//! with and carry the profile's.
//!
//! # The authentication service holds its profile
//!
//! [`authn_service_builder`](crate::profile::ProfileValues::authn_service_builder)
//! also records the profile on the builder, and from then on the profile is
//! a property of the service, not of that one call. The service holds five
//! of the profile's settings itself
//! ([`ProfileSetting`]: the Argon2id cost,
//! the password reset lifetime and its cap, the impersonation recency and
//! the passkey-change recency), and `AuthnServiceBuilder::try_build` refuses
//! any of them looser than the value of the profile the values came from
//! ([`SecurityProfile::values`](crate::profile::SecurityProfile::values),
//! whatever was assigned on a `ProfileValues` field since), whichever setter
//! wrote it and whether it ran before or after the profile was applied. The
//! refusal names the setting
//! ([`AuthnBuildError::BelowProfileFloor`]).
//!
//! The one way below a profile's value is a waiver the caller writes out,
//! per setting: `AuthnServiceBuilder::waive_profile_floor`. A waived setting
//! that is below the profile's value is logged once at `warn` when the
//! service is built and listed by `AuthnService::profile_deviations`, beside
//! `AuthnService::security_profile`: a service that says it runs a profile
//! either holds it or says exactly where it does not.
//!
//! The other settings a profile names are applied to values the service
//! never sees (the session layer's configuration, the refresh configuration
//! handed to each refresh, the CSRF and rate-limit layers, a JWT verifier,
//! the device cookie, a socket's options). For those the guarantee is the
//! one above: the method leaves the tighter of the two at the call, and what
//! the caller writes on the returned value afterwards is the caller's own.
//!
//! The profile is additive: it adds no default and removes none. See
//! `docs/production/strict-profile.md` for the value of each setting, why it
//! is that value, and what the profile leaves to the adopter.

use std::time::Duration;

use axess_factors::Argon2Cost;

pub use crate::authn::service::{AuthnBuildError, ProfileSetting};

use crate::authn::service::AuthnServiceBuilder;
use crate::authn::store::{FactorStore, IdentityStore};
use crate::middleware::csrf::CsrfConfig;
use crate::middleware::ratelimit::RateLimitConfigBuilder;
use crate::session::config::{SessionConfig, SessionConfigBuilder};
use crate::session::refresh::RefreshTokenConfig;

/// Which set of values to start from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityProfile {
    /// The library's own defaults, as values. Applying them changes nothing
    /// on a configuration at the defaults or tighter, and brings one that was
    /// loosened past a default back to it.
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
/// Every setting is a public field: read it back to see what the profile
/// sets, assign to it to override, then apply. The values remember the
/// profile they came from ([`profile`](Self::profile)), which is what a
/// service builder they are applied to is held to: a field assigned looser
/// than that profile's value does not lower the bar, it needs the named
/// waiver (`AuthnServiceBuilder::waive_profile_floor`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileValues {
    /// The profile these values came from.
    profile: SecurityProfile,
    /// Idle lifetime of a session, sliding
    /// ([`SessionConfig::ttl`](crate::session::config::SessionConfig::ttl)).
    pub session_idle_ttl: Duration,
    /// Absolute cap on an authenticated session
    /// ([`SessionConfig::max_authenticated_age`](crate::session::config::SessionConfig::max_authenticated_age)).
    pub session_max_authenticated_age: Option<Duration>,
    /// Sliding lifetime of a refresh token
    /// ([`RefreshTokenConfig::ttl`](crate::session::refresh::RefreshTokenConfig)).
    pub refresh_ttl: Duration,
    /// Absolute lifetime of a refresh-token family
    /// ([`RefreshTokenConfig::max_lifetime`](crate::session::refresh::RefreshTokenConfig)).
    pub refresh_max_lifetime: Option<Duration>,
    /// How recently a session must have authenticated to change a passkey
    /// (`Fido2Options::max_authn_age`). Five minutes under both profiles.
    /// `None` names no limit and leaves the one the options hold, the
    /// library's five minutes included. A service under a profile is held
    /// to the profile's five minutes when it is built; the opt-out that
    /// applies no limit is `max_authn_age: None` on the builder's options
    /// together with the named waiver,
    /// `waive_profile_floor(ProfileSetting::Fido2MaxAuthnAge)`.
    pub fido2_max_authn_age: Option<Duration>,
    /// Clock-skew tolerance of a JWT verifier
    /// (`JwtVerifier::with_clock_skew`).
    pub jwt_leeway: Duration,
    /// The `typ` header a JWT verifier should require of an access token,
    /// applied by [`access_token_verifier`](Self::access_token_verifier)
    /// through `JwtVerifier::with_typ`; `None` requires none.
    pub jwt_expected_typ: Option<String>,
    /// Whether a back-channel logout token must carry `typ: logout+jwt`
    /// (`OAuthProviderBuilder::with_required_logout_typ`).
    pub logout_typ_required: bool,
    /// Whether the server screens the URLs it fetches for discovery and key
    /// sets: HTTPS only and no connection to a reserved address. Under a
    /// screened policy the egress client never follows a proxy named in the
    /// environment. `egress_policy` turns it into the
    /// policy a provider is discovered under and a fetching client is built
    /// from. `true` under both
    /// profiles, as it is the library's default; `false`, assigned before
    /// applying, is the opt-out for an identity provider on the
    /// deployment's own network.
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
    /// Lifetime of a device-key proof cookie
    /// (`DeviceKeyConfig::with_proof_ttl`): what a copied cookie store is
    /// still worth on a device-bound session.
    pub device_key_proof_ttl: Duration,
    /// Oldest challenge a device-key proof may answer
    /// (`DeviceKeyConfig::with_challenge_ttl`).
    pub device_key_challenge_ttl: Duration,
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
            profile: SecurityProfile::Standard,
            session_idle_ttl: Duration::from_secs(DAY),
            session_max_authenticated_age: Some(Duration::from_secs(7 * DAY)),
            refresh_ttl: Duration::from_secs(30 * DAY),
            refresh_max_lifetime: Some(Duration::from_secs(90 * DAY)),
            fido2_max_authn_age: Some(Duration::from_secs(5 * MINUTE)),
            jwt_leeway: Duration::from_secs(MINUTE),
            jwt_expected_typ: None,
            logout_typ_required: false,
            egress_screened: true,
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
            device_key_proof_ttl: Duration::from_secs(10 * MINUTE),
            device_key_challenge_ttl: Duration::from_secs(20 * MINUTE),
        }
    }

    /// The strict set.
    fn strict() -> Self {
        Self {
            profile: SecurityProfile::Strict,
            session_idle_ttl: Duration::from_secs(15 * MINUTE),
            session_max_authenticated_age: Some(Duration::from_secs(8 * HOUR)),
            refresh_ttl: Duration::from_secs(DAY),
            refresh_max_lifetime: Some(Duration::from_secs(7 * DAY)),
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
            device_key_proof_ttl: Duration::from_secs(5 * MINUTE),
            device_key_challenge_ttl: Duration::from_secs(10 * MINUTE),
        }
    }

    /// The profile these values came from: the one a service builder they
    /// are applied to is held to when it is built, whatever was assigned on
    /// a field since.
    #[must_use]
    pub fn profile(&self) -> SecurityProfile {
        self.profile
    }

    /// A [`SessionConfigBuilder`] with the idle lifetime and the
    /// authenticated-age cap set; the caller continues with its own cookie
    /// name, `SameSite` and the rest, then builds. The builder is new, so it
    /// carries the profile's values; another lifetime is set on it, after
    /// the profile.
    #[must_use]
    pub fn session_config_builder(&self) -> SessionConfigBuilder {
        SessionConfig::builder()
            .ttl(self.session_idle_ttl)
            .max_authenticated_age(self.session_max_authenticated_age)
    }

    /// `base` with each refresh lifetime the shorter of its own and the
    /// profile's; a family with no absolute lifetime takes the profile's.
    /// Peppers, per-user limit and rotation stay as `base` has them.
    #[must_use]
    pub fn refresh_config(&self, mut base: RefreshTokenConfig) -> RefreshTokenConfig {
        base.ttl = base.ttl.min(self.refresh_ttl);
        base.max_lifetime = tighter_limit(base.max_lifetime, self.refresh_max_lifetime);
        base
    }

    /// `base` with the passkey-change recency the shorter of its own and
    /// the profile's, a requirement on either side beating none. The
    /// ceremonies and the ceremony timeout are kept.
    #[cfg(feature = "fido2")]
    #[cfg_attr(docsrs, doc(cfg(feature = "fido2")))]
    #[must_use]
    pub fn fido2_options(
        &self,
        mut base: crate::authn::factor::Fido2Options,
    ) -> crate::authn::factor::Fido2Options {
        base.max_authn_age = tighter_limit(base.max_authn_age, self.fido2_max_authn_age);
        base
    }

    /// `verifier`, a verifier of access tokens, with the clock-skew
    /// tolerance the smaller of its own and the profile's and, when the
    /// profile names one, the JOSE `typ` an access token must carry
    /// ([`jwt_expected_typ`](Self::jwt_expected_typ), `at+jwt` under
    /// `Strict`, through `JwtVerifier::with_typ`). A profile that names no
    /// `typ` leaves the requirement `verifier` has.
    ///
    /// Named for the access token because the `typ` is assigned over the
    /// one `verifier` had, two types having no order: a verifier of ID
    /// tokens, logout tokens or DPoP proofs passed through here would be
    /// retyped and refuse every token it was built for. Those go through
    /// [`jwt_leeway_only`](Self::jwt_leeway_only).
    #[cfg(feature = "jwt")]
    #[cfg_attr(docsrs, doc(cfg(feature = "jwt")))]
    #[must_use]
    pub fn access_token_verifier<R>(
        &self,
        verifier: axess_factors::jwt::verifier::JwtVerifier<R>,
    ) -> axess_factors::jwt::verifier::JwtVerifier<R> {
        let verifier = self.jwt_leeway_only(verifier);
        match &self.jwt_expected_typ {
            Some(typ) => verifier.with_typ(typ.clone()),
            None => verifier,
        }
    }

    /// `verifier` with the clock-skew tolerance the smaller of its own and
    /// the profile's, and its `typ` requirement left as it is: for a
    /// verifier of ID tokens, logout tokens or DPoP proofs, whose `typ` is
    /// not the access token's.
    #[cfg(feature = "jwt")]
    #[cfg_attr(docsrs, doc(cfg(feature = "jwt")))]
    #[must_use]
    pub fn jwt_leeway_only<R>(
        &self,
        verifier: axess_factors::jwt::verifier::JwtVerifier<R>,
    ) -> axess_factors::jwt::verifier::JwtVerifier<R> {
        let leeway = verifier.clock_skew().min(self.jwt_leeway);
        verifier.with_clock_skew(leeway)
    }

    /// The egress policy for discovery: pass it to
    /// `OAuthProviderConfig::discover_screened`, or build the client the
    /// OIDC fetches take from it (`egress_policy().build_client(..)` for
    /// `DiscoveryDocument::fetch`, `Discovery::fetch` and `JwksCache::fetch`,
    /// which take a client and no policy).
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

    /// `builder` requiring the logout-token `typ` when the profile does; a
    /// requirement `builder` already has is kept.
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

    /// `store` wrapped in a cache with the profile's time-to-live. The cache
    /// is new, so it carries the profile's value; another one is set on the
    /// returned store, after the profile.
    #[cfg(feature = "device")]
    #[cfg_attr(docsrs, doc(cfg(feature = "device")))]
    #[must_use]
    pub fn cached_device_store<S: crate::device::DeviceStore>(
        &self,
        store: S,
    ) -> crate::device::CachedDeviceStore<S> {
        crate::device::CachedDeviceStore::new(store).with_ttl(self.device_cache_ttl)
    }

    /// `base` with the device-trust cookie lifetime the shorter of its own
    /// and the profile's.
    #[cfg(feature = "device")]
    #[cfg_attr(docsrs, doc(cfg(feature = "device")))]
    #[must_use]
    pub fn device_cookie_config(
        &self,
        base: crate::device::DeviceCookieConfig,
    ) -> crate::device::DeviceCookieConfig {
        let max_age = base.max_age().min(self.device_cookie_max_age);
        base.with_max_age(max_age)
    }

    /// `base` with the device-key proof lifetime and the challenge lifetime
    /// each the shorter of its own and the profile's. The policy is left as
    /// `base` has it: a profile never chooses
    /// [`KeyBindingPolicy::Require`](crate::device_key::KeyBindingPolicy::Require),
    /// which signs out every browser that has no key store.
    ///
    /// The proof lifetime is what a copied proof cookie is worth and how
    /// long a key-bound session is still served after its device is
    /// revoked, so a lifetime the adopter shortened survives the profile.
    /// The acceptance grace stays `base`'s own. Where each side keeps its
    /// challenge lifetime above its proof lifetime plus that grace, the
    /// result does too: the shorter proof lifetime is at most the proof
    /// lifetime of the side whose challenge lifetime is the shorter, so
    /// proof plus grace stays below that challenge lifetime. Where the
    /// profile's own pair leaves no room for `base`'s grace (`Strict`'s five
    /// and ten minutes against a grace of five minutes), the result is one
    /// [`DeviceKeyConfig::validate`](crate::device_key::DeviceKeyConfig::validate)
    /// refuses, and so does the service built from it: no lifetime is
    /// lengthened to make room.
    #[cfg(feature = "device-keys")]
    #[cfg_attr(docsrs, doc(cfg(feature = "device-keys")))]
    #[must_use]
    pub fn device_key_config(
        &self,
        base: crate::device_key::DeviceKeyConfig,
    ) -> crate::device_key::DeviceKeyConfig {
        let proof = base.proof_ttl().min(self.device_key_proof_ttl);
        let challenge = base.challenge_ttl().min(self.device_key_challenge_ttl);
        base.with_proof_ttl(proof).with_challenge_ttl(challenge)
    }

    /// `base` with the application's own origins as the allow-list.
    ///
    /// When the profile requires origin checking, an empty `own_origins`
    /// and any entry that is not an origin are refused; when it does not,
    /// an empty list returns `base` unchanged, so a check `base` already
    /// makes is never turned off. A list `base` already had is replaced by
    /// `own_origins`, not merged: two lists of origins have no order, and
    /// the caller names this one at the call.
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

    /// `base` with the socket lifetime the shorter of its own and the
    /// profile's, a limit on either side beating none.
    #[cfg(feature = "ws")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ws")))]
    #[must_use]
    pub fn watch_options(
        &self,
        mut base: crate::middleware::ws::WatchOptions,
    ) -> crate::middleware::ws::WatchOptions {
        base.max_lifetime = tighter_limit(base.max_lifetime, self.ws_max_lifetime);
        base
    }

    /// A rate-limit builder with the profile's request budget and window,
    /// for the authentication routes; the caller sets the key and builds.
    /// The builder is new, so it carries the profile's values; another
    /// budget is set on it, after the profile.
    #[must_use]
    pub fn auth_rate_limit_builder(&self) -> RateLimitConfigBuilder {
        crate::middleware::ratelimit::RateLimitConfig::builder()
            .max_requests(self.auth_rate_limit_max_requests)
            .window(self.auth_rate_limit_window)
    }

    /// `builder` put under this profile, with the password hashing cost,
    /// the password reset lifetime and cap, the impersonation recency and
    /// (with `fido2`) the passkey-change recency each the tighter of the
    /// builder's own and these values:
    ///
    /// - the reset cap and the default reset lifetime are the shorter of the
    ///   two, a builder with no default lifetime takes the profile's, and
    ///   the default lifetime is never left above the cap;
    /// - the impersonation and passkey-change recency are the shorter of
    ///   the two, a requirement on either side beating none;
    /// - the Argon2id cost takes the larger memory and the larger number of
    ///   passes of the two and keeps the builder's lanes.
    ///
    /// The FIDO2 options the builder already holds (ceremonies, ceremony
    /// timeout) are kept: only `max_authn_age` changes, through
    /// [`fido2_options`](Self::fido2_options).
    ///
    /// The builder remembers the profile ([`profile`](Self::profile), the
    /// stricter one when two are applied) and is held to it when the
    /// service is built: `try_build` refuses a setting looser than the
    /// profile's value, whichever setter wrote it and whenever, a field
    /// assigned looser on these values included, unless the caller named
    /// the setting with `waive_profile_floor`. See the
    /// [module documentation](self).
    #[must_use]
    pub fn authn_service_builder<I, F>(
        &self,
        builder: AuthnServiceBuilder<I, F>,
    ) -> AuthnServiceBuilder<I, F>
    where
        I: IdentityStore,
        F: FactorStore<Error = I::Error>,
    {
        let cap = builder
            .max_password_reset_ttl()
            .min(self.max_password_reset_ttl);
        let cost = builder.argon2_cost().raised_to(self.argon2_cost);
        let mut builder = builder
            .with_max_password_reset_ttl(cap)
            .with_argon2_cost(cost);
        // The shorter of the two default lifetimes, and never above the cap
        // just settled: a default the cap refuses would fail every reset.
        let ttl = tighter_limit(builder.password_reset_ttl(), self.password_reset_ttl);
        if let Some(ttl) = ttl {
            builder = builder.with_password_reset_ttl(ttl.min(cap));
        }
        if let Some(age) = self.impersonation_max_authn_age {
            let age = builder
                .impersonation_max_authn_age()
                .map_or(age, |own| own.min(age));
            builder = builder.with_impersonation_max_authn_age(age);
        }
        #[cfg(feature = "fido2")]
        {
            let current = builder.fido2_options().clone();
            builder = builder.with_fido2_options(self.fido2_options(current));
        }
        builder.under_profile(self.profile)
    }
}

/// The tighter of two limits that may be absent, `None` being no limit: a
/// limit beats none, and of two limits the smaller.
fn tighter_limit<T: Ord>(own: Option<T>, profile: Option<T>) -> Option<T> {
    match (own, profile) {
        (Some(own), Some(profile)) => Some(own.min(profile)),
        (limit, None) | (None, limit) => limit,
    }
}

/// 64 MiB, two passes, one lane: above the OWASP minimum the library pins,
/// within what a login worker pool absorbs.
///
/// The arguments are constants above the floor and within the hashing
/// library's range, so the constructor cannot refuse them; a refusal would
/// be a change to the constants and is a panic at the first use, not a
/// silent fall back to the default cost.
fn strict_argon2_cost() -> Argon2Cost {
    const STRICT_M_COST_KIB: u32 = 64 * 1024;
    Argon2Cost::new(
        STRICT_M_COST_KIB,
        axess_factors::password::ARGON2_T_COST,
        axess_factors::password::ARGON2_P_COST,
    )
    .expect("the strict Argon2id cost is a constant above the floor and within range")
}

#[cfg(all(test, feature = "device-keys"))]
mod tests;
