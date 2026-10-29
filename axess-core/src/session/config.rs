//! Session configuration: cookie attributes and TTL, with a builder for ergonomic construction.
//!
//! # Example
//!
//! ```rust
//! use axess_core::session::config::SessionConfig;
//! use std::time::Duration;
//!
//! let config = SessionConfig::builder()
//!     .ttl(Duration::from_secs(7200))
//!     .cookie_name("my.sid")
//!     .secure(true)
//!     .same_site(axess_core::session::config::SameSite::Strict)
//!     .http_only(true)
//!     .build();
//! ```

use std::sync::Arc;
use std::time::Duration;

// Re-export SameSite so callers don't need tower_cookies in their Cargo.toml.
pub use tower_cookies::cookie::SameSite;

/// Default cookie name when the cookie is `Secure` and scoped to `/`.
const DEFAULT_COOKIE_NAME: &str = "__Host-axess.sid";
/// Cookie name used instead of [`DEFAULT_COOKIE_NAME`] when the config does
/// not name a cookie and the `__Host-` prefix cannot hold (`Secure` off, or a
/// `Path` other than `/`): browsers drop a prefixed cookie that breaks those
/// rules, so the unprefixed name is the one that still works.
const FALLBACK_COOKIE_NAME: &str = "axess.sid";
const DEFAULT_TTL: Duration = Duration::from_secs(24 * 60 * 60); // 24 hours
/// Default maximum size of serialized custom session data (64 KiB).
const DEFAULT_MAX_CUSTOM_BYTES: usize = 64 * 1024;

/// Session configuration controlling cookie attributes and session lifetime.
///
/// Construct via [`SessionConfig::builder()`] (or
/// [`SessionConfig::default()`] for production-safe defaults): fields
/// are crate-private so struct-literal construction cannot bypass the
/// validation `SessionConfigBuilder::build` performs (`__Host-` prefix
/// requires `secure=true`, non-zero TTL, non-empty cookie name). The same
/// checks run when the layer is built from a config, so the layer's
/// own `with_*` setters cannot bypass them either.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub(crate) ttl: Duration,
    pub(crate) cookie_name: Arc<str>,
    /// `true` when the name was chosen by the caller. A name nobody chose is
    /// resolved by [`finalize`](Self::finalize) against `secure` and `path`.
    pub(crate) cookie_name_explicit: bool,
    pub(crate) secure: bool,
    pub(crate) same_site: SameSite,
    pub(crate) http_only: bool,
    pub(crate) path: Arc<str>,
    pub(crate) max_custom_bytes: usize,
    pub(crate) max_authenticated_age: Option<Duration>,
}

impl SessionConfig {
    /// Session time-to-live in the store and `Max-Age` on the cookie.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Cookie name (default: `"__Host-axess.sid"`, or `"axess.sid"` when the
    /// cookie is not `Secure` or its `Path` is not `/`, where the prefix
    /// could not hold).
    ///
    /// The default carries the `__Host-` prefix. Browsers refuse to set a `__Host-` cookie
    /// unless `Secure=true`, `Path="/"`, and the cookie has no `Domain`
    /// attribute: together these prevent subdomain-scoped overwrites and
    /// cross-host injection that the bare name does not. The
    /// [`SessionConfigBuilder`] enforces these constraints at
    /// construction time.
    pub fn cookie_name(&self) -> &str {
        &self.cookie_name
    }

    /// `Secure` cookie flag (default: `true`; disable only for local HTTP dev).
    pub fn secure(&self) -> bool {
        self.secure
    }

    /// `SameSite` policy (default: `Lax`).
    ///
    /// `Lax` is the right default for axess: the OAuth/OIDC callback flow
    /// depends on the cookie being delivered on the IdP's top-level GET
    /// redirect back to the application, which `Strict` would strip.
    /// Applications MUST therefore layer their own CSRF defence on every
    /// state-changing POST/PUT/DELETE; the bundled
    /// [`axess_core::middleware::csrf`](crate::middleware::csrf) module
    /// does this, but it is opt-in.
    pub fn same_site(&self) -> SameSite {
        self.same_site
    }

    /// `HttpOnly` cookie flag (default: `true`).
    pub fn http_only(&self) -> bool {
        self.http_only
    }

    /// Cookie `Path` attribute (default: `"/"`).
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Maximum size (in bytes) of serialized custom session data
    /// (default: 64 KiB; `0` disables the limit). Prevents session-bloat
    /// DoS where an attacker inflates the custom JSON bag to exhaust
    /// storage.
    pub fn max_custom_bytes(&self) -> usize {
        self.max_custom_bytes
    }

    /// Absolute cap on how long an authenticated session may live, measured
    /// from the moment it authenticated (default: none, so the sliding
    /// [`ttl`](Self::ttl) is the only bound). When set, a session whose
    /// authentication is older than this is ended on its next request,
    /// however recently it was used.
    pub fn max_authenticated_age(&self) -> Option<Duration> {
        self.max_authenticated_age
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            ttl: DEFAULT_TTL,
            cookie_name: DEFAULT_COOKIE_NAME.into(),
            cookie_name_explicit: false,
            secure: true,
            same_site: SameSite::Lax,
            http_only: true,
            path: "/".into(),
            max_custom_bytes: DEFAULT_MAX_CUSTOM_BYTES,
            max_authenticated_age: None,
        }
    }
}

impl SessionConfig {
    /// Create a [`SessionConfigBuilder`] with production-safe defaults.
    pub fn builder() -> SessionConfigBuilder {
        SessionConfigBuilder(SessionConfig::default())
    }

    /// Resolve a cookie name nobody chose against `secure` and `path`, then
    /// check the invariants every config must satisfy.
    ///
    /// Returns the resolved config. Runs from the builder's `build` and from
    /// the layer when it is turned into a service, after every setter, so the
    /// order the setters were called in does not matter.
    ///
    /// # Panics
    ///
    /// Panics (with a message naming the setting) if `ttl` is zero, the
    /// cookie name is empty or not a valid cookie token, a `__Host-` or
    /// `__Secure-` name is used without `Secure`, a `__Host-` name is used
    /// with a `Path` other than `/`, or `SameSite=None` is used without
    /// `Secure` (browsers reject that combination).
    pub(crate) fn finalize(mut self) -> Self {
        if !self.cookie_name_explicit {
            self.cookie_name = if self.secure && self.path.as_ref() == "/" {
                DEFAULT_COOKIE_NAME.into()
            } else {
                FALLBACK_COOKIE_NAME.into()
            };
        }
        self.validate();
        self
    }

    fn validate(&self) {
        assert!(
            !self.ttl.is_zero(),
            "SessionConfig: ttl must be > 0 (sessions would expire immediately)"
        );
        let name: &str = &self.cookie_name;
        assert!(
            !name.is_empty(),
            "SessionConfig: cookie_name must not be empty"
        );
        assert!(
            name.bytes().all(is_cookie_token_byte),
            "SessionConfig: cookie name `{name}` contains characters that are not valid in a cookie name"
        );
        if name.starts_with("__Host-") {
            assert!(
                self.secure,
                "SessionConfig: cookie name `{name}` requires `secure = true`"
            );
            assert!(
                self.path.as_ref() == "/",
                "SessionConfig: cookie name `{name}` requires `path = \"/\"`"
            );
        } else if name.starts_with("__Secure-") {
            assert!(
                self.secure,
                "SessionConfig: cookie name `{name}` requires `secure = true`"
            );
        }
        assert!(
            self.max_authenticated_age.is_none_or(|a| !a.is_zero()),
            "SessionConfig: max_authenticated_age must be > 0 (every session would end at once)"
        );
        assert!(
            self.same_site != SameSite::None || self.secure,
            "SessionConfig: `SameSite=None` requires `secure = true` (browsers reject the cookie otherwise)"
        );
    }
}

/// RFC 6265 `token` characters: what a cookie name may contain.
fn is_cookie_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// Whether the builder should emit the "insecure cookie" warning.
///
/// Lifted out of [`SessionConfigBuilder::secure`] so the boolean guard
/// is observable in a unit test without depending on a tracing capture.
fn should_warn_insecure_cookie(secure: bool) -> bool {
    !secure
}

/// Builder for [`SessionConfig`].
///
/// All fields start with production-safe defaults; override only what you need.
///
/// ```rust
/// use axess_core::session::config::SessionConfig;
/// use std::time::Duration;
///
/// let config = SessionConfig::builder()
///     .ttl(Duration::from_secs(7200))  // 2 hours
///     .secure(false)                    // local HTTP dev
///     .build();
/// ```
pub struct SessionConfigBuilder(SessionConfig);

impl SessionConfigBuilder {
    /// Set the session TTL (default: 24 hours).
    pub fn ttl(mut self, ttl: Duration) -> Self {
        self.0.ttl = ttl;
        self
    }

    /// Set the cookie name (default: `"__Host-axess.sid"`, or `"axess.sid"`
    /// when `secure` is off or the path is not `/`).
    pub fn cookie_name(mut self, name: impl Into<Arc<str>>) -> Self {
        self.0.cookie_name = name.into();
        self.0.cookie_name_explicit = true;
        self
    }

    /// Set the `Secure` flag (default: `true`).
    ///
    /// Set to `false` only for local HTTP development.
    pub fn secure(mut self, secure: bool) -> Self {
        if should_warn_insecure_cookie(secure) {
            tracing::warn!(
                "SessionConfig: Secure cookie flag disabled; session cookies \
                 will be sent over plain HTTP. Do not use in production."
            );
        }
        self.0.secure = secure;
        self
    }

    /// Set the `SameSite` policy (default: `Lax`).
    pub fn same_site(mut self, same_site: SameSite) -> Self {
        self.0.same_site = same_site;
        self
    }

    /// Set the `HttpOnly` flag (default: `true`).
    pub fn http_only(mut self, http_only: bool) -> Self {
        self.0.http_only = http_only;
        self
    }

    /// Set the cookie `Path` attribute (default: `"/"`).
    pub fn path(mut self, path: impl Into<Arc<str>>) -> Self {
        self.0.path = path.into();
        self
    }

    /// Set the maximum size of serialized custom session data (default: 64 KiB).
    ///
    /// Set to `0` to disable the limit.
    pub fn max_custom_bytes(mut self, max: usize) -> Self {
        self.0.max_custom_bytes = max;
        self
    }

    /// Cap how long an authenticated session may live, however active it is
    /// (default: no cap). Must be non-zero.
    pub fn max_authenticated_age(mut self, max_age: Duration) -> Self {
        self.0.max_authenticated_age = Some(max_age);
        self
    }

    /// Consume the builder and return the finished [`SessionConfig`].
    ///
    /// # Panics
    ///
    /// Panics if `ttl` is zero (sessions would expire immediately), if
    /// `cookie_name` is empty or not a valid cookie name, if a `__Host-` /
    /// `__Secure-` cookie name prefix is used without `Secure=true` (the
    /// prefix would be silently dropped by browsers and the security promise
    /// lost; better to fail fast at construction time than to ship a
    /// misconfigured cookie), if a `__Host-` name is used with a `Path`
    /// other than `/`, or if `SameSite=None` is used without `Secure=true`.
    pub fn build(self) -> SessionConfig {
        self.0.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_production_safe_values() {
        let config = SessionConfig::default();
        assert_eq!(config.ttl, Duration::from_secs(86400));
        assert_eq!(config.cookie_name.as_ref(), "__Host-axess.sid");
        assert!(config.secure);
        assert_eq!(config.same_site, SameSite::Lax);
        assert!(config.http_only);
        assert_eq!(config.path.as_ref(), "/");
        // Pin DEFAULT_MAX_CUSTOM_BYTES at exactly 64 KiB.
        // Kills `64 * 1024` → `+` (1088) and `/` (0) mutations.
        assert_eq!(
            config.max_custom_bytes, 65536,
            "DEFAULT_MAX_CUSTOM_BYTES must be 64 * 1024 = 65536"
        );
    }

    #[test]
    fn builder_overrides_defaults() {
        let config = SessionConfig::builder()
            .ttl(Duration::from_secs(7200))
            .cookie_name("custom.sid")
            .secure(false)
            .same_site(SameSite::Strict)
            .http_only(false)
            .path("/app")
            .build();

        assert_eq!(config.ttl, Duration::from_secs(7200));
        assert_eq!(config.cookie_name.as_ref(), "custom.sid");
        assert!(!config.secure);
        assert_eq!(config.same_site, SameSite::Strict);
        assert!(!config.http_only);
        assert_eq!(config.path.as_ref(), "/app");
    }

    #[test]
    fn should_warn_insecure_cookie_only_for_disabled_flag() {
        assert!(should_warn_insecure_cookie(false));
        assert!(!should_warn_insecure_cookie(true));
    }

    #[test]
    fn builder_partial_override_keeps_defaults() {
        let config = SessionConfig::builder()
            .ttl(Duration::from_secs(3600))
            .build();

        assert_eq!(config.ttl, Duration::from_secs(3600));
        // Everything else should be default.
        assert!(config.secure);
        assert_eq!(config.same_site, SameSite::Lax);
        assert!(config.http_only);
    }

    #[test]
    fn unnamed_cookie_is_host_prefixed_only_when_the_prefix_can_hold() {
        assert_eq!(
            SessionConfig::builder().build().cookie_name(),
            "__Host-axess.sid"
        );
        assert_eq!(
            SessionConfig::builder().secure(false).build().cookie_name(),
            "axess.sid"
        );
        assert_eq!(
            SessionConfig::builder().path("/app").build().cookie_name(),
            "axess.sid"
        );
    }

    #[test]
    fn a_chosen_name_is_kept_whatever_secure_says() {
        let c = SessionConfig::builder()
            .cookie_name("axess.sid")
            .secure(true)
            .build();
        assert_eq!(c.cookie_name(), "axess.sid");
    }

    #[test]
    #[should_panic(expected = "SameSite=None")]
    fn same_site_none_needs_secure() {
        let _ = SessionConfig::builder()
            .same_site(SameSite::None)
            .secure(false)
            .build();
    }

    #[test]
    fn same_site_none_with_secure_is_accepted() {
        let c = SessionConfig::builder().same_site(SameSite::None).build();
        assert_eq!(c.same_site(), SameSite::None);
    }

    #[test]
    #[should_panic(expected = "not valid in a cookie name")]
    fn cookie_name_must_be_a_token() {
        let _ = SessionConfig::builder().cookie_name("a b").build();
    }
}
