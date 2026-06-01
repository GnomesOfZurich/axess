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

const DEFAULT_COOKIE_NAME: &str = "axess.sid";
const DEFAULT_TTL: Duration = Duration::from_secs(24 * 60 * 60); // 24 hours
/// Default maximum size of serialized custom session data (64 KiB).
const DEFAULT_MAX_CUSTOM_BYTES: usize = 64 * 1024;

/// Session configuration controlling cookie attributes and session lifetime.
///
/// Use [`SessionConfig::builder()`] for ergonomic construction, or
/// [`SessionConfig::default()`] for production-safe defaults.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Session time-to-live in the store and `Max-Age` on the cookie.
    pub ttl: Duration,
    /// Cookie name (default: `"axess.sid"`).
    ///
    /// Prefer the `__Host-` prefix in production (e.g.,
    /// `"__Host-axess.sid"`). Browsers refuse to set a `__Host-` cookie
    /// unless `Secure=true`, `Path="/"`, and the cookie has no `Domain`
    /// attribute: together these prevent subdomain-scoped overwrites and
    /// cross-host injection that the bare name does not. Using the prefix
    /// without `Secure=true` panics in `build()` to fail fast on
    /// misconfiguration. The `__Secure-` prefix is similar but only
    /// requires `Secure=true`.
    pub cookie_name: Arc<str>,
    /// Set the `Secure` flag on the cookie (default: `true`).
    ///
    /// Set to `false` for local HTTP development.
    pub secure: bool,
    /// `SameSite` policy (default: `Lax`).
    ///
    /// `Lax` is the right default for axess: the OAuth/OIDC callback flow
    /// depends on the cookie being delivered on the IdP's top-level GET
    /// redirect back to the application, which `Strict` would strip. `Lax`
    /// still blocks the cookie from cross-site sub-resource requests
    /// (`<img>`, `<iframe>`, `fetch()` without credentials), but **does
    /// deliver the cookie on top-level navigations from a third-party
    /// origin**. Applications MUST therefore layer their own CSRF defence
    /// on every state-changing POST/PUT/DELETE; the bundled
    /// `axess_core::middleware::csrf` middleware does this, but it is opt-in.
    pub same_site: SameSite,
    /// Set the `HttpOnly` flag on the cookie (default: `true`).
    pub http_only: bool,
    /// Cookie `Path` attribute (default: `"/"`).
    pub path: Arc<str>,
    /// Maximum size (in bytes) of serialized custom session data (default: 64 KiB).
    ///
    /// Prevents session-bloat DoS where an attacker inflates the custom JSON
    /// bag to exhaust storage. Set to `0` to disable the limit.
    pub max_custom_bytes: usize,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            ttl: DEFAULT_TTL,
            cookie_name: DEFAULT_COOKIE_NAME.into(),
            secure: true,
            same_site: SameSite::Lax,
            http_only: true,
            path: "/".into(),
            max_custom_bytes: DEFAULT_MAX_CUSTOM_BYTES,
        }
    }
}

impl SessionConfig {
    /// Create a [`SessionConfigBuilder`] with production-safe defaults.
    pub fn builder() -> SessionConfigBuilder {
        SessionConfigBuilder(SessionConfig::default())
    }
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

    /// Set the cookie name (default: `"axess.sid"`).
    pub fn cookie_name(mut self, name: impl Into<Arc<str>>) -> Self {
        self.0.cookie_name = name.into();
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

    /// Consume the builder and return the finished [`SessionConfig`].
    ///
    /// # Panics
    ///
    /// Panics if `ttl` is zero (sessions would expire immediately), if
    /// `cookie_name` is empty, or if a `__Host-` / `__Secure-` cookie name
    /// prefix is used without `Secure=true` (the prefix would be silently
    /// dropped by browsers and the security promise lost; better to fail
    /// fast at construction time than to ship a misconfigured cookie).
    pub fn build(self) -> SessionConfig {
        assert!(
            !self.0.ttl.is_zero(),
            "SessionConfig: ttl must be > 0 (sessions would expire immediately)"
        );
        assert!(
            !self.0.cookie_name.is_empty(),
            "SessionConfig: cookie_name must not be empty"
        );
        let name: &str = &self.0.cookie_name;
        if name.starts_with("__Host-") {
            assert!(
                self.0.secure,
                "SessionConfig: cookie name `{name}` requires `secure = true`"
            );
            assert!(
                self.0.path.as_ref() == "/",
                "SessionConfig: cookie name `{name}` requires `path = \"/\"`"
            );
        } else if name.starts_with("__Secure-") {
            assert!(
                self.0.secure,
                "SessionConfig: cookie name `{name}` requires `secure = true`"
            );
        }
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_production_safe_values() {
        let config = SessionConfig::default();
        assert_eq!(config.ttl, Duration::from_secs(86400));
        assert_eq!(config.cookie_name.as_ref(), "axess.sid");
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
}
