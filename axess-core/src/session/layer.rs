//! Tower middleware layer providing HMAC-signed session cookies and typed session data.
//!
//! # Cookie format
//!
//! `<session_id_base64url>.<hmac_base64url>`
//!
//! The HMAC-SHA256 is computed over the raw 16 bytes of the session UUID.
//! The cookie contains *only* the session ID; session data lives in the store.
//!
//! # Request lifecycle
//!
//! 1. Extract and verify the session cookie (HMAC check with constant-time comparison).
//! 2. Load [`crate::session::SessionData`] from the store (or create an empty default).
//! 3. Insert `SessionHandle` into request extensions.
//! 4. Call the inner service.
//! 5. If the session was modified, save it back to the store (or cycle the ID first).
//! 6. Set the session cookie on the response.

mod handle;
mod lifecycle;
mod service;
mod signing;

pub(crate) use handle::SessionHandle;
// `SessionInner` is `pub(crate)` only so test modules and the
// `testing::*` fixture helpers can construct sessions directly.
// Production callers go through `SessionHandle`, so gate the
// re-export to avoid an unused-import warning in plain prod builds.
#[cfg(any(test, feature = "testing"))]
pub(crate) use handle::SessionInner;
pub use service::SessionService;

#[cfg(feature = "device")]
use crate::device::resolver::{DeviceResolver, ErasedDeviceResolver};
use crate::session::binding::SessionBinding;
use crate::session::config::SessionConfig;
use crate::session::store::SessionStore;
use signing::{SigningKeys, hkdf_expand_subkey};
use std::{sync::Arc, time::Duration};
use tower_cookies::cookie::SameSite;

/// Tower layer that provides signed session cookies and typed [`crate::session::SessionData`].
///
/// Add this layer to your Axum router. Handlers receive an [`super::extractor::AuthSession`] extractor
/// which wraps the `SessionHandle` stored in request extensions.
///
/// ```text
/// let app = Router::new()
///     .route("/login", post(login_handler))
///     .layer(SessionLayer::new(store, signing_key));
/// ```
///
/// # Configuration
///
/// Cookie attributes and TTL are set via the `with_*` builder methods:
///
/// ```text
/// let layer = SessionLayer::new(store, key)
///     .with_ttl(Duration::from_secs(7200))
///     .with_secure(false)
///     .with_same_site(SameSite::Strict);
/// ```
#[derive(Clone)]
pub struct SessionLayer<S> {
    pub(super) store: S,
    pub(super) signing_keys: Arc<SigningKeys>,
    /// Shared via `Arc` so the `Layer::layer` clone (per inner
    /// service) and the per-request `Service::call` clone are both
    /// pointer copies, not full struct copies. `SessionConfig` carries
    /// several `Arc<str>` fields plus a number of small enums; cloning
    /// the whole thing on every request added measurable overhead on
    /// the middleware hot path.
    pub(super) config: Arc<SessionConfig>,
    pub(super) binding: Option<Arc<dyn SessionBinding>>,
    pub(super) metrics: Option<Arc<dyn crate::metrics::AuthnMetrics>>,
    /// Optional device resolver invoked once per request between
    /// session-data load and the inner handler. Stamps
    /// [`SessionData::device_id`](crate::session::SessionData::device_id)
    /// when the resolver returns `Some`.
    #[cfg(feature = "device")]
    pub(super) device_resolver: Option<Arc<dyn ErasedDeviceResolver>>,
}

impl<S: SessionStore> SessionLayer<S> {
    /// Create a session layer with the given store and 32-byte HMAC signing key.
    ///
    /// Uses [`SessionConfig::default()`]: production-safe defaults (24-hour TTL,
    /// `Secure`, `HttpOnly`, `SameSite=Lax`).
    ///
    /// The signing key derives sub-keys via HKDF for cookie HMAC,
    /// fingerprint HMAC, and CSRF; keep it in a secret store and rotate
    /// per your key-management policy (a fresh layer is required on
    /// rotation since the derived keys are cached).
    ///
    /// # Example
    ///
    /// ```no_run
    /// use axess_core::{MemorySessionStore, session::SessionLayer};
    /// use std::time::Duration;
    ///
    /// // Production: load the master key from a secret store (KMS, Vault, …).
    /// // Below uses a fixed value purely for the construction example.
    /// let signing_key: [u8; 32] = [0u8; 32];
    /// let store = MemorySessionStore::default();
    ///
    /// let layer = SessionLayer::new(store, signing_key)
    ///     .with_ttl(Duration::from_secs(3600))
    ///     .with_cookie_name("myapp.sid");
    ///
    /// // Attach to your router:
    /// //     let app = axum::Router::new().layer(layer);
    /// # let _ = layer;
    /// ```
    pub fn new(store: S, signing_key: [u8; 32]) -> Self {
        Self {
            store,
            // Derive distinct cookie / fingerprint HMAC sub-keys
            // from the master so a side-channel on one path cannot be
            // replayed against the other.
            signing_keys: Arc::new(SigningKeys::from_master(signing_key)),
            config: Arc::new(SessionConfig::default()),
            binding: None,
            metrics: None,
            #[cfg(feature = "device")]
            device_resolver: None,
        }
    }

    /// Borrow the per-request `SessionConfig`. Mutating
    /// setters take a fresh copy via `Arc::make_mut`, so production
    /// builds that only mutate during the construction phase share a
    /// single `Arc` across every cloned service.
    ///
    /// # Footgun
    ///
    /// **Mutate before cloning.** If you call `.clone()` on the layer
    /// (or pass it through `tower::Layer`) and *then* invoke a `with_*`
    /// setter, `Arc::make_mut` deep-copies the `SessionConfig` so your
    /// edit only affects the new clone; the previously-cloned service
    /// still holds the original. Always finish configuration before
    /// the layer enters the router. Debug builds catch the surprising
    /// case below.
    fn config_mut(&mut self) -> &mut SessionConfig {
        debug_assert!(
            Arc::strong_count(&self.config) == 1,
            "SessionLayer setter called after the layer was cloned (strong_count = {}). \
             The mutation will deep-copy SessionConfig and only affect this clone. Configure \
             the layer fully before passing it to `tower::Layer` / `Router::layer`.",
            Arc::strong_count(&self.config),
        );
        Arc::make_mut(&mut self.config)
    }

    /// Derive a 32-byte sub-key from this layer's master signing
    /// key using a caller-supplied `info` label. Use this to feed
    /// CSRF token signing, push-notification HMAC, or any other HMAC
    /// site that would otherwise be tempted to reuse the raw master
    /// key. Pick a stable byte-string label per use site (e.g.
    /// `b"my-app.v1.csrf"`); changing the label invalidates every
    /// value previously derived under it.
    ///
    /// The returned bytes are wrapped in [`zeroize::Zeroizing`] so they
    /// are wiped on drop: a compromise of any derived sub-key with a
    /// known label lets an attacker forge against that path, so the
    /// material is held under the same drop discipline as the master
    /// key. Deref through `*` or `as_ref()` to access the raw `[u8; 32]`.
    pub fn derive_subkey(&self, info: &'static [u8]) -> zeroize::Zeroizing<[u8; 32]> {
        zeroize::Zeroizing::new(hkdf_expand_subkey(&self.signing_keys.master, info))
    }

    /// Override the session TTL (default: 24 hours).
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.config_mut().ttl = ttl;
        self
    }

    /// Override the cookie name (default: `"axess.sid"`).
    pub fn with_cookie_name(mut self, name: impl Into<Arc<str>>) -> Self {
        self.config_mut().cookie_name = name.into();
        self
    }

    /// Set the `Secure` flag on the session cookie (default: `true`).
    ///
    /// Set to `false` only for local HTTP development. In production,
    /// cookies without the `Secure` flag can be intercepted on the network.
    pub fn with_secure(mut self, secure: bool) -> Self {
        if !secure {
            tracing::warn!(
                "SessionLayer: Secure cookie flag disabled; session cookies \
                 will be sent over plain HTTP. Do not use in production."
            );
        }
        self.config_mut().secure = secure;
        self
    }

    /// Set the `SameSite` policy (default: `Lax`).
    pub fn with_same_site(mut self, same_site: SameSite) -> Self {
        self.config_mut().same_site = same_site;
        self
    }

    /// Set the `HttpOnly` flag on the session cookie (default: `true`).
    pub fn with_http_only(mut self, http_only: bool) -> Self {
        self.config_mut().http_only = http_only;
        self
    }

    /// Override the maximum size (in bytes) of the JSON-encoded
    /// custom-data payload. Default: 64 KiB. Set to `0` to disable
    /// the clamp entirely (do this only if you have your own size
    /// guarding upstream of the session layer).
    ///
    /// When the clamp fires, the offending custom payload is
    /// dropped to `Value::Null` and a `tracing::warn!` is emitted;
    /// the session itself is preserved.
    pub fn with_max_custom_bytes(mut self, max: usize) -> Self {
        self.config_mut().max_custom_bytes = max;
        self
    }

    /// Set the cookie `Path` attribute (default: `"/"`).
    pub fn with_path(mut self, path: impl Into<Arc<str>>) -> Self {
        self.config_mut().path = path.into();
        self
    }

    /// Enable session-to-client binding for hijacking detection.
    ///
    /// When enabled, the library hashes client-specific request properties
    /// (determined by the [`SessionBinding`] implementation) and stores the
    /// hash in the session upon authentication. On every subsequent request
    /// the hash is recomputed and compared; a mismatch resets the session
    /// to `Guest` (the cookie may have been stolen by a different client).
    ///
    /// ```text
    /// use axess::session::UserAgentBinding;
    ///
    /// let layer = SessionLayer::new(store, key)
    ///     .with_binding(UserAgentBinding);
    /// ```
    pub fn with_binding(mut self, binding: impl SessionBinding) -> Self {
        self.binding = Some(Arc::new(binding));
        self
    }

    /// Attach a metrics hook for session-level observability.
    pub fn with_metrics(mut self, metrics: impl crate::metrics::AuthnMetrics) -> Self {
        self.metrics = Some(Arc::new(metrics));
        self
    }

    /// Configure a [`DeviceResolver`] to stamp
    /// [`SessionData::device_id`](crate::session::SessionData::device_id)
    /// on every request before the inner handler runs.
    ///
    /// Errors returned by the resolver are logged via `tracing::warn!`
    /// and treated as `None`; device resolution never fails the request.
    /// When unset (the default), `device_id` stays at whatever the loaded
    /// session carried, which for new sessions is `None`.
    ///
    /// See [`docs/identity/device.md`](https://github.com/GnomesOfZurich/axess/blob/main/docs/identity/device.md)
    /// for the full design.
    #[cfg(feature = "device")]
    pub fn with_device_resolver<R>(mut self, resolver: R) -> Self
    where
        R: DeviceResolver,
    {
        self.device_resolver = Some(Arc::new(resolver));
        self
    }
}

// Regression: confirm the `config_mut` debug_assert
// actually fires when a `SessionLayer` is cloned and *then* mutated.
// The Arc<SessionConfig> deep-copy in `Arc::make_mut` would otherwise
// silently divorce the two layers' configs. The assertion is a debug-only
// guard so the test is gated behind `debug_assertions`.
#[cfg(all(test, debug_assertions))]
mod make_mut_tests {
    use super::*;
    use crate::session::store::MemorySessionStore;

    #[test]
    #[should_panic(expected = "SessionLayer setter called after the layer was cloned")]
    fn setter_after_clone_panics_in_debug() {
        let store = MemorySessionStore::new();
        let layer = SessionLayer::new(store, [0u8; 32]);
        let cloned = layer.clone();
        // Cloning bumps the Arc strong count to 2; the next `with_ttl`
        // will trip the assertion before `Arc::make_mut` deep-copies.
        layer.with_ttl(Duration::from_secs(60));
        drop(cloned);
    }

    #[test]
    fn setter_before_clone_does_not_panic() {
        let store = MemorySessionStore::new();
        let layer = SessionLayer::new(store, [0u8; 32])
            .with_ttl(Duration::from_secs(60))
            .with_secure(false);
        // Clone after setters is fine; the configuration is already finalised.
        drop(layer.clone());
    }
}

/// `with_secure(false)` MUST emit a tracing warning so an
/// operator running on plain HTTP cannot miss the implication
/// of disabling the cookie's `Secure` flag in production.
/// `with_secure(true)` MUST stay silent: a warning on the safe
/// configuration trains operators to ignore the channel.
///
/// Pins `delete !` on the `if !secure` guard in `with_secure`:
/// with the `!` removed the predicate inverts, the warning fires
/// for `secure=true` (every production deployment) and stays silent
/// for `secure=false` (the actually-dangerous configuration).
#[cfg(test)]
mod with_secure_warning_tests {
    use super::*;
    use crate::session::store::MemorySessionStore;
    use crate::testing::mock_tracing::TracingCapture;

    #[test]
    fn with_secure_false_emits_warning() {
        let capture = TracingCapture::install();
        let store = MemorySessionStore::new();
        drop(SessionLayer::new(store, [0u8; 32]).with_secure(false));
        assert!(
            capture.contains_at_level(tracing::Level::WARN, "Secure cookie flag disabled"),
            "with_secure(false) must warn about plain-HTTP cookies"
        );
    }

    #[test]
    fn with_secure_true_does_not_emit_warning() {
        let capture = TracingCapture::install();
        let store = MemorySessionStore::new();
        drop(SessionLayer::new(store, [0u8; 32]).with_secure(true));
        assert!(
            !capture.contains_at_level(tracing::Level::WARN, "Secure cookie flag disabled"),
            "with_secure(true) must NOT warn; `delete !` mutation would invert this"
        );
    }
}
