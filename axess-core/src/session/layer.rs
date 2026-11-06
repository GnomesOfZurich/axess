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
mod swap;

pub(crate) use handle::SessionHandle;
pub(crate) use lifecycle::mark_cookie_response;
pub(crate) use service::FreshSession;
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
use crate::session::store::{SessionRegistryHandle, SessionStore};
use axess_clock::{Clock, SystemClock};
use axess_rng::{SecureRng, SystemRng};
use cookie::SameSite;
use signing::SigningKeyRing;
use std::{sync::Arc, time::Duration};

/// What the session layer does with an authenticated session when the
/// registry given to [`SessionLayer::new`] cannot answer (it errored).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UnknownLiveness {
    /// Treat the request as a guest for now, leave the stored row alone and
    /// do not replace the client's cookie, so the session works again once
    /// the registry answers. The default, and the fail-closed choice.
    #[default]
    Reject,
    /// Trust the stored session. A registry outage then does not log anyone
    /// out, and does not enforce revocation either.
    Accept,
}

/// Tower layer that provides signed session cookies and typed [`crate::session::SessionData`].
///
/// Add this layer to your Axum router. Handlers receive an [`super::extractor::AuthSession`] extractor
/// which wraps the `SessionHandle` stored in request extensions.
///
/// ```text
/// let app = Router::new()
///     .route("/login", post(login_handler))
///     .layer(SessionLayer::new(store, signing_key, registry));
/// ```
///
/// # Configuration
///
/// Cookie attributes and TTL are set via the `with_*` builder methods:
///
/// ```text
/// let layer = SessionLayer::new(store, key, registry)
///     .with_ttl(Duration::from_secs(7200))
///     .with_secure(false)
///     .with_same_site(SameSite::Strict);
/// ```
///
/// # Panics
///
/// The setters do not check anything, because their order varies. The whole
/// configuration is checked once, when the layer is turned into a service
/// (`Router::layer`, `ServiceBuilder::layer`), with the same rules as
/// [`SessionConfigBuilder::build`](crate::session::SessionConfigBuilder::build):
/// the TTL must be non-zero, the cookie name non-empty and made of valid
/// characters, a `__Host-` or `__Secure-` name needs `Secure`, a `__Host-`
/// name needs `Path=/`, and `SameSite=None` needs `Secure`. A violation
/// panics at startup with a message naming the setting, rather than
/// shipping a cookie browsers drop.
#[derive(Clone)]
pub struct SessionLayer<S> {
    pub(super) store: S,
    pub(super) signing_keys: Arc<SigningKeyRing>,
    /// Shared via `Arc` so the `Layer::layer` clone (per inner
    /// service) and the per-request `Service::call` clone are both
    /// pointer copies, not full struct copies. `SessionConfig` carries
    /// several `Arc<str>` fields plus a number of small enums; cloning
    /// the whole thing on every request added measurable overhead on
    /// the middleware hot path.
    pub(super) config: Arc<SessionConfig>,
    pub(super) binding: Option<Arc<dyn SessionBinding>>,
    pub(super) metrics: Option<Arc<dyn crate::metrics::AuthnMetrics>>,
    /// Source of every session id the layer mints (new sessions and
    /// rotations). Defaults to [`SystemRng`]; see [`with_rng`](Self::with_rng).
    pub(super) rng: Arc<dyn SecureRng>,
    /// Clock for the absolute session age cap; defaults to [`SystemClock`].
    pub(super) clock: Arc<dyn Clock>,
    /// Registry consulted for every authenticated record. `None` only for a
    /// layer built by [`without_registry_insecure`](Self::without_registry_insecure).
    pub(super) registry: Option<Arc<dyn SessionRegistryHandle>>,
    pub(super) unknown_liveness: UnknownLiveness,
    /// Origins a WebSocket upgrade may come from; empty means the request's
    /// own host. See [`with_websocket_origins`](Self::with_websocket_origins).
    pub(super) websocket_origins: Arc<[Arc<str>]>,
    /// Optional device resolver invoked once per request between
    /// session-data load and the inner handler. Stamps
    /// [`SessionData::device_id`](crate::session::SessionData::device_id)
    /// when the resolver returns `Some`.
    #[cfg(feature = "device")]
    pub(super) device_resolver: Option<Arc<dyn ErasedDeviceResolver>>,
}

impl<S: SessionStore> SessionLayer<S> {
    /// Create a session layer with the given store, 32-byte HMAC signing key
    /// and session registry.
    ///
    /// Uses [`SessionConfig::default()`]: production-safe defaults (24-hour
    /// sliding TTL, a 7-day cap from authentication and a 1-hour cap on
    /// impersonation, `Secure`, `HttpOnly`, `SameSite=Lax`). Lift a cap with
    /// [`with_max_session_age(None)`](Self::with_max_session_age) or
    /// [`with_max_impersonation_age(None)`](Self::with_max_impersonation_age).
    ///
    /// The registry is consulted for every authenticated session, so that a
    /// revocation (suspension, password reset, administrator kick,
    /// log-out-everywhere, the per-user session cap) takes effect on the next
    /// request whatever guards the route: an authenticated session the
    /// registry no longer holds is deleted from the store and the request runs
    /// as a new guest, with the client's cookie replaced. Guests and part-way
    /// logins are not checked. The cost is one registry call per authenticated
    /// request. Pass the registry the authentication service was built with.
    /// What happens when the registry cannot answer is set by
    /// [`with_unknown_liveness`](Self::with_unknown_liveness). A deployment
    /// that truly keeps no registry builds with
    /// [`without_registry_insecure`](Self::without_registry_insecure).
    ///
    /// The signing key derives sub-keys via HKDF for cookie HMAC,
    /// fingerprint HMAC, and CSRF; keep it in a secret store and rotate
    /// per your key-management policy (a fresh layer is required on
    /// rotation since the derived keys are cached).
    ///
    /// # Example
    ///
    /// ```no_run
    /// use axess_core::{MemorySessionRegistry, MemorySessionStore, session::SessionLayer};
    /// use axess_core::session::store::SessionRegistryAdapter;
    /// use std::{sync::Arc, time::Duration};
    ///
    /// // Production: load 32 random bytes from a secret store (KMS, Vault, a
    /// // mounted secret). A constant key such as all zeros is refused.
    /// let signing_key: [u8; 32] = std::fs::read("/run/secrets/axess-signing-key")
    ///     .expect("signing key file")
    ///     .try_into()
    ///     .expect("exactly 32 bytes");
    /// let store = MemorySessionStore::default();
    /// let registry = Arc::new(SessionRegistryAdapter(MemorySessionRegistry::new()));
    ///
    /// let layer = SessionLayer::new(store, signing_key, registry)
    ///     .with_ttl(Duration::from_secs(3600))
    ///     .with_cookie_name("myapp.sid");
    ///
    /// // Attach to your router:
    /// //     let app = axum::Router::new().layer(layer);
    /// # let _ = layer;
    /// ```
    ///
    /// # Panics
    ///
    /// On a `signing_key` that is a single repeated byte (all zeros
    /// included), a placeholder that reached production. Use
    /// [`try_new`](Self::try_new) to handle the refusal.
    #[track_caller]
    pub fn new(store: S, signing_key: [u8; 32], registry: Arc<dyn SessionRegistryHandle>) -> Self {
        super::weak_key::refuse_constant_key("session signing key", &signing_key);
        Self::build(store, signing_key, Some(registry))
    }

    /// [`new`](Self::new) without the constant-key check, for tests that use
    /// a placeholder key.
    #[cfg(any(test, feature = "testing"))]
    pub fn new_unchecked(
        store: S,
        signing_key: [u8; 32],
        registry: Arc<dyn SessionRegistryHandle>,
    ) -> Self {
        Self::build(store, signing_key, Some(registry))
    }

    /// Create a session layer that keeps no registry, so a revocation removes
    /// the session from the registry only: the stored row stays valid on any
    /// route not behind the validator middleware. Logs at error level once, at
    /// build. Prefer [`new`](Self::new).
    ///
    /// # Panics
    ///
    /// On a constant `signing_key`, as [`new`](Self::new).
    #[track_caller]
    pub fn without_registry_insecure(store: S, signing_key: [u8; 32]) -> Self {
        super::weak_key::refuse_constant_key("session signing key", &signing_key);
        tracing::error!(
            target: "axess::session::layer",
            "SessionLayer built without a registry: a revoked session (password reset, \
             administrator kick, log-out-everywhere) stays valid in the store on every route \
             not behind the validator middleware"
        );
        Self::build(store, signing_key, None)
    }

    fn build(
        store: S,
        signing_key: [u8; 32],
        registry: Option<Arc<dyn SessionRegistryHandle>>,
    ) -> Self {
        Self {
            store,
            // Derive distinct cookie / fingerprint HMAC sub-keys
            // from the master so a side-channel on one path cannot be
            // replayed against the other. Rotation slot starts empty;
            // adopters opt in via
            // [`with_previous_signing_key`](Self::with_previous_signing_key).
            signing_keys: Arc::new(SigningKeyRing::from_master(signing_key)),
            config: Arc::new(SessionConfig::default()),
            binding: None,
            metrics: None,
            rng: Arc::new(SystemRng),
            clock: Arc::new(SystemClock),
            registry,
            unknown_liveness: UnknownLiveness::default(),
            websocket_origins: Arc::from(Vec::new()),
            #[cfg(feature = "device")]
            device_resolver: None,
        }
    }

    /// Like [`new`](Self::new), refusing a signing key that is a single
    /// repeated byte.
    ///
    /// # Errors
    ///
    /// [`WeakKeyError`](super::weak_key::WeakKeyError) for a signing key that
    /// is a single repeated byte.
    pub fn try_new(
        store: S,
        signing_key: [u8; 32],
        registry: Arc<dyn SessionRegistryHandle>,
    ) -> Result<Self, super::weak_key::WeakKeyError> {
        if super::weak_key::is_constant_key(&signing_key) {
            return Err(super::weak_key::WeakKeyError);
        }
        Ok(Self::build(store, signing_key, Some(registry)))
    }

    /// Configure a previous signing master key for zero-downtime
    /// rotation.
    ///
    /// On every request, cookie and fingerprint verification tries the
    /// CURRENT key first; on mismatch, falls back to this PREVIOUS key.
    /// When the previous key produces the match, the response re-issues
    /// the cookie under the current key and (for fingerprint fallback)
    /// updates the stored fingerprint in the session data so subsequent
    /// requests hit the fast path without falling back.
    ///
    /// Mirrors [`SessionCrypto::with_previous_key`](crate::session::SessionCrypto::with_previous_key)
    /// for the at-rest encryption side. The two rotations are
    /// independent: rotate the signing key without touching encryption,
    /// or vice versa, or plan both to overlap.
    ///
    /// # Operational rule
    ///
    /// **Only one previous slot is maintained.** Plan rotations so at
    /// most one is in flight per session-TTL window. A chained rotation
    /// (rotate again while the previous slot is still populated) drops
    /// the pre-first-rotation key entirely; cookies signed under it
    /// then fail both current and previous verification and their
    /// holders are forced to re-authenticate. This is the correct
    /// security behavior for an emergency-rotate-again scenario
    /// (compromised previous key must not remain valid): see
    /// `OPERATIONS.md#signing-key-rotation`.
    pub fn with_previous_signing_key(mut self, previous_master: [u8; 32]) -> Self {
        // Same "mutate before cloning" contract as `config_mut`. When
        // the Arc has been shared, `Arc::make_mut` deep-copies the
        // ring (key material included) into a fresh Arc and mutates
        // that; the previously-cloned service keeps the un-rotated
        // ring: usually not what the caller intended, and it also
        // means the master key bytes exist in two places briefly.
        // The debug_assert catches this in dev; release builds allow
        // it (matches SessionConfig setter behavior).
        super::weak_key::warn_if_constant_key("previous session signing key", &previous_master);
        debug_assert!(
            Arc::strong_count(&self.signing_keys) == 1,
            "SessionLayer::with_previous_signing_key called after the layer was cloned \
             (strong_count = {}). The rotation slot will only affect this clone; the \
             previously-cloned service keeps its original ring. Configure the layer fully \
             before passing it to `tower::Layer` / `Router::layer`.",
            Arc::strong_count(&self.signing_keys),
        );
        Arc::make_mut(&mut self.signing_keys).set_previous(previous_master);
        self
    }

    /// `true` when a previous signing key is configured, i.e. the
    /// layer is currently in a signing-key rotation window. Adopters
    /// building admin / status endpoints can use this to surface
    /// "rotation in progress" state without inspecting the master
    /// directly.
    pub fn has_previous_signing_key(&self) -> bool {
        self.signing_keys.has_previous()
    }

    /// Clear the previous signing key, ending the rotation window.
    ///
    /// Companion to [`with_previous_signing_key`](Self::with_previous_signing_key):
    /// after one session TTL has elapsed since the rotation began, no
    /// unexpired cookie can still be signed under the previous master,
    /// so retiring the slot is safe and prevents the previous key
    /// material from being validated against indefinitely. See
    /// `OPERATIONS.md#signing-key-rotation` for the procedure.
    ///
    /// Same "mutate before cloning" contract as
    /// [`with_previous_signing_key`](Self::with_previous_signing_key):
    /// invoke on the freshly-built layer, before it is handed to
    /// `tower::Layer` / `Router::layer`; a debug build asserts on the
    /// footgun. Calling this when no previous key is set is a no-op.
    pub fn remove_previous_signing_key(mut self) -> Self {
        debug_assert!(
            Arc::strong_count(&self.signing_keys) == 1,
            "SessionLayer::remove_previous_signing_key called after the layer was cloned \
             (strong_count = {}). The rotation slot will only clear on this clone; the \
             previously-cloned service keeps its previous key. Configure the layer fully \
             before passing it to `tower::Layer` / `Router::layer`.",
            Arc::strong_count(&self.signing_keys),
        );
        Arc::make_mut(&mut self.signing_keys).clear_previous();
        self
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
    ///
    /// # Panics
    ///
    /// Panics on a label that starts with `axess.v1.reserved-label.`: the
    /// layer's own labels are remapped under that prefix, and a label there
    /// would share a key with one of them.
    pub fn derive_subkey(&self, info: &'static [u8]) -> zeroize::Zeroizing<[u8; 32]> {
        // Derives from the CURRENT master only. Adopters using
        // `derive_subkey` to feed their own HMAC sites (CSRF, push
        // tokens, etc.) do NOT get rotation-aware verify-with-fallback
        // for free; if they need it, they hold their own previous key
        // and try-current-then-previous themselves. Wiring rotation
        // into every downstream sub-key derivation would leak the
        // rotation state through an otherwise-simple API.
        zeroize::Zeroizing::new(self.signing_keys.derive_subkey(info))
    }

    /// Replace the layer's cookie and TTL settings with a [`SessionConfig`],
    /// typically one from
    /// [`SessionConfigBuilder::build`](crate::session::SessionConfigBuilder::build),
    /// which has already checked it.
    ///
    /// Settings made by earlier `with_*` calls are overwritten; call this
    /// first. The layer re-checks the whole configuration when it becomes a
    /// service, whichever way it was built.
    ///
    /// See the `# Panics` section of [`SessionLayer`].
    pub fn with_config(mut self, config: SessionConfig) -> Self {
        self.config = Arc::new(config);
        self
    }

    /// Name the origins a WebSocket upgrade may come from.
    ///
    /// The layer checks the `Origin` of every WebSocket upgrade before it
    /// touches the session: a page on any site can open a socket to this
    /// server and the browser sends the session cookie with the upgrade, so
    /// the `Origin` header is the only gate. The rule is the CSRF layer's:
    /// with an allow-list the `Origin` must be one of `origins` (after
    /// canonicalising, so `https://APP.example.com:443` is
    /// `https://app.example.com`), and an upgrade without one is refused;
    /// without one (the default) the `Origin` must be the request's own
    /// `Host` under `https` (`http` or `https` when the cookies are not
    /// `Secure`), and an upgrade with no `Origin`, which is not a browser's,
    /// passes. A refused upgrade answers `403` and no handler runs.
    ///
    /// Call this when the socket is served from another host than the page
    /// that opens it. An entry that is not an origin is dropped, with a
    /// warning.
    #[must_use]
    pub fn with_websocket_origins(
        mut self,
        origins: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Self {
        let mut kept: Vec<Arc<str>> = Vec::new();
        for raw in origins {
            match crate::middleware::csrf::normalize_origin(raw.as_ref()) {
                Some(origin) => kept.push(Arc::from(origin)),
                None => tracing::warn!(
                    "SessionLayer::with_websocket_origins: dropped an entry that is not an origin"
                ),
            }
        }
        self.websocket_origins = Arc::from(kept);
        self
    }

    /// Choose what to do with an authenticated session when the registry
    /// cannot answer (default: [`UnknownLiveness::Reject`]).
    pub fn with_unknown_liveness(mut self, policy: UnknownLiveness) -> Self {
        self.unknown_liveness = policy;
        self
    }

    /// End an authenticated session once it is older than `max_age`
    /// measured from when it authenticated, however recently it was used
    /// (default: 7 days). `None` lifts the cap, so that only the sliding TTL
    /// bounds a session. The age is read from the layer's clock; see
    /// [`with_clock`](Self::with_clock).
    pub fn with_max_session_age(mut self, max_age: Option<Duration>) -> Self {
        self.config_mut().max_authenticated_age = max_age;
        self
    }

    /// End an impersonated session once the impersonation is older than
    /// `max_age`, measured from when `begin_impersonation` made it (default: 1
    /// hour; `None` lifts the cap). An administrator's session in a user's
    /// name then lasts at most this long however active it is; the
    /// administrator signs in again and impersonates afresh. Read on the
    /// layer's clock, like
    /// [`with_max_session_age`](Self::with_max_session_age).
    pub fn with_max_impersonation_age(mut self, max_age: Option<Duration>) -> Self {
        self.config_mut().max_impersonation_age = max_age;
        self
    }

    /// Replace the clock the layer reads (default: [`SystemClock`]). Only the
    /// absolute age cap reads it, so a simulated clock makes that cap
    /// deterministic.
    pub fn with_clock(mut self, clock: impl Clock) -> Self {
        self.clock = Arc::new(clock);
        self
    }

    /// Override the session TTL (default: 24 hours).
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.config_mut().ttl = ttl;
        self
    }

    /// Override the cookie name (default: `"__Host-axess.sid"`, or
    /// `"axess.sid"` when `Secure` is off or the path is not `/`).
    ///
    /// A name without the `__Host-` prefix can be planted from a sibling
    /// subdomain, or by a man in the middle on plain HTTP. A request that
    /// then carries the name twice with different values is treated as
    /// having no session cookie (the layer refuses to choose), so the user
    /// is logged out for as long as the planted cookie lives. Only the
    /// `__Host-` prefix (`Secure`, path `/`) keeps a browser from accepting
    /// such a cookie, so keep it unless you must not.
    pub fn with_cookie_name(mut self, name: impl Into<Arc<str>>) -> Self {
        let config = self.config_mut();
        config.cookie_name = name.into();
        config.cookie_name_explicit = true;
        self
    }

    /// Set the `Secure` flag on the session cookie (default: `true`).
    ///
    /// Set to `false` only for local HTTP development. In production,
    /// cookies without the `Secure` flag can be intercepted on the network.
    /// Without `Secure` the default name loses its `__Host-` prefix, so a
    /// network attacker can also plant a second cookie of the same name and
    /// log the user out for good (see
    /// [`with_cookie_name`](Self::with_cookie_name)).
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
    ///
    /// A path other than `/` makes a cookie whose name was not set with
    /// [`with_cookie_name`](Self::with_cookie_name) lose its `__Host-`
    /// prefix (a warning says so): the browser then accepts a cookie of the
    /// same name planted from a sibling subdomain, which can log the user
    /// out for good (a request with the name twice reads as no cookie) or
    /// fixate a session. Keep `/` where you can.
    pub fn with_path(mut self, path: impl Into<Arc<str>>) -> Self {
        let config = self.config_mut();
        config.path = path.into();
        crate::session::config::warn_if_host_prefix_dropped(
            &config.path,
            config.cookie_name_explicit,
        );
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
    /// let layer = SessionLayer::new(store, key, registry)
    ///     .with_binding(UserAgentBinding);
    /// ```
    pub fn with_binding(mut self, binding: impl SessionBinding) -> Self {
        self.binding = Some(Arc::new(binding));
        self
    }

    /// Replace the RNG that mints session ids (default: [`SystemRng`]).
    ///
    /// Every id the layer creates draws from it: the id of a request that
    /// arrives without a trusted session, the replacement id after a
    /// rotation (login, step-up completion, regenerate), and the id minted
    /// when a binding mismatch resets a session. A seeded RNG makes the
    /// whole sequence reproducible.
    pub fn with_rng(mut self, rng: impl SecureRng) -> Self {
        self.rng = Arc::new(rng);
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
    /// and leave `device_id` as the loaded session carried it; device
    /// resolution never fails the request.
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
        let layer = SessionLayer::new_unchecked(
            store,
            [0u8; 32],
            crate::MemorySessionRegistry::new().handle(),
        );
        let cloned = layer.clone();
        // Cloning bumps the Arc strong count to 2; the next `with_ttl`
        // will trip the assertion before `Arc::make_mut` deep-copies.
        layer.with_ttl(Duration::from_secs(60));
        drop(cloned);
    }

    #[test]
    fn setter_before_clone_does_not_panic() {
        let store = MemorySessionStore::new();
        let layer = SessionLayer::new_unchecked(
            store,
            [0u8; 32],
            crate::MemorySessionRegistry::new().handle(),
        )
        .with_ttl(Duration::from_secs(60))
        .with_secure(false);
        // Clone after setters is fine; the configuration is already finalised.
        drop(layer.clone());
    }
}

/// The constructors refuse a signing key that is a single repeated byte.
#[cfg(test)]
mod weak_signing_key_tests {
    use super::*;
    use crate::session::store::MemorySessionStore;

    fn registry() -> Arc<dyn SessionRegistryHandle> {
        crate::MemorySessionRegistry::new().handle()
    }

    #[test]
    #[should_panic(expected = "session signing key is a single repeated byte")]
    fn new_refuses_a_constant_key() {
        let _ = SessionLayer::new(MemorySessionStore::new(), [0u8; 32], registry());
    }

    #[test]
    #[should_panic(expected = "session signing key is a single repeated byte")]
    fn without_registry_insecure_refuses_a_constant_key() {
        let _ = SessionLayer::without_registry_insecure(MemorySessionStore::new(), [9u8; 32]);
    }

    #[test]
    fn try_new_refuses_and_new_unchecked_accepts_a_constant_key() {
        assert!(SessionLayer::try_new(MemorySessionStore::new(), [0u8; 32], registry()).is_err());
        let _ = SessionLayer::new_unchecked(MemorySessionStore::new(), [0u8; 32], registry());
        let mixed = crate::testing::test_key(1);
        assert!(SessionLayer::try_new(MemorySessionStore::new(), mixed, registry()).is_ok());
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
        drop(
            SessionLayer::new_unchecked(
                store,
                [0u8; 32],
                crate::MemorySessionRegistry::new().handle(),
            )
            .with_secure(false),
        );
        assert!(
            capture.contains_at_level(tracing::Level::WARN, "Secure cookie flag disabled"),
            "with_secure(false) must warn about plain-HTTP cookies"
        );
    }

    #[test]
    fn with_secure_true_does_not_emit_warning() {
        let capture = TracingCapture::install();
        let store = MemorySessionStore::new();
        drop(
            SessionLayer::new_unchecked(
                store,
                [0u8; 32],
                crate::MemorySessionRegistry::new().handle(),
            )
            .with_secure(true),
        );
        assert!(
            !capture.contains_at_level(tracing::Level::WARN, "Secure cookie flag disabled"),
            "with_secure(true) must NOT warn; `delete !` mutation would invert this"
        );
    }
}

/// A path other than `/` drops the `__Host-` prefix of the default cookie
/// name; `with_path` says so once, and stays quiet when nothing is dropped.
#[cfg(test)]
mod with_path_warning_tests {
    use super::*;
    use crate::session::store::MemorySessionStore;
    use crate::testing::mock_tracing::TracingCapture;

    fn warnings(capture: &TracingCapture) -> usize {
        capture
            .events()
            .iter()
            .filter(|e| e.level == tracing::Level::WARN && e.message.contains("__Host-"))
            .count()
    }

    #[test]
    fn a_non_root_path_warns_once_that_the_host_prefix_is_dropped() {
        let capture = TracingCapture::install();
        drop(
            SessionLayer::new_unchecked(
                MemorySessionStore::new(),
                [0u8; 32],
                crate::MemorySessionRegistry::new().handle(),
            )
            .with_path("/app"),
        );
        assert_eq!(warnings(&capture), 1, "events: {:?}", capture.events());
    }

    #[test]
    fn the_root_path_and_a_chosen_name_do_not_warn() {
        let capture = TracingCapture::install();
        drop(
            SessionLayer::new_unchecked(
                MemorySessionStore::new(),
                [0u8; 32],
                crate::MemorySessionRegistry::new().handle(),
            )
            .with_path("/"),
        );
        drop(
            SessionLayer::new_unchecked(
                MemorySessionStore::new(),
                [0u8; 32],
                crate::MemorySessionRegistry::new().handle(),
            )
            .with_cookie_name("sid")
            .with_path("/app"),
        );
        assert_eq!(warnings(&capture), 0);
    }
}

/// Layer-level coverage for the signing-key rotation retire path.
///
/// `SigningKeyRing::clear_previous` is exercised at the ring level in
/// `session::layer::signing::rotation_tests::ring_clear_previous_ends_rotation_window`;
/// these tests pin the layer's `with_*` / `remove_*` orchestration
/// (the `Arc::make_mut` step + `has_previous_signing_key` predicate)
/// so an accidental short-circuit of the retire method surfaces here
/// instead of silently keeping the previous slot alive.
#[cfg(test)]
mod signing_key_retire_tests {
    use super::*;
    use crate::session::store::MemorySessionStore;

    #[test]
    fn remove_previous_signing_key_retires_the_slot() {
        let store = MemorySessionStore::new();
        let layer = SessionLayer::new_unchecked(
            store,
            [0xBB; 32],
            crate::MemorySessionRegistry::new().handle(),
        )
        .with_previous_signing_key([0xAA; 32]);
        assert!(
            layer.has_previous_signing_key(),
            "with_previous_signing_key must install a slot the predicate observes"
        );

        let after = layer.remove_previous_signing_key();
        assert!(
            !after.has_previous_signing_key(),
            "remove_previous_signing_key must retire the slot"
        );
    }

    /// Idempotency: calling the retire method on a layer that has no
    /// previous key must be a no-op, not a panic. Operators sometimes
    /// invoke the retire step unconditionally at startup after a
    /// scheduled rotation window; a panic would take down the process.
    #[test]
    fn remove_previous_signing_key_on_fresh_layer_is_noop() {
        let store = MemorySessionStore::new();
        let layer = SessionLayer::new_unchecked(
            store,
            [0xBB; 32],
            crate::MemorySessionRegistry::new().handle(),
        );
        assert!(!layer.has_previous_signing_key());
        let after = layer.remove_previous_signing_key();
        assert!(!after.has_previous_signing_key());
    }
}
