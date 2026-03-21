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
//! 2. Load [`SessionData`] from the store (or create an empty default).
//! 3. Insert [`SessionHandle`] into request extensions.
//! 4. Call the inner service.
//! 5. If the session was modified, save it back to the store (or cycle the ID first).
//! 6. Set the session cookie on the response.

use crate::session::{
    binding::{self, SessionBinding},
    data::SessionData,
    id::SessionId,
    store::SessionStore,
};
use crate::utils::random::SystemRng;
use axum::{body::Body, http::Request, response::Response};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;
use tower::{Layer, Service};
use tower_cookies::cookie::{Cookie, SameSite};

type HmacSha256 = Hmac<Sha256>;

/// HMAC signing key that is zeroed from memory on drop.
#[derive(Clone)]
struct SigningKey([u8; 32]);

impl Drop for SigningKey {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

impl std::ops::Deref for SigningKey {
    type Target = [u8; 32];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

const DEFAULT_COOKIE_NAME: &str = "axess.sid";
const DEFAULT_TTL: Duration = Duration::from_secs(24 * 60 * 60); // 24 hours

// ── SessionHandle ──────────────────────────────────────────────────────────────

/// The per-request session handle injected into request extensions.
///
/// Handlers access the session through [`AuthSession`], which wraps this handle.
#[derive(Clone)]
pub struct SessionHandle(pub(crate) Arc<RwLock<SessionInner>>);

/// Mutable inner state of a session for a single request.
pub struct SessionInner {
    /// The session's ID (may change if `regenerate` is set).
    pub id: SessionId,
    /// The typed session payload.
    pub data: SessionData,
    /// Set to `true` when any field of `data` is changed — triggers a save on response.
    pub(crate) modified: bool,
    /// Set to `true` to cycle the session ID before saving (session fixation prevention).
    pub(crate) regenerate: bool,
}

// ── SessionLayer ──────────────────────────────────────────────────────────────

/// Tower layer that provides signed session cookies and typed [`SessionData`].
///
/// Add this layer to your Axum router. Handlers receive an [`AuthSession`] extractor
/// which wraps the [`SessionHandle`] stored in request extensions.
///
/// ```text
/// let app = Router::new()
///     .route("/login", post(login_handler))
///     .layer(SessionLayer::new(store, signing_key));
/// ```
#[derive(Clone)]
pub struct SessionLayer<S> {
    store: S,
    cookie_name: Arc<str>,
    signing_key: Arc<SigningKey>,
    ttl: Duration,
    secure: bool,
    same_site: SameSite,
    binding: Option<Arc<dyn SessionBinding>>,
}

impl<S: SessionStore> SessionLayer<S> {
    /// Create a session layer with the given store and 32-byte HMAC signing key.
    pub fn new(store: S, signing_key: [u8; 32]) -> Self {
        Self {
            store,
            cookie_name: DEFAULT_COOKIE_NAME.into(),
            signing_key: Arc::new(SigningKey(signing_key)),
            ttl: DEFAULT_TTL,
            secure: true,
            same_site: SameSite::Lax,
            binding: None,
        }
    }

    /// Override the session TTL (default: 24 hours).
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Override the cookie name (default: `"axess.sid"`).
    pub fn with_cookie_name(mut self, name: impl Into<Arc<str>>) -> Self {
        self.cookie_name = name.into();
        self
    }

    /// Set the `Secure` flag on the session cookie (default: `true`).
    ///
    /// Set to `false` for local HTTP development.
    pub fn with_secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    /// Set the `SameSite` policy (default: `Lax`).
    pub fn with_same_site(mut self, same_site: SameSite) -> Self {
        self.same_site = same_site;
        self
    }

    /// Enable session-to-client binding for hijacking detection.
    ///
    /// When enabled, the library hashes client-specific request properties
    /// (determined by the [`SessionBinding`] implementation) and stores the
    /// hash in the session upon authentication. On every subsequent request
    /// the hash is recomputed and compared — a mismatch resets the session
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
}

impl<S, Inner> Layer<Inner> for SessionLayer<S>
where
    S: SessionStore + Clone,
{
    type Service = SessionService<S, Inner>;

    fn layer(&self, inner: Inner) -> Self::Service {
        SessionService {
            inner,
            store: self.store.clone(),
            cookie_name: self.cookie_name.clone(),
            signing_key: self.signing_key.clone(),
            ttl: self.ttl,
            secure: self.secure,
            same_site: self.same_site,
            binding: self.binding.clone(),
        }
    }
}

// ── SessionService ─────────────────────────────────────────────────────────────

/// Tower service wrapping an inner service with session management.
#[derive(Clone)]
pub struct SessionService<S, Inner> {
    inner: Inner,
    store: S,
    cookie_name: Arc<str>,
    signing_key: Arc<SigningKey>,
    ttl: Duration,
    secure: bool,
    same_site: SameSite,
    binding: Option<Arc<dyn SessionBinding>>,
}

impl<S, Inner, ResBody> Service<Request<Body>> for SessionService<S, Inner>
where
    S: SessionStore + Clone + Send + Sync + 'static,
    S::Error: Send + Sync + 'static,
    Inner: Service<Request<Body>, Response = Response<ResBody>> + Clone + Send + 'static,
    Inner::Future: Send + 'static,
    Inner::Error: Send + 'static,
    ResBody: Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = Inner::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let store = self.store.clone();
        let cookie_name = self.cookie_name.clone();
        let ttl = self.ttl;
        let secure = self.secure;
        let same_site = self.same_site;
        let signing_key = self.signing_key.clone();
        let session_binding = self.binding.clone();

        // Clone inner *before* the async block — required by tower's contract.
        let mut inner = self.inner.clone();
        std::mem::swap(&mut inner, &mut self.inner);

        // Pre-compute the binding hash from the request before moving it.
        let current_fingerprint = session_binding
            .as_deref()
            .and_then(|b| binding::compute_fingerprint(b, &req));

        Box::pin(async move {
            // 1. Extract and verify the session cookie.
            let (existing_id, mut session_data) = {
                let cookie_value = req
                    .headers()
                    .get(axum::http::header::COOKIE)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| {
                        Cookie::split_parse(s.to_string())
                            .filter_map(Result::ok)
                            .find(|c| c.name() == cookie_name.as_ref())
                            .map(|c| c.value().to_string())
                    });

                let verified_id = cookie_value
                    .as_deref()
                    .and_then(|v| signing_decode_cookie(v, &signing_key));

                if let Some(id) = verified_id {
                    // Load from store; fall back to empty on error or absence.
                    let data = store.load(&id).await.unwrap_or(None).unwrap_or_default();
                    (Some(id), data)
                } else {
                    (None, SessionData::default())
                }
            };

            // 1b. Session binding check — invalidate on mismatch.
            let mut binding_invalidated = false;
            if let (Some(stored_hash), Some(current_hash)) =
                (&session_data.fingerprint, &current_fingerprint)
                && stored_hash != current_hash
            {
                tracing::warn!(
                    "session fingerprint mismatch — invalidating session (possible hijacking)"
                );
                session_data = SessionData::default();
                binding_invalidated = true;
            }

            // Generate a new session ID if none exists.
            let mut rng = SystemRng;
            let session_id = existing_id.unwrap_or_else(|| SessionId::new(&mut rng));

            // 2. Insert SessionHandle into request extensions.
            let inner_state = SessionInner {
                id: session_id,
                data: session_data,
                modified: binding_invalidated,
                regenerate: binding_invalidated,
            };
            let handle = SessionHandle(Arc::new(RwLock::new(inner_state)));
            req.extensions_mut().insert(handle.clone());

            // 3. Call the inner service.
            let response = inner.call(req).await?;

            // 4. Persist session if modified.
            let mut guard = handle.0.write().await;

            // 4b. Auto-set fingerprint when session becomes authenticated.
            if session_binding.is_some()
                && guard.data.fingerprint.is_none()
                && guard.data.auth_state.is_authenticated()
                && guard.modified
                && let Some(fp) = &current_fingerprint
            {
                guard.data.fingerprint = Some(fp.clone());
            }

            let session_changed = guard.modified || guard.regenerate || existing_id.is_none();
            let final_id = if session_changed {
                if guard.regenerate || existing_id.is_none() {
                    // Cycle the session ID (session fixation prevention or new session).
                    let old_id = guard.id;
                    let new_id = store
                        .cycle(&old_id, &guard.data, ttl, &mut rng)
                        .await
                        .unwrap_or(old_id);
                    guard.id = new_id;
                    new_id
                } else {
                    let _ = store.save(&guard.id, &guard.data, ttl).await;
                    guard.id
                }
            } else {
                guard.id
            };
            drop(guard);

            // 5. Set the cookie only when the session was created or changed.
            //    Omitting Set-Cookie on unmodified responses reduces header bloat
            //    and prevents spurious cache invalidation on CDN / reverse proxies.
            let mut response = response;
            if session_changed {
                let cookie_value = {
                    let id_enc = URL_SAFE_NO_PAD.encode(final_id.as_bytes());
                    let mac = signing_sign_bytes(final_id.as_bytes(), &signing_key);
                    format!("{}.{}", id_enc, mac)
                };

                let mut cookie = Cookie::new(cookie_name.as_ref().to_string(), cookie_value);
                cookie.set_http_only(true);
                cookie.set_secure(secure);
                cookie.set_same_site(same_site);
                cookie.set_path("/");
                cookie.set_max_age(tower_cookies::cookie::time::Duration::seconds(
                    ttl.as_secs() as i64,
                ));

                if let Ok(hv) = axum::http::HeaderValue::from_str(&cookie.to_string()) {
                    response
                        .headers_mut()
                        .append(axum::http::header::SET_COOKIE, hv);
                }
            }

            Ok(response)
        })
    }
}

// ── Internal signing helpers ───────────────────────────────────────────────────

fn signing_sign_bytes(bytes: &[u8], key: &[u8; 32]) -> String {
    let mut mac =
        HmacSha256::new_from_slice(key.as_ref()).expect("HMAC-SHA256 accepts any key length");
    mac.update(bytes);
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

fn signing_decode_cookie(value: &str, key: &[u8; 32]) -> Option<SessionId> {
    let (id_enc, mac_enc) = value.split_once('.')?;

    let id_bytes = URL_SAFE_NO_PAD.decode(id_enc).ok()?;
    if id_bytes.len() != 16 {
        return None;
    }

    let mac_bytes = URL_SAFE_NO_PAD.decode(mac_enc).ok()?;
    let expected = signing_sign_bytes(&id_bytes, key);
    let expected_bytes = URL_SAFE_NO_PAD.decode(expected).ok()?;

    // Constant-time comparison prevents timing side-channels.
    if mac_bytes.ct_eq(&expected_bytes).into() {
        let arr: [u8; 16] = id_bytes.try_into().ok()?;
        Some(SessionId::from_bytes(arr))
    } else {
        None
    }
}
