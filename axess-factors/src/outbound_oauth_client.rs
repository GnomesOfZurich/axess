//! Outbound OAuth client.
//!
//! Authenticates axess to a 3rd-party token endpoint via the
//! `client_credentials` grant (RFC 6749 §4.4), with optional
//! `private_key_jwt` client assertion (RFC 7523). Caches the resulting
//! access token in-process and silently refreshes it before expiry.
//! Co-located with the JWT primitives and shared secret types it
//! depends on.
//!
//! # Auth methods supported
//!
//! - **`ClientSecretBasic`**: `client_id` + `client_secret` in the
//!   `Authorization: Basic ...` header. Default for most IdPs.
//! - **`ClientSecretPost`**: `client_id` + `client_secret` as form
//!   fields in the POST body. Some legacy IdPs require this shape.
//! - **`PrivateKeyJwt`**: RFC 7523 client assertion. axess signs a
//!   short-lived JWT with its own private key, presented as
//!   `client_assertion` in the form body. Asymmetric: the IdP
//!   validates against axess's published JWKS, no shared secret to
//!   rotate. Recommended for FAPI 2.0 / PSD2-SCA-shaped APIs.
//!
//! # Caching + refresh
//!
//! - First `get_access_token()` → token request, cache the response. The
//!   refresh is due `refresh_threshold` before expiry, or half the token's
//!   lifetime before it if that is shorter, so a token whose lifetime does
//!   not exceed the threshold is cached for half its life instead of being
//!   fetched anew on every call.
//! - Subsequent calls inside the validity window → return cached
//!   value (read-locked, no HTTP).
//! - Inside the refresh window → one caller fetches (single flight); the
//!   others are served the still-unexpired cached token and do not wait on
//!   the fetch.
//! - After expiry → callers wait for the one fetch in flight.
//! - A fetch that fails does not fail every caller: the callers that waited
//!   for it share its outcome instead of each fetching in turn, and a token
//!   that is still unexpired keeps being served until `expires_at`, with
//!   the next call trying the endpoint again. Only when nothing usable is
//!   cached does the failure reach the caller.
//!
//! The fetch holds no lock on the cache, only the single-flight gate, and is
//! bounded by a request timeout (30 s by default, see
//! [`with_request_timeout`](OutboundOAuthClient::with_request_timeout)).
//!
//! `force_refresh()` condemns the cached token and fetches a new one (use
//! after a `401` from the upstream resource): from the moment it is called
//! the condemned token is served to nobody, during the fetch or after one
//! that fails. Callers that arrive together share one fetch.
//! `force_refresh_of(token)` condemns only that token, so a `401` reported
//! late, after another caller already replaced the token, keeps the
//! replacement.
//!
//! # Transport
//!
//! The token URL must be HTTPS (plain HTTP only for `localhost`,
//! `127.0.0.1` and `[::1]`), since the request carries the client secret or
//! assertion. The default HTTP client follows no redirects (a redirect would
//! re-send the credentials to wherever it points) and has connect and request
//! timeouts. A client passed to
//! [`with_http_client`](OutboundOAuthClient::with_http_client) is the
//! caller's to configure the same way.
//!
//! # DST
//!
//! The injectable [`Clock`](axess_clock::Clock) makes expiry deterministic under
//! `MockClock`. The HTTP path uses
//! `reqwest`; point it at a `wiremock` test endpoint for full
//! deterministic replay.

use std::sync::Arc;
use std::time::Duration;

use axess_clock::{Clock, SystemClock};
use axess_rng::{SecureRng, SystemRng};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64_STANDARD;
use chrono::{DateTime, Utc};
use reqwest::header::AUTHORIZATION;
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};
use url::Url;

use crate::secret::ZeroizedString;

/// Errors surfaced by [`OutboundOAuthClient`].
///
/// `Clone`, because the outcome of one fetch is answered to every caller
/// that waited for it.
#[derive(Debug, Clone, thiserror::Error)]
pub enum OAuthClientError {
    /// Transport-level failure: connection refused, TLS error, DNS,
    /// timeout. Distinct from [`Self::TokenEndpoint`] (which is the
    /// IdP returning an error response). The token URL is not echoed: a
    /// configured endpoint can carry a tenant path or a key in its query.
    #[error("HTTP transport error: {0}")]
    Transport(String),
    /// Token endpoint returned a non-2xx response. Carries the HTTP
    /// status and a bounded snippet of the body for adopter logging.
    #[error("token endpoint returned {status}: {body}")]
    TokenEndpoint {
        /// HTTP status code returned by the token endpoint.
        status: u16,
        /// The first [`ERROR_BODY_BYTES`](crate::http_body::ERROR_BODY_BYTES)
        /// of the response body as text, with
        /// [`TRUNCATED_SUFFIX`](crate::http_body::TRUNCATED_SUFFIX) when more
        /// followed; empty if the body could not be read.
        body: String,
    },
    /// 2xx response but the body didn't deserialise as a valid
    /// `TokenResponse` (missing `access_token`, malformed JSON, etc).
    #[error("malformed token response: {0}")]
    MalformedResponse(String),
    /// JWT signing failed when constructing a `private_key_jwt`
    /// client assertion. Should not happen in production: the signer signs
    /// one assertion when it is built.
    #[error("client assertion signing failed: {0}")]
    Signing(String),
    /// The token URL is not HTTPS (and not loopback), so the client secret or
    /// assertion would travel in the clear. The URL is not echoed.
    #[error(
        "token endpoint must use HTTPS (http is only allowed for localhost, 127.0.0.1 and [::1])"
    )]
    InsecureEndpoint,
    /// The token request could not be built from the configuration: the
    /// client credentials do not form an `Authorization` header. A
    /// configuration fault, not a transport one; retrying does not help.
    #[error("token request could not be built: {0}")]
    RequestBuild(String),
    /// The default HTTP client could not be built, which happens when the TLS
    /// backend fails to initialise.
    #[error("HTTP client could not be built: {0}")]
    ClientBuild(String),
}

/// How axess authenticates itself to the token endpoint.
#[derive(Clone)]
pub enum ClientAuthMethod {
    /// `client_id` + `client_secret` in `Authorization: Basic` header.
    /// Default for most off-the-shelf IdPs (Okta, Auth0, Azure AD).
    ClientSecretBasic {
        /// Public client identifier.
        client_id: String,
        /// Shared secret. Zeroized on drop.
        client_secret: ZeroizedString,
    },
    /// `client_id` + `client_secret` as POST form fields. Some legacy
    /// IdPs require this; check the IdP's docs.
    ClientSecretPost {
        /// Public client identifier.
        client_id: String,
        /// Shared secret. Zeroized on drop.
        client_secret: ZeroizedString,
    },
    /// RFC 7523 `private_key_jwt`: the signer makes a short-lived JWT
    /// asserting the client's identity, which the IdP checks against the key
    /// or certificate it holds for the client. No shared secret to rotate.
    /// The assertion's audience is the token URL unless the signer fixes one
    /// ([`ClientAssertionSigner::with_audience`](crate::client_assertion::ClientAssertionSigner::with_audience)),
    /// and its headers (`kid`, `x5t`, `x5t#S256`) are the signer's, so the
    /// certificate thumbprint Microsoft Entra looks for can be set.
    /// Boxed: the signer is several times the size of the other variants.
    PrivateKeyJwt(Box<crate::client_assertion::ClientAssertionSigner>),
}

impl std::fmt::Debug for ClientAuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ClientSecretBasic { client_id, .. } => f
                .debug_struct("ClientSecretBasic")
                .field("client_id", client_id)
                .field("client_secret", &"<redacted>")
                .finish(),
            Self::ClientSecretPost { client_id, .. } => f
                .debug_struct("ClientSecretPost")
                .field("client_id", client_id)
                .field("client_secret", &"<redacted>")
                .finish(),
            Self::PrivateKeyJwt(signer) => f.debug_tuple("PrivateKeyJwt").field(signer).finish(),
        }
    }
}

/// The token endpoint's response (RFC 6749 §5.1). Only the fields the
/// client actually consumes are deserialised: `token_type` (always
/// `Bearer` for client_credentials per RFC 6749) and `scope` (server
/// may echo a subset of requested scopes; we don't enforce against
/// the request) are intentionally dropped. serde's default of
/// ignoring unknown fields keeps the parse robust against IdPs that
/// return extra metadata.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    /// Wire field. Typed [`ZeroizedString`] so the plaintext the
    /// provider sent is redacted in `Debug` and zeroed on drop: this
    /// struct is where the token first lands, and zeroing only the
    /// copy would leave the original in the heap for the process's
    /// lifetime.
    access_token: ZeroizedString,
    #[serde(default)]
    expires_in: Option<u64>,
}

/// In-memory cached access token. The string is zeroized on drop via
/// [`ZeroizedString`] so a heap-dump of axess does not surface
/// plaintext tokens.
struct CachedToken {
    access_token: ZeroizedString,
    /// `now + expires_in` from the token response: the token is unusable
    /// from here on.
    expires_at: DateTime<Utc>,
    /// When a refresh is due: `refresh_threshold` before `expires_at`, or
    /// half the token's lifetime before it if that is shorter. Fixed when the
    /// token is fetched, because the lifetime is known only then.
    refresh_at: DateTime<Utc>,
}

/// The cache and the record of the fetches that filled it, under one lock.
///
/// The states a caller can find: no token (before the first fetch, after a
/// fetch failed with nothing usable left, or from the moment
/// [`OutboundOAuthClient::force_refresh`] condemned the token until a fetch
/// replaces it); a token not yet due; a token due but unexpired; a token
/// expired. A condemned token is removed, never flagged, so no path can
/// serve it.
struct Cache {
    token: Option<CachedToken>,
    /// How many fetches have completed, successful or not. A caller that
    /// waited for the gate compares it with the count it saw before: a
    /// change means a fetch completed meanwhile, and that fetch's outcome
    /// is the waiter's too.
    fetches: u64,
    /// The error of the last completed fetch; `None` again once one
    /// succeeds.
    last_error: Option<OAuthClientError>,
}

impl Cache {
    /// The cached access token when `usable` holds for it.
    fn token_if(&self, usable: impl FnOnce(&CachedToken) -> bool) -> Option<String> {
        self.token
            .as_ref()
            .filter(|t| usable(t))
            .map(|t| (*t.access_token).to_string())
    }
}

/// Outbound OAuth client.
///
/// Construct once at process startup (or once per third-party
/// integration) and share via `Arc`. The cached token is
/// `RwLock`-protected so concurrent `get_access_token()` calls in the
/// fast path are non-blocking.
pub struct OutboundOAuthClient {
    token_url: Url,
    auth_method: ClientAuthMethod,
    scopes: Vec<String>,
    cache: RwLock<Cache>,
    /// Single flight: held across a token fetch, never the cache lock.
    refresh_gate: Mutex<()>,
    /// Bound on one token fetch.
    request_timeout: Duration,
    refresh_threshold: Duration,
    clock: Arc<dyn Clock>,
    /// Entropy source for the `jti` claim of `private_key_jwt` client
    /// assertions. Injected so DST tests can produce reproducible
    /// assertion JWTs.
    rng: Arc<dyn SecureRng>,
    http_client: reqwest::Client,
}

/// Base64 payload of an HTTP Basic `client_secret_basic` credential.
///
/// RFC 6749 §2.3.1: the client id and secret are form-urlencoded before
/// they are joined with `:` and base64-encoded, so a secret carrying
/// `:`, `+` or `%` reaches a strict IdP intact. The value is the secret in
/// another spelling, so it is a [`ZeroizedString`], as is every buffer on
/// the way to it; [`basic_authorization`] builds the header from it.
#[must_use]
pub fn basic_credentials(client_id: &str, client_secret: &str) -> ZeroizedString {
    let enc = |s: &str| {
        ZeroizedString::new(url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>())
    };
    let id = enc(client_id);
    let secret = enc(client_secret);
    // Sized up front: a buffer that grows leaves its earlier allocations
    // behind unzeroed.
    let mut joined = String::with_capacity(id.len() + 1 + secret.len());
    joined.push_str(&id);
    joined.push(':');
    joined.push_str(&secret);
    let joined = ZeroizedString::new(joined);
    ZeroizedString::new(B64_STANDARD.encode(&*joined))
}

/// The `Authorization` header for `client_secret_basic`: `Basic` and
/// [`basic_credentials`], marked sensitive so the header is redacted
/// wherever the request's headers are printed. The buffers it is built from
/// are zeroized; the header value itself is the HTTP layer's copy.
///
/// # Errors
///
/// [`InvalidHeaderValue`](reqwest::header::InvalidHeaderValue) when the
/// value is not a header value, which base64 never is; the `Result` keeps
/// the construction free of a panic path.
pub fn basic_authorization(
    client_id: &str,
    client_secret: &str,
) -> Result<reqwest::header::HeaderValue, reqwest::header::InvalidHeaderValue> {
    const SCHEME: &str = "Basic ";
    let credentials = basic_credentials(client_id, client_secret);
    let mut value = String::with_capacity(SCHEME.len() + credentials.len());
    value.push_str(SCHEME);
    value.push_str(&credentials);
    let value = ZeroizedString::new(value);
    let mut header = reqwest::header::HeaderValue::from_str(&value)?;
    header.set_sensitive(true);
    Ok(header)
}

/// Refuse a token URL that is not HTTPS, other than plain HTTP to a loopback
/// host. The host decides, parsed, and userinfo is refused outright:
/// `http://localhost@evil.example` is not loopback.
fn require_secure_token_url(url: &Url) -> Result<(), OAuthClientError> {
    if !url.username().is_empty() || url.password().is_some() {
        return Err(OAuthClientError::InsecureEndpoint);
    }
    match url.scheme() {
        "https" => Ok(()),
        "http" => match url.host() {
            Some(url::Host::Domain("localhost")) => Ok(()),
            Some(url::Host::Ipv4(ip)) if ip.is_loopback() => Ok(()),
            Some(url::Host::Ipv6(ip)) if ip.is_loopback() => Ok(()),
            _ => Err(OAuthClientError::InsecureEndpoint),
        },
        _ => Err(OAuthClientError::InsecureEndpoint),
    }
}

/// `now + secs`, or `None` when the lifetime does not fit a timestamp.
///
/// An IdP-supplied `expires_in` is untrusted: a huge value must be
/// refused rather than panic or wrap into the past.
#[must_use]
pub fn expiry_after(
    now: chrono::DateTime<chrono::Utc>,
    secs: u64,
) -> Option<chrono::DateTime<chrono::Utc>> {
    let secs = i64::try_from(secs).ok()?;
    now.checked_add_signed(chrono::Duration::try_seconds(secs)?)
}

impl OutboundOAuthClient {
    /// Construct a new outbound OAuth client.
    ///
    /// Defaults: empty scope list, 30-second refresh threshold, 30-second
    /// request timeout, [`SystemClock`], and an HTTP client that follows no
    /// redirects and has connect and request timeouts. Override via the
    /// `with_*` builder methods.
    ///
    /// The default client sends no `User-Agent`. Some token endpoints refuse a
    /// request without one; pass a configured client to
    /// [`with_http_client`](Self::with_http_client) for those, and configure
    /// it with no redirects and timeouts as well.
    ///
    /// # Errors
    ///
    /// * [`OAuthClientError::InsecureEndpoint`] when `token_url` is not HTTPS
    ///   and not a loopback host: the request carries the client secret or
    ///   assertion.
    /// * [`OAuthClientError::ClientBuild`] when the default HTTP client cannot
    ///   be built (the TLS backend failed to initialise).
    pub fn new(token_url: Url, auth_method: ClientAuthMethod) -> Result<Self, OAuthClientError> {
        require_secure_token_url(&token_url)?;
        let request_timeout = Duration::from_secs(30);
        let http_client = reqwest::Client::builder()
            // A redirect would re-send the credentials wherever it points
            // (a 307 or 308 re-POSTs the form), and a downgrade to HTTP would
            // send them in the clear. A 3xx is an error response here.
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(request_timeout)
            .build()
            .map_err(|e| OAuthClientError::ClientBuild(e.to_string()))?;
        Ok(Self {
            token_url,
            auth_method,
            scopes: Vec::new(),
            cache: RwLock::new(Cache {
                token: None,
                fetches: 0,
                last_error: None,
            }),
            refresh_gate: Mutex::new(()),
            request_timeout,
            refresh_threshold: Duration::from_secs(30),
            clock: Arc::new(SystemClock),
            rng: Arc::new(SystemRng),
            http_client,
        })
    }

    /// Set the OAuth scopes requested at the token endpoint.
    pub fn with_scopes<I, S>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.scopes = scopes.into_iter().map(Into::into).collect();
        self
    }

    /// Override the refresh threshold (default: 30 s). Cached tokens
    /// are considered "due for refresh" when they're within this
    /// window of `expires_at`, or within half their lifetime of it if that is
    /// shorter.
    pub fn with_refresh_threshold(mut self, threshold: Duration) -> Self {
        self.refresh_threshold = threshold;
        self
    }

    /// Inject a clock for deterministic simulation testing.
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Inject an RNG for deterministic simulation testing. The RNG
    /// drives the `jti` claim of `private_key_jwt` client assertions;
    /// production wires [`SystemRng`], DST tests inject `MockRng`.
    pub fn with_rng(mut self, rng: Arc<dyn SecureRng>) -> Self {
        self.rng = rng;
        self
    }

    /// Inject a pre-configured `reqwest::Client`; for adopters who
    /// want custom TLS roots, connection pooling, proxies, or
    /// per-request timeouts.
    ///
    /// The client replaces the default one, and with it the default's
    /// protections: configure it with
    /// `redirect(reqwest::redirect::Policy::none())` and a request timeout,
    /// or a redirect carries the client credentials to wherever it points. The
    /// bound set by [`with_request_timeout`](Self::with_request_timeout) still
    /// applies to a whole fetch.
    pub fn with_http_client(mut self, client: reqwest::Client) -> Self {
        self.http_client = client;
        self
    }

    /// Bound one token fetch (default: 30 s). A fetch that takes longer fails
    /// with [`OAuthClientError::Transport`] and releases the single-flight
    /// gate, so one hung token endpoint cannot hold every caller.
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Return a valid access token, refreshing the cache silently if
    /// needed. Concurrent calls share one fetch (single flight); callers that
    /// find a still-unexpired token while a refresh is in flight use it
    /// instead of waiting for the fetch, and callers that waited for a fetch
    /// take its outcome rather than fetching again.
    ///
    /// # Errors
    ///
    /// The fetch's error when it failed and no unexpired token is cached. A
    /// failed refresh of a token that is still unexpired is not an error: the
    /// token is returned, and the next call tries the endpoint again.
    pub async fn get_access_token(&self) -> Result<String, OAuthClientError> {
        let now = self.clock.now();
        // Fast path: read-lock, check validity, return.
        let seen = {
            let cache = self.cache.read().await;
            if let Some(token) = cache.token_if(|t| now < t.refresh_at) {
                return Ok(token);
            }
            cache.fetches
        };

        // Due for refresh, or nothing cached. Someone else may already be
        // fetching: a token that has not expired yet serves meanwhile.
        let guard = match self.refresh_gate.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                if let Some(token) = self.cache.read().await.token_if(|t| now < t.expires_at) {
                    return Ok(token);
                }
                self.refresh_gate.lock().await
            }
        };
        self.settle_holding(guard, seen).await
    }

    /// Condemn the cached token and fetch a new one. Use after the upstream
    /// returned `401`, indicating the cached token has been server-side
    /// revoked or invalidated. The condemned token is served to nobody from
    /// here on: not to callers that arrive during the fetch, and not after
    /// a fetch that fails. Callers that arrive together (a burst of `401`s
    /// from the upstream resource) share one fetch.
    ///
    /// When the `401` names the token it was about, prefer
    /// [`force_refresh_of`](Self::force_refresh_of), which leaves a
    /// replacement another caller already fetched in place.
    ///
    /// # Errors
    ///
    /// The fetch's error. Nothing is cached then; the next call fetches.
    pub async fn force_refresh(&self) -> Result<String, OAuthClientError> {
        self.refresh_condemning(|_| true).await
    }

    /// [`force_refresh`](Self::force_refresh) for a `401` about `condemned`:
    /// that token is condemned when it is the cached one. When the cache
    /// already holds another token (a concurrent caller replaced it), the
    /// replacement is returned without a fetch unless it is due.
    ///
    /// # Errors
    ///
    /// As [`force_refresh`](Self::force_refresh).
    pub async fn force_refresh_of(&self, condemned: &str) -> Result<String, OAuthClientError> {
        self.refresh_condemning(|t| *t.access_token == *condemned)
            .await
    }

    /// The body of both forced refreshes: condemn the cached token when
    /// `is_condemned` holds for it, take the gate, settle.
    async fn refresh_condemning(
        &self,
        is_condemned: impl FnOnce(&CachedToken) -> bool,
    ) -> Result<String, OAuthClientError> {
        let seen = self.condemn(is_condemned).await;
        let guard = self.refresh_gate.lock().await;
        self.settle_holding(guard, seen).await
    }

    /// [`settle`](Self::settle) while holding the single-flight `guard`,
    /// released once the outcome is known.
    async fn settle_holding(
        &self,
        guard: tokio::sync::MutexGuard<'_, ()>,
        seen: u64,
    ) -> Result<String, OAuthClientError> {
        let outcome = self.settle(seen).await;
        drop(guard);
        outcome
    }

    /// Remove the cached token when `is_condemned` holds for it, before
    /// taking the gate, so that no caller is served it while the fetch that
    /// replaces it waits or runs. Returns the fetch count for [`settle`].
    ///
    /// [`settle`]: Self::settle
    async fn condemn(&self, is_condemned: impl FnOnce(&CachedToken) -> bool) -> u64 {
        let mut cache = self.cache.write().await;
        if cache.token.as_ref().is_some_and(is_condemned) {
            cache.token = None;
        }
        cache.fetches
    }

    /// Holding the gate: fetch, unless a fetch completed since the caller
    /// read the count `seen`, in which case that fetch's outcome is this
    /// caller's too (a token it stored, a still-unexpired token after it
    /// failed, or its error), and no second fetch is made.
    async fn settle(&self, seen: u64) -> Result<String, OAuthClientError> {
        let now = self.clock.now();
        {
            let cache = self.cache.read().await;
            if cache.fetches == seen {
                // Nobody fetched meanwhile. A token not yet due is the
                // replacement `force_refresh_of` found in place of the
                // condemned one.
                if let Some(token) = cache.token_if(|t| now < t.refresh_at) {
                    return Ok(token);
                }
            } else {
                if let Some(token) = cache.token_if(|t| now < t.expires_at) {
                    return Ok(token);
                }
                if let Some(err) = &cache.last_error {
                    return Err(err.clone());
                }
            }
        }
        self.fetch_and_store().await
    }

    /// Fetch under the request timeout and record the outcome. The caller
    /// holds the single-flight gate; the cache lock is taken only to store.
    /// A failure leaves a still-unexpired token in place and returns it;
    /// an expired one is dropped and the error returned.
    async fn fetch_and_store(&self) -> Result<String, OAuthClientError> {
        let fetched = tokio::time::timeout(self.request_timeout, self.fetch_new_token())
            .await
            .map_err(|_| {
                OAuthClientError::Transport(format!(
                    "token request timed out after {:?}",
                    self.request_timeout
                ))
            })
            .and_then(|fetched| fetched);
        let now = self.clock.now();
        let mut cache = self.cache.write().await;
        cache.fetches += 1;
        match fetched {
            Ok(fresh) => {
                let token = (*fresh.access_token).to_string();
                cache.token = Some(fresh);
                cache.last_error = None;
                Ok(token)
            }
            Err(err) => {
                cache.last_error = Some(err.clone());
                match cache.token_if(|t| now < t.expires_at) {
                    Some(token) => Ok(token),
                    None => {
                        cache.token = None;
                        Err(err)
                    }
                }
            }
        }
    }

    async fn fetch_new_token(&self) -> Result<CachedToken, OAuthClientError> {
        // The form carries the client secret or the assertion, so every
        // value is zeroized with the form; the body the HTTP layer encodes
        // from it is its own copy.
        let mut form: Vec<(&str, ZeroizedString)> =
            vec![("grant_type", "client_credentials".into())];
        if !self.scopes.is_empty() {
            form.push(("scope", self.scopes.join(" ").into()));
        }

        let mut request = self.http_client.post(self.token_url.clone());

        match &self.auth_method {
            ClientAuthMethod::ClientSecretBasic {
                client_id,
                client_secret,
            } => {
                let header = basic_authorization(client_id, client_secret).map_err(|e| {
                    OAuthClientError::RequestBuild(format!("authorization header: {e}"))
                })?;
                request = request.header(AUTHORIZATION, header);
            }
            ClientAuthMethod::ClientSecretPost {
                client_id,
                client_secret,
            } => {
                form.push(("client_id", client_id.as_str().into()));
                form.push(("client_secret", (**client_secret).into()));
            }
            ClientAuthMethod::PrivateKeyJwt(signer) => {
                let assertion = signer
                    .mint(self.token_url.as_str(), &*self.clock, &*self.rng)
                    .map_err(|e| OAuthClientError::Signing(e.to_string()))?;
                form.push((
                    "client_assertion_type",
                    crate::client_assertion::CLIENT_ASSERTION_TYPE_JWT_BEARER.into(),
                ));
                form.push(("client_assertion", ZeroizedString::new(assertion)));
                form.push(("client_id", signer.client_id().into()));
            }
        }

        // `without_url`: reqwest's message names the URL it was sent to.
        let mut response = request
            .form(&form)
            .send()
            .await
            .map_err(|e| OAuthClientError::Transport(e.without_url().to_string()))?;

        let status = response.status();
        if !status.is_success() {
            let body = crate::http_body::read_error_snippet(&mut response).await;
            return Err(OAuthClientError::TokenEndpoint {
                status: status.as_u16(),
                body,
            });
        }

        let body =
            crate::http_body::read_limited(&mut response, crate::http_body::MAX_TOKEN_BODY_BYTES)
                .await
                .map_err(|e| OAuthClientError::MalformedResponse(e.to_string()))?;
        let parsed: TokenResponse = serde_json::from_slice(&body)
            .map_err(|e| OAuthClientError::MalformedResponse(e.to_string()))?;

        if parsed.access_token.is_empty() {
            return Err(OAuthClientError::MalformedResponse(
                "access_token field is empty".into(),
            ));
        }

        // RFC 6749 §5.1: `expires_in` is optional. If absent, treat the
        // token as a 1-hour bearer (industry convention). Refresh
        // before that anyway via `refresh_threshold`.
        let lifetime_secs = parsed.expires_in.unwrap_or(3600).max(1);
        let expires_at = expiry_after(self.clock.now(), lifetime_secs).ok_or_else(|| {
            OAuthClientError::MalformedResponse(format!(
                "expires_in {lifetime_secs} is out of range"
            ))
        })?;

        // Move the String into the ZeroizedString wrapper so the
        // sole heap allocation gets zeroized when the cached entry
        // drops. Cloning + zeroizing the original would defeat the
        // purpose (leaves the clone unzeroed).
        let access_token = parsed.access_token;

        // Refresh `refresh_threshold` early, or half way through the token's
        // life if that is sooner: a lifetime at or under the threshold would
        // otherwise be due the moment it is fetched.
        let early = self
            .refresh_threshold
            .min(Duration::from_secs(lifetime_secs / 2));
        let early = chrono::Duration::from_std(early).unwrap_or_default();

        Ok(CachedToken {
            access_token,
            expires_at,
            refresh_at: expires_at - early,
        })
    }
}

#[cfg(test)]
mod tests;
