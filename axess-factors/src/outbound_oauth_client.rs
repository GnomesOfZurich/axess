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
//!
//! The fetch holds no lock on the cache, only the single-flight gate, and is
//! bounded by a request timeout (30 s by default, see
//! [`with_request_timeout`](OutboundOAuthClient::with_request_timeout)).
//!
//! `force_refresh()` bypasses the cache and fetches a new token (use after a
//! `401` from the upstream resource); callers that arrive together share one
//! fetch.
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
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use reqwest::header::AUTHORIZATION;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::{Mutex, RwLock};
use url::Url;
use uuid::Builder as UuidBuilder;

use crate::secret::ZeroizedString;

/// Errors surfaced by [`OutboundOAuthClient`].
#[derive(Debug, thiserror::Error)]
pub enum OAuthClientError {
    /// Transport-level failure: connection refused, TLS error, DNS,
    /// timeout. Distinct from [`Self::TokenEndpoint`] (which is the
    /// IdP returning an error response).
    #[error("HTTP transport error: {0}")]
    Transport(String),
    /// Token endpoint returned a non-2xx response. Carries the HTTP
    /// status and (best-effort) body for adopter logging.
    #[error("token endpoint returned {status}: {body}")]
    TokenEndpoint {
        /// HTTP status code returned by the token endpoint.
        status: u16,
        /// Best-effort response body, captured as text for adopter
        /// logging. Empty if the body could not be read.
        body: String,
    },
    /// 2xx response but the body didn't deserialise as a valid
    /// `TokenResponse` (missing `access_token`, malformed JSON, etc).
    #[error("malformed token response: {0}")]
    MalformedResponse(String),
    /// JWT signing failed when constructing a `private_key_jwt`
    /// client assertion. Should not happen in production; the
    /// signing key is validated at client-construction time.
    #[error("client assertion signing failed: {0}")]
    Signing(String),
    /// The token URL is not HTTPS (and not loopback), so the client secret or
    /// assertion would travel in the clear. The URL is not echoed.
    #[error(
        "token endpoint must use HTTPS (http is only allowed for localhost, 127.0.0.1 and [::1])"
    )]
    InsecureEndpoint,
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
    /// RFC 7523 `private_key_jwt`. axess signs a short-lived JWT
    /// asserting its identity; the IdP validates against axess's
    /// published JWKS. No shared secret to rotate.
    PrivateKeyJwt {
        /// Public client identifier; used as both `iss` and `sub`
        /// in the assertion JWT per RFC 7523 §3.
        client_id: String,
        /// PEM-encoded private key for the chosen algorithm.
        /// Validated at client-construction time.
        signing_key: EncodingKey,
        /// JWA algorithm. Typical values: `RS256` (legacy IdPs),
        /// `ES256` (modern / FAPI 2.0), `PS256` (Microsoft Entra +
        /// FAPI 2.0 strict).
        algorithm: Algorithm,
        /// `kid` header for the assertion JWT. The IdP uses this to
        /// pick the right public key from axess's JWKS.
        key_id: Option<String>,
        /// `aud` claim of the assertion JWT. Per RFC 7523 §3 this
        /// must be a value the IdP recognises as identifying itself
        /// typically the token endpoint URL. Some IdPs require
        /// their `issuer` URL instead; consult the IdP's docs.
        audience: String,
        /// Lifetime of each minted assertion JWT. Per RFC 7523 §3
        /// must be short; default is 60 s.
        assertion_ttl: Duration,
    },
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
            Self::PrivateKeyJwt {
                client_id,
                algorithm,
                key_id,
                audience,
                assertion_ttl,
                ..
            } => f
                .debug_struct("PrivateKeyJwt")
                .field("client_id", client_id)
                .field("algorithm", algorithm)
                .field("key_id", key_id)
                .field("audience", audience)
                .field("assertion_ttl", assertion_ttl)
                .field("signing_key", &"<redacted>")
                .finish(),
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

/// RFC 7523 client-assertion JWT body.
#[derive(Serialize)]
struct ClientAssertionClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    exp: i64,
    iat: i64,
    jti: String,
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
    cached_token: Arc<RwLock<Option<CachedToken>>>,
    /// Single flight: held across a token fetch, never the cache lock.
    refresh_gate: Mutex<()>,
    /// Counts stored tokens, so a caller that waited on the gate can tell
    /// that someone else fetched while it waited.
    generation: AtomicU64,
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
/// `:`, `+` or `%` reaches a strict IdP intact. Use as
/// `format!("Basic {}", basic_credentials(id, secret))`.
#[must_use]
pub fn basic_credentials(client_id: &str, client_secret: &str) -> String {
    let enc = |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
    B64_STANDARD.encode(format!("{}:{}", enc(client_id), enc(client_secret)))
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
            cached_token: Arc::new(RwLock::new(None)),
            refresh_gate: Mutex::new(()),
            generation: AtomicU64::new(0),
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
    /// instead of waiting for the fetch.
    pub async fn get_access_token(&self) -> Result<String, OAuthClientError> {
        // Fast path: read-lock, check validity, return.
        if let Some(token) = self.cached_if(|t, now| now < t.refresh_at).await {
            return Ok(token);
        }

        // Due for refresh, or nothing cached. Someone else may already be
        // fetching: a token that has not expired yet serves meanwhile.
        let guard = match self.refresh_gate.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                if let Some(token) = self.cached_if(|t, now| now < t.expires_at).await {
                    return Ok(token);
                }
                self.refresh_gate.lock().await
            }
        };
        // Double-check: the fetch we waited on may have stored a token.
        if let Some(token) = self.cached_if(|t, now| now < t.refresh_at).await {
            return Ok(token);
        }
        let token = self.fetch_and_store().await;
        drop(guard);
        token
    }

    /// Fetch a new token and cache it, unconditionally, unless another caller
    /// stored one while this one waited for the gate: callers that arrive
    /// together (a burst of `401`s from the upstream resource) share one
    /// fetch. Use after the upstream returned `401`, indicating the cached
    /// token has been server-side revoked or invalidated.
    pub async fn force_refresh(&self) -> Result<String, OAuthClientError> {
        let seen = self.generation.load(Ordering::Acquire);
        let guard = self.refresh_gate.lock().await;
        if self.generation.load(Ordering::Acquire) != seen
            && let Some(token) = self.cached_if(|t, now| now < t.expires_at).await
        {
            return Ok(token);
        }
        let token = self.fetch_and_store().await;
        drop(guard);
        token
    }

    /// The cached access token, when `usable` holds for it at the clock's
    /// current time.
    async fn cached_if(
        &self,
        usable: impl FnOnce(&CachedToken, DateTime<Utc>) -> bool,
    ) -> Option<String> {
        let now = self.clock.now();
        let cached = self.cached_token.read().await;
        cached
            .as_ref()
            .filter(|t| usable(t, now))
            .map(|t| (*t.access_token).to_string())
    }

    /// Fetch under the request timeout and store the result. The caller holds
    /// the single-flight gate; the cache lock is taken only to store.
    async fn fetch_and_store(&self) -> Result<String, OAuthClientError> {
        let fresh = tokio::time::timeout(self.request_timeout, self.fetch_new_token())
            .await
            .map_err(|_| {
                OAuthClientError::Transport(format!(
                    "token request timed out after {}s",
                    self.request_timeout.as_secs()
                ))
            })??;
        let token_str = (*fresh.access_token).to_string();
        *self.cached_token.write().await = Some(fresh);
        self.generation.fetch_add(1, Ordering::Release);
        Ok(token_str)
    }

    async fn fetch_new_token(&self) -> Result<CachedToken, OAuthClientError> {
        let mut form: Vec<(&str, String)> = vec![("grant_type", "client_credentials".to_string())];
        if !self.scopes.is_empty() {
            form.push(("scope", self.scopes.join(" ")));
        }

        let mut request = self.http_client.post(self.token_url.clone());

        match &self.auth_method {
            ClientAuthMethod::ClientSecretBasic {
                client_id,
                client_secret,
            } => {
                let encoded = basic_credentials(client_id, client_secret);
                request = request.header(AUTHORIZATION, format!("Basic {encoded}"));
            }
            ClientAuthMethod::ClientSecretPost {
                client_id,
                client_secret,
            } => {
                form.push(("client_id", client_id.clone()));
                form.push(("client_secret", (**client_secret).to_string()));
            }
            ClientAuthMethod::PrivateKeyJwt { .. } => {
                let assertion = self.mint_client_assertion()?;
                form.push((
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".to_string(),
                ));
                form.push(("client_assertion", assertion));
                if let ClientAuthMethod::PrivateKeyJwt { client_id, .. } = &self.auth_method {
                    form.push(("client_id", client_id.clone()));
                }
            }
        }

        let mut response = request
            .form(&form)
            .send()
            .await
            .map_err(|e| OAuthClientError::Transport(e.to_string()))?;

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

    fn mint_client_assertion(&self) -> Result<String, OAuthClientError> {
        let ClientAuthMethod::PrivateKeyJwt {
            client_id,
            signing_key,
            algorithm,
            key_id,
            audience,
            assertion_ttl,
        } = &self.auth_method
        else {
            // Type-system guarantees we only reach this from a
            // PrivateKeyJwt branch; the early return makes that
            // explicit instead of `unreachable!`.
            return Err(OAuthClientError::Signing(
                "mint_client_assertion called on non-PrivateKeyJwt auth method".into(),
            ));
        };

        let now = self.clock.now();
        let iat = now.timestamp();
        let exp = iat + assertion_ttl.as_secs() as i64;

        let mut jti_bytes = [0u8; 16];
        self.rng.fill_bytes(&mut jti_bytes);
        // RFC 4122 v4 from random bytes (sets version + variant bits).
        let jti = UuidBuilder::from_random_bytes(jti_bytes)
            .into_uuid()
            .to_string();

        let claims = ClientAssertionClaims {
            iss: client_id,
            sub: client_id,
            aud: audience,
            exp,
            iat,
            jti,
        };

        let mut header = Header::new(*algorithm);
        header.kid = key_id.clone();

        encode(&header, &claims, signing_key).map_err(|e| OAuthClientError::Signing(e.to_string()))
    }
}

#[cfg(test)]
mod tests;
