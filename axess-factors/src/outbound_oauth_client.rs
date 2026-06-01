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
//! - First `get_access_token()` → token request, cache the response
//!   with `(now + expires_in - refresh_threshold)` as the effective
//!   expiry.
//! - Subsequent calls inside the validity window → return cached
//!   value (read-locked, no HTTP).
//! - Inside `refresh_threshold` of expiry → refresh under a write lock
//!   (one fetch per concurrent burst).
//! - After expiry → blocking refresh.
//!
//! `force_refresh()` bypasses the cache and unconditionally fetches a
//! new token (use after a `401` from the upstream resource).
//!
//! # DST
//!
//! The injectable [`Clock`] makes expiry deterministic under
//! [`MockClock`](axess_clock::testing::MockClock). The HTTP path uses
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
use tokio::sync::RwLock;
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
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
}

/// In-memory cached access token. The string is zeroized on drop via
/// [`ZeroizedString`] so a heap-dump of axess does not surface
/// plaintext tokens.
struct CachedToken {
    access_token: ZeroizedString,
    /// `now + expires_in` from the token response. The effective
    /// "refresh due" point is `expires_at - refresh_threshold`.
    expires_at: DateTime<Utc>,
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
    refresh_threshold: Duration,
    clock: Arc<dyn Clock>,
    /// Entropy source for the `jti` claim of `private_key_jwt` client
    /// assertions. Injected so DST tests can produce reproducible
    /// assertion JWTs.
    rng: Arc<dyn SecureRng>,
    http_client: reqwest::Client,
}

impl OutboundOAuthClient {
    /// Construct a new outbound OAuth client.
    ///
    /// Defaults: empty scope list, 30-second refresh threshold,
    /// [`SystemClock`], default [`reqwest::Client`]. Override via the
    /// `with_*` builder methods.
    pub fn new(token_url: Url, auth_method: ClientAuthMethod) -> Self {
        Self {
            token_url,
            auth_method,
            scopes: Vec::new(),
            cached_token: Arc::new(RwLock::new(None)),
            refresh_threshold: Duration::from_secs(30),
            clock: Arc::new(SystemClock),
            rng: Arc::new(SystemRng),
            http_client: reqwest::Client::new(),
        }
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
    /// window of `expires_at`.
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
    pub fn with_http_client(mut self, client: reqwest::Client) -> Self {
        self.http_client = client;
        self
    }

    /// Return a valid access token, refreshing the cache silently if
    /// needed. Concurrent calls deduplicate the refresh under a write
    /// lock.
    pub async fn get_access_token(&self) -> Result<String, OAuthClientError> {
        // Fast path: read-lock, check validity, return.
        {
            let cached = self.cached_token.read().await;
            if let Some(token) = cached.as_ref()
                && self.token_is_still_fresh(token)
            {
                return Ok((*token.access_token).to_string());
            }
        }

        // Slow path: refresh under write lock with a double-check (a
        // racing thread may have already refreshed by the time we
        // acquire the write lock).
        let mut cached = self.cached_token.write().await;
        if let Some(token) = cached.as_ref()
            && self.token_is_still_fresh(token)
        {
            return Ok((*token.access_token).to_string());
        }
        let fresh = self.fetch_new_token().await?;
        let token_str = (*fresh.access_token).to_string();
        *cached = Some(fresh);
        Ok(token_str)
    }

    /// Bypass the cache and unconditionally fetch a new token. Useful
    /// after the upstream resource returned `401`, indicating the
    /// cached token has been server-side revoked or invalidated.
    pub async fn force_refresh(&self) -> Result<String, OAuthClientError> {
        let mut cached = self.cached_token.write().await;
        let fresh = self.fetch_new_token().await?;
        let token_str = (*fresh.access_token).to_string();
        *cached = Some(fresh);
        Ok(token_str)
    }

    fn token_is_still_fresh(&self, token: &CachedToken) -> bool {
        let now = self.clock.now();
        let refresh_due_at = token.expires_at
            - chrono::Duration::from_std(self.refresh_threshold).unwrap_or_default();
        now < refresh_due_at
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
                let creds = format!("{}:{}", client_id, &**client_secret);
                let encoded = B64_STANDARD.encode(creds);
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

        let response = request
            .form(&form)
            .send()
            .await
            .map_err(|e| OAuthClientError::Transport(e.to_string()))?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(OAuthClientError::TokenEndpoint {
                status: status.as_u16(),
                body,
            });
        }

        let parsed: TokenResponse = response
            .json()
            .await
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
        let expires_at = self.clock.now() + chrono::Duration::seconds(lifetime_secs as i64);

        // Move the String into the ZeroizedString wrapper so the
        // sole heap allocation gets zeroized when the cached entry
        // drops. Cloning + zeroizing the original would defeat the
        // purpose (leaves the clone unzeroed).
        let access_token = ZeroizedString::from(parsed.access_token);

        Ok(CachedToken {
            access_token,
            expires_at,
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
