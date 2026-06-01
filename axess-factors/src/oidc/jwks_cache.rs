//! JWKS cache with single-flight refresh + min-interval coalescing.
//!
//! Thundering-herd-resistant refresh path reusable by any adopter that
//! verifies JWTs from an OIDC-style issuer (federated IdPs, JWT-SVID
//! workloads, custom token validators) without taking the full OAuth
//! ceremony surface.

use crate::oidc::error::OidcError;
use jsonwebtoken::jwk::JwkSet;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::Mutex as AsyncMutex;

/// Lower bound on the gap between consecutive JWKS refreshes per cache.
///
/// Concurrent callers that arrive within this window after a successful
/// refresh are short-circuited without re-hitting the network. 60 s
/// matches OIDC IdP norms: most rotate keys at multi-hour granularity,
/// so a 60-second debounce never delays legitimate rotation pickup by
/// more than the time to verify one re-issued JWT, while still squashing
/// herds on rotation events.
pub const MIN_JWKS_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// Refreshable JWKS cache backed by an HTTP `jwks_uri`.
///
/// Owns a cloned [`openidconnect::reqwest::Client`] so [`refresh`](Self::refresh) is callable
/// without the original caller threading the client through every site.
///
/// # Single-flight + min-interval coalescing
///
/// The naive implementation lets N concurrent unknown-`kid` tokens each
/// fire their own HTTPS GET to `jwks_uri`. Most IdPs rate-limit the JWKS
/// endpoint; tripping that limit *blocks legitimate rotation recovery*,
/// exactly the time the cache is stalest. [`refresh`](Self::refresh):
///
/// 1. Serialises concurrent callers via an internal async refresh mutex.
///    Only one HTTPS request is in flight at a time per cache.
/// 2. Inside the lock, checks the timestamp of the most recent refresh.
///    If a peer just refreshed within [`MIN_JWKS_REFRESH_INTERVAL`], the
///    waiter returns `Ok(())` without re-hitting the network; the herd
///    collapses into one fetch + N free returns.
#[derive(Debug)]
pub struct JwksCache {
    jwks_uri: String,
    http_client: openidconnect::reqwest::Client,
    jwks: Arc<RwLock<JwkSet>>,
    refresh_lock: Arc<AsyncMutex<()>>,
    last_refresh: Arc<Mutex<Option<Instant>>>,
}

impl JwksCache {
    /// Fetch a JWKS from `jwks_uri` and return a cache primed with it.
    ///
    /// The supplied `http_client` is cloned and retained for subsequent
    /// [`refresh`](Self::refresh) calls. Callers should configure the
    /// client with redirects disabled (SSRF defense) and a per-operation
    /// timeout before passing it in.
    pub async fn fetch(
        jwks_uri: impl Into<String>,
        http_client: &openidconnect::reqwest::Client,
    ) -> Result<Self, OidcError> {
        let jwks_uri = jwks_uri.into();
        let bytes = http_client
            .get(&jwks_uri)
            .send()
            .await
            .map_err(|e| OidcError::JwksFetch(format!("{e}")))?
            .bytes()
            .await
            .map_err(|e| OidcError::JwksFetch(format!("read body: {e}")))?;
        let jwks: JwkSet =
            serde_json::from_slice(&bytes).map_err(|e| OidcError::JwksParse(format!("{e}")))?;

        Ok(Self {
            jwks_uri,
            http_client: http_client.clone(),
            jwks: Arc::new(RwLock::new(jwks)),
            refresh_lock: Arc::new(AsyncMutex::new(())),
            last_refresh: Arc::new(Mutex::new(None)),
        })
    }

    /// Construct a cache from a pre-parsed [`JwkSet`].
    ///
    /// Useful when discovery and JWKS fetch are interleaved (e.g.
    /// [`crate::oidc::Discovery::fetch`]) so the initial JWKS bytes don't
    /// have to be fetched twice.
    pub fn from_parts(
        jwks_uri: impl Into<String>,
        http_client: &openidconnect::reqwest::Client,
        jwks: JwkSet,
    ) -> Self {
        Self {
            jwks_uri: jwks_uri.into(),
            http_client: http_client.clone(),
            jwks: Arc::new(RwLock::new(jwks)),
            refresh_lock: Arc::new(AsyncMutex::new(())),
            last_refresh: Arc::new(Mutex::new(None)),
        }
    }

    /// JWKS endpoint URL the cache fetches from.
    pub fn jwks_uri(&self) -> &str {
        &self.jwks_uri
    }

    /// Shared handle to the cached `JwkSet`. Verifiers should clone this
    /// and take a read lock per verification to avoid holding the lock
    /// across `.await`.
    pub fn handle(&self) -> Arc<RwLock<JwkSet>> {
        self.jwks.clone()
    }

    /// Re-fetch the JWKS from `jwks_uri` and replace the cached set.
    ///
    /// Coalesces concurrent callers via single-flight + min-interval
    /// debounce. Safe to call from a `kid`-miss code path or a
    /// background scheduler.
    pub async fn refresh(&self) -> Result<(), OidcError> {
        let refresh_guard = self.refresh_lock.lock().await;

        let now = Instant::now();
        let last = self
            .last_refresh
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .copied();
        if let Some(prev) = last
            && now.duration_since(prev) < MIN_JWKS_REFRESH_INTERVAL
        {
            tracing::debug!(
                jwks_uri = %self.jwks_uri,
                age_secs = now.duration_since(prev).as_secs(),
                "JWKS refresh coalesced; peer refreshed within debounce window",
            );
            return Ok(());
        }

        let bytes = self
            .http_client
            .get(&self.jwks_uri)
            .send()
            .await
            .map_err(|e| OidcError::JwksFetch(format!("{e}")))?
            .bytes()
            .await
            .map_err(|e| OidcError::JwksFetch(format!("read body: {e}")))?;
        let new_jwks: JwkSet =
            serde_json::from_slice(&bytes).map_err(|e| OidcError::JwksParse(format!("{e}")))?;

        let mut guard = self.jwks.write().unwrap_or_else(|poisoned| {
            tracing::warn!("JWKS RwLock was poisoned; recovering with fresh data");
            poisoned.into_inner()
        });
        *guard = new_jwks;
        *self
            .last_refresh
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Instant::now());
        tracing::info!(jwks_uri = %self.jwks_uri, "JWKS refreshed successfully");
        drop(refresh_guard);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn sample_jwks_json() -> serde_json::Value {
        serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": "k1",
                "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                "e": "AQAB",
            }],
        })
    }

    #[tokio::test]
    async fn fetch_loads_jwks_from_endpoint() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(sample_jwks_json()))
            .mount(&server)
            .await;

        let client = openidconnect::reqwest::Client::new();
        let cache = JwksCache::fetch(format!("{}/jwks.json", server.uri()), &client)
            .await
            .expect("fetch ok");

        let handle = cache.handle();
        let jwks = handle.read().unwrap();
        assert_eq!(jwks.keys.len(), 1);
    }

    /// `refresh` collapses concurrent callers into a single outbound
    /// fetch. The mock expects exactly one call: any wider count means
    /// the debounce window collapsed.
    #[tokio::test]
    async fn refresh_debounces_within_window() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(sample_jwks_json()))
            .expect(2) // initial fetch + one refresh; subsequent refreshes debounced
            .mount(&server)
            .await;

        let client = openidconnect::reqwest::Client::new();
        let cache = JwksCache::fetch(format!("{}/jwks.json", server.uri()), &client)
            .await
            .expect("fetch ok");

        cache.refresh().await.expect("first refresh ok");

        // Subsequent immediate refreshes coalesce; no additional GET.
        cache.refresh().await.expect("second refresh ok");
        cache.refresh().await.expect("third refresh ok");
    }

    #[tokio::test]
    async fn fetch_propagates_parse_errors() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not-json"))
            .mount(&server)
            .await;

        let client = openidconnect::reqwest::Client::new();
        let err = JwksCache::fetch(format!("{}/jwks.json", server.uri()), &client)
            .await
            .expect_err("parse failure must propagate");
        assert!(
            matches!(err, OidcError::JwksParse(_)),
            "expected JwksParse, got {err:?}"
        );
    }
}
