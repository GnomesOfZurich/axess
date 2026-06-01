//! Plain-OAuth-2.0 user login (a.k.a. "social login").
//!
//! # Security model; read first
//!
//! **Social providers authenticate users without a signed identity
//! assertion.** Identity comes from a userinfo HTTPS endpoint;
//! your only defense is TLS to the IdP and your trust in that IdP.
//! There is no ID token to verify, no JWKS, no `iss` / `aud` / `exp`
//! claims protecting you against token replay or confused-deputy
//! attacks at the OIDC layer. The IdP can return *anything* in its
//! userinfo response and the adopter must accept it absolutely.
//!
//! Use this **only** when:
//!
//! - The provider does not support OIDC (GitHub user login, Twitter,
//!   Discord, Reddit, Spotify, Strava, …).
//! - You explicitly trust the provider's userinfo response not to
//!   misattribute identity (i.e. a compromised IdP can impersonate
//!   any of its users to your service, and you accept that blast
//!   radius).
//!
//! Prefer
//! [`OAuthProviderConfig::discover`](crate::oauth::OAuthProviderConfig::discover)
//! whenever the IdP supports OIDC. Google, Microsoft, GitLab, Auth0,
//! Okta, Keycloak, Logto, Zitadel; all OIDC-compliant. Going through
//! the OIDC path means signed ID tokens, JWKS rotation handled for
//! you, and standard claim validation.
//!
//! # Why one generic struct, no per-provider sub-features
//!
//! Each provider's userinfo shape is small (a JSON GET) and adopters
//! care about their *specific* provider's exact fields. Hard-coding
//! per-company features (`social-github`, `social-discord`, …) would
//! invite endless additions without any reuse benefit beyond what a
//! small claim parser already provides. Adopters supply the claim
//! parser per provider they care about; this module handles the OAuth
//! 2.0 ceremony + userinfo HTTP + PKCE + CSRF state.
//!
//! # Usage
//!
//! ```ignore
//! use axess_factors::social::{SocialProvider, SocialClaims, SocialError};
//!
//! // Startup wiring; one provider per IdP.
//! let github = SocialProvider::new(
//!     SocialProviderConfig {
//!         name: "github".into(),
//!         authorization_endpoint: "https://github.com/login/oauth/authorize".into(),
//!         token_endpoint: "https://github.com/login/oauth/access_token".into(),
//!         userinfo_endpoint: "https://api.github.com/user".into(),
//!         client_id,
//!         client_secret,
//!         redirect_uri: "https://app.example.com/auth/callback/github".into(),
//!         scopes: vec!["read:user".into(), "user:email".into()],
//!     },
//!     |raw: &serde_json::Value| -> Result<SocialClaims, SocialError> {
//!         let id = raw.get("id").and_then(|v| v.as_i64()).ok_or_else(|| {
//!             SocialError::ClaimMapping("missing numeric `id`".into())
//!         })?;
//!         Ok(SocialClaims {
//!             subject: id.to_string(),
//!             email: raw.get("email").and_then(|v| v.as_str()).map(String::from),
//!             display_name: raw.get("name").and_then(|v| v.as_str()).map(String::from),
//!             raw: raw.clone(),
//!         })
//!     },
//! );
//!
//! // Per request: kick off the flow.
//! let csrf_state = mint_csrf_state();
//! let pkce = github.build_auth_url(&csrf_state);
//! // → store (csrf_state, pkce.verifier) in the user's pre-auth session,
//! //   then redirect to pkce.url.
//!
//! // Callback handler: verify state, exchange code, fetch userinfo.
//! let access_token = github.exchange_code(&code, &pkce_verifier).await?;
//! let claims = github.fetch_userinfo(&access_token).await?;
//! ```

use std::sync::Arc;

use axess_rng::{SecureRng, SystemRng};
use serde::Deserialize;

/// Errors from the social-login flow.
#[derive(Debug, thiserror::Error)]
pub enum SocialError {
    /// Configuration error (invalid URL, missing field, …).
    #[error("social provider config: {0}")]
    Config(String),

    /// HTTP request to the IdP failed (network, TLS, timeout).
    #[error("social provider HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// IdP returned a successful HTTP response with an unexpected shape.
    #[error("social provider invalid response: {0}")]
    InvalidResponse(String),

    /// The caller-supplied claim mapper rejected the userinfo response.
    #[error("social provider claim mapping: {0}")]
    ClaimMapping(String),
}

/// User identity extracted from a social provider's userinfo response.
///
/// Distinct type from
/// [`IdTokenClaims`](crate::oauth::types::IdTokenClaims) so the security
/// difference is visible at every call site: claims here come from a
/// TLS-trusted JSON GET, not from a signed assertion. Treating one as
/// the other is a type error.
#[derive(Debug, Clone)]
pub struct SocialClaims {
    /// Stable identifier for the user at this provider. Required;
    /// the claim mapper MUST produce one. For GitHub this is the
    /// numeric `id`; for Twitter the `data.id` UUID; for Discord the
    /// snowflake `id`; etc.
    pub subject: String,

    /// Email address if the provider supplied one. May be `None` for
    /// providers that don't return email or where the user has not
    /// verified theirs.
    pub email: Option<String>,

    /// Display name suitable for UI rendering. May be `None`.
    pub display_name: Option<String>,

    /// Full userinfo JSON response. Adopter has access for provider-
    /// specific fields beyond the normalised shape above.
    pub raw: serde_json::Value,
}

/// Result of building the authorization URL.
///
/// The adopter stores `csrf_state` + `pkce_verifier` in the user's
/// pre-auth session, then redirects to `url`. On callback both values
/// come back out of the session and feed
/// [`SocialProvider::exchange_code`].
#[derive(Debug)]
pub struct AuthUrl {
    /// Redirect URL to send the user to.
    pub url: String,
    /// PKCE verifier (RFC 7636); store, then pass back to
    /// [`SocialProvider::exchange_code`]. Empty string when PKCE is
    /// disabled via [`SocialProvider::without_pkce`].
    pub pkce_verifier: String,
}

/// Static provider configuration for a plain-OAuth-2.0 social-login
/// IdP.
///
/// All fields are required. The struct is `Deserialize` so adopters
/// can load provider definitions from config files (TOML, YAML, JSON)
/// and feed them to [`SocialProvider::new`] alongside a claim-mapping
/// closure.
#[derive(Debug, Clone, Deserialize)]
pub struct SocialProviderConfig {
    /// Provider name (e.g. `"github"`). Used for audit-log attribution
    /// and to disambiguate when multiple providers are wired.
    pub name: String,
    /// OAuth 2.0 authorization endpoint URL (RFC 6749 §3.1).
    pub authorization_endpoint: String,
    /// OAuth 2.0 token endpoint URL (RFC 6749 §3.2).
    pub token_endpoint: String,
    /// Userinfo endpoint URL: the GET that returns the user's profile
    /// JSON (consumed by the caller-supplied `claim_mapper`).
    pub userinfo_endpoint: String,
    /// OAuth 2.0 `client_id` for this adopter.
    pub client_id: String,
    /// OAuth 2.0 `client_secret` for this adopter.
    pub client_secret: String,
    /// Adopter's callback URL: the IdP redirects back to this after
    /// authorization. Must match what the adopter registered with the IdP.
    pub redirect_uri: String,
    /// Scopes the adopter requests at authorization (e.g.
    /// `vec!["read:user".into(), "user:email".into()]`).
    pub scopes: Vec<String>,
}

/// Generic plain-OAuth-2.0 social-login provider.
///
/// Configured with a claim-mapping closure that turns the IdP's
/// userinfo JSON into normalised [`SocialClaims`]. The library handles
/// the OAuth 2.0 ceremony (authorization URL with PKCE + CSRF state,
/// authorization-code exchange, userinfo fetch); the closure handles
/// IdP-specific claim shape.
pub struct SocialProvider<F>
where
    F: Fn(&serde_json::Value) -> Result<SocialClaims, SocialError> + Send + Sync,
{
    name: Arc<str>,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    scopes: Vec<String>,
    use_pkce: bool,
    claim_mapper: F,
    http: reqwest::Client,
    // Routes through the axess RNG abstraction so DST tests can pin
    // the PKCE verifier by swapping in a `MockRng`. Default: `SystemRng`.
    rng: Arc<dyn SecureRng>,
}

impl<F> SocialProvider<F>
where
    F: Fn(&serde_json::Value) -> Result<SocialClaims, SocialError> + Send + Sync,
{
    /// Construct a provider from a [`SocialProviderConfig`] and a
    /// claim-mapping closure.
    ///
    /// PKCE (RFC 7636) is ON by default. Disable via
    /// [`without_pkce`](Self::without_pkce) for the rare provider that
    /// rejects unrecognised query parameters; modern OAuth 2.0
    /// implementations accept PKCE even when not required, and it's a
    /// strict security improvement.
    pub fn new(config: SocialProviderConfig, claim_mapper: F) -> Self {
        Self {
            name: Arc::from(config.name.as_str()),
            authorization_endpoint: config.authorization_endpoint,
            token_endpoint: config.token_endpoint,
            userinfo_endpoint: config.userinfo_endpoint,
            client_id: config.client_id,
            client_secret: config.client_secret,
            redirect_uri: config.redirect_uri,
            scopes: config.scopes,
            use_pkce: true,
            claim_mapper,
            // No-redirects HTTP client (SSRF defense), 30s per-op timeout.
            http: reqwest::ClientBuilder::new()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("reqwest client build"),
            rng: Arc::new(SystemRng),
        }
    }

    /// Disable PKCE for providers that reject the extra query
    /// parameter. Strongly discouraged; PKCE is a strict security
    /// improvement and almost every OAuth 2.0 implementation accepts
    /// it even when not required.
    pub fn without_pkce(mut self) -> Self {
        self.use_pkce = false;
        self
    }

    /// Swap the RNG used to mint the PKCE verifier and CSRF state.
    /// Tests inject a [`MockRng`](axess_rng::testing::MockRng) here
    /// so both are deterministic under DST; production keeps the
    /// default [`SystemRng`].
    pub fn with_rng(mut self, rng: Arc<dyn SecureRng>) -> Self {
        self.rng = rng;
        self
    }

    /// Swap the `reqwest::Client` used for token-exchange and
    /// userinfo calls.
    ///
    /// Default: no-redirect (SSRF defense) + 30s per-op timeout +
    /// `axess-social/<version>` `User-Agent`. Override when the
    /// adopter needs a custom User-Agent (some providers reject the
    /// default), a custom TLS provider, an outbound HTTP proxy, or a
    /// different per-op timeout.
    ///
    /// Adopters are responsible for keeping the no-redirect SSRF
    /// defense in their custom client; the library does not enforce
    /// it on the supplied instance.
    pub fn with_http_client(mut self, http: reqwest::Client) -> Self {
        self.http = http;
        self
    }

    /// Mint a fresh CSRF state token (32 random bytes, base64url-encoded,
    /// 43 chars).
    ///
    /// The adopter stores the returned value in the pre-auth session
    /// before redirecting, then verifies on the callback that the
    /// IdP-echoed `state` query parameter matches. Routes through the
    /// same injected RNG as PKCE so DST tests pin both deterministically.
    ///
    /// Provided as a helper so adopters don't reimplement CSRF-state
    /// minting (which has a sharp edge: too few bytes invites
    /// collisions, the wrong character set breaks URL safety).
    pub fn mint_csrf_state(&self) -> String {
        use base64::Engine as _;
        let mut buf = [0u8; 32];
        self.rng.fill_bytes(&mut buf);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
    }

    /// Provider name (e.g. `"github"`). Used for audit-log attribution
    /// and to disambiguate when multiple providers are wired.
    pub fn name(&self) -> &Arc<str> {
        &self.name
    }

    /// Build the authorization URL the user is redirected to.
    ///
    /// `csrf_state` is the per-flow CSRF token the adopter mints
    /// (32+ random bytes, base64url, stored in pre-auth session).
    /// The IdP echoes it back on the callback; verify equality
    /// before calling [`exchange_code`](Self::exchange_code).
    pub fn build_auth_url(&self, csrf_state: &str) -> AuthUrl {
        use base64::Engine as _;

        let pkce_verifier = if self.use_pkce {
            // RFC 7636 §4.1: 43–128 chars from the unreserved set.
            // 32 random bytes → 43 base64url chars. crate::pkce::CodeVerifier
            // exists but is gated on `oauth`; mint inline here so `social`
            // stays independent of the OIDC feature.
            let mut buf = [0u8; 32];
            self.rng.fill_bytes(&mut buf);
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
        } else {
            String::new()
        };

        let mut url = format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&state={}&scope={}",
            self.authorization_endpoint,
            urlencode(&self.client_id),
            urlencode(&self.redirect_uri),
            urlencode(csrf_state),
            urlencode(&self.scopes.join(" ")),
        );

        if self.use_pkce {
            use sha2::{Digest as _, Sha256};
            let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(Sha256::digest(pkce_verifier.as_bytes()));
            url.push_str(&format!(
                "&code_challenge={}&code_challenge_method=S256",
                urlencode(&challenge)
            ));
        }

        AuthUrl { url, pkce_verifier }
    }

    /// Exchange an authorization code for an access token.
    ///
    /// Sends the standard RFC 6749 §4.1.3 token request to the
    /// provider's token endpoint. Returns the access token only;
    /// social providers do not issue ID tokens.
    pub async fn exchange_code(
        &self,
        code: &str,
        pkce_verifier: &str,
    ) -> Result<String, SocialError> {
        let mut form: Vec<(&str, &str)> = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &self.redirect_uri),
            ("client_id", &self.client_id),
            ("client_secret", &self.client_secret),
        ];
        if self.use_pkce {
            form.push(("code_verifier", pkce_verifier));
        }

        let resp = self
            .http
            .post(&self.token_endpoint)
            .header("Accept", "application/json")
            .form(&form)
            .send()
            .await?
            .error_for_status()?;

        // GitHub returns either application/json or form-urlencoded based on
        // the Accept header; we ask for JSON. Other providers always return
        // JSON. Parse defensively.
        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
        }
        let body: TokenResponse = resp.json().await.map_err(|e| {
            SocialError::InvalidResponse(format!(
                "token endpoint did not return JSON access_token: {e}"
            ))
        })?;
        Ok(body.access_token)
    }

    /// Fetch the userinfo response, run the adopter-supplied claim
    /// mapper, and return the normalised claims.
    pub async fn fetch_userinfo(&self, access_token: &str) -> Result<SocialClaims, SocialError> {
        let raw: serde_json::Value = self
            .http
            .get(&self.userinfo_endpoint)
            .bearer_auth(access_token)
            .header("Accept", "application/json")
            // Some providers (notably GitHub) require a User-Agent.
            // axess by default sends `axess-social/<version>`; adopters
            // can pre-bake a customised client and pass it in via a
            // future `with_http_client` if they need to override.
            .header(
                "User-Agent",
                concat!("axess-social/", env!("CARGO_PKG_VERSION")),
            )
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        (self.claim_mapper)(&raw)
    }
}

/// Minimal `application/x-www-form-urlencoded` encoder for the auth-URL
/// query string. Used in `build_auth_url`; the token-endpoint POST uses
/// reqwest's `.form()` which encodes properly.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push_str(&format!("{b:02X}"));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use axess_rng::testing::MockRng;
    use wiremock::matchers::{body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn github_style_mapper(raw: &serde_json::Value) -> Result<SocialClaims, SocialError> {
        let id = raw
            .get("id")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| SocialError::ClaimMapping("missing numeric `id`".into()))?;
        Ok(SocialClaims {
            subject: id.to_string(),
            email: raw.get("email").and_then(|v| v.as_str()).map(String::from),
            display_name: raw.get("name").and_then(|v| v.as_str()).map(String::from),
            raw: raw.clone(),
        })
    }

    fn make_provider(
        mock: &MockServer,
    ) -> SocialProvider<
        impl Fn(&serde_json::Value) -> Result<SocialClaims, SocialError> + Send + Sync,
    > {
        SocialProvider::new(
            SocialProviderConfig {
                name: "github".into(),
                authorization_endpoint: format!("{}/login/oauth/authorize", mock.uri()),
                token_endpoint: format!("{}/login/oauth/access_token", mock.uri()),
                userinfo_endpoint: format!("{}/user", mock.uri()),
                client_id: "demo-client-id".into(),
                client_secret: "demo-client-secret".into(),
                redirect_uri: "https://app.example.com/auth/callback/github".into(),
                scopes: vec!["read:user".into(), "user:email".into()],
            },
            github_style_mapper,
        )
        // Pin the PKCE verifier so the assertion on the generated URL
        // is reproducible. `MockRng::new(seed)` is the standard DST
        // pattern used elsewhere in the workspace.
        .with_rng(std::sync::Arc::new(MockRng::new(42)))
    }

    #[test]
    fn build_auth_url_includes_pkce_and_state_by_default() {
        let provider = SocialProvider::new(
            SocialProviderConfig {
                name: "github".into(),
                authorization_endpoint: "https://github.com/login/oauth/authorize".into(),
                token_endpoint: "https://github.com/login/oauth/access_token".into(),
                userinfo_endpoint: "https://api.github.com/user".into(),
                client_id: "demo-client".into(),
                client_secret: "demo-secret".into(),
                redirect_uri: "https://app.example.com/auth/callback".into(),
                scopes: vec!["read:user".into()],
            },
            github_style_mapper,
        )
        .with_rng(std::sync::Arc::new(MockRng::new(7)));

        let result = provider.build_auth_url("csrf-state-xyz");

        assert!(
            result
                .url
                .starts_with("https://github.com/login/oauth/authorize?")
        );
        assert!(result.url.contains("response_type=code"));
        assert!(result.url.contains("client_id=demo-client"));
        assert!(result.url.contains("state=csrf-state-xyz"));
        assert!(result.url.contains("code_challenge="));
        assert!(result.url.contains("code_challenge_method=S256"));
        assert!(
            !result.pkce_verifier.is_empty(),
            "PKCE verifier should be present by default"
        );
    }

    #[test]
    fn without_pkce_omits_code_challenge() {
        let provider = SocialProvider::new(
            SocialProviderConfig {
                name: "discord".into(),
                authorization_endpoint: "https://discord.com/api/oauth2/authorize".into(),
                token_endpoint: "https://discord.com/api/oauth2/token".into(),
                userinfo_endpoint: "https://discord.com/api/users/@me".into(),
                client_id: "demo-client".into(),
                client_secret: "demo-secret".into(),
                redirect_uri: "https://app.example.com/auth/callback".into(),
                scopes: vec!["identify".into()],
            },
            github_style_mapper,
        )
        .without_pkce();

        let result = provider.build_auth_url("csrf-1");

        assert!(!result.url.contains("code_challenge"));
        assert!(result.pkce_verifier.is_empty());
    }

    #[tokio::test]
    async fn happy_path_exchanges_code_then_fetches_userinfo() {
        let mock = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/login/oauth/access_token"))
            .and(header("Accept", "application/json"))
            .and(body_string_contains("grant_type=authorization_code"))
            .and(body_string_contains("code=the-code"))
            .and(body_string_contains("client_id=demo-client-id"))
            .and(body_string_contains("code_verifier=pkce-verifier-stub"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "tok-abc",
                "token_type": "bearer",
            })))
            .expect(1)
            .mount(&mock)
            .await;

        Mock::given(method("GET"))
            .and(path("/user"))
            .and(header("Authorization", "Bearer tok-abc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 12345,
                "login": "octocat",
                "name": "The Octocat",
                "email": "octocat@example.com",
            })))
            .expect(1)
            .mount(&mock)
            .await;

        let provider = make_provider(&mock);
        let access_token = provider
            .exchange_code("the-code", "pkce-verifier-stub")
            .await
            .expect("exchange_code");
        assert_eq!(access_token, "tok-abc");

        let claims = provider
            .fetch_userinfo(&access_token)
            .await
            .expect("userinfo");
        assert_eq!(claims.subject, "12345");
        assert_eq!(claims.email.as_deref(), Some("octocat@example.com"));
        assert_eq!(claims.display_name.as_deref(), Some("The Octocat"));
        assert_eq!(
            claims.raw.get("login").and_then(|v| v.as_str()),
            Some("octocat")
        );
    }

    #[tokio::test]
    async fn token_endpoint_without_access_token_is_invalid_response() {
        let mock = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/login/oauth/access_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "authorization code expired",
            })))
            .mount(&mock)
            .await;

        let provider = make_provider(&mock);
        let err = provider
            .exchange_code("stale-code", "pkce-verifier-stub")
            .await
            .expect_err("missing access_token must error");
        assert!(
            matches!(err, SocialError::InvalidResponse(_)),
            "expected InvalidResponse, got {err:?}"
        );
    }

    #[tokio::test]
    async fn userinfo_4xx_is_http_error() {
        let mock = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/user"))
            .respond_with(ResponseTemplate::new(401).set_body_string("Bad credentials"))
            .mount(&mock)
            .await;

        let provider = make_provider(&mock);
        let err = provider
            .fetch_userinfo("revoked-token")
            .await
            .expect_err("401 must error");
        assert!(
            matches!(err, SocialError::Http(_)),
            "expected Http, got {err:?}"
        );
    }

    #[tokio::test]
    async fn claim_mapper_rejection_is_claim_mapping_error() {
        let mock = MockServer::start().await;

        // Userinfo lacks the `id` field the mapper requires.
        Mock::given(method("GET"))
            .and(path("/user"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "login": "octocat",
                "email": "octocat@example.com",
            })))
            .mount(&mock)
            .await;

        let provider = make_provider(&mock);
        let err = provider
            .fetch_userinfo("tok-anything")
            .await
            .expect_err("missing id must reject");
        assert!(
            matches!(err, SocialError::ClaimMapping(_)),
            "expected ClaimMapping, got {err:?}"
        );
    }
}
