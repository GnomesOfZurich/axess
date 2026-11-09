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
//! ```no_run
//! // no_run: the flow calls the provider's endpoints over the network.
//! use axess_factors::ZeroizedString;
//! use axess_factors::social::{SocialClaims, SocialError, SocialProvider, SocialProviderConfig};
//!
//! # async fn demo(client_id: String, client_secret: String, code: String) -> Result<(), SocialError> {
//! // Startup wiring; one provider per IdP.
//! let github = SocialProvider::new(
//!     SocialProviderConfig {
//!         name: "github".into(),
//!         authorization_endpoint: "https://github.com/login/oauth/authorize".into(),
//!         token_endpoint: "https://github.com/login/oauth/access_token".into(),
//!         userinfo_endpoint: "https://api.github.com/user".into(),
//!         client_id,
//!         client_secret: ZeroizedString::new(client_secret),
//!         redirect_uri: "https://app.example.com/auth/callback/github".into(),
//!         scopes: vec!["read:user".into(), "user:email".into()],
//!     },
//!     |raw: &serde_json::Value| -> Result<SocialClaims, SocialError> {
//!         let id = raw.get("id").and_then(|v| v.as_i64()).ok_or_else(|| {
//!             SocialError::ClaimMapping("missing numeric `id`".into())
//!         })?;
//!         Ok(SocialClaims {
//!             subject: id.to_string(),
//!             // A profile address is the user's own text. Pass it on as
//!             // verified only when the provider says it checked it.
//!             email: raw.get("email").and_then(|v| v.as_str()).map(String::from),
//!             email_verified: false,
//!             display_name: raw.get("name").and_then(|v| v.as_str()).map(String::from),
//!             raw: raw.clone(),
//!         })
//!     },
//! )?;
//!
//! // Per request: kick off the flow. The provider mints the state itself.
//! let auth = github.build_auth_url();
//! // → store (auth.state, auth.pkce_verifier) in the user's pre-auth session,
//! //   then redirect to auth.url.
//!
//! // Callback handler: the stored state and the one the IdP echoed are
//! // compared (in constant time) by the exchange, which then trades the code
//! // for a token; fetch userinfo with it.
//! # let returned_state = auth.state.clone();
//! let access_token = github
//!     .exchange_code(&auth.state, &returned_state, &code, &auth.pkce_verifier)
//!     .await?;
//! let claims = github.fetch_userinfo(&access_token).await?;
//! # let _ = claims;
//! # Ok(())
//! # }
//! ```

use std::sync::Arc;

use subtle::ConstantTimeEq as _;

use axess_rng::{SecureRng, SystemRng};
use serde::Deserialize;

use crate::secret::ZeroizedString;

/// Errors from the social-login flow.
#[derive(Debug, thiserror::Error)]
pub enum SocialError {
    /// Configuration error (invalid URL, missing field, …).
    #[error("social provider config: {0}")]
    Config(String),

    /// HTTP request to the IdP failed (network, TLS, timeout).
    #[error("social provider HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// The HTTP client could not be built, which happens when the TLS
    /// backend fails to initialise. The builder's error is the source.
    #[error("social provider HTTP client could not be built: {0}")]
    ClientBuild(#[source] reqwest::Error),

    /// IdP returned a successful HTTP response with an unexpected shape.
    #[error("social provider invalid response: {0}")]
    InvalidResponse(String),

    /// The caller-supplied claim mapper rejected the userinfo response.
    #[error("social provider claim mapping: {0}")]
    ClaimMapping(String),

    /// The `state` the IdP returned is not the one the flow stored (or none
    /// was stored). The code is not exchanged.
    #[error("social provider state does not match the flow")]
    StateMismatch,

    /// PKCE is on and the verifier is shorter than the 43 characters RFC
    /// 7636 requires: it did not come from [`SocialProvider::build_auth_url`]
    /// (a missing cookie read as empty, say). The code is not exchanged.
    #[error("social provider PKCE verifier is missing or too short")]
    InvalidPkceVerifier,
}

/// Refuse `url` unless it is HTTPS or loopback HTTP; `what` names the
/// setting in the error and the URL is not echoed.
fn require_secure_endpoint(url: &str, what: &str) -> Result<(), SocialError> {
    if crate::endpoint::is_https_or_loopback(url) {
        return Ok(());
    }
    Err(SocialError::Config(format!(
        "{what} must use HTTPS (http is only allowed for localhost, 127.0.0.1 and [::1])"
    )))
}

/// User identity extracted from a social provider's userinfo response.
///
/// Distinct type from
/// [`OAuthClaims`](crate::oauth::types::OAuthClaims) so the security
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
    /// providers that don't return email.
    ///
    /// **Not proof of control.** Read it as verified only when
    /// [`email_verified`](Self::email_verified) is `true`; linking or
    /// creating an account by an address the provider did not verify lets
    /// anyone who can put a stranger's address on their profile take that
    /// stranger's account.
    pub email: Option<String>,

    /// Whether the provider states that it verified [`email`](Self::email)
    /// (the user proved control of the address to the provider). The claim
    /// mapper must say so, per provider; there is no default, so a mapper
    /// cannot forget. When in doubt, `false`: an adopter links accounts by
    /// email only when this is `true`.
    pub email_verified: bool,

    /// Display name suitable for UI rendering. May be `None`.
    pub display_name: Option<String>,

    /// Full userinfo JSON response. Adopter has access for provider-
    /// specific fields beyond the normalised shape above.
    pub raw: serde_json::Value,
}

/// Result of building the authorization URL.
///
/// The adopter stores `state` + `pkce_verifier` in the user's pre-auth
/// session, then redirects to `url`. On callback both values come back out of
/// the session, with the `state` the IdP echoed, and feed
/// [`SocialProvider::exchange_code`]. A plain-OAuth-2.0 flow has no nonce:
/// there is no ID token for one to bind to.
pub struct AuthUrl {
    /// Redirect URL to send the user to.
    pub url: String,
    /// The CSRF state the provider minted for this flow (32 random bytes,
    /// base64url, 43 characters); it is in `url`. Store it, and pass it back
    /// as the expected state to [`SocialProvider::exchange_code`].
    pub state: String,
    /// PKCE verifier (RFC 7636); store, then pass back to
    /// [`SocialProvider::exchange_code`]. Empty string when PKCE is
    /// disabled via [`SocialProvider::without_pkce`].
    pub pkce_verifier: String,
}

/// Prints the URL but not the PKCE verifier, which is the secret half of the
/// code challenge in that URL.
impl std::fmt::Debug for AuthUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthUrl")
            .field("url", &self.url)
            .field("state", &self.state)
            .field("pkce_verifier", &"[redacted]")
            .finish()
    }
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
    ///
    /// Held as [`ZeroizedString`] so it is redacted in `Debug` output and
    /// zeroed on drop. This type derives `Debug` and is meant to be loaded
    /// from a config file, so a plain `String` here would print the secret
    /// verbatim the first time an adopter logged their own configuration.
    pub client_secret: ZeroizedString,
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
    client_secret: ZeroizedString,
    redirect_uri: String,
    scopes: Vec<String>,
    use_pkce: bool,
    missing_token_type_is_bearer: bool,
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
    ///
    /// The HTTP client is built here with no redirects, a 30-second
    /// per-operation timeout and an `axess-social/<version>` `User-Agent`
    /// (GitHub, among others, refuses requests without one).
    ///
    /// The token and userinfo endpoints receive the client secret, the
    /// code, the PKCE verifier and the access token, and the user is sent to
    /// the authorization endpoint, so all three must be HTTPS (plain HTTP
    /// only to `localhost`, `127.0.0.1` or `[::1]`); so must the
    /// `redirect_uri`, which the authorization code is returned to. They are
    /// checked here,
    /// once: the provider's fields do not change after construction.
    ///
    /// # Errors
    ///
    /// [`SocialError::Config`] naming the endpoint or the `redirect_uri` that is not
    /// HTTPS or loopback HTTP, without echoing its URL; [`SocialError::ClientBuild`]
    /// when the HTTP client cannot be built.
    pub fn new(config: SocialProviderConfig, claim_mapper: F) -> Result<Self, SocialError> {
        require_secure_endpoint(&config.authorization_endpoint, "authorization_endpoint")?;
        require_secure_endpoint(&config.token_endpoint, "token_endpoint")?;
        require_secure_endpoint(&config.userinfo_endpoint, "userinfo_endpoint")?;
        require_secure_endpoint(&config.redirect_uri, "redirect_uri")?;
        let http = build_http_client(|builder| builder)?;
        Ok(Self {
            name: Arc::from(config.name.as_str()),
            authorization_endpoint: config.authorization_endpoint,
            token_endpoint: config.token_endpoint,
            userinfo_endpoint: config.userinfo_endpoint,
            client_id: config.client_id,
            client_secret: config.client_secret,
            redirect_uri: config.redirect_uri,
            scopes: config.scopes,
            use_pkce: true,
            missing_token_type_is_bearer: false,
            claim_mapper,
            http,
            rng: Arc::new(SystemRng),
        })
    }

    /// Disable PKCE for providers that reject the extra query
    /// parameter. Strongly discouraged; PKCE is a strict security
    /// improvement and almost every OAuth 2.0 implementation accepts
    /// it even when not required.
    pub fn without_pkce(mut self) -> Self {
        self.use_pkce = false;
        self
    }

    /// Accept a token response that has no `token_type` and read it as
    /// `Bearer`.
    ///
    /// By default a response without `token_type` is refused
    /// ([`SocialError::InvalidResponse`]): RFC 6749 section 5.1 requires the
    /// field, and the token is sent on as a bearer token. A few providers
    /// leave it out (LinkedIn's token endpoint is the usual example; check
    /// the provider's own documentation, since this changes between
    /// versions), and every login against one fails without this call. It
    /// only supplies the missing value: a `token_type` that is present and is
    /// not `Bearer` (any case), such as `mac` or `DPoP`, is still refused.
    #[must_use]
    pub fn accept_missing_token_type(mut self) -> Self {
        self.missing_token_type_is_bearer = true;
        self
    }

    /// Swap the RNG used to mint the PKCE verifier and CSRF state.
    /// Tests inject a `MockRng` here
    /// so both are deterministic under DST; production keeps the
    /// default [`SystemRng`].
    pub fn with_rng(mut self, rng: Arc<dyn SecureRng>) -> Self {
        self.rng = rng;
        self
    }

    /// Adjust the `reqwest::ClientBuilder` behind the token-exchange and
    /// userinfo calls.
    ///
    /// `adjust` receives a builder that already carries the
    /// `axess-social/<version>` `User-Agent` and returns it changed: a
    /// custom User-Agent (some providers reject the default), a TLS
    /// provider or root store, an outbound HTTP proxy. The library then sets
    /// the no-redirect policy (SSRF defense) and the 30-second per-operation
    /// timeout on the result, so nothing `adjust` does can drop them; a
    /// whole `reqwest::Client` cannot be supplied for the same reason.
    ///
    /// # Errors
    ///
    /// [`SocialError::ClientBuild`] when the adjusted builder cannot build.
    pub fn with_http_client_builder(
        mut self,
        adjust: impl FnOnce(reqwest::ClientBuilder) -> reqwest::ClientBuilder,
    ) -> Result<Self, SocialError> {
        self.http = build_http_client(adjust)?;
        Ok(self)
    }

    /// Mint a fresh CSRF state token: 32 random bytes, base64url, 43 chars.
    /// Routes through the same injected RNG as PKCE so DST tests pin both
    /// deterministically.
    fn mint_csrf_state(&self) -> String {
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
    /// The provider mints the per-flow CSRF state itself (the caller cannot
    /// pass an empty or constant one) and returns it in [`AuthUrl::state`].
    /// The IdP echoes it back on the callback;
    /// [`exchange_code`](Self::exchange_code) compares the two.
    pub fn build_auth_url(&self) -> AuthUrl {
        use base64::Engine as _;

        let state = self.mint_csrf_state();

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

        // An endpoint that already has a query takes the parameters after it.
        let separator = if self.authorization_endpoint.contains('?') {
            if self.authorization_endpoint.ends_with(['?', '&']) {
                ""
            } else {
                "&"
            }
        } else {
            "?"
        };
        let mut url = format!(
            "{}{separator}response_type=code&client_id={}&redirect_uri={}&state={}&scope={}",
            self.authorization_endpoint,
            urlencode(&self.client_id),
            urlencode(&self.redirect_uri),
            urlencode(&state),
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

        AuthUrl {
            url,
            state,
            pkce_verifier,
        }
    }

    /// Exchange an authorization code for an access token.
    ///
    /// `expected_state` is the [`AuthUrl::state`] the flow stored and
    /// `returned_state` the `state` query parameter the IdP echoed. They are
    /// compared in constant time first, and a difference (or an empty
    /// expected state: nothing was stored) is [`SocialError::StateMismatch`]
    /// with no request made. With PKCE on, a `pkce_verifier` under 43
    /// characters is [`SocialError::InvalidPkceVerifier`], also before any
    /// request.
    ///
    /// Sends the standard RFC 6749 §4.1.3 token request to the
    /// provider's token endpoint. Returns the access token only, as a
    /// [`ZeroizedString`] that is zeroed when dropped and derefs to `str`;
    /// social providers do not issue ID tokens. The response's `token_type`
    /// must be `Bearer` (any case): another scheme, or none, is
    /// [`SocialError::InvalidResponse`] (a missing one is read as `Bearer` after
    /// [`accept_missing_token_type`](Self::accept_missing_token_type)).
    pub async fn exchange_code(
        &self,
        expected_state: &str,
        returned_state: &str,
        code: &str,
        pkce_verifier: &str,
    ) -> Result<ZeroizedString, SocialError> {
        if expected_state.is_empty()
            || !bool::from(expected_state.as_bytes().ct_eq(returned_state.as_bytes()))
        {
            return Err(SocialError::StateMismatch);
        }
        if self.use_pkce && pkce_verifier.len() < MIN_PKCE_VERIFIER_LEN {
            return Err(SocialError::InvalidPkceVerifier);
        }
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
        let mut resp = resp;
        let bytes =
            crate::http_body::read_limited(&mut resp, crate::http_body::MAX_TOKEN_BODY_BYTES)
                .await
                .map_err(|e| {
                    SocialError::InvalidResponse(format!("token endpoint response: {e}"))
                })?;

        // GitHub returns either application/json or form-urlencoded based on
        // the Accept header; we ask for JSON. Other providers always return
        // JSON. Parse defensively.
        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: ZeroizedString,
            #[serde(default)]
            token_type: Option<String>,
        }
        let body: TokenResponse = serde_json::from_slice(&bytes).map_err(|e| {
            SocialError::InvalidResponse(format!(
                "token endpoint did not return JSON access_token: {e}"
            ))
        })?;
        // The token is sent to the userinfo endpoint as a bearer token. One
        // issued under another scheme (`DPoP`, `mac`) is bound to something
        // this client does not hold, and `token_type` is required by RFC 6749
        // section 5.1: a response without it is refused, not assumed.
        let bearer = match body.token_type.as_deref() {
            Some(scheme) => scheme.eq_ignore_ascii_case("bearer"),
            None => self.missing_token_type_is_bearer,
        };
        if !bearer {
            return Err(SocialError::InvalidResponse(
                "token endpoint token_type is missing or is not Bearer".to_string(),
            ));
        }
        Ok(body.access_token)
    }

    /// Fetch the userinfo response, run the adopter-supplied claim
    /// mapper, and return the normalised claims.
    pub async fn fetch_userinfo(&self, access_token: &str) -> Result<SocialClaims, SocialError> {
        let mut resp = self
            .http
            .get(&self.userinfo_endpoint)
            .bearer_auth(access_token)
            .header("Accept", "application/json")
            .send()
            .await?
            .error_for_status()?;
        let bytes =
            crate::http_body::read_limited(&mut resp, crate::http_body::MAX_USERINFO_BODY_BYTES)
                .await
                .map_err(|e| SocialError::InvalidResponse(format!("userinfo response: {e}")))?;
        let raw: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|e| SocialError::InvalidResponse(format!("userinfo is not JSON: {e}")))?;

        (self.claim_mapper)(&raw)
    }
}

/// RFC 7636 §4.1: a code verifier is at least 43 characters.
const MIN_PKCE_VERIFIER_LEN: usize = 43;

/// The HTTP client: the default `User-Agent`, then the adopter's changes,
/// then no redirects (SSRF defense) and a 30-second per-operation timeout,
/// which come last so nothing before them can undo them.
fn build_http_client(
    adjust: impl FnOnce(reqwest::ClientBuilder) -> reqwest::ClientBuilder,
) -> Result<reqwest::Client, SocialError> {
    adjust(
        reqwest::ClientBuilder::new()
            .user_agent(concat!("axess-social/", env!("CARGO_PKG_VERSION"))),
    )
    .redirect(reqwest::redirect::Policy::none())
    .timeout(std::time::Duration::from_secs(30))
    .build()
    .map_err(SocialError::ClientBuild)
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
mod tests;
