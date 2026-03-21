//! OAuth 2.0 / OpenID Connect relying party support.
//!
//! Provides federated authentication via external identity providers (Google,
//! GitHub, Microsoft, enterprise IdPs). The flow is:
//!
//! 1. [`AuthnService::begin_oauth_login`] — generates an authorization URL with
//!    PKCE, state, and nonce. Redirect the user's browser there.
//! 2. The IdP authenticates the user and redirects back with an authorization code.
//! 3. [`AuthnService::finish_oauth_login`] — exchanges the code for tokens,
//!    validates the ID token, and returns the OIDC claims. The application maps
//!    these to a local user and completes the session.

use openidconnect::{ClientId, ClientSecret, IssuerUrl, RedirectUrl, core::CoreProviderMetadata};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// ── Session keys ─────────────────────────────────────────────────────────────

pub(crate) mod keys {
    pub const PKCE_VERIFIER: &str = "axess.oauth.pkce_verifier";
    pub const CSRF_STATE: &str = "axess.oauth.csrf_state";
    pub const NONCE: &str = "axess.oauth.nonce";
    pub const PROVIDER: &str = "axess.oauth.provider";
    pub const STARTED: &str = "axess.oauth.started";
}

// ── OAuthProviderConfig ──────────────────────────────────────────────────────

/// Configuration for an OAuth 2.0 / OIDC identity provider.
pub struct OAuthProviderConfig {
    /// Short identifier for this provider (e.g. `"google"`, `"github"`).
    pub name: Arc<str>,
    /// OIDC provider metadata (endpoints, keys).
    pub(crate) metadata: CoreProviderMetadata,
    /// OAuth client ID.
    pub(crate) client_id: ClientId,
    /// OAuth client secret.
    pub(crate) client_secret: Option<ClientSecret>,
    /// Redirect URL for the callback.
    pub(crate) redirect_url: RedirectUrl,
    /// HTTP client for token exchange (configured not to follow redirects).
    pub(crate) http_client: openidconnect::reqwest::Client,
    /// Scopes to request. Default: `["openid", "email", "profile"]`.
    pub scopes: Vec<String>,
    /// How long the OAuth ceremony (redirect → callback) is valid.
    /// Default: 10 minutes. Set higher for IdPs with slow MFA prompts.
    pub ceremony_timeout: std::time::Duration,
}

impl OAuthProviderConfig {
    /// Create a provider using OIDC discovery.
    ///
    /// Fetches `{issuer_url}/.well-known/openid-configuration` to configure
    /// authorization, token, and userinfo endpoints automatically.
    pub async fn discover(
        name: &str,
        issuer_url: &str,
        client_id: &str,
        client_secret: &str,
        redirect_url: &str,
    ) -> Result<Self, OAuthError> {
        let issuer = IssuerUrl::new(issuer_url.to_string())
            .map_err(|e| OAuthError::Config(format!("invalid issuer URL: {e}")))?;

        // HTTP client MUST NOT follow redirects (SSRF prevention).
        let http_client = openidconnect::reqwest::ClientBuilder::new()
            .redirect(openidconnect::reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| OAuthError::Config(format!("HTTP client build failed: {e}")))?;

        let metadata = CoreProviderMetadata::discover_async(issuer, &http_client)
            .await
            .map_err(|e| OAuthError::Discovery(format!("{e}")))?;

        let redirect = RedirectUrl::new(redirect_url.to_string())
            .map_err(|e| OAuthError::Config(format!("invalid redirect URL: {e}")))?;

        Ok(Self {
            name: name.into(),
            metadata,
            client_id: ClientId::new(client_id.to_string()),
            client_secret: Some(ClientSecret::new(client_secret.to_string())),
            redirect_url: redirect,
            http_client,
            scopes: vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ],
            ceremony_timeout: std::time::Duration::from_secs(600),
        })
    }

    /// Override the default scopes.
    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes;
        self
    }

    /// Override the ceremony timeout (default: 10 minutes).
    pub fn with_ceremony_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.ceremony_timeout = timeout;
        self
    }

    /// Construct a fully-configured OIDC client for a single operation.
    ///
    /// openidconnect 4.0 uses typestates that make the fully-configured client
    /// type unwieldy to store as a struct field. We construct it on-the-fly
    /// instead — this is cheap (no network calls, just copying Arc'd data).
    #[allow(clippy::type_complexity)]
    pub(crate) fn make_client(
        &self,
    ) -> openidconnect::Client<
        openidconnect::EmptyAdditionalClaims,
        openidconnect::core::CoreAuthDisplay,
        openidconnect::core::CoreGenderClaim,
        openidconnect::core::CoreJweContentEncryptionAlgorithm,
        openidconnect::core::CoreJsonWebKey,
        openidconnect::core::CoreAuthPrompt,
        openidconnect::StandardErrorResponse<openidconnect::core::CoreErrorResponseType>,
        openidconnect::core::CoreTokenResponse,
        openidconnect::core::CoreTokenIntrospectionResponse,
        openidconnect::core::CoreRevocableToken,
        openidconnect::core::CoreRevocationErrorResponse,
        openidconnect::EndpointSet,
        openidconnect::EndpointNotSet,
        openidconnect::EndpointNotSet,
        openidconnect::EndpointNotSet,
        openidconnect::EndpointMaybeSet,
        openidconnect::EndpointMaybeSet,
    > {
        openidconnect::core::CoreClient::from_provider_metadata(
            self.metadata.clone(),
            self.client_id.clone(),
            self.client_secret.clone(),
        )
        .set_redirect_uri(self.redirect_url.clone())
    }
}

// ── OAuthClaims ──────────────────────────────────────────────────────────────

/// OIDC claims extracted from a validated ID token.
///
/// The fixed fields (`subject`, `email`, `name`) cover the most common claims.
/// For Azure AD `groups`, `roles`, `tid`, `preferred_username`, or any other
/// provider-specific claims, use the [`additional_claims`](OAuthClaims::additional_claims) map.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClaims {
    /// Provider name (e.g. `"google"`).
    pub provider: Arc<str>,
    /// OIDC subject — unique, stable identifier at this provider.
    pub subject: String,
    /// Email address (if `email` scope was granted).
    pub email: Option<String>,
    /// Whether the email has been verified by the provider.
    pub email_verified: Option<bool>,
    /// Display name (if `profile` scope was granted).
    pub name: Option<String>,
    /// Group memberships from the IdP (e.g. Azure AD `groups` claim).
    /// Empty if the IdP doesn't include groups or the scope wasn't requested.
    pub groups: Vec<String>,
    /// Role assignments from the IdP (e.g. Azure AD `roles` claim).
    pub roles: Vec<String>,
    /// The refresh token returned by the IdP, if any.
    /// Use with [`AuthnService::refresh_oauth_token`] to renew access.
    /// `None` if the IdP didn't return a refresh token (e.g. `offline_access`
    /// scope not requested).
    #[serde(skip_serializing)]
    pub refresh_token: Option<String>,
    /// All additional claims from the ID token as a raw JSON map.
    /// Includes provider-specific claims (Azure AD `tid`, `preferred_username`,
    /// `oid`, `auth_time`, etc.) that the fixed fields don't cover.
    pub additional_claims: serde_json::Value,
}

// ── OAuthLoginOptions ────────────────────────────────────────────────────────

/// Options for a single OAuth login flow.
///
/// Pass to [`AuthnService::begin_oauth_login`] to control the authorization
/// request parameters.
#[derive(Debug, Clone, Default)]
pub struct OAuthLoginOptions {
    /// OIDC `prompt` parameter. Controls IdP UI behavior:
    /// - `"none"` — silent auth (check for existing IdP session, no UI)
    /// - `"login"` — force re-authentication even if the user has a session
    /// - `"consent"` — force consent screen
    /// - `"select_account"` — show account picker (useful for multi-account users)
    pub prompt: Option<String>,

    /// OIDC `login_hint` parameter. Pre-fills the identifier field at the IdP.
    /// Typically the user's email address or UPN.
    pub login_hint: Option<String>,

    /// Additional scopes beyond the provider's default scopes.
    /// Useful for requesting `offline_access` (refresh tokens) per-flow.
    pub extra_scopes: Vec<String>,
}

impl OAuthLoginOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn prompt(mut self, prompt: &str) -> Self {
        self.prompt = Some(prompt.to_string());
        self
    }

    pub fn login_hint(mut self, hint: &str) -> Self {
        self.login_hint = Some(hint.to_string());
        self
    }

    pub fn extra_scope(mut self, scope: &str) -> Self {
        self.extra_scopes.push(scope.to_string());
        self
    }
}

// ── OAuthError ───────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum OAuthError {
    #[error("OAuth configuration error: {0}")]
    Config(String),

    #[error("OIDC discovery failed: {0}")]
    Discovery(String),

    #[error("token exchange failed: {0}")]
    TokenExchange(String),

    #[error("ID token validation failed: {0}")]
    IdTokenValidation(String),

    #[error("unknown provider: {0}")]
    UnknownProvider(String),

    #[error("CSRF state mismatch")]
    CsrfMismatch,

    #[error("no OAuth flow in progress")]
    NoFlow,

    #[error("OAuth ceremony expired")]
    Expired,

    #[error("invalid OAuth callback parameter")]
    InvalidParameter,
}

// ── OAuthProviderRegistry ────────────────────────────────────────────────────

#[derive(Default)]
pub(crate) struct OAuthProviderRegistry {
    providers: std::collections::HashMap<Arc<str>, OAuthProviderConfig>,
}

impl OAuthProviderRegistry {
    pub fn add(&mut self, config: OAuthProviderConfig) {
        self.providers.insert(config.name.clone(), config);
    }

    pub fn get(&self, name: &str) -> Option<&OAuthProviderConfig> {
        self.providers.get(name)
    }
}
