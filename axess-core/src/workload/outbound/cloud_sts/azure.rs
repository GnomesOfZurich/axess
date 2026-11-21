//! Azure AD Federated Identity Credentials (FIC) adapter.
//!
//! An Azure AD app registration can be configured with a **federated
//! identity credential** that trusts an external OIDC issuer. A
//! workload presenting a token from that issuer can then obtain an
//! Azure AD access token via the standard OAuth 2.0
//! `client_credentials` grant, supplying the federated token as the
//! `client_assertion`.
//!
//! # Protocol
//!
//! `POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`
//! with `application/x-www-form-urlencoded` body:
//!
//! ```text
//! grant_type=client_credentials
//! client_id={azure-application-id}
//! scope={resource}/.default
//! client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
//! client_assertion={federated-token}
//! ```
//!
//! Response is the standard OAuth shape:
//!
//! ```json
//! { "access_token": "...", "token_type": "Bearer", "expires_in": 3599 }
//! ```
//!
//! # Token sources
//!
//! As with the other [`crate::workload::outbound::cloud_sts`] adapters,
//! axess does not mint Azure-bound OIDC tokens directly; the
//! federated token comes from K8s SA, GitHub Actions OIDC, axess's
//! own `LocalIdP` (feature `local-idp`), or any other JWT the configured
//! Azure FIC trusts.
//!
//! # Example
//!
//! ```rust,ignore
//! use axess::workload::outbound::cloud_sts::azure::{AzureFicClient, AzureFicRequest};
//!
//! let client = AzureFicClient::new(
//!     "tenant-guid",
//!     "azure-app-client-id",
//! )?;
//! let req = AzureFicRequest::new(federated_token)
//!     .with_scope("https://graph.microsoft.com/.default");
//! let resp = client.acquire_token(&req).await?;
//! // resp.access_token is a Bearer token for Microsoft Graph (or
//! // whatever resource the scope identified).
//! ```

use std::sync::Arc;
use std::time::Duration;

use reqwest::header::CONTENT_TYPE;
use serde::Deserialize;
use url::Url;
use zeroize::Zeroizing;

use crate::authn::factor::ZeroizedString;
use axess_factors::http_body::log_safe;

/// Time allowed for one token request from send to last response byte,
/// unless [`AzureFicClient::with_timeout`] says otherwise.
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

const CLIENT_ASSERTION_TYPE_JWT_BEARER: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// Compose the standard tenant-scoped token endpoint URL.
fn token_endpoint_for_tenant(tenant: &str) -> Url {
    // The tenant is one path segment: percent-encode it so a value
    // carrying `/`, `?`, `#` or `@` cannot redirect the request to a
    // different path or host. A segment that is exactly `.` or `..`
    // would be collapsed by URL parsing, so the percent sign itself is
    // escaped there; the endpoint names a tenant that does not exist
    // and the token request is refused by the IdP.
    let segment = match tenant {
        "." | ".." | "" => format!("%25{}", super::encode_path_segment(tenant)),
        other => super::encode_path_segment(other),
    };
    Url::parse(&format!(
        "https://login.microsoftonline.com/{segment}/oauth2/v2.0/token"
    ))
    .expect("Azure AD token endpoint URL is well-formed")
}

// ── Request ──────────────────────────────────────────────────────────────────

/// Inputs to an Azure FIC token request.
///
/// The federated token is held in a [`ZeroizedString`], whose buffer is
/// zeroed when the request is dropped. Copies made by `Clone` are each zeroed
/// when they drop; the form body reqwest builds from the token is beyond this
/// type's reach.
#[derive(Clone)]
pub struct AzureFicRequest {
    /// The federated token: passed as `client_assertion` in the
    /// `client_credentials` form body. Zeroed on drop.
    pub federated_token: ZeroizedString,
    /// Requested scopes. Azure's v2.0 endpoint expects one
    /// resource-scoped value, typically `{resource}/.default`
    /// (e.g. `https://graph.microsoft.com/.default`).
    pub scopes: Vec<String>,
}

impl std::fmt::Debug for AzureFicRequest {
    /// Redacts `federated_token`: it is a bearer credential and
    /// `Debug` output ends up in logs and panic messages.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AzureFicRequest")
            .field("federated_token", &"[redacted]")
            .field("scopes", &self.scopes)
            .finish()
    }
}

impl AzureFicRequest {
    /// Build with just the federated token. Add scopes via
    /// [`with_scope`](Self::with_scope) or
    /// [`with_scopes`](Self::with_scopes).
    pub fn new(federated_token: impl Into<String>) -> Self {
        Self {
            federated_token: ZeroizedString::new(federated_token),
            scopes: Vec::new(),
        }
    }

    /// Add a single scope.
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scopes.push(scope.into());
        self
    }

    /// Set the full scope list (replaces any existing entries).
    pub fn with_scopes<I, S>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.scopes = scopes.into_iter().map(Into::into).collect();
        self
    }
}

// ── Response ─────────────────────────────────────────────────────────────────

/// Issued Azure AD access token.
#[derive(Debug)]
pub struct AzureFicResponse {
    /// The Bearer access token. Zeroed on drop.
    pub access_token: ZeroizedString,
    /// `token_type` per OAuth: `Bearer` for Azure AD.
    pub token_type: String,
    /// Seconds until expiry.
    pub expires_in: Option<u64>,
}

/// Error from an Azure FIC call.
#[derive(Debug, thiserror::Error)]
pub enum AzureFicError {
    /// TLS / DNS / connection-level failure.
    #[error("Azure AD transport error: {0}")]
    Transport(String),
    /// Azure returned a structured OAuth error response.
    /// `error_codes` is Azure-specific numeric codes for
    /// finer-grained dispatch (e.g. 70021 = no matching federated
    /// identity credential).
    #[error("Azure AD error [{error}] (HTTP {http_status}): {error_description}")]
    AzureError {
        /// HTTP status code on the response.
        http_status: u16,
        /// OAuth `error` code (e.g. `invalid_client`).
        error: String,
        /// OAuth `error_description`.
        error_description: String,
        /// Azure-specific numeric error codes.
        error_codes: Vec<u64>,
        /// Azure correlation id, for support escalation.
        correlation_id: Option<String>,
    },
    /// 2xx response that did not parse as the expected shape.
    #[error("malformed Azure AD response: {0}")]
    MalformedResponse(String),
    /// The default HTTP client could not be built; nothing is sent. See
    /// [`ClientBuildError`](crate::ClientBuildError).
    #[error(transparent)]
    ClientBuild(#[from] crate::ClientBuildError),
}

// ── Client ───────────────────────────────────────────────────────────────────

/// Adapter over Azure AD's tenant-scoped OAuth `client_credentials`
/// flow with a federated `client_assertion`.
///
/// One client per (tenant, application). Construct at startup and
/// reuse: `clone()` is cheap (`Arc`-backed reqwest client).
///
/// Every token request is bounded by a timeout (30 seconds by default,
/// [`with_timeout`](Self::with_timeout)), whichever HTTP client is used; it
/// replaces the default client's own 30-second request bound, and the
/// default client also bounds connection setup to 10 seconds.
#[derive(Clone)]
pub struct AzureFicClient {
    token_endpoint: Arc<Url>,
    client_id: String,
    http: reqwest::Client,
    timeout: Duration,
}

impl AzureFicClient {
    /// Construct with the Azure tenant id (or domain name) and the
    /// application's client id. Default token endpoint is
    /// `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`;
    /// override with [`with_token_endpoint`](Self::with_token_endpoint)
    /// for Azure clouds other than the public cloud (US Gov, China
    /// 21Vianet, Germany) or for testing.
    ///
    /// # Errors
    ///
    /// [`AzureFicError::ClientBuild`] when the default HTTP client cannot be built (the
    /// TLS backend failed to initialise). No client with the protections
    /// missing is built in its place.
    pub fn new(
        tenant: impl AsRef<str>,
        client_id: impl Into<String>,
    ) -> Result<Self, AzureFicError> {
        let http = crate::outbound_http::hardened_client(|settings| settings)?;
        Ok(Self {
            token_endpoint: Arc::new(token_endpoint_for_tenant(tenant.as_ref())),
            client_id: client_id.into(),
            http,
            timeout: DEFAULT_REQUEST_TIMEOUT,
        })
    }

    /// Bound each token request to `timeout` (default 30 seconds). The
    /// bound applies to the request whichever HTTP client is configured.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Override the token endpoint URL. Use for Azure sovereign
    /// clouds (`login.microsoftonline.us`,
    /// `login.partner.microsoftonline.cn`,
    /// `login.microsoftonline.de`) or for tests pointing at
    /// wiremock. The endpoint must be HTTPS (plain HTTP only to a loopback
    /// host); any other is refused before a request is sent.
    pub fn with_token_endpoint(mut self, endpoint: Url) -> Self {
        self.token_endpoint = Arc::new(endpoint);
        self
    }

    /// Add settings to the HTTP client of the token request: a `User-Agent`, a
    /// trusted root certificate, a client certificate for outbound mTLS,
    /// timeouts.
    ///
    /// The client is built again with `configure`'s settings before the
    /// library's own, so it still follows no redirect: a
    /// [`ClientSettings`](axess_factors::egress::ClientSettings) offers
    /// nothing that could change that, and a whole client of the caller's
    /// own is not taken, since a redirect it followed would carry the
    /// credentials to wherever it points. A proxy named in the environment
    /// (`HTTPS_PROXY`) is followed, as before. The endpoint check (HTTPS, or
    /// HTTP to a loopback host) still applies.
    ///
    /// # Errors
    ///
    /// [`AzureFicError::ClientBuild`] when the client cannot be built with the
    /// settings.
    pub fn with_client_settings(
        mut self,
        configure: impl FnOnce(
            axess_factors::egress::ClientSettings,
        ) -> axess_factors::egress::ClientSettings,
    ) -> Result<Self, AzureFicError> {
        self.http = crate::outbound_http::hardened_client(configure)?;
        Ok(self)
    }

    /// Borrow the token endpoint URL.
    pub fn token_endpoint(&self) -> &Url {
        &self.token_endpoint
    }

    /// Borrow the configured Azure AD application client id.
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// Perform the FIC token request.
    pub async fn acquire_token(
        &self,
        request: &AzureFicRequest,
    ) -> Result<AzureFicResponse, AzureFicError> {
        crate::outbound_http::require_https_or_loopback(&self.token_endpoint)
            .map_err(|reason| AzureFicError::Transport(reason.to_string()))?;
        let scope = request.scopes.join(" ");
        let assertion: &str = &request.federated_token;
        let form: Vec<(&str, &str)> = vec![
            ("grant_type", "client_credentials"),
            ("client_id", &self.client_id),
            ("scope", scope.as_str()),
            ("client_assertion_type", CLIENT_ASSERTION_TYPE_JWT_BEARER),
            ("client_assertion", assertion),
        ];

        let mut response = self
            .http
            .post((*self.token_endpoint).clone())
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .timeout(self.timeout)
            .form(&form)
            .send()
            .await
            .map_err(|e| AzureFicError::Transport(e.to_string()))?;

        let status = response.status();
        if !status.is_success() {
            // Read to 64 KiB, so a long description does not cost the code.
            let body = axess_factors::http_body::ErrorBody::read(&mut response).await;
            return Err(parse_azure_error(status.as_u16(), &body));
        }
        // The success body carries the access token, so it is zeroed on drop.
        let body = axess_factors::http_body::read_limited(
            &mut response,
            axess_factors::http_body::MAX_TOKEN_BODY_BYTES,
        )
        .await
        .map_err(|e| AzureFicError::Transport(e.to_string()))?;
        let body = Zeroizing::new(String::from_utf8_lossy(&body).into_owned());

        let parsed: AzureSuccessBody = serde_json::from_str(&body).map_err(|e| {
            AzureFicError::MalformedResponse(format!(
                "success JSON: {}",
                axess_factors::http_body::log_safe_parse_error(&e)
            ))
        })?;
        if parsed.access_token.is_empty() {
            return Err(AzureFicError::MalformedResponse(
                "access_token field is empty".to_string(),
            ));
        }
        Ok(AzureFicResponse {
            access_token: parsed.access_token,
            token_type: parsed.token_type.unwrap_or_else(|| "Bearer".to_string()),
            expires_in: parsed.expires_in,
        })
    }
}

#[derive(Debug, Deserialize)]
struct AzureSuccessBody {
    /// Wire field. Typed [`ZeroizedString`] so the plaintext the
    /// provider sent is redacted in `Debug` and zeroed on drop: this
    /// struct is where the token first lands, and zeroing only the
    /// copy would leave the original in the heap for the process's
    /// lifetime.
    access_token: ZeroizedString,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct AzureErrorBody {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
    #[serde(default)]
    error_codes: Vec<u64>,
    #[serde(default)]
    correlation_id: Option<String>,
}

/// The longest `error_description` kept in an error: the text is the
/// provider's, and the error ends up in logs.
const MAX_DESCRIPTION_BYTES: usize = 512;
/// The longest `error` code or correlation id kept in an error.
const MAX_CODE_BYTES: usize = 128;

fn parse_azure_error(
    http_status: u16,
    body: &axess_factors::http_body::ErrorBody,
) -> AzureFicError {
    match serde_json::from_slice::<AzureErrorBody>(body.as_bytes()) {
        Ok(parsed) => AzureFicError::AzureError {
            http_status,
            error: log_safe(&parsed.error, MAX_CODE_BYTES),
            error_description: log_safe(
                &parsed.error_description.unwrap_or_default(),
                MAX_DESCRIPTION_BYTES,
            ),
            error_codes: parsed.error_codes,
            correlation_id: parsed
                .correlation_id
                .map(|id| log_safe(&id, MAX_CODE_BYTES)),
        },
        // A body cut at the read bound still names its code when the code
        // came before the cut.
        Err(_) => match body.string_member("error") {
            Some(code) => AzureFicError::AzureError {
                http_status,
                error: log_safe(&code, MAX_CODE_BYTES),
                error_description: log_safe(
                    &body.string_member("error_description").unwrap_or_default(),
                    MAX_DESCRIPTION_BYTES,
                ),
                error_codes: Vec::new(),
                correlation_id: None,
            },
            None => AzureFicError::AzureError {
                http_status,
                error: "unknown".to_string(),
                error_description: log_safe(
                    &format!("non-JSON error body: {}", body.snippet()),
                    MAX_DESCRIPTION_BYTES,
                ),
                error_codes: Vec::new(),
                correlation_id: None,
            },
        },
    }
}

#[cfg(test)]
mod tests;
