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
//! own `LocalIdP` (forthcoming), or any other JWT the configured
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
//! );
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
use zeroize::{Zeroize, Zeroizing};

use crate::authn::factor::ZeroizedString;

/// Time allowed to establish a connection, on the default HTTP client.
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

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
#[derive(Clone)]
pub struct AzureFicRequest {
    /// The federated token: passed as `client_assertion` in the
    /// `client_credentials` form body.
    pub federated_token: String,
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

impl Drop for AzureFicRequest {
    /// Zeroes the federated token's buffer. Copies made by `Clone` are
    /// each zeroed when they drop; the form body reqwest builds from the
    /// token is beyond this type's reach.
    fn drop(&mut self) {
        self.federated_token.zeroize();
    }
}

impl AzureFicRequest {
    /// Build with just the federated token. Add scopes via
    /// [`with_scope`](Self::with_scope) or
    /// [`with_scopes`](Self::with_scopes).
    pub fn new(federated_token: impl Into<String>) -> Self {
        Self {
            federated_token: federated_token.into(),
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
}

// ── Client ───────────────────────────────────────────────────────────────────

/// Adapter over Azure AD's tenant-scoped OAuth `client_credentials`
/// flow with a federated `client_assertion`.
///
/// One client per (tenant, application). Construct at startup and
/// reuse: `clone()` is cheap (`Arc`-backed reqwest client).
///
/// Every token request is bounded by a timeout (30 seconds by default,
/// [`with_timeout`](Self::with_timeout)), whichever HTTP client is used,
/// and the default client also bounds connection setup to 10 seconds.
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
    pub fn new(tenant: impl AsRef<str>, client_id: impl Into<String>) -> Self {
        Self {
            token_endpoint: Arc::new(token_endpoint_for_tenant(tenant.as_ref())),
            client_id: client_id.into(),
            http: reqwest::Client::builder()
                .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
                .build()
                .unwrap_or_default(),
            timeout: DEFAULT_REQUEST_TIMEOUT,
        }
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
    /// wiremock.
    pub fn with_token_endpoint(mut self, endpoint: Url) -> Self {
        self.token_endpoint = Arc::new(endpoint);
        self
    }

    /// Override the HTTP client.
    pub fn with_http_client(mut self, http: reqwest::Client) -> Self {
        self.http = http;
        self
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
        let scope = request.scopes.join(" ");
        let form: Vec<(&str, &str)> = vec![
            ("grant_type", "client_credentials"),
            ("client_id", &self.client_id),
            ("scope", scope.as_str()),
            ("client_assertion_type", CLIENT_ASSERTION_TYPE_JWT_BEARER),
            ("client_assertion", &request.federated_token),
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
        // The success body carries the access token, so it is zeroed on drop.
        let body = Zeroizing::new(
            axess_factors::http_body::read_for_status(
                &mut response,
                axess_factors::http_body::MAX_TOKEN_BODY_BYTES,
            )
            .await
            .map_err(|e| AzureFicError::Transport(e.to_string()))?,
        );
        let body = Zeroizing::new(String::from_utf8_lossy(&body).into_owned());

        if !status.is_success() {
            return Err(parse_azure_error(status.as_u16(), &body));
        }

        let parsed: AzureSuccessBody = serde_json::from_str(&body)
            .map_err(|e| AzureFicError::MalformedResponse(format!("success JSON: {e}")))?;
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

fn parse_azure_error(http_status: u16, body: &str) -> AzureFicError {
    match serde_json::from_str::<AzureErrorBody>(body) {
        Ok(parsed) => AzureFicError::AzureError {
            http_status,
            error: parsed.error,
            error_description: parsed.error_description.unwrap_or_default(),
            error_codes: parsed.error_codes,
            correlation_id: parsed.correlation_id,
        },
        Err(_) => AzureFicError::AzureError {
            http_status,
            error: "unknown".to_string(),
            error_description: format!("non-JSON error body: {body}"),
            error_codes: Vec::new(),
            correlation_id: None,
        },
    }
}

#[cfg(test)]
mod tests;
