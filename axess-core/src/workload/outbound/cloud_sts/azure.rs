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

use reqwest::header::CONTENT_TYPE;
use serde::Deserialize;
use url::Url;

use crate::authn::factor::ZeroizedString;

const CLIENT_ASSERTION_TYPE_JWT_BEARER: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// Compose the standard tenant-scoped token endpoint URL.
fn token_endpoint_for_tenant(tenant: &str) -> Url {
    // Tenant values are well-formed Azure tenant ids or domain names;
    // a join failure is a programmer error.
    Url::parse(&format!(
        "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    ))
    .expect("Azure AD token endpoint URL is well-formed")
}

// ── Request ──────────────────────────────────────────────────────────────────

/// Inputs to an Azure FIC token request.
#[derive(Debug, Clone)]
pub struct AzureFicRequest {
    /// The federated token: passed as `client_assertion` in the
    /// `client_credentials` form body.
    pub federated_token: String,
    /// Requested scopes. Azure's v2.0 endpoint expects one
    /// resource-scoped value, typically `{resource}/.default`
    /// (e.g. `https://graph.microsoft.com/.default`).
    pub scopes: Vec<String>,
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
#[derive(Clone)]
pub struct AzureFicClient {
    token_endpoint: Arc<Url>,
    client_id: String,
    http: reqwest::Client,
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
            http: reqwest::Client::new(),
        }
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

        let response = self
            .http
            .post((*self.token_endpoint).clone())
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .form(&form)
            .send()
            .await
            .map_err(|e| AzureFicError::Transport(e.to_string()))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| AzureFicError::Transport(e.to_string()))?;

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
            access_token: ZeroizedString::from(parsed.access_token),
            token_type: parsed.token_type.unwrap_or_else(|| "Bearer".to_string()),
            expires_in: parsed.expires_in,
        })
    }
}

#[derive(Debug, Deserialize)]
struct AzureSuccessBody {
    access_token: String,
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
