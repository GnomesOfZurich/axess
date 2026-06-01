//! GCP Workload Identity Federation adapter.
//!
//! Two-stage exchange of an external OIDC token for usable GCP
//! credentials:
//!
//! 1. **GCP STS token exchange**: RFC 8693 POST to
//!    `https://sts.googleapis.com/v1/token`. The external token
//!    (K8s SA, GitHub Actions OIDC, axess JWT) is the
//!    `subject_token`; the response is a short-lived **federated
//!    access token** scoped to the GCP workload identity pool
//!    provider.
//! 2. **Service-account impersonation** (optional, common):
//!    POST to
//!    `https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{email}:generateAccessToken`
//!    with the federated token as the `Authorization: Bearer` header.
//!    Returns an **SA-scoped access token** usable for the broad
//!    range of GCP APIs that won't accept a raw federated token.
//!
//! # Why two stages
//!
//! GCP's federated token alone can only call APIs that explicitly
//! accept WIF principals (a small subset). Most adopters configure
//! their workload identity pool to grant
//! `roles/iam.serviceAccountTokenCreator` on a target SA, then
//! impersonate that SA per request. Stage 2 surfaces that pattern
//! as a first-class call rather than asking adopters to roll their
//! own.
//!
//! # `audience` shape
//!
//! GCP rejects WIF token exchanges whose `audience` claim doesn't
//! match the configured pool provider. The format is fixed:
//!
//! ```text
//! //iam.googleapis.com/projects/<NUMBER>/locations/global/workloadIdentityPools/<POOL>/providers/<PROVIDER>
//! ```
//!
//! [`WorkloadIdentityPoolProvider`] composes a valid string from
//! the three components.
//!
//! # Example
//!
//! ```rust,ignore
//! use axess::workload::outbound::cloud_sts::gcp::{
//!     GcpStsClient, GcpServiceAccountImpersonator,
//!     WorkloadIdentityPoolProvider,
//! };
//!
//! let audience = WorkloadIdentityPoolProvider::new(
//!     123_456_789, "axess-pool", "github-actions",
//! );
//! let sts = GcpStsClient::new();
//! let federated = sts
//!     .exchange_token(
//!         oidc_token,
//!         &audience,
//!         &["https://www.googleapis.com/auth/cloud-platform"],
//!     )
//!     .await?;
//!
//! let imp = GcpServiceAccountImpersonator::new();
//! let sa_token = imp
//!     .generate_access_token(
//!         &federated.access_token,
//!         "axess-worker@my-project.iam.gserviceaccount.com",
//!         &["https://www.googleapis.com/auth/bigquery"],
//!         None,
//!     )
//!     .await?;
//! ```

use std::sync::Arc;

use chrono::{DateTime, Utc};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::authn::factor::ZeroizedString;

const STS_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const STS_SUBJECT_TOKEN_TYPE_JWT: &str = "urn:ietf:params:oauth:token-type:jwt";
const STS_REQUESTED_TOKEN_TYPE_ACCESS: &str = "urn:ietf:params:oauth:token-type:access_token";

fn default_sts_endpoint() -> Url {
    Url::parse("https://sts.googleapis.com/v1/token").expect("default GCP STS endpoint is valid")
}

fn default_iam_credentials_base() -> Url {
    Url::parse("https://iamcredentials.googleapis.com/")
        .expect("default GCP IAM Credentials endpoint is valid")
}

// ── Audience helper ──────────────────────────────────────────────────────────

/// Identifies a GCP workload identity pool provider. The
/// [`as_str`](Self::as_str) form is exactly what GCP's STS expects as
/// the `audience` claim.
#[derive(Debug, Clone)]
pub struct WorkloadIdentityPoolProvider {
    audience: String,
}

impl WorkloadIdentityPoolProvider {
    /// Compose the provider URN from its three components.
    ///
    /// - `project_number`: the numeric GCP project number (not the
    ///   project id string).
    /// - `pool_id`: the workload identity pool name.
    /// - `provider_id`: the provider within the pool.
    pub fn new(
        project_number: u64,
        pool_id: impl AsRef<str>,
        provider_id: impl AsRef<str>,
    ) -> Self {
        Self {
            audience: format!(
                "//iam.googleapis.com/projects/{}/locations/global/workloadIdentityPools/{}/providers/{}",
                project_number,
                pool_id.as_ref(),
                provider_id.as_ref(),
            ),
        }
    }

    /// Construct directly from a pre-formatted audience string:
    /// escape hatch for adopters loading the value from config.
    pub fn from_audience(audience: impl Into<String>) -> Self {
        Self {
            audience: audience.into(),
        }
    }

    /// Borrow the audience URN.
    pub fn as_str(&self) -> &str {
        &self.audience
    }
}

// ── STS step (stage 1) ───────────────────────────────────────────────────────

/// Federated access token returned by [`GcpStsClient::exchange_token`].
#[derive(Debug)]
pub struct GcpFederatedToken {
    /// The federated access token. Zeroed on drop.
    pub access_token: ZeroizedString,
    /// Seconds until expiry per GCP's response.
    pub expires_in: Option<u64>,
    /// `token_type`: `Bearer` per GCP.
    pub token_type: String,
}

/// Step 1 client: exchanges an external OIDC token for a GCP
/// federated access token at the GCP STS endpoint.
#[derive(Clone)]
pub struct GcpStsClient {
    endpoint: Arc<Url>,
    http: reqwest::Client,
}

impl Default for GcpStsClient {
    fn default() -> Self {
        Self::new()
    }
}

impl GcpStsClient {
    /// Construct with the default GCP STS endpoint
    /// (`https://sts.googleapis.com/v1/token`).
    pub fn new() -> Self {
        Self {
            endpoint: Arc::new(default_sts_endpoint()),
            http: reqwest::Client::new(),
        }
    }

    /// Override the STS endpoint (for tests or pinned-regional
    /// deployments, though GCP STS itself is global).
    pub fn with_endpoint(mut self, endpoint: Url) -> Self {
        self.endpoint = Arc::new(endpoint);
        self
    }

    /// Override the HTTP client.
    pub fn with_http_client(mut self, http: reqwest::Client) -> Self {
        self.http = http;
        self
    }

    /// Borrow the STS endpoint. For diagnostics; do not use to
    /// compare config; `Url` may differ from the supplied form
    /// post-normalisation.
    pub fn endpoint(&self) -> &Url {
        &self.endpoint
    }

    /// Perform stage 1 of WIF: exchange `web_identity_token` for a
    /// federated GCP access token scoped against `audience` and the
    /// requested `scopes`.
    pub async fn exchange_token(
        &self,
        web_identity_token: &str,
        audience: &WorkloadIdentityPoolProvider,
        scopes: &[&str],
    ) -> Result<GcpFederatedToken, GcpError> {
        let scope = scopes.join(" ");
        let form = [
            ("grant_type", STS_GRANT_TYPE),
            ("audience", audience.as_str()),
            ("scope", scope.as_str()),
            ("requested_token_type", STS_REQUESTED_TOKEN_TYPE_ACCESS),
            ("subject_token", web_identity_token),
            ("subject_token_type", STS_SUBJECT_TOKEN_TYPE_JWT),
        ];

        let response = self
            .http
            .post((*self.endpoint).clone())
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .form(&form)
            .send()
            .await
            .map_err(|e| GcpError::Transport(e.to_string()))?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(GcpError::Sts {
                http_status: status.as_u16(),
                body,
            });
        }

        let parsed: GcpStsResponseBody = response
            .json()
            .await
            .map_err(|e| GcpError::MalformedResponse(format!("STS JSON: {e}")))?;
        if parsed.access_token.is_empty() {
            return Err(GcpError::MalformedResponse(
                "STS access_token field is empty".to_string(),
            ));
        }

        Ok(GcpFederatedToken {
            access_token: ZeroizedString::from(parsed.access_token),
            expires_in: parsed.expires_in,
            token_type: parsed.token_type.unwrap_or_else(|| "Bearer".to_string()),
        })
    }
}

#[derive(Debug, Deserialize)]
struct GcpStsResponseBody {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    token_type: Option<String>,
}

// ── Service-account impersonation (stage 2) ──────────────────────────────────

/// SA-scoped access token returned by
/// [`GcpServiceAccountImpersonator::generate_access_token`].
#[derive(Debug)]
pub struct GcpServiceAccountToken {
    /// The SA access token. Zeroed on drop.
    pub access_token: ZeroizedString,
    /// RFC3339 timestamp when the token expires.
    pub expire_time: DateTime<Utc>,
}

/// Step 2 client: exchanges a federated GCP access token for an
/// SA-scoped access token via service-account impersonation. Most
/// GCP APIs require this shape rather than a raw federated token.
#[derive(Clone)]
pub struct GcpServiceAccountImpersonator {
    /// Base URL up to and including the trailing slash:
    /// `https://iamcredentials.googleapis.com/`. The per-SA path is
    /// appended at call time.
    endpoint_base: Arc<Url>,
    http: reqwest::Client,
}

impl Default for GcpServiceAccountImpersonator {
    fn default() -> Self {
        Self::new()
    }
}

impl GcpServiceAccountImpersonator {
    /// Construct with the default IAM Credentials endpoint base.
    pub fn new() -> Self {
        Self {
            endpoint_base: Arc::new(default_iam_credentials_base()),
            http: reqwest::Client::new(),
        }
    }

    /// Override the IAM Credentials endpoint base: primarily for
    /// tests pointing at wiremock.
    pub fn with_endpoint_base(mut self, base: Url) -> Self {
        self.endpoint_base = Arc::new(base);
        self
    }

    /// Override the HTTP client.
    pub fn with_http_client(mut self, http: reqwest::Client) -> Self {
        self.http = http;
        self
    }

    /// Borrow the endpoint base.
    pub fn endpoint_base(&self) -> &Url {
        &self.endpoint_base
    }

    /// Impersonate `service_account_email` using `federated_token`
    /// as bearer, requesting an SA token with the given `scopes` and
    /// optional `lifetime_seconds` (GCP default 3600, max 43200).
    pub async fn generate_access_token(
        &self,
        federated_token: &str,
        service_account_email: &str,
        scopes: &[&str],
        lifetime_seconds: Option<u32>,
    ) -> Result<GcpServiceAccountToken, GcpError> {
        let path = format!(
            "v1/projects/-/serviceAccounts/{}:generateAccessToken",
            service_account_email
        );
        let url = self
            .endpoint_base
            .join(&path)
            .map_err(|e| GcpError::MalformedResponse(format!("URL join: {e}")))?;

        let body = GenerateAccessTokenRequest {
            scope: scopes.iter().map(|s| s.to_string()).collect(),
            lifetime: lifetime_seconds.map(|secs| format!("{secs}s")),
        };

        let response = self
            .http
            .post(url)
            .header(AUTHORIZATION, format!("Bearer {federated_token}"))
            .json(&body)
            .send()
            .await
            .map_err(|e| GcpError::Transport(e.to_string()))?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(GcpError::IamCredentials {
                http_status: status.as_u16(),
                body,
            });
        }

        let parsed: GenerateAccessTokenResponse = response
            .json()
            .await
            .map_err(|e| GcpError::MalformedResponse(format!("IAM Credentials JSON: {e}")))?;
        if parsed.access_token.is_empty() {
            return Err(GcpError::MalformedResponse(
                "IAM Credentials accessToken field is empty".to_string(),
            ));
        }
        let expire_time = DateTime::parse_from_rfc3339(&parsed.expire_time)
            .map_err(|e| GcpError::MalformedResponse(format!("expireTime not RFC3339: {e}")))?
            .with_timezone(&Utc);

        Ok(GcpServiceAccountToken {
            access_token: ZeroizedString::from(parsed.access_token),
            expire_time,
        })
    }
}

#[derive(Debug, Serialize)]
struct GenerateAccessTokenRequest {
    scope: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lifetime: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GenerateAccessTokenResponse {
    access_token: String,
    expire_time: String,
}

// ── Errors ───────────────────────────────────────────────────────────────────

/// Error from a GCP WIF call (either stage).
#[derive(Debug, thiserror::Error)]
pub enum GcpError {
    /// TLS / DNS / connection-level failure.
    #[error("GCP transport error: {0}")]
    Transport(String),
    /// Stage 1 (STS token exchange) returned non-2xx.
    #[error("GCP STS error (HTTP {http_status}): {body}")]
    Sts {
        /// HTTP status on the STS response.
        http_status: u16,
        /// Raw response body.
        body: String,
    },
    /// Stage 2 (IAM Credentials impersonation) returned non-2xx.
    #[error("GCP IAM Credentials error (HTTP {http_status}): {body}")]
    IamCredentials {
        /// HTTP status on the IAM Credentials response.
        http_status: u16,
        /// Raw response body.
        body: String,
    },
    /// 2xx response that did not parse as the expected shape.
    #[error("malformed GCP response: {0}")]
    MalformedResponse(String),
}

#[cfg(test)]
mod tests;
