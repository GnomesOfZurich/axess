//! AWS STS `AssumeRoleWithWebIdentity` adapter.
//!
//! Exchanges a federated OIDC token (typically a K8s service-account
//! projected token, GitHub Actions OIDC token, or axess-issued JWT)
//! for short-lived AWS credentials usable by the AWS SDKs / signed
//! requests.
//!
//! # Why this isn't an "OAuth client"
//!
//! AWS STS uses a pre-OAuth-token-exchange protocol:
//!
//! - **POST `https://sts.amazonaws.com/`** with `Action`,
//!   `Version=2011-06-15`, `RoleArn`, `RoleSessionName`,
//!   `WebIdentityToken`, and optional `DurationSeconds`, `Policy`,
//!   `PolicyArns.member.N.arn`, `ProviderId` as form fields.
//! - **No transport-layer authentication.** The web-identity token
//!   itself is the credential: AWS validates it against the OIDC
//!   provider it has been pre-configured to trust (via an IAM Identity
//!   Provider in the target AWS account).
//! - **XML response body.** The historical AWS Query API shape. We
//!   parse it via `quick-xml`'s serde adapter.
//!
//! # Token sources
//!
//! axess does not mint AWS-bound OIDC tokens directly. Typical inputs:
//!
//! - **GitHub Actions**: `id-token: write` permission produces a
//!   token usable with `AssumeRoleWithWebIdentity` against an IAM
//!   identity provider configured for `token.actions.githubusercontent.com`.
//! - **Kubernetes**: a projected service-account token with the
//!   target AWS account's STS URL as the audience and IAM-IRSA
//!   wiring at the cluster.
//! - **axess `LocalIdP`**: once shipped, axess-issued workload JWTs
//!   can be terminated at an IAM identity provider in the adopter's
//!   account, identifying axess workloads to AWS.
//!
//! # Endpoint choice
//!
//! The default endpoint is `https://sts.amazonaws.com/` (global). For
//! deployments pinned to a regional endpoint (`sts.us-east-1.amazonaws.com`)
//! or testing against LocalStack, construct the client with
//! [`AwsStsClient::with_endpoint`].
//!
//! # Example
//!
//! ```rust,ignore
//! use axess::workload::outbound::cloud_sts::aws::{
//!     AssumeRoleWithWebIdentityRequest, AwsStsClient,
//! };
//!
//! let client = AwsStsClient::new();
//! let req = AssumeRoleWithWebIdentityRequest::new(
//!     "arn:aws:iam::123456789012:role/axess-worker",
//!     "axess-session-001",
//!     web_identity_token,
//! )
//! .with_duration_seconds(900);
//! let resp = client.assume_role_with_web_identity(&req).await?;
//! // resp.credentials.{access_key_id, secret_access_key, session_token}
//! ```

use std::sync::Arc;

use chrono::{DateTime, Utc};
use reqwest::header::CONTENT_TYPE;
use serde::Deserialize;
use url::Url;

use crate::authn::factor::ZeroizedString;

/// AWS Query API version pinned by the `AssumeRoleWithWebIdentity` shape.
const STS_API_VERSION: &str = "2011-06-15";

/// Default global AWS STS endpoint.
fn default_endpoint() -> Url {
    // Safe: literal known-good URL.
    Url::parse("https://sts.amazonaws.com/").expect("default AWS STS endpoint is valid")
}

// ── Request ──────────────────────────────────────────────────────────────────

/// `AssumeRoleWithWebIdentity` request inputs. Builder-style:
///
/// ```rust,ignore
/// let req = AssumeRoleWithWebIdentityRequest::new(
///     "arn:aws:iam::123:role/r", "session-name", token,
/// )
/// .with_duration_seconds(900)
/// .with_policy(r#"{"Version":"2012-10-17","Statement":[…]}"#);
/// ```
#[derive(Debug, Clone)]
pub struct AssumeRoleWithWebIdentityRequest {
    /// The IAM role's full ARN to assume.
    pub role_arn: String,
    /// Adopter-supplied session identifier: appears in CloudTrail
    /// and the resulting `AssumedRoleUser` ARN. 2..64 chars,
    /// `[\w+=,.@-]*` per AWS spec.
    pub role_session_name: String,
    /// The federated OIDC / JWT token. AWS validates it against the
    /// IAM identity provider it was configured against.
    pub web_identity_token: String,
    /// Lifetime of the issued credentials, in seconds. AWS clamps to
    /// `900..43200`; the role's `MaxSessionDuration` clamps further.
    /// `None` defers to AWS's default (3600 = 1h).
    pub duration_seconds: Option<u32>,
    /// Optional inline session policy (JSON). Restricts the
    /// resulting session's permissions to the intersection of the
    /// role's policies and this policy.
    pub policy: Option<String>,
    /// Optional managed session policy ARNs. Same intersection
    /// semantics as `policy`.
    pub policy_arns: Vec<String>,
    /// `ProviderId`: only used with **non-AWS** OIDC providers
    /// (Login with Amazon / Facebook / Google). For OIDC tokens from
    /// an IAM-configured identity provider (the common case for K8s
    /// / GitHub Actions / axess), leave as `None`.
    pub provider_id: Option<String>,
}

impl AssumeRoleWithWebIdentityRequest {
    /// Build with the three required fields. Optional fields default
    /// to `None` / empty.
    pub fn new(
        role_arn: impl Into<String>,
        role_session_name: impl Into<String>,
        web_identity_token: impl Into<String>,
    ) -> Self {
        Self {
            role_arn: role_arn.into(),
            role_session_name: role_session_name.into(),
            web_identity_token: web_identity_token.into(),
            duration_seconds: None,
            policy: None,
            policy_arns: Vec::new(),
            provider_id: None,
        }
    }

    /// Set the requested credential lifetime in seconds (AWS clamps
    /// to 900..43200).
    pub fn with_duration_seconds(mut self, duration: u32) -> Self {
        self.duration_seconds = Some(duration);
        self
    }

    /// Set an inline session policy (JSON).
    pub fn with_policy(mut self, policy: impl Into<String>) -> Self {
        self.policy = Some(policy.into());
        self
    }

    /// Add a managed session policy ARN.
    pub fn with_policy_arn(mut self, arn: impl Into<String>) -> Self {
        self.policy_arns.push(arn.into());
        self
    }

    /// Set the `ProviderId` (rare: only Login with Amazon / FB /
    /// Google).
    pub fn with_provider_id(mut self, provider_id: impl Into<String>) -> Self {
        self.provider_id = Some(provider_id.into());
        self
    }
}

// ── Response ─────────────────────────────────────────────────────────────────

/// Issued AWS credentials. All three string fields are held in
/// [`ZeroizedString`] so the in-memory copies zero on drop.
#[derive(Debug)]
pub struct AwsCredentials {
    /// `AccessKeyId`: typically `ASIA…` for STS-issued credentials.
    pub access_key_id: ZeroizedString,
    /// `SecretAccessKey`: paired with `access_key_id`.
    pub secret_access_key: ZeroizedString,
    /// `SessionToken`: required by AWS SDKs in addition to the
    /// access key pair.
    pub session_token: ZeroizedString,
    /// When the credentials become invalid. AWS guarantees ISO-8601
    /// UTC timestamps in the response.
    pub expiration: DateTime<Utc>,
}

/// Successful response from `AssumeRoleWithWebIdentity`.
#[derive(Debug)]
pub struct AssumeRoleWithWebIdentityResponse {
    /// The temporary AWS credentials.
    pub credentials: AwsCredentials,
    /// `Arn` of the resulting `assumed-role` principal,
    /// `arn:aws:sts::ACCOUNT:assumed-role/RoleName/RoleSessionName`.
    pub assumed_role_arn: String,
    /// AWS-internal id for the assumed role session.
    pub assumed_role_id: String,
    /// The `sub` claim of the federated token, echoed back.
    pub subject_from_web_identity_token: String,
    /// The `iss` claim of the federated token, echoed back (the
    /// OIDC provider URL).
    pub provider: Option<String>,
    /// The `aud` claim of the federated token, echoed back.
    pub audience: Option<String>,
}

/// Error from an `AssumeRoleWithWebIdentity` call.
#[derive(Debug, thiserror::Error)]
pub enum AwsStsError {
    /// TLS / DNS / connection-level failure reaching the STS
    /// endpoint.
    #[error("AWS STS transport error: {0}")]
    Transport(String),
    /// AWS returned a structured error response. `code` is the AWS
    /// error code (`InvalidIdentityToken`, `ExpiredTokenException`,
    /// `AccessDenied`, …); `message` is the human-readable
    /// description.
    #[error("AWS STS error [{code}] (HTTP {http_status}): {message}")]
    StsError {
        /// HTTP status code on the response.
        http_status: u16,
        /// AWS error code (machine-readable).
        code: String,
        /// Human-readable error description.
        message: String,
        /// `Sender` / `Receiver` / unknown: fault attribution.
        fault_type: Option<String>,
        /// AWS-assigned request id, for support escalation.
        request_id: Option<String>,
    },
    /// 2xx response but the body did not parse as the expected
    /// XML shape.
    #[error("malformed AWS STS response: {0}")]
    MalformedResponse(String),
}

// ── Client ───────────────────────────────────────────────────────────────────

/// Adapter over the AWS STS `AssumeRoleWithWebIdentity` endpoint.
///
/// Clone is cheap (the underlying [`reqwest::Client`] is `Arc`-backed
/// internally); construct once at startup and reuse across requests.
#[derive(Clone)]
pub struct AwsStsClient {
    endpoint: Arc<Url>,
    http: reqwest::Client,
}

impl Default for AwsStsClient {
    fn default() -> Self {
        Self::new()
    }
}

impl AwsStsClient {
    /// Construct a client pointed at the default global AWS STS
    /// endpoint (`https://sts.amazonaws.com/`).
    pub fn new() -> Self {
        Self {
            endpoint: Arc::new(default_endpoint()),
            http: reqwest::Client::new(),
        }
    }

    /// Override the STS endpoint. Use this to pin to a regional
    /// endpoint (`https://sts.us-east-1.amazonaws.com/`) or to point
    /// at LocalStack for testing.
    pub fn with_endpoint(mut self, endpoint: Url) -> Self {
        self.endpoint = Arc::new(endpoint);
        self
    }

    /// Override the HTTP client: useful for timeout / proxy / outbound
    /// mTLS configuration.
    pub fn with_http_client(mut self, http: reqwest::Client) -> Self {
        self.http = http;
        self
    }

    /// Borrow the endpoint URL. Provided for diagnostics; do not use
    /// to compare endpoint configuration in production code (the
    /// `Url` may differ from the configured form post-normalisation).
    pub fn endpoint(&self) -> &Url {
        &self.endpoint
    }

    /// Perform an `AssumeRoleWithWebIdentity` call.
    pub async fn assume_role_with_web_identity(
        &self,
        request: &AssumeRoleWithWebIdentityRequest,
    ) -> Result<AssumeRoleWithWebIdentityResponse, AwsStsError> {
        let form = build_form(request);

        let response = self
            .http
            .post((*self.endpoint).clone())
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .form(&form)
            .send()
            .await
            .map_err(|e| AwsStsError::Transport(e.to_string()))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| AwsStsError::Transport(e.to_string()))?;

        if !status.is_success() {
            return Err(parse_error(status.as_u16(), &body));
        }

        parse_success(&body)
    }
}

fn build_form(request: &AssumeRoleWithWebIdentityRequest) -> Vec<(String, String)> {
    let mut form: Vec<(String, String)> = vec![
        (
            "Action".to_string(),
            "AssumeRoleWithWebIdentity".to_string(),
        ),
        ("Version".to_string(), STS_API_VERSION.to_string()),
        ("RoleArn".to_string(), request.role_arn.clone()),
        (
            "RoleSessionName".to_string(),
            request.role_session_name.clone(),
        ),
        (
            "WebIdentityToken".to_string(),
            request.web_identity_token.clone(),
        ),
    ];
    if let Some(d) = request.duration_seconds {
        form.push(("DurationSeconds".to_string(), d.to_string()));
    }
    if let Some(policy) = &request.policy {
        form.push(("Policy".to_string(), policy.clone()));
    }
    for (i, arn) in request.policy_arns.iter().enumerate() {
        // AWS Query API list encoding: PolicyArns.member.1.arn=…,
        // PolicyArns.member.2.arn=…
        form.push((format!("PolicyArns.member.{}.arn", i + 1), arn.clone()));
    }
    if let Some(pid) = &request.provider_id {
        form.push(("ProviderId".to_string(), pid.clone()));
    }
    form
}

// ── Response parsing ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct StsSuccessEnvelope {
    #[serde(rename = "AssumeRoleWithWebIdentityResult")]
    result: StsAssumeRoleResult,
}

#[derive(Debug, Deserialize)]
struct StsAssumeRoleResult {
    #[serde(rename = "Credentials")]
    credentials: StsCredentialsXml,
    #[serde(rename = "AssumedRoleUser")]
    assumed_role_user: StsAssumedRoleUserXml,
    #[serde(rename = "SubjectFromWebIdentityToken")]
    subject_from_web_identity_token: String,
    #[serde(rename = "Provider", default)]
    provider: Option<String>,
    #[serde(rename = "Audience", default)]
    audience: Option<String>,
}

#[derive(Debug, Deserialize)]
struct StsCredentialsXml {
    #[serde(rename = "AccessKeyId")]
    access_key_id: String,
    #[serde(rename = "SecretAccessKey")]
    secret_access_key: String,
    #[serde(rename = "SessionToken")]
    session_token: String,
    #[serde(rename = "Expiration")]
    expiration: String,
}

#[derive(Debug, Deserialize)]
struct StsAssumedRoleUserXml {
    #[serde(rename = "Arn")]
    arn: String,
    #[serde(rename = "AssumedRoleId")]
    assumed_role_id: String,
}

fn parse_success(body: &str) -> Result<AssumeRoleWithWebIdentityResponse, AwsStsError> {
    let parsed: StsSuccessEnvelope = quick_xml::de::from_str(body)
        .map_err(|e| AwsStsError::MalformedResponse(format!("XML decode: {e}")))?;

    let creds = parsed.result.credentials;
    let expiration = DateTime::parse_from_rfc3339(&creds.expiration)
        .map_err(|e| AwsStsError::MalformedResponse(format!("Expiration not RFC3339: {e}")))?
        .with_timezone(&Utc);

    if creds.access_key_id.is_empty()
        || creds.secret_access_key.is_empty()
        || creds.session_token.is_empty()
    {
        return Err(AwsStsError::MalformedResponse(
            "credentials block missing one of access_key_id / secret_access_key / session_token"
                .to_string(),
        ));
    }

    Ok(AssumeRoleWithWebIdentityResponse {
        credentials: AwsCredentials {
            access_key_id: ZeroizedString::from(creds.access_key_id),
            secret_access_key: ZeroizedString::from(creds.secret_access_key),
            session_token: ZeroizedString::from(creds.session_token),
            expiration,
        },
        assumed_role_arn: parsed.result.assumed_role_user.arn,
        assumed_role_id: parsed.result.assumed_role_user.assumed_role_id,
        subject_from_web_identity_token: parsed.result.subject_from_web_identity_token,
        provider: parsed.result.provider,
        audience: parsed.result.audience,
    })
}

#[derive(Debug, Deserialize)]
struct StsErrorEnvelope {
    #[serde(rename = "Error")]
    error: StsErrorBody,
    #[serde(rename = "RequestId", default)]
    request_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct StsErrorBody {
    #[serde(rename = "Type", default)]
    fault_type: Option<String>,
    #[serde(rename = "Code")]
    code: String,
    #[serde(rename = "Message")]
    message: String,
}

fn parse_error(http_status: u16, body: &str) -> AwsStsError {
    match quick_xml::de::from_str::<StsErrorEnvelope>(body) {
        Ok(env) => AwsStsError::StsError {
            http_status,
            code: env.error.code,
            message: env.error.message,
            fault_type: env.error.fault_type,
            request_id: env.request_id,
        },
        Err(_) => AwsStsError::StsError {
            http_status,
            code: "Unknown".to_string(),
            message: format!("non-XML error body: {body}"),
            fault_type: None,
            request_id: None,
        },
    }
}

#[cfg(test)]
mod tests;
