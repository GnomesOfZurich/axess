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
//! - **XML response body.** The historical AWS Query API shape. A
//!   success document is parsed via `quick-xml`'s serde adapter; an
//!   error document is read element by element, so a document cut at the
//!   read bound still names a code that came before the cut.
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
//! let client = AwsStsClient::new()?;
//! let req = AssumeRoleWithWebIdentityRequest::new(
//!     "arn:aws:iam::123456789012:role/axess-worker",
//!     "axess-session-001",
//!     web_identity_token,
//! )
//! .with_duration(std::time::Duration::from_secs(900))?;
//! let resp = client.assume_role_with_web_identity(&req).await?;
//! // resp.credentials.{access_key_id, secret_access_key, session_token}
//! ```

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use axess_clock::Timestamp;
use reqwest::header::CONTENT_TYPE;
use serde::Deserialize;
use url::Url;
use zeroize::Zeroizing;

/// Time allowed for one request from send to last response byte, unless
/// `with_timeout` on the client says otherwise.
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The most bytes of the XML parser's error, which can quote the body, that
/// a refusal keeps.
const XML_ERROR_LOG_BYTES: usize = 256;

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
/// .with_duration(Duration::from_secs(900))?
/// .with_policy(r#"{"Version":"2012-10-17","Statement":[…]}"#);
/// ```
///
/// The web-identity token is held in a [`ZeroizedString`], whose buffer is
/// zeroed when the request is dropped. Copies made by `Clone` are each zeroed
/// when they drop; the form body reqwest builds from the token is beyond this
/// type's reach.
#[derive(Clone)]
pub struct AssumeRoleWithWebIdentityRequest {
    /// The IAM role's full ARN to assume.
    pub role_arn: String,
    /// Adopter-supplied session identifier: appears in CloudTrail
    /// and the resulting `AssumedRoleUser` ARN. 2..64 chars,
    /// `[\w+=,.@-]*` per AWS spec.
    pub role_session_name: String,
    /// The federated OIDC / JWT token. AWS validates it against the
    /// IAM identity provider it was configured against. Zeroed on drop.
    pub web_identity_token: ZeroizedString,
    /// Lifetime of the issued credentials, sent as `DurationSeconds`. Set
    /// only through [`with_duration`](Self::with_duration), which refuses a
    /// value AWS does not take, and read with
    /// [`duration`](Self::duration). `None` defers to AWS's default (one
    /// hour).
    duration: Option<Duration>,
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

impl std::fmt::Debug for AssumeRoleWithWebIdentityRequest {
    /// Redacts `web_identity_token`: it is a bearer credential and
    /// `Debug` output ends up in logs and panic messages.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AssumeRoleWithWebIdentityRequest")
            .field("role_arn", &self.role_arn)
            .field("role_session_name", &self.role_session_name)
            .field("web_identity_token", &"[redacted]")
            .field("duration", &self.duration)
            .field("policy", &self.policy)
            .field("policy_arns", &self.policy_arns)
            .field("provider_id", &self.provider_id)
            .finish()
    }
}

impl AssumeRoleWithWebIdentityRequest {
    /// The shortest `DurationSeconds` AWS takes: fifteen minutes.
    pub const MIN_DURATION: Duration = Duration::from_secs(900);
    /// The longest `DurationSeconds` AWS takes: twelve hours.
    pub const MAX_DURATION: Duration = Duration::from_secs(43_200);

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
            web_identity_token: ZeroizedString::new(web_identity_token),
            duration: None,
            policy: None,
            policy_arns: Vec::new(),
            provider_id: None,
        }
    }

    /// Set the requested credential lifetime, sent as `DurationSeconds`.
    /// The role's `MaxSessionDuration` may bound it further, on AWS's side.
    ///
    /// # Errors
    ///
    /// [`AwsStsError::InvalidDuration`] for a duration that is not a whole
    /// number of seconds from [`MIN_DURATION`](Self::MIN_DURATION) to
    /// [`MAX_DURATION`](Self::MAX_DURATION), the range AWS takes: it is
    /// refused here, where it is configured, and never rounded.
    pub fn with_duration(mut self, duration: Duration) -> Result<Self, AwsStsError> {
        if duration.subsec_nanos() != 0
            || !(Self::MIN_DURATION..=Self::MAX_DURATION).contains(&duration)
        {
            return Err(AwsStsError::InvalidDuration(duration));
        }
        self.duration = Some(duration);
        Ok(self)
    }

    /// The requested credential lifetime, `None` for AWS's default.
    pub fn duration(&self) -> Option<Duration> {
        self.duration
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
    pub expiration: Timestamp,
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
    /// The default HTTP client could not be built; nothing is sent. See
    /// [`ClientBuildError`](crate::ClientBuildError).
    #[error(transparent)]
    ClientBuild(#[from] crate::ClientBuildError),
    /// The duration handed to
    /// [`with_duration`](AssumeRoleWithWebIdentityRequest::with_duration) is
    /// not a whole number of seconds from
    /// [`MIN_DURATION`](AssumeRoleWithWebIdentityRequest::MIN_DURATION) to
    /// [`MAX_DURATION`](AssumeRoleWithWebIdentityRequest::MAX_DURATION), so
    /// AWS's `DurationSeconds` cannot carry it.
    #[error(
        "the requested `duration` of {0:?} is refused: AWS takes `DurationSeconds` as a whole \
         number of seconds from 900 to 43200"
    )]
    InvalidDuration(Duration),
}

// ── Client ───────────────────────────────────────────────────────────────────

/// Adapter over the AWS STS `AssumeRoleWithWebIdentity` endpoint.
///
/// Clone is cheap (the underlying [`reqwest::Client`] is `Arc`-backed
/// internally); construct once at startup and reuse across requests.
///
/// Every call is bounded by a timeout (30 seconds by default,
/// [`with_timeout`](Self::with_timeout)), whichever HTTP client is used.
#[derive(Clone)]
pub struct AwsStsClient {
    endpoint: Arc<Url>,
    http: reqwest::Client,
    timeout: Duration,
}

impl AwsStsClient {
    /// Construct a client pointed at the default global AWS STS
    /// endpoint (`https://sts.amazonaws.com/`). The default HTTP client
    /// follows no redirects and bounds connection setup to 10 seconds; each
    /// request carries this client's own timeout
    /// ([`with_timeout`](Self::with_timeout)), which replaces the default
    /// client's 30-second request bound.
    ///
    /// # Errors
    ///
    /// [`AwsStsError::ClientBuild`] when the default HTTP client cannot be built (the
    /// TLS backend failed to initialise). No client with the protections
    /// missing is built in its place.
    pub fn new() -> Result<Self, AwsStsError> {
        let http = crate::outbound_http::hardened_client(|settings| settings)?;
        Ok(Self {
            endpoint: Arc::new(default_endpoint()),
            http,
            timeout: DEFAULT_REQUEST_TIMEOUT,
        })
    }

    /// Override the STS endpoint. Use this to pin to a regional
    /// endpoint (`https://sts.us-east-1.amazonaws.com/`) or to point
    /// at LocalStack for testing. The endpoint must be HTTPS (plain HTTP only to
    /// a loopback host); any other endpoint is refused before a request is sent.
    pub fn with_endpoint(mut self, endpoint: Url) -> Self {
        self.endpoint = Arc::new(endpoint);
        self
    }

    /// Add settings to the HTTP client of the STS call: a `User-Agent`, a
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
    /// [`AwsStsError::ClientBuild`] when the client cannot be built with the
    /// settings.
    pub fn with_client_settings(
        mut self,
        configure: impl FnOnce(
            axess_factors::egress::ClientSettings,
        ) -> axess_factors::egress::ClientSettings,
    ) -> Result<Self, AwsStsError> {
        self.http = crate::outbound_http::hardened_client(configure)?;
        Ok(self)
    }

    /// Bound each call to `timeout` (default 30 seconds). The bound applies
    /// to the request whichever HTTP client is configured.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
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
        crate::outbound_http::require_https_or_loopback(&self.endpoint)
            .map_err(|reason| AwsStsError::Transport(reason.to_string()))?;
        let form = build_form(request, request.duration.map(|d| d.as_secs()));

        let mut response = self
            .http
            .post((*self.endpoint).clone())
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .timeout(self.timeout)
            .form(&form)
            .send()
            .await
            .map_err(|e| AwsStsError::Transport(e.to_string()))?;

        let status = response.status();
        if !status.is_success() {
            // The error document is read to 64 KiB and its fields element
            // by element, so a long message does not cost the code; what
            // reaches the error is still cut.
            let body = axess_factors::http_body::ErrorBody::read(&mut response).await;
            return Err(parse_error(status.as_u16(), &body));
        }
        // The success body carries the secret key and session token, so
        // both the bytes and the text made from them are zeroed on drop.
        let body = axess_factors::http_body::read_limited(
            &mut response,
            axess_factors::http_body::MAX_TOKEN_BODY_BYTES,
        )
        .await
        .map_err(|e| AwsStsError::Transport(e.to_string()))?;
        let body = Zeroizing::new(String::from_utf8_lossy(&body).into_owned());

        parse_success(&body)
    }
}

fn build_form(
    request: &AssumeRoleWithWebIdentityRequest,
    duration_seconds: Option<u64>,
) -> Vec<(Cow<'_, str>, Cow<'_, str>)> {
    // Borrowed from the request wherever possible, so the token is not
    // copied into a second buffer this function cannot zero.
    let token: &str = &request.web_identity_token;
    let mut form: Vec<(Cow<'_, str>, Cow<'_, str>)> = vec![
        ("Action".into(), "AssumeRoleWithWebIdentity".into()),
        ("Version".into(), STS_API_VERSION.into()),
        ("RoleArn".into(), request.role_arn.as_str().into()),
        (
            "RoleSessionName".into(),
            request.role_session_name.as_str().into(),
        ),
        ("WebIdentityToken".into(), token.into()),
    ];
    if let Some(seconds) = duration_seconds {
        form.push(("DurationSeconds".into(), seconds.to_string().into()));
    }
    if let Some(policy) = &request.policy {
        form.push(("Policy".into(), policy.as_str().into()));
    }
    for (i, arn) in request.policy_arns.iter().enumerate() {
        // AWS Query API list encoding: PolicyArns.member.1.arn=…,
        // PolicyArns.member.2.arn=…
        form.push((
            format!("PolicyArns.member.{}.arn", i + 1).into(),
            arn.as_str().into(),
        ));
    }
    if let Some(pid) = &request.provider_id {
        form.push(("ProviderId".into(), pid.as_str().into()));
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

/// The credentials block as parsed. The three secrets are
/// [`ZeroizedString`]s, which zero on drop and print as redacted in `Debug`.
#[derive(Debug, Deserialize)]
struct StsCredentialsXml {
    #[serde(rename = "AccessKeyId")]
    access_key_id: ZeroizedString,
    #[serde(rename = "SecretAccessKey")]
    secret_access_key: ZeroizedString,
    #[serde(rename = "SessionToken")]
    session_token: ZeroizedString,
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
    let parsed: StsSuccessEnvelope = quick_xml::de::from_str(body).map_err(|e| {
        AwsStsError::MalformedResponse(format!(
            "XML decode: {}",
            axess_factors::http_body::log_safe(&e.to_string(), XML_ERROR_LOG_BYTES)
        ))
    })?;

    let creds = parsed.result.credentials;
    let expiration = Timestamp::parse_rfc3339(&creds.expiration)
        .map_err(|e| AwsStsError::MalformedResponse(format!("Expiration not RFC3339: {e}")))?;

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
            access_key_id: creds.access_key_id,
            secret_access_key: creds.secret_access_key,
            session_token: creds.session_token,
            expiration,
        },
        assumed_role_arn: parsed.result.assumed_role_user.arn,
        assumed_role_id: parsed.result.assumed_role_user.assumed_role_id,
        subject_from_web_identity_token: parsed.result.subject_from_web_identity_token,
        provider: parsed.result.provider,
        audience: parsed.result.audience,
    })
}

/// The fields of an STS error document: `Type`, `Code` and `Message` inside
/// the root's `Error`, and the root's `RequestId`. Raw: each passes through
/// `log_safe` before it reaches an error.
#[derive(Debug, Default)]
struct StsErrorFields {
    fault_type: Option<String>,
    code: Option<String>,
    message: Option<String>,
    request_id: Option<String>,
}

/// An element the reader is inside: its local name and the text read in it
/// so far, the text of the elements inside it included.
type OpenElement = (String, String);

impl StsErrorFields {
    /// Read `body` element by element, the first element of each name
    /// counting, and the text of an element taken as written, with the text
    /// of any element inside it. Reading stops at the end of the body or at
    /// the first thing that is not well-formed XML, a reference XML does not
    /// define included, and keeps the fields whose end tag came before, so a
    /// body cut at the read bound still names a code that came before the
    /// cut. A `Code`, `Type` or `RequestId` the stop fell inside is not kept,
    /// since its start is not the value; a `Message` keeps its text up to
    /// the stop.
    fn read(body: &str) -> Self {
        use quick_xml::events::Event;

        let mut reader = quick_xml::Reader::from_str(body);
        let mut fields = Self::default();
        let mut open: Vec<OpenElement> = Vec::new();
        loop {
            match reader.read_event() {
                Ok(Event::Start(element)) => open.push((local_name(&element), String::new())),
                Ok(Event::Empty(element)) => fields.keep(&open, &local_name(&element), ""),
                Ok(Event::End(_)) => {
                    if let Some((name, text)) = open.pop() {
                        fields.keep(&open, &name, &text);
                        append_to_parent(&mut open, &text);
                    }
                }
                Ok(Event::Text(chunk)) => append_to_parent(&mut open, &chunk.xml10_content()),
                Ok(Event::CData(chunk)) => append_to_parent(&mut open, &chunk.xml10_content()),
                Ok(Event::GeneralRef(reference)) => match resolve_reference(&reference) {
                    Some(resolved) => append_to_parent(&mut open, &resolved),
                    None => break,
                },
                Ok(Event::Eof) | Err(_) => break,
                Ok(_) => {}
            }
        }
        fields.keep_cut(open);
        fields
    }

    /// The field an element named `name` inside `open` is, if it is one.
    fn slot(&mut self, open: &[OpenElement], name: &str) -> Option<&mut Option<String>> {
        match open {
            [_, (error, _)] if error == "Error" => match name {
                "Type" => Some(&mut self.fault_type),
                "Code" => Some(&mut self.code),
                "Message" => Some(&mut self.message),
                _ => None,
            },
            [_] if name == "RequestId" => Some(&mut self.request_id),
            _ => None,
        }
    }

    /// Keep `text` as the field an element named `name` inside `open` is,
    /// unless an element of that name came first.
    fn keep(&mut self, open: &[OpenElement], name: &str, text: &str) {
        if let Some(slot @ None) = self.slot(open, name) {
            *slot = Some(text.to_owned());
        }
    }

    /// Close the elements open where reading stopped, innermost first,
    /// keeping only a `Message` among them.
    fn keep_cut(&mut self, mut open: Vec<OpenElement>) {
        while let Some((name, text)) = open.pop() {
            if name == "Message" {
                self.keep(&open, &name, &text);
            }
            append_to_parent(&mut open, &text);
        }
    }
}

/// The local name of `element`, its namespace prefix dropped.
fn local_name(element: &quick_xml::events::BytesStart<'_>) -> String {
    element.local_name().as_ref().to_owned()
}

/// Add `text` to the text of the innermost open element; text outside every
/// element is dropped.
fn append_to_parent(open: &mut [OpenElement], text: &str) {
    if let Some((_, parent)) = open.last_mut() {
        parent.push_str(text);
    }
}

/// What a character reference or a predefined entity reference stands for;
/// `None` for a reference XML does not define, which stops the read.
fn resolve_reference(reference: &quick_xml::events::BytesRef<'_>) -> Option<String> {
    match reference.resolve_char_ref() {
        Ok(Some(c)) => Some(c.to_string()),
        Ok(None) => quick_xml::escape::resolve_predefined_entity(reference).map(str::to_owned),
        Err(_) => None,
    }
}

/// Longest error message kept from an STS response, and longest code, fault
/// type and request id: the rest is cut. Every one of them is copied from the
/// response with every character `escapes` names (control characters, the
/// line and paragraph separators, bidirectional controls, zero-width
/// characters, the byte order mark, the Hangul fillers) escaped, so the
/// endpoint cannot forge a log line through the error's text.
const MAX_MESSAGE_BYTES: usize = 512;
const MAX_CODE_BYTES: usize = 128;

/// What starts the message of a refusal that names no code, before the
/// start of its body.
const NO_CODE_MESSAGE: &str = "error body with no code: ";

/// The error for a refusal: the document's fields when it names a code,
/// read from as much of the body as was read, so a long message before or
/// after the code does not cost it; otherwise `Unknown` with the start of
/// the body as the message, after [`NO_CODE_MESSAGE`].
fn parse_error(http_status: u16, body: &axess_factors::http_body::ErrorBody) -> AwsStsError {
    use axess_factors::http_body::log_safe;
    let fields = StsErrorFields::read(&String::from_utf8_lossy(body.as_bytes()));
    match fields.code {
        Some(code) => AwsStsError::StsError {
            http_status,
            code: log_safe(&code, MAX_CODE_BYTES),
            message: log_safe(&fields.message.unwrap_or_default(), MAX_MESSAGE_BYTES),
            fault_type: fields.fault_type.map(|t| log_safe(&t, MAX_CODE_BYTES)),
            request_id: fields.request_id.map(|id| log_safe(&id, MAX_CODE_BYTES)),
        },
        None => AwsStsError::StsError {
            http_status,
            code: "Unknown".to_string(),
            message: format!(
                "{NO_CODE_MESSAGE}{}",
                log_safe(&body.snippet(), MAX_MESSAGE_BYTES)
            ),
            fault_type: None,
            request_id: None,
        },
    }
}

#[cfg(test)]
mod tests;
