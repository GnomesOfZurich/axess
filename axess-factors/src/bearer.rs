//! Bearer JWT workload authentication middleware.
//!
//! Validates JWT bearer tokens from the `Authorization: Bearer <token>` header
//! against configured issuers and JWKS endpoints. Maps verified claims to a
//! `WorkloadIdentity` that downstream handlers and Cedar policies can inspect.
//! Co-located with the JWT validation primitives it depends on.
//!
//! # Use cases
//!
//! - **SPIFFE JWT-SVID**: service mesh identity (Envoy, Istio).
//! - **Kubernetes Service Account tokens**: projected volume JWTs.
//! - **GitHub Actions OIDC**: CI pipeline identity for deployment gates.
//! - **AI agent tokens**: LLM tool-use identity for audit attribution.
//!
//! # Architecture
//!
//! `BearerTokenLayer` is a Tower layer that wraps any Axum service. On each
//! request it:
//!
//! 1. Extracts the `Authorization: Bearer <token>` header.
//! 2. Decodes the JWT header to find the `kid`.
//! 3. Verifies the signature against the key set configured for the issuer
//!    (a snapshot the caller refreshes; the layer does not fetch or cache).
//! 4. Validates standard claims (`exp`, `nbf` against the configured
//!    [`Clock`](axess_clock::Clock), `iss`, `aud`).
//! 5. Inserts a [`WorkloadIdentity`] into request extensions.
//!
//! Requests without a bearer token pass through unchanged (the layer is
//! non-rejecting). Downstream handlers use the presence/absence of
//! `WorkloadIdentity` in extensions to decide whether workload auth was
//! provided. Cedar policies can require it via a `Workload` entity type.
//!
//! # No sessions
//!
//! This path is explicitly sessionless. Service-to-service calls don't
//! need cookie-based session state; the JWT *is* the credential on every
//! request. There is no session store interaction.

use crate::jwt::validation::{self, ALLOWED_ALGORITHMS, JwtError, ValidationConfig};
use axess_clock::{Clock, SystemClock};
use jsonwebtoken::jwk::JwkSet;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// ── WorkloadIdentity ─────────────────────────────────────────────────────────

/// Verified workload identity extracted from a bearer JWT.
///
/// Inserted into Axum request extensions by [`BearerTokenLayer`] after
/// successful validation. Handlers access it via:
///
/// ```ignore
/// use axess_core::authn::bearer::WorkloadIdentity;
///
/// async fn handler(Extension(workload): Extension<WorkloadIdentity>) {
///     println!("request from: {}", workload.subject);
/// }
/// ```
///
/// For Cedar integration, map `subject` → `Workload::"{subject}"` entity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadIdentity {
    /// The `sub` claim: identifies the workload (e.g. SPIFFE ID,
    /// Kubernetes service account, GitHub repo slug).
    pub subject: String,
    /// The `iss` claim: which identity provider minted the token.
    pub issuer: String,
    /// The `aud` claim(s): intended recipient(s).
    pub audiences: Vec<String>,
    /// Additional claims from the JWT payload that the application
    /// may want for policy decisions (e.g. `github.repository`,
    /// `kubernetes.namespace`). Only string-valued claims are captured;
    /// nested objects are flattened with dot-notation keys.
    pub claims: std::collections::HashMap<String, String>,
}

// ── Audience ─────────────────────────────────────────────────────────────────

/// The `aud` an issuer's tokens must name.
///
/// There is no silent way to skip the audience check: a token minted for
/// any other service of the same issuer verifies against the same JWKS, so
/// without a pin that service's token is accepted here. Skipping it is
/// spelled [`Audience::AnyDangerous`] and nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Audience {
    /// The token's `aud` must contain exactly this value.
    Exact(String),
    /// Accept a token for any audience. Dangerous: every token the issuer
    /// mints for any of its relying parties is accepted here, so a service
    /// that can obtain one can act as the workload it names. Only for an
    /// issuer that mints tokens for this application alone, and
    /// [`BearerConfig::new`] warns for every issuer configured this way.
    AnyDangerous,
}

impl Audience {
    /// The pinned value, or `None` under [`Audience::AnyDangerous`].
    pub fn exact(&self) -> Option<&str> {
        match self {
            Self::Exact(audience) => Some(audience),
            Self::AnyDangerous => None,
        }
    }
}

impl From<String> for Audience {
    fn from(audience: String) -> Self {
        Self::Exact(audience)
    }
}

impl From<&str> for Audience {
    fn from(audience: &str) -> Self {
        Self::Exact(audience.to_string())
    }
}

// ── BearerIssuerConfig ───────────────────────────────────────────────────────

/// Configuration for a single trusted JWT issuer.
///
/// Multiple issuers can be configured (e.g. one for SPIFFE, one for GitHub
/// Actions). The layer tries each issuer whose `issuer` claim matches
/// the token's `iss`.
#[derive(Debug, Clone)]
pub struct BearerIssuerConfig {
    /// Expected `iss` claim value. Tokens whose `iss` doesn't match
    /// are skipped (tried against the next issuer).
    pub issuer: String,
    /// Expected `aud` value. Under [`Audience::Exact`] the token's `aud`
    /// must contain the value. [`Audience::AnyDangerous`] skips the check
    /// and accepts a token minted for any service of the same issuer;
    /// [`BearerConfig::new`](crate::bearer::BearerConfig::new) logs a
    /// warning for such an issuer.
    /// [`BearerIssuerConfig::new`](crate::bearer::BearerIssuerConfig::new)
    /// pins one.
    pub audience: Audience,
    /// JWKS key set for this issuer. Typically fetched at startup and
    /// refreshed periodically via a background task.
    pub jwks: Arc<JwkSet>,
    /// Additional claim names to extract into `WorkloadIdentity.claims`.
    /// Only top-level string-valued claims are captured.
    pub extra_claims: Vec<String>,
}

impl BearerIssuerConfig {
    /// A trusted issuer whose tokens must name `audience`, verified against
    /// `jwks`, with no extra claims captured.
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>, jwks: Arc<JwkSet>) -> Self {
        Self {
            issuer: issuer.into(),
            audience: Audience::Exact(audience.into()),
            jwks,
            extra_claims: Vec::new(),
        }
    }

    /// Capture these top-level string claims into
    /// [`WorkloadIdentity::claims`].
    #[must_use]
    pub fn with_extra_claims(
        mut self,
        claims: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.extra_claims = claims.into_iter().map(Into::into).collect();
        self
    }
}

// ── BearerConfig ─────────────────────────────────────────────────────────────

/// Configuration for the bearer token middleware.
#[derive(Clone)]
pub struct BearerConfig {
    /// Trusted issuers. A token is accepted if its `iss` matches any
    /// issuer in this list AND the signature verifies against that
    /// issuer's JWKS.
    pub issuers: Vec<BearerIssuerConfig>,
    /// Clock `exp` and `nbf` are judged against. [`SystemClock`] unless
    /// replaced through [`with_clock`](Self::with_clock).
    clock: Arc<dyn Clock>,
}

impl BearerConfig {
    /// Configuration trusting `issuers`, judging token lifetimes on the
    /// system clock.
    pub fn new(issuers: Vec<BearerIssuerConfig>) -> Self {
        for issuer in issuers
            .iter()
            .filter(|i| i.audience == Audience::AnyDangerous)
        {
            tracing::warn!(
                target: "axess::factors::bearer",
                issuer = %issuer.issuer,
                "bearer issuer has no audience pin: a token minted for any other service \
                 of this issuer is accepted"
            );
        }
        Self {
            issuers,
            clock: Arc::new(SystemClock),
        }
    }

    /// Judge `exp` and `nbf` against `clock`. Pass a `MockClock` to drive
    /// token expiry deterministically.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }
}

impl std::fmt::Debug for BearerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BearerConfig")
            .field("issuers", &self.issuers)
            .finish_non_exhaustive()
    }
}

// ── Validation logic ─────────────────────────────────────────────────────────

/// Extract and validate a bearer token against the configured issuers.
///
/// Returns `Ok(Some(identity))` on success, `Ok(None)` when no bearer
/// token is present, `Err` on validation failure, including a header that
/// names the Bearer scheme and carries no token.
pub fn validate_bearer_token(
    authorization_header: Option<&str>,
    config: &BearerConfig,
) -> Result<Option<WorkloadIdentity>, BearerError> {
    let token = match extract_bearer_token(authorization_header)? {
        Some(t) => t,
        None => return Ok(None),
    };

    // Decode payload to read `iss` without signature verification.
    let payload =
        crate::jwt::claims::decode_jwt_payload(token).map_err(BearerError::InvalidToken)?;

    let iss = payload
        .get("iss")
        .and_then(|v| v.as_str())
        .ok_or(BearerError::MissingIssuer)?;

    // Several configs may name one issuer (an old and a new key set, one per
    // audience): the token is accepted by the first that verifies it, and
    // refused with the first one's reason when none does.
    let mut first_error = None;
    let mut verified = None;
    for issuer_cfg in config.issuers.iter().filter(|c| c.issuer == iss) {
        // Verify signature against the issuer's JWKS.
        let mut validation_config = ValidationConfig::new();
        validation_config.audience = issuer_cfg.audience.exact().map(String::from);
        // `AnyDangerous` is the configured decision to accept any audience.
        validation_config.allow_any_audience = issuer_cfg.audience == Audience::AnyDangerous;
        // The issuer was chosen by the token's own `iss`, so pinning it adds
        // nothing against a forged claim, but it makes `iss` a required claim
        // checked by the same code path as every other verifier, rather than a
        // string compared once above.
        validation_config.issuer = Some(issuer_cfg.issuer.clone());
        match validation::verify_jwt(
            token,
            &issuer_cfg.jwks,
            &validation_config,
            ALLOWED_ALGORITHMS,
            &*config.clock,
        ) {
            Ok(claims) => {
                verified = Some((issuer_cfg, claims));
                break;
            }
            Err(e) => {
                first_error.get_or_insert(e);
            }
        }
    }
    let Some((issuer_cfg, claims)) = verified else {
        return Err(match first_error {
            Some(e) => BearerError::Jwt(JwtVerificationError::from(e)),
            None => BearerError::UntrustedIssuer(iss.to_string()),
        });
    };

    // Extract identity fields.
    let subject = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or(BearerError::MissingSubject)?
        .to_string();

    let audiences = match claims.get("aud") {
        Some(serde_json::Value::String(s)) => vec![s.clone()],
        Some(serde_json::Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect(),
        _ => Vec::new(),
    };

    // Capture extra claims.
    let mut extra = std::collections::HashMap::new();
    for key in &issuer_cfg.extra_claims {
        if let Some(serde_json::Value::String(v)) = claims.get(key.as_str()) {
            extra.insert(key.clone(), v.clone());
        }
    }

    Ok(Some(WorkloadIdentity {
        subject,
        issuer: iss.to_string(),
        audiences,
        claims: extra,
    }))
}

/// Extract the token from `Authorization: Bearer <token>`. The scheme is
/// case-insensitive (RFC 7235 section 2.1), any whitespace may separate it
/// from the token, and whitespace around the token is not part of it.
///
/// `Ok(None)` is a header that names another scheme, or none. A header that
/// names the Bearer scheme and carries no token is malformed, not absent, and
/// is refused.
fn extract_bearer_token(header: Option<&str>) -> Result<Option<&str>, BearerError> {
    let Some(value) = header else {
        return Ok(None);
    };
    let (scheme, rest) = match value.split_once(|c: char| c.is_ascii_whitespace()) {
        Some(parts) => parts,
        None => (value, ""),
    };
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Ok(None);
    }
    match rest.trim() {
        "" => Err(BearerError::InvalidToken(
            "the Bearer scheme carries no token".to_string(),
        )),
        token => Ok(Some(token)),
    }
}

// ── BearerError ──────────────────────────────────────────────────────────────

/// Opaque wrapper around internal JWT verification errors. The inner
/// type is `pub(crate)` to avoid leaking `jsonwebtoken` types through
/// the public API.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct JwtVerificationError(String);

impl From<JwtError> for JwtVerificationError {
    fn from(e: JwtError) -> Self {
        Self(e.to_string())
    }
}

/// Errors from bearer token validation.
#[derive(Debug, thiserror::Error)]
pub enum BearerError {
    /// The token could not be decoded (malformed JWT).
    #[error("invalid bearer token: {0}")]
    InvalidToken(String),

    /// The token has no `iss` claim.
    #[error("bearer token missing `iss` claim")]
    MissingIssuer,

    /// The token's `iss` doesn't match any configured issuer.
    #[error("untrusted issuer: {0}")]
    UntrustedIssuer(String),

    /// The token has no `sub` claim.
    #[error("bearer token missing `sub` claim")]
    MissingSubject,

    /// JWT signature or claim validation failed.
    #[error("JWT validation: {0}")]
    Jwt(#[from] JwtVerificationError),
}

// ── Tower Layer + Service ────────────────────────────────────────────────────

/// Tower layer that validates bearer JWTs and inserts [`WorkloadIdentity`]
/// into request extensions.
///
/// Non-rejecting: requests without a bearer token pass through without
/// a `WorkloadIdentity` extension. Requests with an invalid token get
/// a 401 response.
#[derive(Clone)]
pub struct BearerTokenLayer {
    config: Arc<BearerConfig>,
}

impl BearerTokenLayer {
    /// Create a new bearer token layer with the given configuration.
    pub fn new(config: BearerConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    /// Judge `exp` and `nbf` against `clock`, replacing the one the
    /// configuration carried.
    #[must_use]
    pub fn with_clock(self, clock: Arc<dyn Clock>) -> Self {
        let config = (*self.config).clone().with_clock(clock);
        Self {
            config: Arc::new(config),
        }
    }
}

impl<S> tower::Layer<S> for BearerTokenLayer {
    type Service = BearerTokenService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        BearerTokenService {
            inner,
            config: self.config.clone(),
        }
    }
}

/// The `401` for a bearer token that did not validate: a fixed body and the
/// RFC 6750 challenge, the same whatever the reason.
fn invalid_token_response() -> axum::response::Response {
    let mut response =
        axum::response::Response::new(axum::body::Body::from(r#"{"error":"invalid_token"}"#));
    *response.status_mut() = axum::http::StatusCode::UNAUTHORIZED;
    let headers = response.headers_mut();
    headers.insert(
        axum::http::header::WWW_AUTHENTICATE,
        axum::http::HeaderValue::from_static(r#"Bearer error="invalid_token""#),
    );
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    response
}

/// The service produced by [`BearerTokenLayer`].
#[derive(Clone)]
pub struct BearerTokenService<S> {
    inner: S,
    config: Arc<BearerConfig>,
}

impl<S> tower::Service<axum::http::Request<axum::body::Body>> for BearerTokenService<S>
where
    S: tower::Service<axum::http::Request<axum::body::Body>, Response = axum::response::Response>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    type Response = axum::response::Response;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: axum::http::Request<axum::body::Body>) -> Self::Future {
        let config = self.config.clone();
        let mut inner = self.inner.clone();
        // Swap `self.inner` with the clone to satisfy Tower's poll_ready contract.
        std::mem::swap(&mut self.inner, &mut inner);

        Box::pin(async move {
            // A header that is not text carries a credential nobody can
            // read: refused, not passed on as if there were none.
            let auth_header = match req.headers().get(axum::http::header::AUTHORIZATION) {
                None => None,
                Some(value) => match value.to_str() {
                    Ok(text) => Some(text.to_string()),
                    Err(_) => {
                        tracing::debug!("Bearer token rejected: Authorization is not text");
                        return Ok(invalid_token_response());
                    }
                },
            };

            match validate_bearer_token(auth_header.as_deref(), &config) {
                Ok(Some(identity)) => {
                    req.extensions_mut().insert(identity);
                    inner.call(req).await
                }
                Ok(None) => {
                    // No bearer token; pass through without workload identity.
                    inner.call(req).await
                }
                Err(e) => {
                    // The reason stays in the log: a body that says which
                    // check failed (unknown `kid`, wrong audience, expired)
                    // is a probe for an attacker.
                    tracing::debug!("Bearer token rejected: {e}");
                    Ok(invalid_token_response())
                }
            }
        })
    }
}

#[cfg(test)]
mod tests;
