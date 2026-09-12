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
//! 3. Verifies the signature against the issuer's JWKS (cached).
//! 4. Validates standard claims (`exp`, `iss`, `aud`).
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

use crate::jwt::validation::{self, ALLOWED_ALGORITHMS, JwtError};
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
    /// Expected `aud` value. When `Some`, the token's `aud` must contain
    /// this value. When `None`, audience validation is skipped.
    pub audience: Option<String>,
    /// JWKS key set for this issuer. Typically fetched at startup and
    /// refreshed periodically via a background task.
    pub jwks: Arc<JwkSet>,
    /// Additional claim names to extract into `WorkloadIdentity.claims`.
    /// Only top-level string-valued claims are captured.
    pub extra_claims: Vec<String>,
}

// ── BearerConfig ─────────────────────────────────────────────────────────────

/// Configuration for the bearer token middleware.
#[derive(Debug, Clone)]
pub struct BearerConfig {
    /// Trusted issuers. A token is accepted if its `iss` matches any
    /// issuer in this list AND the signature verifies against that
    /// issuer's JWKS.
    pub issuers: Vec<BearerIssuerConfig>,
}

// ── Validation logic ─────────────────────────────────────────────────────────

/// Extract and validate a bearer token against the configured issuers.
///
/// Returns `Ok(Some(identity))` on success, `Ok(None)` when no bearer
/// token is present, `Err` on validation failure.
pub fn validate_bearer_token(
    authorization_header: Option<&str>,
    config: &BearerConfig,
) -> Result<Option<WorkloadIdentity>, BearerError> {
    let token = match extract_bearer_token(authorization_header) {
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

    // Find a matching issuer config.
    let issuer_cfg = config
        .issuers
        .iter()
        .find(|c| c.issuer == iss)
        .ok_or_else(|| BearerError::UntrustedIssuer(iss.to_string()))?;

    // Verify signature against the issuer's JWKS.
    let claims = validation::verify_jwt_signature(
        token,
        &issuer_cfg.jwks,
        issuer_cfg.audience.as_deref(),
        ALLOWED_ALGORITHMS,
    )
    .map_err(|e| BearerError::Jwt(JwtVerificationError::from(e)))?;

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

/// Extract the token from `Authorization: Bearer <token>`.
fn extract_bearer_token(header: Option<&str>) -> Option<&str> {
    let value = header?;
    let stripped = value.strip_prefix("Bearer ")?;
    if stripped.is_empty() {
        return None;
    }
    Some(stripped)
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
            let auth_header = req
                .headers()
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

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
                    tracing::debug!("Bearer token rejected: {e}");
                    let response = axum::response::Response::builder()
                        .status(axum::http::StatusCode::UNAUTHORIZED)
                        .header("WWW-Authenticate", "Bearer")
                        .body(axum::body::Body::from(format!("{{\"error\":\"{e}\"}}")))
                        .unwrap();
                    Ok(response)
                }
            }
        })
    }
}

#[cfg(test)]
mod tests;
