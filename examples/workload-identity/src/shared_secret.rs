//! Shared secrets: the recipe for a machine caller that can do none of
//! the above.
//!
//! The other recipes in this crate give a caller an identity an IdP
//! vouches for. Some callers cannot have one: an intake worker reporting
//! a bounced email, a cron job, a relay that can only be told "send this
//! string". For those, both ends share a secret, and this recipe uses it
//! the strongest way available: the caller **signs** each request with
//! it (an HMAC over time, method, path and body) instead of sending it.
//!
//! It is still the weakest machine credential axess offers. Whoever
//! reads the server's configuration can act as the caller, and nothing
//! expires until someone rotates the secret. Prefer the
//! [`github_actions`](crate::github_actions) or
//! [`kubernetes`](crate::kubernetes) recipes whenever the caller can use
//! them. The book chapter "Shared secrets: the last resort" sets the
//! options side by side.
//!
//! Both sides load the secret the same way:
//! [`ServiceSecret::from_env`] reads `INTAKE_WEBHOOK_SECRET_FILE` (a
//! mounted container secret) or `INTAKE_WEBHOOK_SECRET`. Generate one
//! with `openssl rand -hex 32`.

use axess::service_secret::{
    SIGNATURE_HEADER, ServiceCaller, ServiceSecret, ServiceSecretError, ServiceSecretLayer,
    ServiceSecrets, ServiceSigner, SignedRequests,
};
use axum::{
    Json, Router,
    body::Body,
    http::{Method, Request, StatusCode, header::CONTENT_TYPE},
    routing::post,
};
use serde::{Deserialize, Serialize};

/// The environment variable both sides read the secret from.
pub const SECRET_VAR: &str = "INTAKE_WEBHOOK_SECRET";

/// The route the caller posts to.
pub const BOUNCE_PATH: &str = "/webhooks/bounce";

/// What the caller reports: one address whose mail bounced.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BounceReport {
    /// The address that bounced.
    pub address: String,
    /// The mail server's reason, as reported.
    pub reason: String,
}

// ── Receiving side ────────────────────────────────────────────────────────

/// The secrets the route accepts, from the environment.
///
/// During a rotation, add the new secret beside the old one under a
/// different name (`ServiceSecrets::with`), move the caller over, then
/// drop the old one; the handler's [`ServiceCaller`] shows which one each
/// request used.
pub fn secrets_from_env() -> Result<ServiceSecrets, ServiceSecretError> {
    Ok(ServiceSecret::from_env("intake", SECRET_VAR)?
        .into_iter()
        .collect())
}

/// The bounce route, admitting only requests signed with one of
/// `secrets`. With no secret configured the route answers `404`.
pub fn bounce_routes(secrets: ServiceSecrets) -> Router {
    Router::new()
        .route(BOUNCE_PATH, post(receive_bounce))
        .layer(ServiceSecretLayer::signed(
            secrets,
            SignedRequests::default(),
        ))
}

async fn receive_bounce(caller: ServiceCaller, Json(report): Json<BounceReport>) -> StatusCode {
    tracing::info!(caller = caller.name(), address = %report.address, "bounce reported");
    StatusCode::ACCEPTED
}

// ── Calling side ──────────────────────────────────────────────────────────

/// The signer for the calling side, from the same secret.
pub fn signer_from_env() -> Result<Option<ServiceSigner>, ServiceSecretError> {
    Ok(ServiceSecret::from_env("intake", SECRET_VAR)?.map(|secret| secret.signer()))
}

/// A signed request reporting `report`, sent at `now_unix_seconds`.
///
/// Built as an `http::Request` so the recipe needs no HTTP client; with
/// `reqwest`, sign the same way and set the header and body on the
/// request builder. The body must go out exactly as signed.
pub fn signed_bounce(
    signer: &ServiceSigner,
    now_unix_seconds: i64,
    report: &BounceReport,
) -> Request<Body> {
    let body = serde_json::to_vec(report).expect("a BounceReport always serializes");
    let signature = signer.sign(now_unix_seconds, &Method::POST, BOUNCE_PATH, &body);
    Request::builder()
        .method(Method::POST)
        .uri(BOUNCE_PATH)
        .header(CONTENT_TYPE, "application/json")
        .header(SIGNATURE_HEADER, signature)
        .body(Body::from(body))
        .expect("static parts form a valid request")
}
