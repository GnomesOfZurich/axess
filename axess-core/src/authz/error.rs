//! Authorization error types.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// Returned (and converted to a 403 response) when a Cedar policy check denies access.
///
/// Implements [`IntoResponse`] so handlers can use `?` directly:
/// ```text
/// authz.require("ViewLedger", &ledger_id).await?;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthzDenied;

impl IntoResponse for AuthzDenied {
    fn into_response(self) -> Response {
        (
            StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({ "error": "Access denied" })),
        )
            .into_response()
    }
}

/// Authorization infrastructure errors.
///
/// These indicate misconfiguration or programming errors, not denied access.
/// Denied access is represented by [`AuthzDenied`].
///
/// ## HTTP status mapping
///
/// | Variant | Suggested HTTP status | Rationale |
/// |---------|----------------------|-----------|
/// | `PolicyParse` | 500 | Server misconfiguration |
/// | `SchemaParse` | 500 | Server misconfiguration |
/// | `InvalidEntityUid` | 500 | Programming error |
/// | `EntityBuild` | 500 | Entity graph construction failed |
/// | `NoPrincipal` | 401 | Unauthenticated, no session |
/// | `Provider` | 502 | Upstream entity provider failure |
/// | `Context` | 500 | Request context build error |
#[derive(Debug, thiserror::Error)]
pub enum AuthzError {
    /// Cedar policy text failed to parse at startup.
    #[error("Failed to parse Cedar policy: {0}")]
    PolicyParse(String),

    /// Cedar schema text failed to parse at startup.
    #[error("Failed to parse Cedar schema: {0}")]
    SchemaParse(String),

    /// Constructed entity UID is not valid Cedar syntax.
    #[error("Invalid entity UID: {0}")]
    InvalidEntityUid(String),

    /// Building the Cedar entity graph from provider data failed.
    #[error("Failed to build Cedar entities: {0}")]
    EntityBuild(String),

    /// Authorization called on a session that has no authenticated principal.
    #[error("Principal not established; session is not authenticated")]
    NoPrincipal,

    /// The pluggable [`AuthzEntityProvider`](super::provider::AuthzEntityProvider) returned an error.
    #[error("Entity provider error: {0}")]
    Provider(Box<dyn std::error::Error + Send + Sync>),

    /// Constructing the per-request Cedar context failed.
    #[error("Request context error: {0}")]
    Context(String),
}

impl AuthzError {
    /// Create a provider error from any error type.
    ///
    /// The original error is boxed so callers can downcast to the concrete
    /// type if needed: `err.downcast_ref::<MyStoreError>()`.
    pub fn provider(err: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Provider(Box::new(err))
    }
}

#[cfg(test)]
mod authz_error_tests {
    use super::*;

    /// `AuthzDenied` surfaces as `403 Forbidden` with a JSON
    /// body. Pins the `into_response -> Default::default()` body
    /// mutation, which would emit an empty `200 OK` and silently
    /// authorize denied requests at the handler boundary.
    #[test]
    fn authz_denied_into_response_is_403_forbidden() {
        let response = AuthzDenied.into_response();
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "AuthzDenied must surface as 403, not Default::default() (which would return 200)"
        );
    }

    /// `AuthzError::provider` wraps the supplied error in the
    /// `Provider` variant. Pins the `provider -> Default::default()`
    /// body mutation (correctly classified unviable since `AuthzError`
    /// has no `Default` impl); the test still asserts the
    /// constructor's contract so future refactors can't silently
    /// strip the wrapper.
    #[test]
    fn authz_error_provider_wraps_into_provider_variant() {
        use std::io;
        let inner = io::Error::other("downstream");
        let err = AuthzError::provider(inner);
        assert!(
            matches!(err, AuthzError::Provider(_)),
            "provider() must yield AuthzError::Provider, not any other variant"
        );
        // Display surfaces the wrapped error.
        let msg = err.to_string();
        assert!(
            msg.contains("Entity provider error") && msg.contains("downstream"),
            "Provider Display must surface the wrapped error (got: {msg})"
        );
    }
}
