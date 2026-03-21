//! Authorization error types.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// Returned (and converted to a 403 response) when a Cedar policy check denies access.
///
/// Implements [`IntoResponse`] so handlers can use `?` directly:
/// ```rust,ignore
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
#[derive(Debug, thiserror::Error)]
pub enum AuthzError {
    #[error("Failed to parse Cedar policy: {0}")]
    PolicyParse(String),

    #[error("Failed to parse Cedar schema: {0}")]
    SchemaParse(String),

    #[error("Invalid entity UID: {0}")]
    InvalidEntityUid(String),

    #[error("Failed to build Cedar entities: {0}")]
    EntityBuild(String),

    #[error("Principal not established — session is not authenticated")]
    NoPrincipal,

    #[error("Entity provider error: {0}")]
    Provider(String),

    #[error("Request context error: {0}")]
    Context(String),
}
