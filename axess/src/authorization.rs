use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use cedar_policy::Entities;

pub use axess_core::authz::{
    AuthzDecision, AuthzError, AuthzRequest, PolicyStore, SYSTEM_ROLES,
    action_uid, document_uid, ledger_uid, platform_uid, role_uid, user_uid,
};

/// Returned (and converted to a 403 response) when a Cedar policy check denies access.
#[derive(Debug)]
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

/// Evaluate the authorization request against the policy store.
///
/// Returns `Ok(())` when Cedar permits; `Err(AuthzDenied)` otherwise.
/// Thread-safe — `PolicyStore` is `Send + Sync` and the entity set is per-call.
pub fn require(
    store: &PolicyStore,
    entities: Entities,
    req: &AuthzRequest,
) -> Result<(), AuthzDenied> {
    match axess_core::authz::is_authorized(store, entities, req) {
        AuthzDecision::Allow => Ok(()),
        AuthzDecision::Deny => Err(AuthzDenied),
    }
}
