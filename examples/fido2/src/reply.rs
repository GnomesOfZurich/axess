//! The JSON answers the handlers share.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// A refusal: `status` with `{"error": "<code>"}`.
pub(crate) fn refuse(status: StatusCode, code: &str) -> Response {
    (status, Json(serde_json::json!({ "error": code }))).into_response()
}

/// The one answer every failed sign-in gets, whatever failed: an unknown
/// user, a wrong password, a refused assertion, a locked account. The cause
/// is in the server's log and its audit rows, not in the response.
pub(crate) fn invalid_credentials() -> Response {
    refuse(StatusCode::UNAUTHORIZED, "invalid_credentials")
}

/// The request needs a signed-in user and has none.
pub(crate) fn not_authenticated() -> Response {
    refuse(StatusCode::UNAUTHORIZED, "not_authenticated")
}

/// The session is authenticated.
pub(crate) fn signed_in() -> Response {
    Json(serde_json::json!({ "authenticated": true })).into_response()
}
