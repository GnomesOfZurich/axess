//! Administrative HTTP handlers for session management.
//!
//! These helpers expose Axum endpoints that invalidate user, tenant, or all
//! sessions via the shared [`SessionRegistry`](crate::authn::session::registry::SessionRegistry).

use crate::authn::session::registry::SessionRegistry;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse
};
use std::{fmt::Display, sync::Arc};

/// Invalidates all sessions for a specific user.
///
/// This handler receives a user ID as a path parameter and calls
/// [`SessionRegistry::invalidate_user_sessions`] to log out all sessions for that user.
/// Returns HTTP 200 with the number of invalidated sessions, or HTTP 500 on error.
///
/// # Parameters
/// - `State(registry)`: Shared session registry.
/// - `Path(user_id)`: The user ID whose sessions should be invalidated.
///
/// # Response
/// - `200 OK`: Number of sessions invalidated.
/// - `500 INTERNAL_SERVER_ERROR`: Error message if logout fails.
pub async fn logout_user<T: Display + Send + Sync, R: SessionRegistry>(
    State(registry): State<Arc<R>>,
    Path(user_id): Path<T>,
) -> impl IntoResponse {
    match registry.invalidate_user_sessions(&user_id).await {
        Ok(count) => (StatusCode::OK, format!("Invalidated {count} sessions")),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to logout user: {e}"),
        ),
    }
}

/// Invalidates all sessions for a specific tenant.
///
/// This handler receives a tenant ID as a path parameter and calls
/// [`SessionRegistry::invalidate_tenant_sessions`] to log out all sessions for that tenant.
/// Returns HTTP 200 with the number of invalidated sessions, or HTTP 500 on error.
///
/// # Parameters
/// - `State(registry)`: Shared session registry.
/// - `Path(tenant_id)`: The tenant ID whose sessions should be invalidated.
///
/// # Response
/// - `200 OK`: Number of sessions invalidated.
/// - `500 INTERNAL_SERVER_ERROR`: Error message if logout fails.
pub async fn logout_tenant<T: Display + Send + Sync, R: SessionRegistry>(
    State(registry): State<Arc<R>>,
    Path(tenant_id): Path<T>,
) -> impl IntoResponse {
    match registry.invalidate_tenant_sessions(&tenant_id).await {
        Ok(count) => (StatusCode::OK, format!("Invalidated {count} sessions")),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to logout tenant: {e}"),
        ),
    }
}

/// Invalidates all sessions in the system.
///
/// This handler calls [`SessionRegistry::invalidate_all_sessions`] to log out all sessions.
/// Returns HTTP 200 with the number of invalidated sessions, or HTTP 500 on error.
///
/// # Parameters
/// - `State(registry)`: Shared session registry.
///
/// # Response
/// - `200 OK`: Number of sessions invalidated.
/// - `500 INTERNAL_SERVER_ERROR`: Error message if logout fails.
pub async fn logout_all<R: SessionRegistry>(State(registry): State<Arc<R>>) -> impl IntoResponse {
    match registry.invalidate_all_sessions().await {
        Ok(count) => (StatusCode::OK, format!("Invalidated {count} sessions")),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to logout all sessions: {e}"),
        ),
    }
}
