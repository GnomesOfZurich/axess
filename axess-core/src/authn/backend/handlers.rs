//! Administrative HTTP handlers for session management.
//!
//! These helpers expose Axum endpoints that invalidate user, tenant, or all
//! sessions via the shared [`SessionRegistry`](crate::authn::session::registry::SessionRegistry).

use crate::authn::session::registry::SessionRegistry;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use std::{fmt::Display, sync::Arc};

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

pub async fn logout_all<R: SessionRegistry>(State(registry): State<Arc<R>>) -> impl IntoResponse {
    match registry.invalidate_all_sessions().await {
        Ok(count) => (StatusCode::OK, format!("Invalidated {count} sessions")),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to logout all sessions: {e}"),
        ),
    }
}
