//! Protected routes — accessible only to fully authenticated users.

use crate::web::app::AppState;
use axess::{AuthSession, login_required}; // AuthSession used in handler signature
use axum::{
    Router,
    extract::State,
    response::{Html, IntoResponse},
    routing::get,
};

/// Build the sub-router for protected routes.
///
/// All routes are guarded by `login_required!` — unauthenticated requests are
/// redirected to `/login`.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/dashboard", get(dashboard))
        .route_layer(login_required!("/login"))
}

/// GET /dashboard — requires authentication.
pub async fn dashboard(session: AuthSession, State(_state): State<AppState>) -> impl IntoResponse {
    let user_id = session
        .user_id()
        .await
        .map(|id| id.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    Html(format!(
        r#"<!doctype html>
<html><head><title>Dashboard</title></head><body>
<h1>Welcome, {user_id}!</h1>
<p>You are authenticated.</p>
<form method="POST" action="/logout">
  <button type="submit">Logout</button>
</form>
</body></html>"#
    ))
}
