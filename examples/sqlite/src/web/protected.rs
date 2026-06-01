//! Protected routes; accessible only to fully authenticated users.

use crate::web::app::AppState;
use axess::authn::{AuthnScope, FactorKind, FactorStore};
use axess::{AuthSession, require_authn};
use axum::{
    Router,
    extract::State,
    response::{Html, IntoResponse},
    routing::get,
};

/// Build the sub-router for protected routes.
///
/// All routes are guarded by `require_authn!`; unauthenticated requests are
/// redirected to `/login`.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/dashboard", get(dashboard))
        .route_layer(require_authn!("/login"))
}

/// GET /dashboard; requires authentication.
pub async fn dashboard(session: AuthSession, State(state): State<AppState>) -> impl IntoResponse {
    let user_id = session.user_id().await;
    let tenant_id = session.tenant_id().await;
    let user_display = user_id
        .as_ref()
        .map(|id| id.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // Ask the FactorStore whether a TOTP factor is already enrolled for this
    // user. Demonstrates `load_factor` and keeps the dashboard truthful: an
    // already-enrolled user sees a status note instead of a stale enrollment
    // link.
    let totp_enrolled = match (user_id, tenant_id) {
        (Some(user_id), Some(tenant_id)) => {
            let scope = AuthnScope::User { tenant_id, user_id };
            state
                .backend
                .load_factor(&scope, FactorKind::Totp)
                .await
                .ok()
                .flatten()
                .is_some()
        }
        _ => false,
    };

    let totp_block = if totp_enrolled {
        "<li>TOTP is enrolled. Log out and back in to exercise the second factor.</li>".to_string()
    } else {
        r#"<li><a href="/setup-totp">Enroll TOTP (two-factor authentication)</a></li>"#.to_string()
    };

    Html(format!(
        r#"<!doctype html>
<html><head><title>Dashboard</title></head><body>
<h1>Welcome, {user_display}!</h1>
<p>You are authenticated.</p>
<ul>
  {totp_block}
</ul>
<form method="POST" action="/logout">
  <button type="submit">Logout</button>
</form>
</body></html>"#
    ))
}
