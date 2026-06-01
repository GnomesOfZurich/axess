//! Axum handlers demonstrating Cedar authorization patterns.
//!
//! Each handler shows a different Axess authz API:
//! - `require()`; hard 403 on denial (typical for mutations)
//! - `is_permitted()`; boolean check (typical for UI capability hints)
//! - `batch_check()`; multiple checks in one call (typical for list views)

use crate::AppState;
use axess::authorization::{AuthzDenied, AuthzError, StandardRequestContext};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse},
};
use serde::{Deserialize, Serialize};

// ── GET /; clickable index of demo URLs ─────────────────────────────────────

/// Browser-friendly landing page. The example is a JSON/curl demo;
/// without this, hitting `/` in a browser just 404s to a blank page.
pub async fn index() -> Html<&'static str> {
    Html(
        r#"<!doctype html>
<html><head><title>axess-example-authz</title>
<style>
body{font-family:system-ui,sans-serif;max-width:780px;margin:2em auto;padding:0 1em;color:#222}
code,kbd{background:#f4f4f4;padding:.1em .35em;border-radius:3px}
table{border-collapse:collapse;margin:.5em 0 1.5em}
th,td{border:1px solid #ddd;padding:.4em .8em;text-align:left}
th{background:#f8f8f8}
li{margin:.3em 0}
section{margin-bottom:1.6em}
.method{display:inline-block;min-width:3.5em;font-weight:600;color:#0a5}
.method.post{color:#a50}
.method.delete{color:#c33}
</style></head><body>
<h1>axess-example-authz</h1>
<p>Cedar Policy authorization demo. No auth, no DB; three seeded users, three seeded documents,
and a handful of routes showing RBAC, ReBAC (ownership), and ABAC (MFA) policy checks.</p>

<section>
<h2>Seeded data</h2>
<table>
  <tr><th>User</th><th>Role</th><th>Note</th></tr>
  <tr><td><code>alice</code></td><td>admin</td><td>can do everything</td></tr>
  <tr><td><code>bob</code></td><td>viewer</td><td>view-only</td></tr>
  <tr><td><code>carol</code></td><td>editor</td><td>view + edit; owns <code>doc-1</code></td></tr>
</table>
<table>
  <tr><th>Document</th><th>Owner</th><th>Title</th></tr>
  <tr><td><code>doc-1</code></td><td>carol</td><td>Q4 Financial Report</td></tr>
  <tr><td><code>doc-2</code></td><td>alice</td><td>Board Minutes</td></tr>
  <tr><td><code>doc-3</code></td><td>bob</td><td>Public Handbook</td></tr>
</table>
</section>

<section>
<h2>GET endpoints (clickable in a browser)</h2>
<ul>
  <li><span class="method">GET</span> <a href="/users/bob/documents/doc-1">/users/bob/documents/doc-1</a>; bob can view</li>
  <li><span class="method">GET</span> <a href="/users/bob/documents/doc-3/permissions">/users/bob/documents/doc-3/permissions</a>; what bob can do with doc-3</li>
  <li><span class="method">GET</span> <a href="/users/bob/capabilities">/users/bob/capabilities</a>; bob's capabilities across all docs</li>
  <li><span class="method">GET</span> <a href="/users/carol/capabilities">/users/carol/capabilities</a>; carol's capabilities (editor + owns doc-1)</li>
  <li><span class="method">GET</span> <a href="/users/alice/capabilities">/users/alice/capabilities</a>; alice's capabilities (admin)</li>
</ul>
</section>

<section>
<h2>Mutating endpoints (curl only)</h2>
<pre><code># Bob cannot edit (viewer role):
curl -X POST http://localhost:3000/users/bob/documents/doc-1/edit
# → 403

# Carol can edit doc-1 (she owns it):
curl -X POST http://localhost:3000/users/carol/documents/doc-1/edit

# Alice can delete, but only with MFA:
curl -X DELETE "http://localhost:3000/users/alice/documents/doc-1?mfa=false"   # → 403
curl -X DELETE "http://localhost:3000/users/alice/documents/doc-1?mfa=true"    # → 200
</code></pre>
</section>

</body></html>"#,
    )
}

// ── GET /users/:user_id/documents/:doc_id; require ViewDocument ─────────────

/// View a single document. Returns 403 if the user lacks permission.
///
/// Demonstrates `authz_session.require("ViewDocument", &doc_id)`.
pub async fn view_document(
    State(state): State<AppState>,
    Path((user_id, doc_id)): Path<(String, String)>,
) -> Result<Json<DocumentResponse>, AppError> {
    let authz = state.authz.for_user_id(&user_id)?;
    authz.require("ViewDocument", &doc_id).await?;

    let doc = state
        .data
        .documents
        .get(&doc_id)
        .ok_or(AppError::NotFound)?;

    Ok(Json(DocumentResponse {
        id: doc.id.clone(),
        title: doc.title.clone(),
        owner: doc.owner_id.clone(),
    }))
}

// ── POST /users/:user_id/documents/:doc_id/edit; require EditDocument ───────

/// Edit a document. Returns 403 if the user lacks permission.
pub async fn edit_document(
    State(state): State<AppState>,
    Path((user_id, doc_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, AppError> {
    let authz = state.authz.for_user_id(&user_id)?;
    authz.require("EditDocument", &doc_id).await?;

    Ok(Json(serde_json::json!({
        "status": "ok",
        "message": format!("Document {doc_id} edited by {user_id}")
    })))
}

// ── DELETE /users/:user_id/documents/:doc_id; require DeleteDocument + MFA ──

/// Delete a document. Requires MFA verification (ABAC policy).
///
/// The `mfa` query parameter simulates MFA status for this example.
/// In a real app, MFA status comes from the authenticated session.
pub async fn delete_document(
    State(state): State<AppState>,
    Path((user_id, doc_id)): Path<(String, String)>,
    Query(params): Query<DeleteParams>,
) -> Result<Json<serde_json::Value>, AppError> {
    let ctx = StandardRequestContext::new(params.mfa.unwrap_or(false), None);
    let authz = state.authz.for_user_id_with_context(&user_id, ctx)?;
    authz.require("DeleteDocument", &doc_id).await?;

    Ok(Json(serde_json::json!({
        "status": "ok",
        "message": format!("Document {doc_id} deleted by {user_id}")
    })))
}

#[derive(Deserialize)]
pub struct DeleteParams {
    pub mfa: Option<bool>,
}

// ── GET /users/:user_id/documents/:doc_id/permissions; capability hints ─────

/// Check what the user can do with a document. Returns a capability map.
///
/// Demonstrates `is_permitted()` for UI capability hints.
pub async fn document_permissions(
    State(state): State<AppState>,
    Path((user_id, doc_id)): Path<(String, String)>,
) -> Result<Json<PermissionsResponse>, AppError> {
    let authz = state.authz.for_user_id(&user_id)?;

    Ok(Json(PermissionsResponse {
        document_id: doc_id.clone(),
        can_view: authz.is_permitted("ViewDocument", &doc_id).await,
        can_edit: authz.is_permitted("EditDocument", &doc_id).await,
        can_delete: authz.is_permitted("DeleteDocument", &doc_id).await,
    }))
}

// ── GET /users/:user_id/capabilities; batch_check across documents ──────────

/// Check a user's permissions across all documents in one call.
///
/// Demonstrates `batch_check()` for computing per-resource capability sets.
pub async fn user_capabilities(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<Json<Vec<CapabilityEntry>>, AppError> {
    let authz = state.authz.for_user_id(&user_id)?;

    let mut results = Vec::new();
    for doc in state.data.documents.values() {
        let checks: Vec<(&str, &String)> =
            vec![("ViewDocument", &doc.id), ("EditDocument", &doc.id)];
        let decisions = authz.batch_check(&checks).await;

        results.push(CapabilityEntry {
            document_id: doc.id.clone(),
            document_title: doc.title.clone(),
            permissions: decisions
                .into_iter()
                .map(|(action, decision)| PermissionEntry {
                    action,
                    allowed: matches!(decision, axess::authorization::AuthzDecision::Allow),
                })
                .collect(),
        });
    }

    Ok(Json(results))
}

// ── Response types ───────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct DocumentResponse {
    pub id: String,
    pub title: String,
    pub owner: String,
}

#[derive(Serialize)]
pub struct PermissionsResponse {
    pub document_id: String,
    pub can_view: bool,
    pub can_edit: bool,
    pub can_delete: bool,
}

#[derive(Serialize)]
pub struct CapabilityEntry {
    pub document_id: String,
    pub document_title: String,
    pub permissions: Vec<PermissionEntry>,
}

#[derive(Serialize)]
pub struct PermissionEntry {
    pub action: String,
    pub allowed: bool,
}

// ── Error type ───────────────────────────────────────────────────────────────

pub enum AppError {
    NotFound,
    Authz(AuthzError),
    Denied,
}

impl From<AuthzDenied> for AppError {
    fn from(_: AuthzDenied) -> Self {
        AppError::Denied
    }
}

impl From<AuthzError> for AppError {
    fn from(e: AuthzError) -> Self {
        AppError::Authz(e)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        match self {
            AppError::NotFound => (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "not found"})),
            )
                .into_response(),
            AppError::Denied => (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"error": "access denied"})),
            )
                .into_response(),
            AppError::Authz(e) => {
                tracing::error!(error = %e, "authorization infrastructure error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "internal error"})),
                )
                    .into_response()
            }
        }
    }
}
