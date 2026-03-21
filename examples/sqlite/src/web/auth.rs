//! Authentication handlers: login page, login POST, TOTP verify, logout.

use crate::web::app::AppState;
use axess::{AuthSession, FactorCredential, FactorKind, LoginOutcome, FactorOutcome};
use axum::{
    Form,
    extract::State,
    response::{Html, IntoResponse, Redirect},
};
use serde::Deserialize;

// ── Form types ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct LoginForm {
    pub identifier: String,
    pub password: String,
    /// Optional tenant identifier — defaults to `"default"` if blank.
    pub tenant: Option<String>,
}

#[derive(Deserialize)]
pub struct TotpForm {
    pub code: String,
}

// ── GET /login ────────────────────────────────────────────────────────────────

pub async fn login_page() -> Html<&'static str> {
    Html(LOGIN_HTML)
}

// ── POST /login ───────────────────────────────────────────────────────────────

pub async fn post_login(
    State(state): State<AppState>,
    session: AuthSession,
    Form(form): Form<LoginForm>,
) -> impl IntoResponse {
    let tenant = form
        .tenant
        .as_deref()
        .filter(|t| !t.trim().is_empty())
        .unwrap_or("default");

    // begin_login finds the user, checks account status, and starts the factor flow.
    // It stores intermediate state in the session so verify_factor can continue.
    let outcome = match state.service.begin_login(&form.identifier, tenant, &session).await {
        Ok(o) => o,
        Err(err) => {
            tracing::warn!(error = %err, "begin_login error");
            return error_page("An internal error occurred. Please try again.").into_response();
        }
    };

    // begin_login returns FactorRequired even for the first factor — call verify_factor
    // immediately with the password credential.
    match outcome {
        LoginOutcome::FactorRequired(FactorKind::Password) => {
            let cred = FactorCredential::Password(form.password.into());
            match state.service.verify_factor(&cred, &session).await {
                Ok(FactorOutcome::Authenticated) => Redirect::to("/dashboard").into_response(),
                Ok(FactorOutcome::FactorRequired(FactorKind::Totp)) => {
                    Redirect::to("/totp").into_response()
                }
                Ok(FactorOutcome::InvalidCredential) => {
                    Html(login_with_error("Invalid username or password.")).into_response()
                }
                Ok(FactorOutcome::Locked { .. }) => {
                    Html(login_with_error(
                        "Account locked due to too many failed attempts. Try again later.",
                    ))
                    .into_response()
                }
                Ok(FactorOutcome::FactorRequired(other)) => {
                    tracing::warn!(kind = ?other, "unexpected factor kind after password");
                    error_page("Unsupported factor type.").into_response()
                }
                Err(err) => {
                    tracing::warn!(error = %err, "verify_factor error");
                    error_page("An internal error occurred.").into_response()
                }
            }
        }
        LoginOutcome::InvalidCredentials => {
            Html(login_with_error("Invalid username or password.")).into_response()
        }
        LoginOutcome::Locked { .. } => {
            Html(login_with_error(
                "Account locked due to too many failed attempts. Try again later.",
            ))
            .into_response()
        }
        other => {
            tracing::warn!(outcome = ?std::mem::discriminant(&other), "unexpected login outcome");
            Html(login_with_error("Unexpected error. Please try again.")).into_response()
        }
    }
}

// ── GET /totp ─────────────────────────────────────────────────────────────────

pub async fn totp_page() -> Html<&'static str> {
    Html(TOTP_HTML)
}

// ── POST /totp ────────────────────────────────────────────────────────────────

pub async fn post_totp(
    State(state): State<AppState>,
    session: AuthSession,
    Form(form): Form<TotpForm>,
) -> impl IntoResponse {
    let cred = FactorCredential::OtpCode(form.code.into());
    match state.service.verify_factor(&cred, &session).await {
        Ok(FactorOutcome::Authenticated) => Redirect::to("/dashboard").into_response(),
        Ok(FactorOutcome::InvalidCredential) => {
            Html(totp_with_error("Wrong code — please try again.")).into_response()
        }
        Ok(FactorOutcome::Locked { .. }) => {
            // Session is locked — send back to login to start fresh.
            Redirect::to("/login").into_response()
        }
        Ok(FactorOutcome::FactorRequired(_)) => {
            // Shouldn't happen in this two-factor flow.
            Redirect::to("/dashboard").into_response()
        }
        Err(err) => {
            tracing::warn!(error = %err, "totp verify_factor error");
            error_page("An internal error occurred.").into_response()
        }
    }
}

// ── POST /logout ──────────────────────────────────────────────────────────────

pub async fn logout(
    State(state): State<AppState>,
    session: AuthSession,
) -> impl IntoResponse {
    if let Err(err) = state.service.logout(&session).await {
        tracing::warn!(error = %err, "logout error");
    }
    Redirect::to("/login")
}

// ── HTML helpers ──────────────────────────────────────────────────────────────

fn login_with_error(msg: &str) -> String {
    format!(
        r#"<!doctype html><html><head><title>Login</title></head><body>
<h1>Login</h1>
<p style="color:red">{msg}</p>
{LOGIN_FORM}
</body></html>"#
    )
}

fn totp_with_error(msg: &str) -> String {
    format!(
        r#"<!doctype html><html><head><title>TOTP Verification</title></head><body>
<h1>Enter TOTP Code</h1>
<p style="color:red">{msg}</p>
{TOTP_FORM}
</body></html>"#
    )
}

fn error_page(msg: &str) -> Html<String> {
    Html(format!(
        r#"<!doctype html><html><head><title>Error</title></head><body>
<h1>Error</h1><p>{msg}</p>
<a href="/login">Back to login</a>
</body></html>"#
    ))
}

const LOGIN_FORM: &str = r#"
<form method="POST" action="/login">
  <label>Identifier (username):<br>
    <input type="text" name="identifier" required autofocus>
  </label><br><br>
  <label>Password:<br>
    <input type="password" name="password" required>
  </label><br><br>
  <label>Tenant (leave blank for "default"):<br>
    <input type="text" name="tenant" placeholder="default">
  </label><br><br>
  <button type="submit">Login</button>
</form>"#;

const TOTP_FORM: &str = r#"
<form method="POST" action="/totp">
  <label>6-digit code:<br>
    <input type="text" name="code" inputmode="numeric" pattern="[0-9]*"
           autocomplete="one-time-code" required autofocus maxlength="6">
  </label><br><br>
  <button type="submit">Verify</button>
</form>"#;

const LOGIN_HTML: &str = r#"<!doctype html>
<html><head><title>Login</title></head><body>
<h1>Login</h1>
<form method="POST" action="/login">
  <label>Identifier (username):<br>
    <input type="text" name="identifier" required autofocus>
  </label><br><br>
  <label>Password:<br>
    <input type="password" name="password" required>
  </label><br><br>
  <label>Tenant (leave blank for "default"):<br>
    <input type="text" name="tenant" placeholder="default">
  </label><br><br>
  <button type="submit">Login</button>
</form>
<hr>
<p><strong>Test accounts:</strong></p>
<ul>
  <li><code>alice</code> / <code>hunter2</code> — password only</li>
  <li><code>bob</code> / <code>hunter2</code> — password + TOTP (secret printed in server log)</li>
</ul>
</body></html>"#;

const TOTP_HTML: &str = r#"<!doctype html>
<html><head><title>TOTP Verification</title></head><body>
<h1>Enter TOTP Code</h1>
<form method="POST" action="/totp">
  <label>6-digit code:<br>
    <input type="text" name="code" inputmode="numeric" pattern="[0-9]*"
           autocomplete="one-time-code" required autofocus maxlength="6">
  </label><br><br>
  <button type="submit">Verify</button>
</form>
</body></html>"#;
