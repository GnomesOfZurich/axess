//! Authentication handlers: login page, login POST, TOTP verify, logout.

use crate::web::app::AppState;
use axess::AuthSession;
use axess::authn::{FactorCredential, FactorKind, FactorOutcome, LoginOutcome};
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
    /// Optional tenant identifier; defaults to `"default"` if blank.
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
    // Since this form submits username + password together, we skip prepare_factor
    // (it returns Ready for passwords) and call verify_factor immediately.
    // For EmailOtp or FIDO2 flows, call prepare_factor first to generate the challenge.
    let outcome = match state
        .service
        .begin_login(&form.identifier, tenant, &session, None)
        .await
    {
        Ok(o) => o,
        Err(err) => {
            tracing::warn!(error = %err, "begin_login error");
            return error_page("An internal error occurred. Please try again.").into_response();
        }
    };

    // begin_login returns FactorRequired even for the first factor; call verify_factor
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
                Ok(FactorOutcome::Locked { .. }) => Html(login_with_error(
                    "Account locked due to too many failed attempts. Try again later.",
                ))
                .into_response(),
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
        LoginOutcome::Locked { .. } => Html(login_with_error(
            "Account locked due to too many failed attempts. Try again later.",
        ))
        .into_response(),
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
            Html(totp_with_error("Wrong code; please try again.")).into_response()
        }
        Ok(FactorOutcome::Locked { .. }) => {
            // Session is locked; send back to login to start fresh.
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

pub async fn logout(State(state): State<AppState>, session: AuthSession) -> impl IntoResponse {
    if let Err(err) = state.service.logout(&session).await {
        tracing::warn!(error = %err, "logout error");
    }
    Redirect::to("/login")
}

// ── GET /signup ──────────────────────────────────────────────────────────────

pub async fn signup_page() -> Html<&'static str> {
    Html(SIGNUP_HTML)
}

// ── POST /signup ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SignupForm {
    pub tenant: String,
    pub username: String,
    pub fullname: String,
    pub email: String,
    pub password: String,
}

pub async fn post_signup(
    State(state): State<AppState>,
    session: AuthSession,
    Form(form): Form<SignupForm>,
) -> impl IntoResponse {
    use axess::authn::{
        AuthnScope, EntityState, FactorConfig, FactorStore, PasswordConfig, PasswordRules,
        SignupOutcome, User, ZeroizedString,
    };

    let tenant = if form.tenant.trim().is_empty() {
        "default"
    } else {
        form.tenant.trim()
    };

    // Build a Candidate user; not yet activated.
    // Self-service signup: the signup flow itself is the creator, but at
    // this moment the user row has no authenticated session yet. Attribute
    // the `created_by` to the system actor; once the user completes
    // activation their own actions carry their own `updated_by`.
    let user = match User::new(
        form.username.as_str(),
        "pending",
        form.username.as_str(),
        form.fullname.as_str(),
        EntityState::Candidate,
        axess::authn::UserId::system(),
        state.backend.clock().now(),
    ) {
        Ok(u) => u,
        Err(e) => return Html(signup_with_error(&format!("Invalid input: {e}"))).into_response(),
    };

    match state.service.begin_signup(user, tenant, &session).await {
        Ok(SignupOutcome::Started) => {
            // The user is now created (Candidate state). Store their password
            // factor and auth method so they can log in after activation.
            let user_id = match session.user_id().await {
                Some(id) => id,
                None => return error_page("Signup session lost.").into_response(),
            };
            let tenant_id = match session.tenant_id().await {
                Some(t) => t,
                None => return error_page("Signup session lost tenant.").into_response(),
            };

            // Hash password and store as a factor.
            let hash = axess::generate_password_hash(&form.password);
            let scope = AuthnScope::User { tenant_id, user_id };
            let pw_config = FactorConfig::Password(PasswordConfig {
                hash: ZeroizedString::new(hash),
                rules: PasswordRules::default(),
            });
            if let Err(e) = state.backend.save_factor(&scope, pw_config).await {
                tracing::warn!(error = %e, "failed to store password factor");
                return error_page("Signup failed; could not save credentials.").into_response();
            }

            // Store auth method (password-only for now; user can enroll TOTP later).
            let method_json = serde_json::json!([{"Required": "Password"}]).to_string();
            if let Err(e) = sqlx::query(
                "INSERT INTO auth_methods (id, name, steps_json, user_id, tenant_id, enabled)
                 VALUES (?1, 'password', ?2, ?3, ?4, 1)
                 ON CONFLICT(id) DO NOTHING",
            )
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(&method_json)
            .bind(user_id.to_string())
            .bind(tenant_id.to_string())
            .execute(state.backend.pool())
            .await
            {
                tracing::warn!(error = %e, "failed to store auth method");
                return error_page("Signup failed; could not save auth method.").into_response();
            }

            // Auto-complete signup (skip email verification for this example).
            match state.service.complete_signup(&session).await {
                Ok(()) => Redirect::to("/dashboard").into_response(),
                Err(e) => {
                    tracing::warn!(error = %e, "complete_signup error");
                    error_page("Signup completion failed.").into_response()
                }
            }
        }
        Ok(SignupOutcome::AlreadyExists) => Html(signup_with_error(
            "A user with that username already exists.",
        ))
        .into_response(),
        Ok(SignupOutcome::TenantNotActive) => Html(signup_with_error(
            "That tenant does not exist or is not active.",
        ))
        .into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "begin_signup error");
            error_page("Signup failed.").into_response()
        }
    }
}

// ── GET /setup-totp ──────────────────────────────────────────────────────────

pub async fn setup_totp_page(
    State(state): State<AppState>,
    session: AuthSession,
) -> impl IntoResponse {
    use axess::authn::{AuthnScope, FactorKind, FactorStore};

    if !session.is_authenticated().await {
        return Redirect::to("/login").into_response();
    }

    // Refuse to issue a fresh QR if the user already has TOTP enrolled;
    // the example does not implement a replace/revoke flow, so the only
    // honest answer is to bounce back to the dashboard.
    if let (Some(user_id), Some(tenant_id)) = (session.user_id().await, session.tenant_id().await) {
        let scope = AuthnScope::User { tenant_id, user_id };
        if matches!(
            state.backend.load_factor(&scope, FactorKind::Totp).await,
            Ok(Some(_))
        ) {
            return Redirect::to("/dashboard").into_response();
        }
    }

    let username = session
        .user_id()
        .await
        .map(|id| id.to_string())
        .unwrap_or_else(|| "user".to_string());

    // Generate a new TOTP secret.
    let secret = axess::generate_totp_secret(&axess::SystemRng);
    let uri = axess::build_totp_uri(&username, "axess-example", &secret, 6, 30);
    let qr_svg = totp_qr_svg(&uri);

    Html(format!(
        r#"<!doctype html>
<html><head><title>Setup TOTP</title></head><body>
<h1>Enroll TOTP</h1>
<p>Scan this QR code with your authenticator app (Aegis, Authy, Google Authenticator):</p>
<div style="display:inline-block; padding:8px; background:#fff; border:1px solid #ddd">{qr_svg}</div>
<p>Or enter the secret manually: <pre style="background:#f0f0f0; padding:10px; font-size:1.2em">{secret}</pre></p>
<details><summary>Show otpauth:// URI</summary><p><code>{uri}</code></p></details>
<form method="POST" action="/setup-totp">
  <input type="hidden" name="secret" value="{secret}">
  <label>Enter the 6-digit code to verify enrollment:<br>
    <input type="text" name="code" inputmode="numeric" pattern="[0-9]*"
           autocomplete="one-time-code" required autofocus maxlength="6">
  </label><br><br>
  <button type="submit">Verify & Enable TOTP</button>
</form>
<hr>
<p><a href="/dashboard">Cancel</a></p>
</body></html>"#
    ))
    .into_response()
}

/// Render the `otpauth://` URI as an inline SVG QR code.
///
/// Secret never leaves the server (no external QR API). Returns an
/// empty string on encode failure so the page still works with the
/// secret + URI fallbacks instead of 500-ing.
fn totp_qr_svg(uri: &str) -> String {
    use qrcode::render::svg;
    qrcode::QrCode::new(uri.as_bytes())
        .map(|code| {
            code.render::<svg::Color<'_>>()
                .min_dimensions(220, 220)
                .quiet_zone(true)
                .build()
        })
        .unwrap_or_default()
}

// ── POST /setup-totp ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SetupTotpForm {
    pub secret: String,
    pub code: String,
}

pub async fn post_setup_totp(
    State(state): State<AppState>,
    session: AuthSession,
    Form(form): Form<SetupTotpForm>,
) -> impl IntoResponse {
    use axess::authn::{AuthnScope, FactorConfig, FactorStore, TotpConfig, ZeroizedString};

    if !session.is_authenticated().await {
        return Redirect::to("/login").into_response();
    }

    // Verify the code against the secret before storing.
    // Use defaults: 6 digits, 30s period, ±1 window.
    match axess::verify_totp(
        &form.secret,
        &form.code,
        state.backend.clock().now(),
        axess::TotpVerifyParams::default(),
    ) {
        Some(_step) => {} // Valid code; proceed.
        None => {
            return Html(format!(
                r#"<!doctype html><html><head><title>Setup TOTP</title></head><body>
<h1>Enroll TOTP</h1>
<p style="color:red">Invalid code; please try again.</p>
<p>Secret: <pre>{}</pre></p>
<form method="POST" action="/setup-totp">
  <input type="hidden" name="secret" value="{}">
  <label>6-digit code:<br>
    <input type="text" name="code" inputmode="numeric" required autofocus maxlength="6">
  </label><br><br>
  <button type="submit">Verify & Enable TOTP</button>
</form>
</body></html>"#,
                form.secret, form.secret
            ))
            .into_response();
        }
    }

    let user_id = match session.user_id().await {
        Some(id) => id,
        None => return Redirect::to("/login").into_response(),
    };
    let tenant_id = match session.tenant_id().await {
        Some(t) => t,
        None => return Redirect::to("/login").into_response(),
    };

    let scope = AuthnScope::User { tenant_id, user_id };

    // Store the TOTP factor config.
    let totp_config = FactorConfig::Totp(TotpConfig {
        secret: ZeroizedString::new(form.secret),
        ..TotpConfig::default()
    });
    if let Err(e) = state.backend.save_factor(&scope, totp_config).await {
        tracing::warn!(error = %e, "failed to store TOTP config");
        return error_page("Failed to save TOTP configuration.").into_response();
    }

    // Upgrade the auth method to password+totp.
    if let Err(e) = sqlx::query(
        "UPDATE auth_methods SET name = 'password+totp', steps_json = '[{\"Required\":\"Password\"},{\"Required\":\"Totp\"}]'
         WHERE user_id = ?1 AND tenant_id = ?2",
    )
    .bind(user_id.to_string())
    .bind(tenant_id.to_string())
    .execute(state.backend.pool())
    .await
    {
        tracing::warn!(error = %e, "failed to upgrade auth method");
        return error_page("Failed to update auth method.").into_response();
    }

    // Enabling MFA is a privilege boundary: it raises Alice's AAL and
    // changes what `auth_methods` will demand from her next login. Rotate
    // the session id so any pre-existing cookie (including an
    // attacker-fixated one) cannot ride the new binding. The library does
    // not auto-cycle here because the boundary is app-defined; see
    // `AuthSession::regenerate` docs for the full list of moments where
    // this call belongs.
    session.regenerate().await;

    tracing::info!(user = %user_id, "TOTP enrolled successfully");

    Html(
        r#"<!doctype html><html><head><title>TOTP Enrolled</title></head><body>
<h1>TOTP Enrolled Successfully!</h1>
<p>Your next login will require both your password and a TOTP code.</p>
<p><a href="/dashboard">Back to dashboard</a></p>
</body></html>"#,
    )
    .into_response()
}

// ── GET /forgot-password ─────────────────────────────────────────────────────

pub async fn forgot_password_page() -> Html<&'static str> {
    Html(FORGOT_PASSWORD_HTML)
}

// ── POST /forgot-password ───────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ForgotPasswordForm {
    pub identifier: String,
    pub tenant: Option<String>,
}

pub async fn post_forgot_password(
    State(state): State<AppState>,
    Form(form): Form<ForgotPasswordForm>,
) -> impl IntoResponse {
    let tenant = form
        .tenant
        .as_deref()
        .filter(|t| !t.trim().is_empty())
        .unwrap_or("default");

    // Always show the same response regardless of whether the user exists
    // (prevents user enumeration).
    let ttl = std::time::Duration::from_secs(15 * 60); // 15 minutes
    match state
        .service
        .begin_password_reset(&form.identifier, tenant, ttl)
        .await
    {
        Ok(Some(token)) => {
            // In production: send this token via email.
            // For this example: log it to stdout.
            tracing::info!(
                identifier = %form.identifier,
                token = %token,
                "PASSWORD RESET TOKEN (would be emailed in production)"
            );
        }
        Ok(None) => {
            // User not found; log but show the same response.
            tracing::debug!(identifier = %form.identifier, "password reset requested for unknown user");
        }
        Err(e) => {
            tracing::warn!(error = %e, "begin_password_reset error");
        }
    }

    Html(
        r#"<!doctype html><html><head><title>Password Reset</title></head><body>
<h1>Check Your Email</h1>
<p>If an account with that identifier exists, a password reset link has been sent.</p>
<p>For this example, check the <strong>server log</strong> for the reset token.</p>
<p><a href="/reset-password">Enter reset token</a> | <a href="/login">Back to login</a></p>
</body></html>"#,
    )
}

// ── GET /reset-password ─────────────────────────────────────────────────────

pub async fn reset_password_page() -> Html<&'static str> {
    Html(RESET_PASSWORD_HTML)
}

// ── POST /reset-password ────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ResetPasswordForm {
    pub user_id: String,
    pub token: String,
    pub new_password: String,
}

pub async fn post_reset_password(
    State(state): State<AppState>,
    Form(form): Form<ResetPasswordForm>,
) -> impl IntoResponse {
    let user_id = match axess::authn::UserId::try_new(form.user_id.as_str()) {
        Ok(id) => id,
        Err(_) => {
            return Html(
                r#"<!doctype html><html><head><title>Password Reset</title></head><body>
<h1>Invalid Request</h1>
<p>Malformed user id.</p>
</body></html>"#,
            )
            .into_response();
        }
    };

    match state
        .service
        .complete_password_reset(&user_id, &form.token, &form.new_password)
        .await
    {
        Ok(true) => Html(
            r#"<!doctype html><html><head><title>Password Reset</title></head><body>
<h1>Password Changed</h1>
<p>Your password has been updated. <a href="/login">Log in</a> with your new password.</p>
</body></html>"#,
        )
        .into_response(),
        Ok(false) => Html(
            r#"<!doctype html><html><head><title>Password Reset</title></head><body>
<h1>Invalid or Expired Token</h1>
<p>The reset token is invalid, expired, or has already been used.</p>
<p><a href="/forgot-password">Request a new token</a></p>
</body></html>"#,
        )
        .into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "complete_password_reset error");
            error_page("Password reset failed.").into_response()
        }
    }
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
  <li><code>alice</code> / <code>Gnomes2+</code>; password only</li>
  <li><code>bob</code> / <code>Gnomes2+</code>; password + TOTP (secret printed in server log)</li>
</ul>
<p><em>Or <a href="/signup">sign up</a> to create your own account, then enroll TOTP from the dashboard.</em></p>
<p><a href="/forgot-password">Forgot your password?</a></p>
</body></html>"#;

fn signup_with_error(msg: &str) -> String {
    format!(
        r#"<!doctype html><html><head><title>Sign Up</title></head><body>
<h1>Create Account</h1>
<p style="color:red">{msg}</p>
{SIGNUP_FORM}
</body></html>"#
    )
}

const SIGNUP_FORM: &str = r#"
<form method="POST" action="/signup">
  <label>Tenant (leave blank for "default"):<br>
    <input type="text" name="tenant" placeholder="default">
  </label><br><br>
  <label>Username:<br>
    <input type="text" name="username" required>
  </label><br><br>
  <label>Full name:<br>
    <input type="text" name="fullname" required>
  </label><br><br>
  <label>Email:<br>
    <input type="email" name="email" required>
  </label><br><br>
  <label>Password:<br>
    <input type="password" name="password" required minlength="12">
  </label><br><br>
  <button type="submit">Create Account</button>
</form>"#;

const SIGNUP_HTML: &str = r#"<!doctype html>
<html><head><title>Sign Up</title></head><body>
<h1>Create Account</h1>
<form method="POST" action="/signup">
  <label>Tenant (leave blank for "default"):<br>
    <input type="text" name="tenant" placeholder="default">
  </label><br><br>
  <label>Username:<br>
    <input type="text" name="username" required autofocus>
  </label><br><br>
  <label>Full name:<br>
    <input type="text" name="fullname" required>
  </label><br><br>
  <label>Email:<br>
    <input type="email" name="email" required>
  </label><br><br>
  <label>Password:<br>
    <input type="password" name="password" required minlength="12">
  </label><br><br>
  <button type="submit">Create Account</button>
</form>
<hr>
<p>Already have an account? <a href="/login">Log in</a></p>
</body></html>"#;

const FORGOT_PASSWORD_HTML: &str = r#"<!doctype html>
<html><head><title>Forgot Password</title></head><body>
<h1>Reset Your Password</h1>
<form method="POST" action="/forgot-password">
  <label>Username:<br>
    <input type="text" name="identifier" required autofocus>
  </label><br><br>
  <label>Tenant (leave blank for "default"):<br>
    <input type="text" name="tenant" placeholder="default">
  </label><br><br>
  <button type="submit">Send Reset Token</button>
</form>
<hr>
<p><a href="/login">Back to login</a></p>
</body></html>"#;

const RESET_PASSWORD_HTML: &str = r#"<!doctype html>
<html><head><title>Reset Password</title></head><body>
<h1>Set New Password</h1>
<p>Enter the reset token from the server log (or email in production), your user ID, and a new password.</p>
<form method="POST" action="/reset-password">
  <label>User ID (username):<br>
    <input type="text" name="user_id" required autofocus>
  </label><br><br>
  <label>Reset Token:<br>
    <input type="text" name="token" required>
  </label><br><br>
  <label>New Password:<br>
    <input type="password" name="new_password" required minlength="12">
  </label><br><br>
  <button type="submit">Reset Password</button>
</form>
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
