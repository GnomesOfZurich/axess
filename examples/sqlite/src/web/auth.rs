//! Authentication handlers: login page, login POST, TOTP verify, logout.

use crate::web::app::AppState;
use crate::web::{csrf_hidden_input, html_escape};
use axess::AuthSession;
use axess::authn::{
    AuditContext, FactorCredential, FactorKind, FactorOutcome, IdentityLookup, LoginOutcome,
};
use axess::csrf::CsrfToken;
use axum::{
    Extension, Form,
    extract::State,
    response::{Html, IntoResponse, Redirect},
};
use serde::Deserialize;

// ── CSRF rendering helper ────────────────────────────────────────────────────
//
// Templates carry the literal marker `__CSRF_INPUT__` where the hidden
// `_csrf` form field should appear. `render_with_csrf` replaces the
// marker with the actual hidden input carrying the current token
// (HTML-escaped defensively even though the token is a URL-safe base64
// string with no special characters).
//
// The value comes from the `CsrfToken` request extension injected by
// [`axess::middleware::csrf::CsrfLayer`], which the app wires inside
// the session layer in [`crate::web::app::build_router`].

fn render_with_csrf(template: &'static str, csrf: &CsrfToken) -> Html<String> {
    Html(
        template
            .replace("__RECOVERY_FORM__", RECOVERY_FORM)
            .replace("__CSRF_INPUT__", &csrf_hidden_input(csrf)),
    )
}

/// Whether `password` satisfies `rules` (length counted in characters).
fn meets_rules(password: &str, rules: &axess::authn::PasswordRules) -> bool {
    password.chars().count() >= rules.min_length
        && (!rules.require_uppercase || password.chars().any(|c| c.is_uppercase()))
        && (!rules.require_lowercase || password.chars().any(|c| c.is_lowercase()))
        && (!rules.require_digit || password.chars().any(|c| c.is_ascii_digit()))
        && (!rules.require_special || password.chars().any(|c| !c.is_alphanumeric()))
}

/// Tenant that self-service signup creates accounts in.
const SIGNUP_TENANT: &str = "default";

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

pub async fn login_page(Extension(csrf): Extension<CsrfToken>) -> Html<String> {
    render_with_csrf(LOGIN_HTML, &csrf)
}

// ── POST /login ───────────────────────────────────────────────────────────────

pub async fn post_login(
    State(state): State<AppState>,
    session: AuthSession,
    Extension(csrf): Extension<CsrfToken>,
    audit: AuditContext,
    Form(form): Form<LoginForm>,
) -> impl IntoResponse {
    // Derive the request-scoped handle. Both calls below go through it
    // because there is no other way to reach them: `begin_login` and
    // `verify_factor` live on `RequestAuthnService`, not on the shared service.
    // Until 0.7.0 they were on both, and routing only the first through it
    // left the failed-password rows, the ones a brute-force query counts,
    // with no address on them.
    let service = state.service.with_audit_context(audit);

    let tenant = form
        .tenant
        .as_deref()
        .filter(|t| !t.trim().is_empty())
        .unwrap_or("default");

    // begin_login finds the user, checks account status, and starts the factor flow.
    // Since this form submits username + password together, we skip prepare_factor
    // (it returns Ready for passwords) and call verify_factor immediately.
    // For EmailOtp or FIDO2 flows, call prepare_factor first to generate the challenge.
    let outcome = match service
        .begin_login(&form.identifier, tenant, &session)
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
    //
    // The Guest→Authenticated session-id rotation that closes the login-side
    // session-fixation window is done inside `verify_factor` itself (see
    // `AuthSession::regenerate` docs), so no explicit `session.regenerate()`
    // call is required here. Every application-defined privilege boundary
    // (MFA add, tenant switch, impersonation, etc.) still needs its own
    // `regenerate()`: the library only auto-cycles at login-completion and
    // OAuth-callback finish.
    match outcome {
        LoginOutcome::FactorRequired(FactorKind::Password) => {
            let cred = FactorCredential::Password(form.password.into());
            match service.verify_factor(&cred, &session).await {
                Ok(FactorOutcome::Authenticated) => Redirect::to("/dashboard").into_response(),
                Ok(FactorOutcome::FactorRequired(FactorKind::Totp)) => {
                    Redirect::to("/totp").into_response()
                }
                Ok(FactorOutcome::InvalidCredential) => {
                    Html(login_with_error("Invalid username or password.", &csrf)).into_response()
                }
                Ok(FactorOutcome::Locked { .. }) => Html(login_with_error(
                    "Account locked due to too many failed attempts. Try again later.",
                    &csrf,
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
            Html(login_with_error("Invalid username or password.", &csrf)).into_response()
        }
        LoginOutcome::Locked { .. } => Html(login_with_error(
            "Account locked due to too many failed attempts. Try again later.",
            &csrf,
        ))
        .into_response(),
        other => {
            tracing::warn!(outcome = ?std::mem::discriminant(&other), "unexpected login outcome");
            Html(login_with_error(
                "Unexpected error. Please try again.",
                &csrf,
            ))
            .into_response()
        }
    }
}

// ── GET /totp ─────────────────────────────────────────────────────────────────

pub async fn totp_page(Extension(csrf): Extension<CsrfToken>) -> Html<String> {
    render_with_csrf(TOTP_HTML, &csrf)
}

// ── POST /totp ────────────────────────────────────────────────────────────────

pub async fn post_totp(
    State(state): State<AppState>,
    session: AuthSession,
    Extension(csrf): Extension<CsrfToken>,
    audit: AuditContext,
    Form(form): Form<TotpForm>,
) -> impl IntoResponse {
    let cred = FactorCredential::OtpCode(form.code.into());
    second_factor(state, session, csrf, audit, cred).await
}

// ── POST /recovery-code ───────────────────────────────────────────────────────

/// A recovery code in place of the TOTP code. The method's second step is
/// `AnyOf([Totp, RecoveryCode])`, so `verify_factor` takes either: it
/// picks the choice the credential's shape fits, and spends the code it
/// matched so it cannot be used again.
pub async fn post_recovery_code(
    State(state): State<AppState>,
    session: AuthSession,
    Extension(csrf): Extension<CsrfToken>,
    audit: AuditContext,
    Form(form): Form<TotpForm>,
) -> impl IntoResponse {
    let cred = FactorCredential::RecoveryCode(form.code.into());
    second_factor(state, session, csrf, audit, cred).await
}

async fn second_factor(
    state: AppState,
    session: AuthSession,
    csrf: CsrfToken,
    audit: AuditContext,
    cred: FactorCredential,
) -> axum::response::Response {
    // Second-factor failures are the half of a credential-stuffing run that
    // survives a leaked password, so these rows need an address as much as
    // the first-factor ones do.
    let service = state.service.with_audit_context(audit);

    match service.verify_factor(&cred, &session).await {
        Ok(FactorOutcome::Authenticated) => Redirect::to("/dashboard").into_response(),
        Ok(FactorOutcome::InvalidCredential) => {
            Html(totp_with_error("Wrong code; please try again.", &csrf)).into_response()
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

pub async fn logout(
    State(state): State<AppState>,
    session: AuthSession,
    audit: AuditContext,
) -> impl IntoResponse {
    let service = state.service.with_audit_context(audit);
    if let Err(err) = service.logout(&session).await {
        tracing::warn!(error = %err, "logout error");
    }
    Redirect::to("/login")
}

// ── GET /signup ──────────────────────────────────────────────────────────────

pub async fn signup_page(Extension(csrf): Extension<CsrfToken>) -> Html<String> {
    render_with_csrf(SIGNUP_HTML, &csrf)
}

// ── POST /signup ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SignupForm {
    pub username: String,
    pub fullname: String,
    pub email: String,
    pub password: String,
}

pub async fn post_signup(
    State(state): State<AppState>,
    session: AuthSession,
    Extension(csrf): Extension<CsrfToken>,
    audit: AuditContext,
    Form(form): Form<SignupForm>,
) -> impl IntoResponse {
    use axess::authn::{
        AuthnScope, EntityState, FactorConfig, FactorStore, PasswordConfig, PasswordRules,
        SignupOutcome, User, ZeroizedString,
    };

    // The tenant a new account joins is the application's decision (here
    // the single seeded tenant; a multi-tenant app derives it from the
    // host name or an invitation), never a field the visitor fills in:
    // otherwise anyone could create an account inside any tenant by naming it.
    let tenant = SIGNUP_TENANT;

    // The form's `minlength` is a hint to the browser. Enforce the rules on
    // the server, where a script that skips the form is checked too.
    let rules = PasswordRules::default();
    if !meets_rules(&form.password, &rules) {
        return Html(signup_with_error(
            "The password must be at least 12 characters with upper case, lower case and a digit.",
            &csrf,
        ))
        .into_response();
    }

    // Build a Candidate user; not yet activated.
    // Self-service signup: the signup flow itself is the creator, but at
    // this moment the user row has no authenticated session yet. Attribute
    // the `created_by` to the system actor; once the user completes
    // activation their own actions carry their own `updated_by`.
    // The id is a fresh UUID. The tenant id here is a placeholder:
    // `begin_signup` resolves `tenant` by name and stores the user there.
    let user = match User::new(
        uuid::Uuid::new_v4().to_string(),
        axess::authn::TenantId::system().to_string(),
        form.username.as_str(),
        form.fullname.as_str(),
        EntityState::Candidate,
        axess::authn::UserId::system(),
        state.backend.clock().now(),
    ) {
        Ok(u) => u,
        Err(e) => {
            return Html(signup_with_error(&format!("Invalid input: {e}"), &csrf)).into_response();
        }
    };

    // Account creation is an audited event in its own right; registration
    // abuse is spotted by grouping those rows by address.
    let service = state.service.with_audit_context(audit);

    match service.begin_signup(user, tenant, &session).await {
        Ok(SignupOutcome::Started) => {
            // The user is now created (Candidate state). Store their password
            // factor and auth method so they can log in after activation.
            let user_id = match session.pending_user_id().await {
                Some(id) => id,
                None => return error_page("Signup session lost.").into_response(),
            };
            let tenant_id = match session.pending_tenant_id().await {
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
            match service.complete_signup(&session).await {
                Ok(()) => Redirect::to("/dashboard").into_response(),
                Err(e) => {
                    tracing::warn!(error = %e, "complete_signup error");
                    error_page("Signup completion failed.").into_response()
                }
            }
        }
        Ok(SignupOutcome::AlreadyExists) => Html(signup_with_error(
            "A user with that username already exists.",
            &csrf,
        ))
        .into_response(),
        Ok(SignupOutcome::TenantNotActive) => Html(signup_with_error(
            "That tenant does not exist or is not active.",
            &csrf,
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
    Extension(csrf): Extension<CsrfToken>,
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
    let csrf_input = csrf_hidden_input(&csrf);

    Html(format!(
        r#"<!doctype html>
<html><head><title>Setup TOTP</title></head><body>
<h1>Enroll TOTP</h1>
<p>Scan this QR code with your authenticator app (Aegis, Authy, Google Authenticator):</p>
<div style="display:inline-block; padding:8px; background:#fff; border:1px solid #ddd">{qr_svg}</div>
<p>Or enter the secret manually: <pre style="background:#f0f0f0; padding:10px; font-size:1.2em">{secret}</pre></p>
<details><summary>Show otpauth:// URI</summary><p><code>{uri}</code></p></details>
<form method="POST" action="/setup-totp">
  {csrf_input}
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
    Extension(csrf): Extension<CsrfToken>,
    Form(form): Form<SetupTotpForm>,
) -> impl IntoResponse {
    use axess::authn::{
        AuthnScope, FactorConfig, FactorKind, FactorStep, FactorStore, TotpConfig, ZeroizedString,
    };

    if !session.is_authenticated().await {
        return Redirect::to("/login").into_response();
    }

    // Verify the code against the secret before storing.
    // Use defaults: 6 digits, 30s period, ±1 window.
    let verified_step = match axess::verify_totp(
        &form.secret,
        &form.code,
        state.backend.clock().now(),
        axess::TotpVerifyParams::default(),
    ) {
        Some(step) => step, // Valid code; proceed.
        None => {
            let csrf_input = csrf_hidden_input(&csrf);
            return Html(format!(
                r#"<!doctype html><html><head><title>Setup TOTP</title></head><body>
<h1>Enroll TOTP</h1>
<p style="color:red">Invalid code; please try again.</p>
<p>Secret: <pre>{secret}</pre></p>
<form method="POST" action="/setup-totp">
  {csrf_input}
  <input type="hidden" name="secret" value="{secret}">
  <label>6-digit code:<br>
    <input type="text" name="code" inputmode="numeric" required autofocus maxlength="6">
  </label><br><br>
  <button type="submit">Verify & Enable TOTP</button>
</form>
</body></html>"#,
                secret = html_escape(&form.secret),
            ))
            .into_response();
        }
    };

    let user_id = match session.user_id().await {
        Some(id) => id,
        None => return Redirect::to("/login").into_response(),
    };
    let tenant_id = match session.tenant_id().await {
        Some(t) => t,
        None => return Redirect::to("/login").into_response(),
    };

    let scope = AuthnScope::User { tenant_id, user_id };

    // Fail closed: an enrolled factor is never replaced from here (that
    // would need step-up first), and a store error is not "not enrolled".
    match state.backend.load_factor(&scope, FactorKind::Totp).await {
        Ok(None) => {}
        Ok(Some(_)) => return Redirect::to("/dashboard").into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "failed to check existing TOTP enrolment");
            return error_page("Failed to check TOTP configuration.").into_response();
        }
    }

    // Store the TOTP factor config.
    let totp_config = FactorConfig::Totp(TotpConfig {
        secret: ZeroizedString::new(form.secret).into(),
        // The enrolment code is spent: the same code cannot then log in.
        last_step: Some(verified_step),
        ..TotpConfig::default()
    });
    // Seal the secret for this user's row before the store sees it.
    let totp_config = match state.factor_cipher.seal_config(totp_config, &scope) {
        Ok(config) => config,
        Err(e) => {
            tracing::warn!(error = %e, "failed to seal TOTP secret");
            return error_page("Failed to save TOTP configuration.").into_response();
        }
    };
    if let Err(e) = state.backend.save_factor(&scope, totp_config).await {
        tracing::warn!(error = %e, "failed to store TOTP config");
        return error_page("Failed to save TOTP configuration.").into_response();
    }

    // Recovery codes for when the authenticator is lost. Only the hashes
    // are stored; the plaintext is shown once, below, and never again.
    let codes = axess::generate_recovery_codes(&axess::SystemRng, axess::RECOVERY_CODE_COUNT);
    if let Err(e) = state
        .backend
        .save_factor(&scope, FactorConfig::RecoveryCodes(codes.config))
        .await
    {
        tracing::warn!(error = %e, "failed to store recovery codes");
        return error_page("Failed to save recovery codes.").into_response();
    }

    // Upgrade the auth method: password, then TOTP or a recovery code.
    let steps = vec![
        FactorStep::Required(FactorKind::Password),
        FactorStep::AnyOf(vec![FactorKind::Totp, FactorKind::RecoveryCode]),
    ];
    let steps_json = serde_json::to_string(&steps).expect("factor steps always serialize");
    if let Err(e) = sqlx::query(
        "UPDATE auth_methods SET name = 'password+totp', steps_json = ?3
         WHERE user_id = ?1 AND tenant_id = ?2",
    )
    .bind(user_id.to_string())
    .bind(tenant_id.to_string())
    .bind(steps_json)
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

    let code_list: String = codes
        .display
        .iter()
        .map(|code| format!("  <li><code>{}</code></li>\n", &**code))
        .collect();
    Html(format!(
        r#"<!doctype html><html><head><title>TOTP Enrolled</title></head><body>
<h1>TOTP Enrolled Successfully!</h1>
<p>Your next login will require both your password and a TOTP code.</p>
<h2>Your recovery codes</h2>
<p>If you lose your authenticator, sign in with one of these instead of a
TOTP code. Each works once. Store them somewhere safe now: this is the
only time they are shown.</p>
<ul>
{code_list}</ul>
<p><a href="/dashboard">Back to dashboard</a></p>
</body></html>"#
    ))
    .into_response()
}

// ── GET /forgot-password ─────────────────────────────────────────────────────

pub async fn forgot_password_page(Extension(csrf): Extension<CsrfToken>) -> Html<String> {
    render_with_csrf(FORGOT_PASSWORD_HTML, &csrf)
}

// ── POST /forgot-password ───────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ForgotPasswordForm {
    pub identifier: String,
    pub tenant: Option<String>,
}

pub async fn post_forgot_password(
    State(state): State<AppState>,
    audit: AuditContext,
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
        .with_audit_context(audit)
        .begin_password_reset(&form.identifier, tenant, ttl)
        .await
    {
        Ok(Some(token)) => {
            // In production: email the link. This example has no mailer, so a
            // DEBUG BUILD writes it to the `dev_mail` log target. A release
            // build writes nothing: the token is a bearer credential and
            // must not reach an info-level log.
            if cfg!(debug_assertions)
                && let Ok(Some(tenant_row)) = state.backend.find_tenant(tenant).await
                && let Ok(Some(user)) = state
                    .backend
                    .find_user(&form.identifier, &tenant_row.id)
                    .await
            {
                tracing::debug!(
                    target: "dev_mail",
                    "password reset link: /reset-password?user_id={}&tenant_id={}&token={}",
                    user.id,
                    tenant_row.id,
                    token
                );
            }
        }
        Ok(None) => {
            // User not found; show the same response.
            tracing::debug!("password reset requested for an unknown user");
        }
        Err(e) => {
            tracing::warn!(error = %e, "begin_password_reset error");
        }
    }

    Html(
        r#"<!doctype html><html><head><title>Password Reset</title></head><body>
<h1>Check Your Email</h1>
<p>If an account with that identifier exists, a password reset link has been sent.</p>
<p>For this example, a debug build prints the reset link to the <strong>server log</strong> (target <code>dev_mail</code>).</p>
<p><a href="/login">Back to login</a></p>
</body></html>"#,
    )
}

// ── GET /reset-password ─────────────────────────────────────────────────────

#[derive(Deserialize, Default)]
pub struct ResetLinkQuery {
    pub user_id: Option<String>,
    pub tenant_id: Option<String>,
    pub token: Option<String>,
}

pub async fn reset_password_page(
    Extension(csrf): Extension<CsrfToken>,
    axum::extract::Query(link): axum::extract::Query<ResetLinkQuery>,
) -> Html<String> {
    // The emailed link carries the user, tenant and token; the person only
    // chooses the new password. The values are echoed into hidden inputs.
    let field = |v: &Option<String>| html_escape(v.as_deref().unwrap_or(""));
    Html(
        RESET_PASSWORD_HTML
            .replace("__USER_ID__", &field(&link.user_id))
            .replace("__TENANT_ID__", &field(&link.tenant_id))
            .replace("__TOKEN__", &field(&link.token))
            .replace("__CSRF_INPUT__", &csrf_hidden_input(&csrf)),
    )
}

// ── POST /reset-password ────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ResetPasswordForm {
    pub user_id: String,
    pub tenant_id: String,
    pub token: String,
    pub new_password: String,
}

pub async fn post_reset_password(
    State(state): State<AppState>,
    audit: AuditContext,
    Form(form): Form<ResetPasswordForm>,
) -> impl IntoResponse {
    let ids = (
        axess::authn::UserId::try_new(form.user_id.as_str()),
        axess::authn::TenantId::try_new(form.tenant_id.as_str()),
    );
    let (user_id, tenant_id) = match ids {
        (Ok(user_id), Ok(tenant_id)) => (user_id, tenant_id),
        _ => {
            return Html(
                r#"<!doctype html><html><head><title>Password Reset</title></head><body>
<h1>Invalid Request</h1>
<p>Malformed reset link.</p>
</body></html>"#,
            )
            .into_response();
        }
    };

    // Check the tenant's password rules first so a weak password is reported
    // as that, not as an invalid token. The library checks them again, before
    // it spends the token, so the link still works for a second attempt.
    match state.backend.password_rules_for_tenant(&tenant_id).await {
        Ok(rules) if !meets_rules(&form.new_password, &rules) => {
            return Html(format!(
                r#"<!doctype html><html><head><title>Password Reset</title></head><body>
<h1>Password Too Weak</h1>
<p>The password must be at least {} characters with upper case, lower case and a digit. Your link is still valid: go back and choose another.</p>
</body></html>"#,
                rules.min_length
            ))
            .into_response();
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(error = %e, "password_rules_for_tenant error");
            return error_page("Password reset failed.").into_response();
        }
    }

    match state
        .service
        .with_audit_context(audit)
        .complete_password_reset_in_tenant(&user_id, &tenant_id, &form.token, &form.new_password)
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

fn login_with_error(msg: &str, csrf: &CsrfToken) -> String {
    let form = LOGIN_FORM.replace("__CSRF_INPUT__", &csrf_hidden_input(csrf));
    format!(
        r#"<!doctype html><html><head><title>Login</title></head><body>
<h1>Login</h1>
<p style="color:red">{msg}</p>
{form}
</body></html>"#
    )
}

fn totp_with_error(msg: &str, csrf: &CsrfToken) -> String {
    let form =
        format!("{TOTP_FORM}\n{RECOVERY_FORM}").replace("__CSRF_INPUT__", &csrf_hidden_input(csrf));
    format!(
        r#"<!doctype html><html><head><title>TOTP Verification</title></head><body>
<h1>Enter TOTP Code</h1>
<p style="color:red">{msg}</p>
{form}
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
  __CSRF_INPUT__
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
  __CSRF_INPUT__
  <label>6-digit code:<br>
    <input type="text" name="code" inputmode="numeric" pattern="[0-9]*"
           autocomplete="one-time-code" required autofocus maxlength="6">
  </label><br><br>
  <button type="submit">Verify</button>
</form>"#;

const RECOVERY_FORM: &str = r#"
<details>
  <summary>Lost your authenticator? Use a recovery code</summary>
  <form method="POST" action="/recovery-code">
    __CSRF_INPUT__
    <label>Recovery code:<br>
      <input type="text" name="code" autocomplete="off" required
             placeholder="ABCDE-FGHJK" maxlength="16">
    </label><br><br>
    <button type="submit">Use recovery code</button>
  </form>
  <p>Each code works once.</p>
</details>"#;

const LOGIN_HTML: &str = r#"<!doctype html>
<html><head><title>Login</title></head><body>
<h1>Login</h1>
<form method="POST" action="/login">
  __CSRF_INPUT__
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

fn signup_with_error(msg: &str, csrf: &CsrfToken) -> String {
    let form = SIGNUP_FORM.replace("__CSRF_INPUT__", &csrf_hidden_input(csrf));
    format!(
        r#"<!doctype html><html><head><title>Sign Up</title></head><body>
<h1>Create Account</h1>
<p style="color:red">{msg}</p>
{form}
</body></html>"#
    )
}

const SIGNUP_FORM: &str = r#"
<form method="POST" action="/signup">
  __CSRF_INPUT__
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
  __CSRF_INPUT__
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
  __CSRF_INPUT__
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
<p>Open the reset link from your email (in this example, from the server log) and choose a new password.</p>
<form method="POST" action="/reset-password">
  __CSRF_INPUT__
  <input type="hidden" name="user_id" value="__USER_ID__">
  <input type="hidden" name="tenant_id" value="__TENANT_ID__">
  <input type="hidden" name="token" value="__TOKEN__">
  <label>New Password:<br>
    <input type="password" name="new_password" required minlength="12" autofocus>
  </label><br><br>
  <button type="submit">Reset Password</button>
</form>
</body></html>"#;

const TOTP_HTML: &str = r#"<!doctype html>
<html><head><title>TOTP Verification</title></head><body>
<h1>Enter TOTP Code</h1>
<form method="POST" action="/totp">
  __CSRF_INPUT__
  <label>6-digit code:<br>
    <input type="text" name="code" inputmode="numeric" pattern="[0-9]*"
           autocomplete="one-time-code" required autofocus maxlength="6">
  </label><br><br>
  <button type="submit">Verify</button>
</form>
__RECOVERY_FORM__
</body></html>"#;
