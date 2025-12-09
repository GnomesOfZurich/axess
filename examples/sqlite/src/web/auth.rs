// use std::sync::Arc;

use crate::models::{authn::Session, backend::OurBackend};
use askama::Template;
use axess::{
    Action, AuthnAdminBackend, AuthnBackend, FactorConfigBuilder, FactorInstance, Kind,
    TOTP_LENGTH, TOTP_PERIOD,
    form::{
        EmailChangeForm, FactorResetForm, PasswordChangeForm, PasswordSetupForm,
        PasswordVerifyForm, TotpChangeForm, TotpSetupForm, TotpVerifyForm,
    },
    generate_password_hash, generate_totp_secret,
};
use axum::{
    Form, Router,
    extract::Query,
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use axum_messages::{Message, Messages};
use serde::Deserialize;
use uuid::Uuid;

const DEFAULT_TENANT_NAME: &str = "Default Tenant";

fn redirect_after_auth(next: Option<String>, fallback: &str) -> Response {
    if let Some(url) = next {
        Redirect::to(&url).into_response()
    } else {
        Redirect::to(fallback).into_response()
    }
}

pub fn router() -> Router {
    Router::new()
        // Web-facing GET endpoints (serve forms/pages)
        .route("/login", get(get::login))
        .route("/logout", get(get::logout))
        .route("/signup", get(get::signup))
        .route("/password/setup", get(get::password_setup))
        .route("/password/change", get(get::password_change))
        .route("/email/verify", get(get::email_verify))
        .route("/email/change", get(get::email_change))
        .route("/totp/setup", get(get::totp_setup))
        .route("/totp/verify", get(get::totp_verify))
        .route("/totp/change", get(get::totp_change))
        .route("/factor/reset", get(get::factor_reset))
        // API POST endpoints (handle submissions)
        .nest(
            "/api/v1",
            Router::new()
                .route("/login", post(post::login))
                .route("/signup", post(post::signup))
                .route("/password/setup", post(post::password_setup))
                .route("/password/change", post(post::password_change))
                .route("/email/verify", post(post::email_verify))
                .route("/email/change", post(post::email_change))
                .route("/totp/setup", post(post::totp_setup))
                .route("/totp/verify", post(post::totp_verify))
                .route("/totp/change", post(post::totp_change))
                .route("/factor/reset", post(post::factor_reset)),
        )
}

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    messages: Vec<Message>,
    next: Option<String>,
}

#[derive(Template)]
#[template(path = "signup.html")]
struct SignupTemplate;

#[derive(Template)]
#[template(path = "totp_setup.html")]
struct TotpSetupTemplate {
    messages: Vec<String>,
    secret: Option<String>,
    provisioning_uri: Option<String>,
}

#[derive(Template)]
#[template(path = "totp_verify.html")]
struct TotpVerifyTemplate;

// This allows us to extract the "next" field from the query string. We use this
// to redirect after log in.
#[derive(Debug, Deserialize)]
pub struct NextUrl {
    next: Option<String>,
}

pub mod post {

    use crate::models::entities::OurUser;

    use super::*;
    use axess::{
        AuthnScope, EnablementState, FactorStateChange, Kind, Operation, SessionState, TOTP_PERIOD,
        form::EmailVerifyForm,
    };
    use axum::Extension;

    #[derive(Deserialize)]
    pub struct SignupRequest {
        pub tenant: String,
        pub username: String,
        pub fullname: String,
        pub email: String,
        pub password: String,
    }

    #[derive(Deserialize)]
    pub struct TotpSetupRequest {
        pub secret: String,
    }

    #[derive(Deserialize)]
    pub struct TotpVerifyRequest {
        pub otp_code: String,
    }

    #[axum::debug_handler]
    pub async fn login(
        Extension(mut session): Extension<Session>,
        messages: Messages,
        Form(mut form): Form<PasswordVerifyForm>,
    ) -> impl IntoResponse {
        if form
            .tenant
            .as_ref()
            .map(|tenant| tenant.trim().is_empty())
            .unwrap_or(true)
        {
            form.tenant = Some(DEFAULT_TENANT_NAME.to_string());
        }

        match session.authenticate_from_form(Form(form)).await {
            Ok(response) => response.into_response(),
            Err(err) => {
                messages.error(format!("Login failed: {}", err));
                Redirect::to("/login").into_response()
            }
        }
    }

    /// Handle signup requests
    #[axum::debug_handler]
    pub async fn signup(
        Extension(mut session): Extension<Session>,
        messages: Messages,
        Form(mut payload): Form<SignupRequest>,
    ) -> impl IntoResponse {
        let tenant_name = if payload.tenant.trim().is_empty() {
            DEFAULT_TENANT_NAME.to_string()
        } else {
            payload.tenant.trim().to_string()
        };
        payload.tenant = tenant_name.clone();

        let backend = session.backend.clone();
        let tenant = match backend.get_tenant_by_name(&tenant_name).await {
            Ok(t) => t,
            Err(err) => {
                messages.error(format!("Unknown tenant: {err}"));
                return Redirect::to("/signup").into_response();
            }
        };

        let user_id = Uuid::new_v4();
        let user = OurUser::new(
            user_id,
            tenant.id,
            payload.username.clone(),
            payload.fullname.clone(),
            payload.email.clone(),
            user_id,
        );

        if let Err(err) = backend.upsert_user(user.clone(), user.id).await {
            messages.error(format!("Failed to create user: {err}"));
            return Redirect::to("/signup").into_response();
        }

        // Create factors
        let password_factor = FactorInstance::new(
            Uuid::new_v4(),
            Kind::Password,
            "password-login",
            "Password factor",
            user_id,
        );
        let email_factor = FactorInstance::new(
            Uuid::new_v4(),
            Kind::EmailOtp,
            "email-verification",
            "Email verification factor",
            user_id,
        );
        let totp_factor = FactorInstance::new(
            Uuid::new_v4(),
            Kind::Totp,
            "totp-setup",
            "TOTP setup factor",
            user_id,
        );

        // Persist factors
        for factor in [&password_factor, &email_factor, &totp_factor] {
            if let Err(err) = backend.upsert_auth_factor(factor.clone(), user_id).await {
                messages.error(format!("Failed to persist factor: {err}"));
                return Redirect::to("/signup").into_response();
            }
        }

        // Activate password factor
        let password_state = FactorStateChange::new(password_factor.id)
            .with_scope(AuthnScope::User(user.tenant_id, user_id))
            .with_state(EnablementState::Active)
            .with_config(
                FactorConfigBuilder::password(generate_password_hash(&payload.password)).into(),
            );
        if let Err(err) = backend.upsert_factor_state(password_state, user_id).await {
            messages.error(format!("Failed to activate password factor: {err}"));
            return Redirect::to("/signup").into_response();
        }

        // Stage TOTP factor as pending
        let totp_secret = generate_totp_secret();
        let totp_state = FactorStateChange::new(totp_factor.id)
            .with_scope(AuthnScope::User(user.tenant_id, user_id))
            .with_state(EnablementState::Pending)
            .with_config(
                FactorConfigBuilder::totp(totp_secret.clone())
                    .with_length(TOTP_LENGTH)
                    .with_period(TOTP_PERIOD)
                    .with_windows(1, 0)
                    .into(),
            );
        if let Err(err) = backend.upsert_factor_state(totp_state, user_id).await {
            messages.error(format!("Failed to stage TOTP factor: {err}"));
            return Redirect::to("/signup").into_response();
        }

        // Generate email verification code (for demo, just a UUID)
        let email_code = Uuid::new_v4().to_string();

        // Build workflow steps using axess-core's WorkflowState
        use axess::{WorkflowState, WorkflowStep, WorkflowStepKind};
        let workflow = WorkflowState {
            steps: vec![
                WorkflowStep {
                    kind: WorkflowStepKind::FactorAction(Operation::new(
                        Kind::EmailOtp,
                        Action::Verify,
                    )), // Email verification
                    description: format!("Verify your email (code: {})", email_code),
                    completed: false,
                    completed_at: None,
                    metadata: Some({
                        let mut m = std::collections::HashMap::new();
                        m.insert(
                            "email_code".to_string(),
                            serde_json::Value::String(email_code.clone()),
                        );
                        m
                    }),
                },
                WorkflowStep {
                    kind: WorkflowStepKind::FactorAction(Operation::new(Kind::Totp, Action::Setup)), // TOTP setup
                    description: "Setup TOTP".to_string(),
                    completed: false,
                    completed_at: None,
                    metadata: None,
                },
            ],
            current_step: 0,
            started_at: chrono::Utc::now(),
            last_updated: chrono::Utc::now(),
            blocking: true,
        };

        session.state = SessionState::<OurBackend>::PendingWorkflow(workflow);
        session.save_session_data().await.ok();

        messages.success(format!(
            "Account created! Please verify your email using this code: {}",
            email_code
        ));
        Redirect::to("/email/verify").into_response()
    }

    /// Handle password setup requests
    #[axum::debug_handler]
    pub async fn password_setup(
        Extension(mut session): Extension<Session>,
        messages: Messages,
        Form(form): Form<PasswordSetupForm>,
    ) -> impl IntoResponse {
        match session.handle_factor_setup(&form).await {
            Ok(_) => {
                messages.success("Password setup complete!");
                Redirect::to("/login").into_response()
            }
            Err(err) => {
                messages.error(format!("Password setup failed: {}", err));
                Redirect::to("/password/setup").into_response()
            }
        }
    }

    /// Handle password change requests
    #[axum::debug_handler]
    pub async fn password_change(
        Extension(mut session): Extension<Session>,
        messages: Messages,
        Form(form): Form<PasswordChangeForm>,
    ) -> impl IntoResponse {
        match session.handle_factor_setup(&form).await {
            Ok(_) => {
                messages.success("Password changed successfully!");
                Redirect::to("/dashboard").into_response()
            }
            Err(err) => {
                messages.error(format!("Password change failed: {}", err));
                Redirect::to("/password/change").into_response()
            }
        }
    }

    #[axum::debug_handler]
    pub async fn totp_setup(
        Extension(mut session): Extension<Session>,
        messages: Messages,
        Form(form): Form<TotpSetupForm>,
    ) -> impl IntoResponse {
        if let SessionState::<OurBackend>::PendingWorkflow(ref mut workflow) = session.state {
            match workflow.advance() {
                Ok(_) => {
                    // After advancing, check if workflow is complete and transition to authenticated
                    if workflow.is_complete() {
                        session.state = SessionState::<OurBackend>::Authenticated;
                        session.save_session_data().await.ok();
                        messages.success("TOTP setup complete! You are now authenticated.");
                        redirect_after_auth(form.next.clone(), "/dashboard")
                    } else {
                        session.save_session_data().await.ok();
                        messages.success("TOTP setup step complete.");
                        redirect_after_auth(form.next.clone(), "/dashboard")
                    }
                }
                Err(err) => {
                    messages.error(format!("TOTP setup failed: {}", err));
                    Redirect::to("/totp/setup").into_response()
                }
            }
        } else {
            messages.error("No pending workflow for TOTP setup. This is unexpected after signup.");
            Redirect::to("/login").into_response()
        }
    }

    #[axum::debug_handler]
    pub async fn totp_change(
        Extension(mut session): Extension<Session>,
        messages: Messages,
        Form(form): Form<TotpChangeForm>,
    ) -> impl IntoResponse {
        match session.handle_factor_setup(&form).await {
            Ok(_) => {
                messages.success("TOTP changed successfully!");
                Redirect::to("/dashboard").into_response()
            }
            Err(err) => {
                messages.error(format!("TOTP change failed: {}", err));
                Redirect::to("/factors/totp/change").into_response()
            }
        }
    }

    /// Handle TOTP verification requests
    #[axum::debug_handler]
    pub async fn totp_verify(
        Extension(mut session): Extension<Session>,
        messages: Messages,
        Form(form): Form<TotpVerifyForm>,
    ) -> impl IntoResponse {
        match session.authenticate_from_form(Form(form)).await {
            Ok(response) => response,
            Err(err) => {
                messages.error(format!("TOTP verification failed: {}", err));
                Redirect::to("/factors/totp/verify").into_response()
            }
        }
    }

    /// Handle email verification requests
    #[axum::debug_handler]
    pub async fn email_verify(
        Extension(mut session): Extension<Session>,
        messages: Messages,
        Form(form): Form<EmailVerifyForm>,
    ) -> impl IntoResponse {
        if let SessionState::<OurBackend>::PendingWorkflow(ref mut workflow) = session.state {
            match workflow.advance() {
                Ok(_) => {
                    // Drop mutable borrow of workflow before using session again
                    let workflow_complete = workflow.is_complete();
                    // End the mutable borrow of workflow here by limiting its scope

                    session.save_session_data().await.ok();
                    if workflow_complete {
                        session.state = SessionState::<OurBackend>::Authenticated;
                        session.save_session_data().await.ok();
                        messages.success("Signup complete! You are now authenticated.");
                        redirect_after_auth(form.next.clone(), "/dashboard")
                    } else {
                        messages.success("Email verified! Please setup TOTP.");
                        Redirect::to("/totp/setup").into_response()
                    }
                }
                Err(err) => {
                    messages.error(format!("Email verification failed: {}", err));
                    Redirect::to("/email/verify").into_response()
                }
            }
        } else {
            messages.error("No pending workflow for email verification.");
            Redirect::to("/login").into_response()
        }
    }

    /// Handle email change requests
    #[axum::debug_handler]
    pub async fn email_change(
        Extension(mut session): Extension<Session>,
        messages: Messages,
        Form(form): Form<EmailChangeForm>,
    ) -> impl IntoResponse {
        match session.handle_factor_setup(&form).await {
            Ok(_) => {
                messages.success("Email changed successfully!");
                Redirect::to("/dashboard").into_response()
            }
            Err(err) => {
                messages.error(format!("Email change failed: {}", err));
                Redirect::to("/email/change").into_response()
            }
        }
    }

    /// Handle factor reset requests
    #[axum::debug_handler]
    pub async fn factor_reset(
        Extension(mut session): Extension<Session>,
        messages: Messages,
        Form(form): Form<FactorResetForm>,
    ) -> impl IntoResponse {
        match session.handle_factor_setup(&form).await {
            Ok(_) => {
                messages.success("Factor reset request submitted!");
                Redirect::to("/dashboard").into_response()
            }
            Err(err) => {
                messages.error(format!("Factor reset failed: {}", err));
                Redirect::to("/factor/reset").into_response()
            }
        }
    }
}

pub mod get {
    use super::*;
    use axess::{AuthnScope, EnablementState, build_totp_uri};
    use axum::Extension;

    #[axum::debug_handler]
    pub async fn login(
        messages: Messages,
        Query(NextUrl { next }): Query<NextUrl>,
    ) -> Html<String> {
        Html(
            LoginTemplate {
                messages: messages.into_iter().collect(),
                next,
            }
            .to_string(),
        )
    }

    #[axum::debug_handler]
    pub async fn logout(Extension(mut session): Extension<Session>) -> impl IntoResponse {
        match session.logout().await {
            Ok(_) => Redirect::to("/login").into_response(),
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }

    #[axum::debug_handler]
    pub async fn totp_setup(
        Extension(session): Extension<Session>,
        messages: Messages,
    ) -> impl IntoResponse {
        let user = session.get_user();
        let backend = session.backend.clone();
        let tenant_name = match backend.get_tenant(&user.tenant_id).await {
            Ok(tenant) => tenant.name,
            Err(err) => {
                messages
                    .clone()
                    .info(format!("Using default tenant because lookup failed: {err}"));
                DEFAULT_TENANT_NAME.to_string()
            }
        };

        let scope = AuthnScope::User(user.tenant_id, user.id);
        let mut secret: Option<String> = None;
        let mut provisioning_uri: Option<String> = None;

        match backend
            .get_scoped_auth_factors(scope.clone(), vec![EnablementState::Pending])
            .await
        {
            Ok(factors) => {
                if let Some(factor) = factors
                    .into_iter()
                    .find(|factor| matches!(factor.kind, Kind::Totp))
                {
                    match backend.get_factor_states(&factor.id, scope.clone()).await {
                        Ok(states) => {
                            if let Some(state) = states
                                .into_iter()
                                .find(|state| state.state == EnablementState::Pending)
                            {
                                if let Some(value) =
                                    state.config.get("secret").and_then(|v| v.as_str())
                                {
                                    let digits = state
                                        .config
                                        .get("length")
                                        .and_then(|v| v.as_u64())
                                        .map(|v| v as usize)
                                        .unwrap_or(TOTP_LENGTH);
                                    let period = state
                                        .config
                                        .get("period")
                                        .and_then(|v| v.as_u64())
                                        .unwrap_or(TOTP_PERIOD);

                                    secret = Some(value.to_string());
                                    provisioning_uri = Some(build_totp_uri(
                                        &user.username,
                                        &tenant_name,
                                        value,
                                        digits,
                                        period,
                                    ));
                                } else {
                                    messages.clone().error(
                                        "Pending TOTP factor missing shared secret.".to_string(),
                                    );
                                }
                            } else {
                                messages
                                    .clone()
                                    .info("No pending TOTP factor to configure.".to_string());
                            }
                        }
                        Err(err) => {
                            messages
                                .clone()
                                .error(format!("Failed to load TOTP factor state: {err}"));
                        }
                    }
                } else {
                    messages
                        .clone()
                        .info("No pending TOTP factors for this user.".to_string());
                }
            }
            Err(err) => {
                messages
                    .clone()
                    .error(format!("Failed to load TOTP factors: {err}"));
            }
        }

        let message_list: Vec<String> = messages.clone().map(|m| m.to_string()).collect();

        Html(
            TotpSetupTemplate {
                messages: message_list,
                secret,
                provisioning_uri,
            }
            .render()
            .unwrap_or_default(),
        )
        .into_response()
    }

    pub async fn signup() -> impl IntoResponse {
        Html(SignupTemplate.render().unwrap_or_default())
    }

    pub async fn totp_verify() -> impl IntoResponse {
        Html(TotpVerifyTemplate.render().unwrap_or_default())
    }

    #[axum::debug_handler]
    pub async fn password_setup(messages: Messages) -> impl IntoResponse {
        Html(
            PasswordSetupTemplate {
                messages: messages.into_iter().map(|m| m.to_string()).collect(),
            }
            .render()
            .unwrap_or_default(),
        )
    }

    #[axum::debug_handler]
    pub async fn password_change(messages: Messages) -> impl IntoResponse {
        Html(
            PasswordChangeTemplate {
                messages: messages.into_iter().map(|m| m.to_string()).collect(),
            }
            .render()
            .unwrap_or_default(),
        )
    }

    #[axum::debug_handler]
    pub async fn email_verify(messages: Messages) -> impl IntoResponse {
        Html(
            EmailVerifyTemplate {
                messages: messages.into_iter().map(|m| m.to_string()).collect(),
            }
            .render()
            .unwrap_or_default(),
        )
    }

    #[axum::debug_handler]
    pub async fn email_change(messages: Messages) -> impl IntoResponse {
        Html(
            EmailChangeTemplate {
                messages: messages.into_iter().map(|m| m.to_string()).collect(),
            }
            .render()
            .unwrap_or_default(),
        )
    }

    #[axum::debug_handler]
    pub async fn totp_change(messages: Messages) -> impl IntoResponse {
        Html(
            TotpChangeTemplate {
                messages: messages.into_iter().map(|m| m.to_string()).collect(),
            }
            .render()
            .unwrap_or_default(),
        )
    }

    #[axum::debug_handler]
    pub async fn factor_reset(messages: Messages) -> impl IntoResponse {
        Html(
            FactorResetTemplate {
                messages: messages.into_iter().map(|m| m.to_string()).collect(),
            }
            .render()
            .unwrap_or_default(),
        )
    }
}

// Add these Askama templates at the top of the file or in a suitable module:
#[derive(Template)]
#[template(path = "password_setup.html")]
struct PasswordSetupTemplate {
    messages: Vec<String>,
}

#[derive(Template)]
#[template(path = "password_change.html")]
struct PasswordChangeTemplate {
    messages: Vec<String>,
}

#[derive(Template)]
#[template(path = "email_verify.html")]
struct EmailVerifyTemplate {
    messages: Vec<String>,
}

#[derive(Template)]
#[template(path = "email_change.html")]
struct EmailChangeTemplate {
    messages: Vec<String>,
}

#[derive(Template)]
#[template(path = "totp_change.html")]
struct TotpChangeTemplate {
    messages: Vec<String>,
}

#[derive(Template)]
#[template(path = "factor_reset.html")]
struct FactorResetTemplate {
    messages: Vec<String>,
}
