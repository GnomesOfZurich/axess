// use std::sync::Arc;

use askama::Template;
use axess::{
    AuthnAdminBackend, AuthnBackend, TOTP_LENGTH, TOTP_PERIOD,
    authn::methods::{
        MethodBuilder,
        factor::{FactorInstance, FactorStateChangeBuilder},
        form::{PasswordForm, TotpForm, TotpSetupForm},
        policy::FactorConfigBuilder,
    },
    generate_password_hash, generate_totp_secret, verify_totp,
};
use axum::{
    Form, Router,
    extract::Query,
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
};
use axum_messages::{Message, Messages};
use serde::Deserialize;
use std::time::SystemTime;
use uuid::Uuid;

use crate::models::authn::Session;

const DEFAULT_TENANT_NAME: &str = "Default Tenant";

pub fn router() -> Router {
    Router::new()
        .route("/login", post(self::post::login))
        .route("/login", get(self::get::login))
        .route("/logout", get(self::get::logout))
        .route("/signup", get(get::signup))
        .route("/signup", post(post::signup))
        .route("/factors/totp/setup", get(get::totp_setup))
        .route("/factors/totp/setup", post(post::totp_setup))
        .route("/factors/totp/verify", get(get::totp_verify))
        .route("/factors/totp/verify", post(post::totp_verify))
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
    use axess::{AuthFactorKind, EnablementState, MethodStateChange, PermissionScope, TOTP_PERIOD};
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
        pub otp_secret: String,
    }

    #[derive(Deserialize)]
    pub struct TotpVerifyRequest {
        pub otp_code: String,
    }

    #[axum::debug_handler]
    pub async fn login(
        Extension(mut session): Extension<Session>,
        messages: Messages,
        Form(mut form): Form<PasswordForm>,
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
            Ok(response) => response,
            Err(err) => {
                messages.error(format!("Login failed: {}", err));
                Redirect::to("/login").into_response()
            }
        }
    }

    #[axum::debug_handler]
    pub async fn signup(
        Extension(session): Extension<Session>,
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

        let user = OurUser::new(
            Uuid::new_v4(),
            tenant.id,
            payload.username.clone(),
            payload.fullname.clone(),
            payload.email.clone(),
            tenant.created_by,
        );

        if let Err(err) = backend.upsert_user(user.clone()).await {
            messages.error(format!("Failed to create user: {err}"));
            return Redirect::to("/signup").into_response();
        }
        let password_factor = FactorInstance::new(
            Uuid::new_v4(),
            AuthFactorKind::Password,
            "password-login",
            "Password factor",
            user.id,
        );
        let totp_factor = FactorInstance::new(
            Uuid::new_v4(),
            AuthFactorKind::Otp,
            "totp-login",
            "TOTP factor",
            user.id,
        );

        if let Err(err) = backend.upsert_auth_factor(password_factor.clone()).await {
            messages.error(format!("Failed to persist password factor: {err}"));
            return Redirect::to("/signup").into_response();
        }
        if let Err(err) = backend.upsert_auth_factor(totp_factor.clone()).await {
            messages.error(format!("Failed to persist TOTP factor: {err}"));
            return Redirect::to("/signup").into_response();
        }
        let password_state = FactorStateChangeBuilder::new(password_factor.id, user.id)
            .with_scope(PermissionScope::User(user.tenant_id, user.id))
            .with_state(EnablementState::Active)
            .set_password_hash(generate_password_hash(&payload.password))
            .build();

        if let Err(err) = backend.upsert_factor_state(password_state).await {
            messages.error(format!("Failed to activate password factor: {err}"));
            return Redirect::to("/signup").into_response();
        }

        let totp_secret = generate_totp_secret();
        let totp_state = FactorStateChangeBuilder::new(totp_factor.id, user.id)
            .with_scope(PermissionScope::User(user.tenant_id, user.id))
            .with_state(EnablementState::Pending)
            .set_otp_config(
                FactorConfigBuilder::totp(totp_secret.clone())
                    .with_length(TOTP_LENGTH)
                    .with_period(TOTP_PERIOD)
                    .with_windows(1, 0),
            )
            .build();

        if let Err(err) = backend.upsert_factor_state(totp_state).await {
            messages.error(format!("Failed to stage TOTP factor: {err}"));
            return Redirect::to("/signup").into_response();
        }

        let factors = vec![password_factor.clone(), totp_factor.clone()];

        let method = MethodBuilder::new(
            Uuid::new_v4(),
            "password+totp",
            "Password followed by TOTP",
            user.id,
        )
        .add_factors(factors)
        .build();
        if let Err(err) = backend.upsert_auth_method(method.clone()).await {
            messages.error(format!("Failed to persist auth method: {err}"));
            return Redirect::to("/signup").into_response();
        }

        let method_state = MethodStateChange::new(method.id, user.id)
            .with_scope(PermissionScope::User(user.tenant_id, user.id))
            .with_state(EnablementState::Active);

        if let Err(err) = backend.upsert_method_state(method_state).await {
            messages.error(format!("Failed to activate auth method: {err}"));
            return Redirect::to("/signup").into_response();
        }

        messages.success("Account created. Please enter your password.");
        Redirect::to("/login").into_response()
    }

    #[axum::debug_handler]
    pub async fn totp_setup(
        Extension(mut session): Extension<Session>,
        messages: Messages,
        Form(payload): Form<TotpSetupRequest>,
    ) -> impl IntoResponse {
        let form = TotpSetupForm {
            otp_secret: payload.otp_secret,
            tenant: None,
            next: None,
        };

        match session
            .handle_factor_setup(&form, AuthFactorKind::Otp)
            .await
        {
            Ok(_) => Redirect::to("/factors/totp/verify").into_response(),
            Err(err) => {
                messages.error(format!("TOTP setup failed: {}", err));
                Redirect::to("/factors/totp/setup").into_response()
            }
        }
    }

    #[axum::debug_handler]
    pub async fn totp_verify(
        Extension(mut session): Extension<Session>,
        messages: Messages,
        Form(payload): Form<TotpVerifyRequest>,
    ) -> impl IntoResponse {
        let otp_code = payload.otp_code.trim().to_string();
        let user = session.get_user();
        let backend = session.backend.clone();
        let scope = PermissionScope::User(user.tenant_id, user.id);

        let pending = match backend
            .get_scoped_auth_factors(scope.clone(), vec![EnablementState::Pending])
            .await
        {
            Ok(factors) => factors,
            Err(err) => {
                messages.error(format!("Failed to load pending factors: {err}"));
                return Html(TotpVerifyTemplate.render().unwrap_or_default()).into_response();
            }
        };

        let mut activated = false;

        for factor in pending
            .into_iter()
            .filter(|factor| matches!(factor.kind, AuthFactorKind::Otp))
        {
            let states = match backend.get_factor_states(&factor.id, scope.clone()).await {
                Ok(states) => states,
                Err(err) => {
                    messages.error(format!("Failed to load factor state: {err}"));
                    return Html(TotpVerifyTemplate.render().unwrap_or_default()).into_response();
                }
            };

            if let Some(state) = states
                .into_iter()
                .find(|state| state.state == EnablementState::Pending)
            {
                let secret = match state.config.get("otp_secret").and_then(|v| v.as_str()) {
                    Some(value) => value,
                    None => {
                        messages.error("TOTP factor is missing its shared secret.".to_string());
                        return Html(TotpVerifyTemplate.render().unwrap_or_default())
                            .into_response();
                    }
                };

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

                let past_window = state
                    .config
                    .get("past_window")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(1);

                let future_window = state
                    .config
                    .get("future_window")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);

                let matched_step = match verify_totp(
                    secret,
                    &otp_code,
                    SystemTime::now(),
                    Some(digits),
                    Some(period),
                    Some(past_window),
                    Some(future_window),
                ) {
                    Some(step) => step,
                    None => {
                        messages.error("Invalid TOTP code.".to_string());
                        return Html(TotpVerifyTemplate.render().unwrap_or_default())
                            .into_response();
                    }
                };

                let config_builder = FactorConfigBuilder::from_map(state.config.clone())
                    .with_length(digits)
                    .with_period(period)
                    .with_windows(past_window, future_window)
                    .with_last_totp_step(matched_step);

                let change = FactorStateChangeBuilder::new(factor.id, user.id)
                    .with_scope(scope.clone())
                    .with_state(EnablementState::Active)
                    .set_otp_config(config_builder)
                    .build();

                if let Err(err) = backend.upsert_factor_state(change).await {
                    messages.error(format!("Failed to activate TOTP factor: {err}"));
                    return Html(TotpVerifyTemplate.render().unwrap_or_default()).into_response();
                }

                activated = true;
                break;
            }
        }

        if !activated {
            messages.error("No pending TOTP factor available for verification.".to_string());
            return Html(TotpVerifyTemplate.render().unwrap_or_default()).into_response();
        }

        let tenant_name = match backend.get_tenant(&user.tenant_id).await {
            Ok(tenant) => tenant.name,
            Err(err) => {
                messages
                    .clone()
                    .info(format!("Using default tenant because lookup failed: {err}"));
                DEFAULT_TENANT_NAME.to_string()
            }
        };

        let form = TotpForm {
            otp_code,
            tenant: Some(tenant_name),
            next: None,
        };

        match session.authenticate_from_form(Form(form)).await {
            Ok(response) => response,
            Err(err) => {
                messages.error(format!("TOTP verification failed: {}", err));
                Html(TotpVerifyTemplate.render().unwrap_or_default()).into_response()
            }
        }
    }
}

pub mod get {
    use super::*;
    use axess::{AuthFactorKind, EnablementState, PermissionScope, build_totp_uri};
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

        let scope = PermissionScope::User(user.tenant_id, user.id);
        let mut secret: Option<String> = None;
        let mut provisioning_uri: Option<String> = None;

        match backend
            .get_scoped_auth_factors(scope.clone(), vec![EnablementState::Pending])
            .await
        {
            Ok(factors) => {
                if let Some(factor) = factors
                    .into_iter()
                    .find(|factor| matches!(factor.kind, AuthFactorKind::Otp))
                {
                    match backend.get_factor_states(&factor.id, scope.clone()).await {
                        Ok(states) => {
                            if let Some(state) = states
                                .into_iter()
                                .find(|state| state.state == EnablementState::Pending)
                            {
                                if let Some(value) =
                                    state.config.get("otp_secret").and_then(|v| v.as_str())
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
}
