//! Authentication error types used across Axess forms, sessions, and handlers.

use crate::{
    authn::{backend::AuthnBackend, session::registry::SessionRegistryError},
    axum::{
        http::StatusCode,
        response::{IntoResponse, Response},
    },
};
use std::fmt::Debug;
use thiserror::Error as ThisError;
use tower_sessions::session::Error as SessionError;

/// Form validation errors
#[derive(ThisError, Debug, PartialEq)]
pub enum FormError {
    #[error("Invalid form data")]
    InvalidFormData,
    #[error("Form validation failed: {0}")]
    ValidationFailed(String),
    #[error("Missing required field: {0}")]
    MissingField(String),
    #[error("Unable to extract expected stored auth config data for '{:?}' factor kind", { 0 })]
    AuthConfigError(String),
}

impl<B> From<FormError> for AuthError<B>
where
    B: AuthnBackend,
{
    fn from(err: FormError) -> Self {
        match err {
            FormError::InvalidFormData => AuthError::InvalidCredentials,
            FormError::ValidationFailed(_) => AuthError::InvalidCredentials,
            FormError::MissingField(_) => AuthError::InvalidCredentials,
            FormError::AuthConfigError(kind) => AuthError::UnexpectedAuthConfig(kind),
        }
    }
}

#[derive(Debug, ThisError)]
pub enum FactorKindError {
    #[error("Unexpected factor kind: {0}")]
    UnexpectedValue(String),
}

/// Authentication errors
#[derive(ThisError, Debug)]
pub enum AuthError<B: AuthnBackend> {
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Too many authentication attempts")]
    TooManyAttempts,
    #[error("Invalid authentication state transition")]
    InvalidStateTransition,

    #[error("User not authenticated")]
    NotAuthenticated,
    #[error("Partial authentication required")]
    PartialAuthenticationRequired,
    #[error("User already authenticated")]
    AlreadyAuthenticated,
    #[error("Unexpected authentication state")]
    UnexpectedAuthState,

    #[error("Unauthorized")]
    Unauthorized,
    #[error("Invalid scope")]
    InvalidScope,

    #[error("Authentication method not supported")]
    MethodNotSupported,
    #[error("Authentication method not found")]
    MethodNotFound,
    #[error("Authentication factor not supported")]
    FactorNotSupported,
    #[error("Authentication factor not found")]
    FactorNotFound,
    #[error("Unexpected factor kind: {0}")]
    UnexpectedFactorKind(#[from] FactorKindError),
    #[error("Unexpected auth config for factor kind: {0}")]
    UnexpectedAuthConfig(String),
    #[error("Unsupported OTP type")]
    UnsupportedOtpType,

    #[error("User not found")]
    UserNotFound,
    #[error("User not active")]
    UserNotActive,
    #[error("Incorrect user data")]
    IncorrectUserData,
    #[error("Tenant not found")]
    TenantNotFound,
    #[error("Incorrect tenant data")]
    IncorrectTenantData,

    #[error("Session not found")]
    SessionNotFound,
    #[error("Session expired")]
    SessionExpired,
    #[error("Failed to acquire Session lock")]
    SessionLockError,
    #[error("Session is invalid")]
    SessionInvalid,
    #[error(transparent)]
    SessionError(SessionError),
    #[error("Session registry error: {0}")]
    SessionRegistryError(#[from] SessionRegistryError),
    #[error("Backend error: {0}")]
    BackendError(#[source] B::Error),
}

impl<B> IntoResponse for AuthError<B>
where
    B: AuthnBackend,
{
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AuthError::InvalidCredentials => (StatusCode::UNAUTHORIZED, "Invalid credentials"),
            AuthError::TooManyAttempts => (StatusCode::TOO_MANY_REQUESTS, "Too many attempts"),
            AuthError::InvalidStateTransition => (StatusCode::CONFLICT, "Invalid state transition"),
            AuthError::NotAuthenticated => (StatusCode::UNAUTHORIZED, "Not authenticated"),
            AuthError::PartialAuthenticationRequired => {
                (StatusCode::UNAUTHORIZED, "Partial authentication required")
            }
            AuthError::AlreadyAuthenticated => (StatusCode::CONFLICT, "Already authenticated"),
            AuthError::UnexpectedAuthState => {
                (StatusCode::BAD_REQUEST, "Unexpected authentication state")
            }
            AuthError::UnsupportedOtpType => (StatusCode::BAD_REQUEST, "Unsupported OTP type"),
            AuthError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized"),
            AuthError::InvalidScope => (StatusCode::BAD_REQUEST, "Invalid scope"),
            AuthError::MethodNotSupported | AuthError::MethodNotFound => (
                StatusCode::BAD_REQUEST,
                "Authentication method not available",
            ),
            AuthError::FactorNotSupported | AuthError::FactorNotFound => (
                StatusCode::BAD_REQUEST,
                "Authentication factor not available",
            ),
            AuthError::UnexpectedFactorKind(_) | AuthError::UnexpectedAuthConfig(_) => (
                StatusCode::BAD_REQUEST,
                "Invalid authentication configuration",
            ),
            AuthError::UserNotFound => (StatusCode::UNAUTHORIZED, "User not found"),
            AuthError::UserNotActive => (StatusCode::FORBIDDEN, "User account not active"),
            AuthError::IncorrectUserData => (StatusCode::BAD_REQUEST, "Incorrect user data"),
            AuthError::TenantNotFound => (StatusCode::NOT_FOUND, "Tenant not found"),
            AuthError::IncorrectTenantData => (StatusCode::BAD_REQUEST, "Incorrect tenant data"),
            AuthError::SessionNotFound => (StatusCode::UNAUTHORIZED, "Session not found"),
            AuthError::SessionExpired => (StatusCode::UNAUTHORIZED, "Session expired"),
            AuthError::SessionLockError => (StatusCode::CONFLICT, "Session lock error"),
            AuthError::SessionError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Session error"),
            AuthError::SessionRegistryError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Session registry error")
            }
            AuthError::BackendError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Backend error"),
            AuthError::SessionInvalid => (StatusCode::UNAUTHORIZED, "Session is invalid"),
        };

        (status, message).into_response()
    }
}

#[derive(Debug, ThisError)]
pub enum HandlerError {
    #[error("Access denied")]
    AccessDenied,

    #[error("Unauthorized access")]
    Unauthorized,

    // #[error("Invalid OTP code")]
    // InvalidOTP,
    #[error("Invalid login credentials")]
    InvalidCredentials,

    #[error("Wrong format")]
    WrongFormat,

    #[error("Bad request")]
    BadRequest,

    #[error("Server error")]
    ServerError,

    #[error("{0}")]
    Other(String), // Handle other types of errors
}

impl<B: AuthnBackend> From<AuthError<B>> for HandlerError {
    fn from(_err: AuthError<B>) -> HandlerError {
        HandlerError::ServerError
    }
}

impl IntoResponse for HandlerError {
    fn into_response(self) -> Response {
        match self {
            HandlerError::AccessDenied => (StatusCode::FORBIDDEN, "Access denied").into_response(),
            HandlerError::Unauthorized => StatusCode::UNAUTHORIZED.into_response(),
            // HandlerError::InvalidOTP => {
            //     (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response()
            // }
            HandlerError::InvalidCredentials => {
                (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response()
            }
            HandlerError::BadRequest => StatusCode::BAD_REQUEST.into_response(),
            HandlerError::WrongFormat => StatusCode::BAD_REQUEST.into_response(),
            HandlerError::ServerError => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            HandlerError::Other(message) => {
                (StatusCode::INTERNAL_SERVER_ERROR, message).into_response()
            }
        }
    }
}
