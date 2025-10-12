use crate::{
    authn::{backend::AuthnBackend, session::registry::SessionRegistryError},
    axum::{http::StatusCode, response::{IntoResponse, Response}},
};
use std::fmt::Debug;
use thiserror::Error as ThisError;
use tower_sessions::session::Error as SessionError;

/// Form validation errors
#[derive(ThisError, Debug)]
pub enum FormError {
    #[error("Invalid form data")]
    InvalidFormData,
    #[error("Form validation failed: {0}")]
    ValidationFailed(String),
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
            FormError::AuthConfigError(kind) => AuthError::UnexpectedAuthConfig(kind),
        }
    }
}

#[derive(ThisError, Debug)]
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
    #[error(transparent)]
    SessionError(SessionError),
    #[error("Session registry error: {0}")]
    SessionRegistryError(#[from] SessionRegistryError),
    #[error("Backend error: {0}")]
    BackendError(#[source] B::Error),
}

#[derive(Debug, ThisError)]
pub enum HandlerError {
    #[error("Access denied")]
    AccessDenied,

    #[error("Unauthorized access")]
    Unauthorized,

    #[error("Invalid TOTP code")]
    InvalidTOTP,

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
            HandlerError::InvalidTOTP => {
                (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response()
            }
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
