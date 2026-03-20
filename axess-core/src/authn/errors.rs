//! Authentication error types used across Axess forms, sessions, and handlers.

use crate::{
    authn::backend::{AuthnBackend, EntityState},
    axum::{
        http::StatusCode,
        response::{IntoResponse, Response},
    },
};
use std::fmt::Debug;
use thiserror::Error as ThisError;
use tower_sessions::{session::Error as SessionError, session_store::Error as SessionStoreError};

/// Error type for authentication factor form validation and extraction.
///
/// `FormError` is used throughout Axess to represent failures when validating, parsing,
/// or extracting fields from factor forms (e.g., password, OTP, signup, reset).
/// It distinguishes between generic invalid data, specific validation failures,
/// missing required fields, and errors extracting stored configuration for a factor kind.
///
/// # Variants
/// - `InvalidFormData`: The form contains invalid or malformed data (e.g., bad format, empty fields).
/// - `ValidationFailed(String)`: The form failed a specific validation rule, with a message describing the reason.
/// - `MissingField(String)`: A required field is missing from the form, with the field name.
/// - `AuthConfigError(String)`: Unable to extract expected stored authentication config for a given factor kind.
///
/// # Usage
/// - Returned by [`FactorForm::validate_form`] and [`FactorForm::verify_against_config`] for all built-in and custom forms.
/// - Used to map form errors to authentication errors and HTTP responses.
/// - Enables granular error reporting in session flows and UI feedback.
///
/// # Example
/// ```rust
/// use axess_core::authn::errors::FormError;
///
/// let err = FormError::ValidationFailed("Password too short".to_string());
/// assert_eq!(format!("{}", err), "Form validation failed: Password too short");
/// ```
#[derive(ThisError, Debug, PartialEq)]
pub enum FormError {
    /// The form contains invalid or malformed data (e.g., bad format, empty fields).
    #[error("Invalid form data")]
    InvalidFormData,
    /// The form action is unexpected or unsupported.
    #[error("Unexpected form action")]
    UnexpectedFormAction,
    /// The form failed a specific validation rule, with a message describing the reason.
    #[error("Form validation failed: {0}")]
    ValidationFailed(String),
    /// A required field is missing from the form, with the field name.
    #[error("Missing required field: {0}")]
    MissingField(String),
    /// Unable to extract expected stored auth config data for a given factor kind.
    #[error("Unable to extract expected stored auth config data for '{:?}' factor kind", { 0 })]
    AuthConfigError(String),
}

impl<B> From<FormError> for AuthError<B>
where
    B: AuthnBackend,
{
    fn from(err: FormError) -> Self {
        match err {
            FormError::InvalidFormData => AuthError::UnexpectedFormContent,
            FormError::UnexpectedFormAction => AuthError::UnexpectedFormAction,
            FormError::ValidationFailed(_) => AuthError::InvalidCredentials,
            FormError::MissingField(_) => AuthError::UnexpectedFormContent,
            FormError::AuthConfigError(kind) => AuthError::UnexpectedAuthConfig(kind),
        }
    }
}

/// Error type for unexpected or unsupported authentication factor kinds.
///
/// `FactorKindError` is used when an authentication flow encounters a factor kind
/// that is not recognized or supported by the backend, such as a custom or misconfigured value.
/// This error is surfaced in session flows, backend lookups, and form validation to ensure
/// only valid factor kinds are processed.
///
/// # Variants
/// - `UnexpectedValue(String)`: The factor kind is not recognized or supported; includes the unexpected value.
///
/// # Usage
/// - Returned by [`Kind::from_str`] when parsing an unknown factor kind.
/// - Used in session flows and backend logic to reject unsupported factor kinds.
/// - Propagated via [`AuthError::UnexpectedFactorKind`] for HTTP error mapping.
///
/// # Example
/// ```rust
/// use axess_core::authn::errors::FactorKindError;
///
/// let err = FactorKindError::UnexpectedValue("webauthn".to_string());
/// assert_eq!(format!("{}", err), "Unexpected factor kind: webauthn");
/// ```
#[derive(Debug, ThisError)]
pub enum FactorKindError {
    /// The factor kind is not recognized or supported; includes the unexpected value.
    #[error("Unexpected factor kind: {0}")]
    UnexpectedValue(String),
}

/// Error type for session registry operations.
///
/// `SessionRegistryError` represents all possible failures that can occur when
/// registering, validating, serializing, or invalidating sessions in the registry.
/// It wraps errors from the underlying session store and provides context for
/// serialization and registry management failures.
///
/// # Variants
/// - `StoreError`: Error from the underlying session store (e.g., Redis, Valkey, in-memory).
/// - `SerializationError`: Failure to serialize or deserialize session metadata or registry state.
///
/// # Usage
/// This error type is returned by all async methods on [`SessionRegistry`] and [`SessionRegistryStore`].
/// It should be handled at the API boundary and logged for audit and debugging purposes.
///
/// # Example
/// ```rust
/// use axess_core::authn::{session::registry::SessionRegistry, errors::SessionRegistryError};
///
/// async fn invalidate_session(registry: &impl SessionRegistry, session_id: &str) {
///     match registry.invalidate_session(session_id).await {
///         Ok(_) => println!("Session invalidated"),
///         Err(SessionRegistryError::StoreError(e)) => eprintln!("Store error: {e}"),
///         Err(SessionRegistryError::SerializationError(msg)) => eprintln!("Serialization error: {msg}"),
///     }
/// }
/// ```
#[derive(Debug, thiserror::Error)]
pub enum SessionRegistryError {
    /// Error from the underlying session store (e.g., Redis, Valkey, in-memory).
    #[error("Session store error: {0}")]
    StoreError(#[from] SessionStoreError),

    /// Failure to serialize or deserialize session metadata or registry state.
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Comprehensive error type for authentication flows in Axess.
///
/// `AuthError` is used throughout Axess to represent all possible failures that can occur
/// during authentication, session management, factor and method verification, and backend operations.
/// It supports granular error reporting for forms, sessions, factors, methods, and backend integration,
/// and is convertible to HTTP responses for ergonomic error handling in Axum routes and middleware.
///
/// # Variants
/// - `InvalidCredentials`: Submitted credentials are invalid or do not match backend records.
/// - `TooManyAttempts`: Exceeded maximum allowed authentication attempts (lockout).
/// - `InvalidStateTransition`: Invalid transition between authentication states.
/// - `NotAuthenticated`: User is not authenticated.
/// - `PartialAuthenticationRequired`: Multi-factor authentication is required.
/// - `AlreadyAuthenticated`: User is already authenticated.
/// - `UnexpectedAuthState`: Unexpected authentication state encountered.
/// - `Unauthorized`: User is not authorized for the requested action.
/// - `InvalidScope`: Invalid permission scope for the operation.
/// - `MethodNotSupported`: Authentication method is not supported.
/// - `MethodNotFound`: Authentication method not found.
/// - `FactorNotSupported`: Authentication factor is not supported.
/// - `FactorNotFound`: Authentication factor not found.
/// - `UnexpectedFactorKind(FactorKindError)`: Unexpected or unsupported factor kind.
/// - `UnexpectedAuthConfig(String)`: Unexpected or invalid configuration for factor kind.
/// - `UserNotFound`: User not found in backend.
/// - `UnexpectedUserState`: User is not in the expected state (e.g., suspended, terminated).
/// - `IncorrectUserData`: User data is incorrect or malformed.
/// - `TenantNotFound`: Tenant not found in backend.
/// - `IncorrectTenantData`: Tenant data is incorrect or malformed.
/// - `SessionNotFound`: Session not found in registry.
/// - `SessionExpired`: Session has expired.
/// - `SessionLockError`: Failed to acquire session lock.
/// - `SessionInvalid`: Session is invalid or corrupted.
/// - `SessionError(SessionError)`: Error from session store.
/// - `SessionRegistryError(SessionRegistryError)`: Error from session registry.
/// - `BackendError(B::Error)`: Error from backend implementation.
/// - `Base64DecodeError(base64::DecodeError)`: Error decoding base64 data.
///
/// # Usage
/// - Returned by all authentication flows, session extractors, and backend trait methods.
/// - Convertible to HTTP responses via [`IntoResponse`] for Axum handlers and middleware.
/// - Enables granular error handling and user feedback in web applications.
///
/// # Example
/// ```rust
/// use axess_core::authn::{backend::AuthnBackend, errors::AuthError};
///
/// fn handle_auth_error<B: AuthnBackend + std::fmt::Debug>(err: AuthError<B>) {
///     match err {
///         AuthError::InvalidCredentials => println!("Invalid credentials"),
///         AuthError::TooManyAttempts => println!("Too many attempts"),
///         AuthError::SessionExpired => println!("Session expired"),
///         AuthError::BackendError(e) => println!("Backend error: {e:?}"),
///         _ => println!("Other error: {err:?}"),
///     }
/// }
/// ```
#[derive(ThisError, Debug)]
pub enum AuthError<B: AuthnBackend> {
    /// Submitted credentials are invalid or do not match backend records.
    #[error("Invalid credentials")]
    InvalidCredentials,
    /// The form contains invalid or malformed fields or field values.
    #[error("Unexpected form content")]
    UnexpectedFormContent,
    /// Exceeded maximum allowed authentication attempts (lockout).
    #[error("Too many authentication attempts")]
    TooManyAttempts,
    /// Invalid transition between authentication states.
    #[error("Invalid authentication state transition")]
    InvalidStateTransition,

    /// User is not authenticated.
    #[error("User not authenticated")]
    NotAuthenticated,
    /// Multi-factor authentication is required.
    #[error("Partial authentication required")]
    PartialAuthenticationRequired,
    /// User is already authenticated.
    #[error("User already authenticated")]
    AlreadyAuthenticated,
    /// Unexpected authentication state encountered.
    #[error("Unexpected authentication state")]
    UnexpectedAuthState,

    /// User is not authorized for the requested action.
    #[error("Unauthorized")]
    Unauthorized,
    /// Invalid permission scope for the operation.
    #[error("Invalid scope")]
    InvalidScope,

    /// Authentication method is not supported.
    #[error("Authentication method not supported")]
    MethodNotSupported,
    /// Authentication method not found.
    #[error("Authentication method not found")]
    MethodNotFound,
    /// Authentication factor is not supported.
    #[error("Authentication factor not supported")]
    FactorNotSupported,
    /// Authentication factor not found.
    #[error("Authentication factor not found")]
    FactorNotFound,
    /// Unexpected or unsupported factor state object.
    #[error("No relevant factor state found")]
    FactorStateNotFound,
    /// Unexpected or unsupported factor kind.
    #[error("Unexpected factor kind: {0}")]
    UnexpectedFactorKind(#[from] FactorKindError),
    /// The form action is unexpected or unsupported.
    #[error("Unexpected form action")]
    UnexpectedFormAction,
    /// Unexpected or invalid authentication configuration (as stored on FactorState).
    #[error("Unexpected auth config: {0}")]
    UnexpectedAuthConfig(String),

    /// User not found in backend.
    #[error("User not found")]
    UserNotFound,
    /// User is not active (i.e. suspended, terminated or archived).
    #[error("User is {0}")]
    UserDeactivated(Box<EntityState>),
    /// User is not active (e.g., suspended, terminated).
    #[error("Unexpected user state")]
    UnexpectedUserState,
    /// User data is incorrect or malformed.
    #[error("Incorrect user data")]
    IncorrectUserData,
    /// Tenant not found in backend.
    #[error("Tenant not found")]
    TenantNotFound,
    /// Tenant data is incorrect or malformed.
    #[error("Incorrect tenant data")]
    IncorrectTenantData,

    /// Session not found in registry.
    #[error("Session not found")]
    SessionNotFound,
    /// Session has expired.
    #[error("Session expired")]
    SessionExpired,
    /// Failed to acquire session lock.
    #[error("Failed to acquire Session lock")]
    SessionLockError,
    /// Session is invalid or corrupted.
    #[error("Session is invalid")]
    SessionInvalid,
    /// Error from session store.
    #[error(transparent)]
    SessionError(SessionError),
    /// Session Registry not found.
    #[error("Session Registry not found")]
    SessionRegistryNotFound,
    /// Error from session registry.
    #[error("Session registry error: {0}")]
    SessionRegistryError(#[from] SessionRegistryError),
    /// Error from backend implementation.
    #[error("Backend error: {0}")]
    BackendError(#[source] B::Error),
    /// Error decoding base64 data.
    #[error("Base64 decode error: {0}")]
    Base64DecodeError(#[from] base64::DecodeError),
}

impl<B> IntoResponse for AuthError<B>
where
    B: AuthnBackend,
{
    fn into_response(self) -> Response {
        let (status, message): (StatusCode, String) = match self {
            AuthError::InvalidCredentials => (StatusCode::UNAUTHORIZED, "Invalid credentials".to_string()),
            AuthError::UnexpectedFormContent => (StatusCode::BAD_REQUEST, "Unexpected form content".to_string()),
            AuthError::TooManyAttempts => (StatusCode::TOO_MANY_REQUESTS, "Too many attempts".to_string()),
            AuthError::InvalidStateTransition => (StatusCode::CONFLICT, "Invalid state transition".to_string()),
            AuthError::NotAuthenticated => (StatusCode::UNAUTHORIZED, "Not authenticated".to_string()),
            AuthError::PartialAuthenticationRequired => (StatusCode::UNAUTHORIZED, "Partial authentication required".to_string()),
            AuthError::AlreadyAuthenticated => (StatusCode::CONFLICT, "Already authenticated".to_string()),
            AuthError::UnexpectedAuthState => (StatusCode::BAD_REQUEST, "Unexpected authentication state".to_string()),
            AuthError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()),
            AuthError::InvalidScope => (StatusCode::BAD_REQUEST, "Invalid scope".to_string()),
            AuthError::MethodNotSupported | AuthError::MethodNotFound => (
                StatusCode::BAD_REQUEST,
                "Authentication method not available".to_string(),
            ),
            AuthError::FactorNotSupported | AuthError::FactorNotFound | AuthError::FactorStateNotFound => (
                StatusCode::BAD_REQUEST,
                "Authentication factor not available".to_string(),
            ),
            AuthError::UnexpectedFactorKind(_) | AuthError::UnexpectedAuthConfig(_) => (
                StatusCode::BAD_REQUEST,
                "Invalid authentication configuration".to_string(),
            ),
            AuthError::UnexpectedFormAction => (StatusCode::BAD_REQUEST, "Unexpected form action".to_string()),
            AuthError::UserNotFound => (StatusCode::UNAUTHORIZED, "User not found".to_string()),
            AuthError::UserDeactivated(state) => (
                StatusCode::UNAUTHORIZED,
                format!("User is {:?}", state),
            ),
            AuthError::UnexpectedUserState => (StatusCode::FORBIDDEN, "Unexpected user state".to_string()),
            AuthError::IncorrectUserData => (StatusCode::BAD_REQUEST, "Incorrect user data".to_string()),
            AuthError::TenantNotFound => (StatusCode::NOT_FOUND, "Tenant not found".to_string()),
            AuthError::IncorrectTenantData => (StatusCode::BAD_REQUEST, "Incorrect tenant data".to_string()),
            AuthError::SessionNotFound => (StatusCode::UNAUTHORIZED, "Session not found".to_string()),
            AuthError::SessionExpired => (StatusCode::UNAUTHORIZED, "Session expired".to_string()),
            AuthError::SessionLockError => (StatusCode::CONFLICT, "Session lock error".to_string()),
            AuthError::SessionInvalid => (StatusCode::UNAUTHORIZED, "Session is invalid".to_string()),
            AuthError::SessionError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Session error".to_string()),
            AuthError::SessionRegistryNotFound => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Session registry not found".to_string(),
            ),
            AuthError::SessionRegistryError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Session registry error".to_string(),
            ),
            AuthError::BackendError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Backend error".to_string()),
            AuthError::Base64DecodeError(_) => (StatusCode::BAD_REQUEST, "Base64 decode error".to_string()),
        };

        (status, message).into_response()
    }
}

/// Error type for mapping authentication and authorization failures to HTTP responses in Axess handlers.
///
/// `HandlerError` is used in Axum route handlers and middleware to represent access control failures,
/// invalid credentials, bad requests, and server errors. It provides ergonomic conversion from [`AuthError`]
/// and supports granular mapping to HTTP status codes for user feedback and API clients.
///
/// # Variants
/// - `AccessDenied`: The user is forbidden from accessing the resource (HTTP 403).
/// - `Unauthorized`: The user is not authenticated (HTTP 401).
/// - `InvalidCredentials`: Submitted credentials are invalid (HTTP 401).
/// - `WrongFormat`: The request or payload is incorrectly formatted (HTTP 400).
/// - `BadRequest`: The request is invalid or malformed (HTTP 400).
/// - `ServerError`: Internal server error (HTTP 500).
/// - `Other(String)`: Custom error message (HTTP 500).
///
/// # Usage
/// - Returned by Axum handlers and middleware for authentication and authorization failures.
/// - Used to convert [`AuthError`] and other error types into HTTP responses.
/// - Enables clear and consistent error handling for web APIs and UIs.
///
/// # Example
/// ```rust
/// use axess_core::authn::errors::HandlerError;
/// use axum::response::IntoResponse;
///
/// fn handle_error(err: HandlerError) -> impl IntoResponse {
///     err.into_response()
/// }
/// ```
#[derive(Debug, ThisError)]
pub enum HandlerError {
    /// The user is forbidden from accessing the resource (HTTP 403).
    #[error("Access denied")]
    AccessDenied,

    /// The user is not authenticated (HTTP 401).
    #[error("Unauthorized access")]
    Unauthorized,

    /// Submitted credentials are invalid (HTTP 401).
    #[error("Invalid login credentials")]
    InvalidCredentials,

    /// The request or payload is incorrectly formatted (HTTP 400).
    #[error("Wrong format")]
    WrongFormat,

    /// The request is invalid or malformed (HTTP 400).
    #[error("Bad request")]
    BadRequest,

    /// Internal server error (HTTP 500).
    #[error("Server error")]
    ServerError,

    /// Custom error message (HTTP 500).
    #[error("{0}")]
    Other(String),
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

/// Error type for workflow state transitions and handling.
#[derive(Debug, ThisError)]
pub enum WorkflowError {
    #[error("Workflow is blocking further progress")]
    Blocking,
    #[error("Workflow is not complete")]
    Incomplete,
    #[error("Invalid workflow state transition")]
    InvalidTransition,
    #[error("Workflow failed: {0}")]
    Failed(String),
    #[error("Unknown workflow error")]
    Unknown,
}

/// Converts a `WorkflowError` into an `AuthError`.
///
/// This implementation maps specific variants of `WorkflowError` to corresponding
/// `AuthError` variants, ensuring that authentication errors are handled consistently
/// within the authentication workflow. This mapping is particularly relevant after
/// the introduction of the `Workflow` trait and `WorkflowError`, aligning error handling
/// with the new workflow-based authentication logic.
///
/// # Mapping
/// - `WorkflowError::Blocking` and `WorkflowError::InvalidTransition` are mapped to `AuthError::InvalidStateTransition`.
/// - `WorkflowError::Incomplete` is mapped to `AuthError::PartialAuthenticationRequired`.
/// - `WorkflowError::Failed(msg)` is mapped to `AuthError::UnexpectedAuthConfig(msg)`.
/// - `WorkflowError::Unknown` is mapped to `AuthError::UnexpectedAuthState`.
///
/// # Examples
/// ```rust ignore
/// use axess_core::authn::{errors::{AuthError, WorkflowError}, backend::AuthnBackend};
/// use crate::DummyBackend;
///
/// let err = WorkflowError::Blocking;
/// let auth_err: AuthError<DummyBackend> = AuthError::from(err);
/// assert!(matches!(auth_err, AuthError::InvalidStateTransition));
///
/// let err = WorkflowError::Incomplete;
/// let auth_err: AuthError<DummyBackend> = AuthError::from(err);
/// assert!(matches!(auth_err, AuthError::PartialAuthenticationRequired));
///
/// let err = WorkflowError::Failed("config error".to_string());
/// let auth_err: AuthError<DummyBackend> = AuthError::from(err);
/// if let AuthError::UnexpectedAuthConfig(msg) = auth_err {
///     assert_eq!(msg, "config error");
/// } else {
///     panic!("Expected UnexpectedAuthConfig");
/// }
/// ```
impl<B> From<WorkflowError> for AuthError<B>
where
    B: AuthnBackend,
{
    fn from(err: WorkflowError) -> Self {
        match err {
            WorkflowError::Blocking => AuthError::InvalidStateTransition,
            WorkflowError::Incomplete => AuthError::PartialAuthenticationRequired,
            WorkflowError::InvalidTransition => AuthError::InvalidStateTransition,
            WorkflowError::Failed(msg) => AuthError::UnexpectedAuthConfig(msg),
            WorkflowError::Unknown => AuthError::UnexpectedAuthState,
        }
    }
}
