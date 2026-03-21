//! Error type for authentication service operations.

use crate::authn::types::EntityState;

/// Errors that can occur during authentication flows.
///
/// Parameterised over the backend error type `E` so that storage errors are
/// propagated with their original type rather than being erased.
#[derive(Debug, thiserror::Error)]
pub enum AuthnError<E: std::error::Error + Send + Sync + 'static> {
    /// An error from the underlying identity or factor store.
    #[error("store error: {0}")]
    Store(#[source] E),

    /// No active authentication flow found in the session.
    ///
    /// Returned by `verify_factor` when the session is not in `Authenticating` state.
    #[error("no active authentication flow")]
    NoFlow,

    /// The account exists but is not in a state that permits login.
    #[error("account not active: {0:?}")]
    NotActive(EntityState),

    /// The account is locked due to too many failed authentication attempts.
    ///
    /// Returned by discoverable FIDO2 login when the lockout threshold is
    /// reached. Callers should display a generic "account locked" message.
    #[error("account locked")]
    Locked,

    /// A FIDO2/WebAuthn assertion or registration failed validation.
    ///
    /// Distinct from [`NoFlow`] (no ceremony in progress) — this means a
    /// ceremony was in progress but the cryptographic validation failed.
    #[error("invalid FIDO2 assertion")]
    InvalidAssertion,
}
