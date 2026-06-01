//! Phase 5a: stored delegation.
//!
//! User-authorized OBO with a refresh token persisted at rest.
//! Authorization flow: user → IdP (via browser redirect) → axess
//! callback receives the authorization code → axess exchanges it at
//! the IdP's token endpoint → axess stores
//! `(access_token, refresh_token, expires_at, scopes)` keyed by
//! `(tenant, user, provider)`. Runtime: `StoredDelegationSession`
//! loads the credential, refreshes the access token if needed, and
//! returns a fresh bearer string to the caller.
//!
//! See [`super`] module docs for the broader OBO concept and the
//! distinction vs [`super::exchange`](crate::delegated::exchange).
//!
//! # Module layout
//!
//! - `provider`: `DelegatedProvider` config (one per 3rd-party
//!   integration: Gmail, Outlook, Zoho, …).
//! - `credential`: `StoredDelegation` data shape, the
//!   `DelegatedCredentialStore` trait, and `MemoryDelegatedCredentialStore`
//!   for dev / test.
//! - `grant`: `begin_grant` (mints authorization URL + state +
//!   PKCE verifier) and `complete_grant` (validates state, exchanges
//!   code for tokens).
//! - `session`: `StoredDelegationSession::get_access_token()`
//!   with silent refresh.
//! - [`encrypted`](crate::delegated::stored::encrypted) (feature `delegated-stored-encrypted`):
//!   transparent encryption-at-rest wrapper over any inner
//!   `DelegatedCredentialStore`. AES-256-GCM with per-row random
//!   nonce and AAD bound to `(provider, tenant, user, field)`.

pub mod credential;
#[cfg(feature = "delegated-stored-encrypted")]
pub mod encrypted;
pub mod grant;
pub mod provider;
pub mod session;

pub use credential::{DelegatedCredentialStore, MemoryDelegatedCredentialStore, StoredDelegation};
#[cfg(feature = "delegated-stored-encrypted")]
pub use encrypted::{
    CurrentKey, EncryptedDelegatedCredentialStore, EncryptionKey, KeyProvider, KeyProviderError,
    MemoryKeyProvider,
};
pub use grant::{GrantContext, begin_grant, complete_grant};
pub use provider::DelegatedProvider;
pub use session::StoredDelegationSession;

#[cfg(test)]
mod tests;
