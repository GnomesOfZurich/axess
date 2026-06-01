//! OAuth/OIDC public types, errors, and the provider trait.
//!
//! Re-exports are flat: consumers like the `oauth` module root reach
//! every name via `pub use types::*` without import-path churn.

// Sub-modules are crate-internal; every public type is re-exported
// below by name, so external consumers reach them via
// `axess::OAuthClaims` etc. (no module-path access). Keeping the
// sub-mods `pub(crate)` also avoids the
// `hidden_glob_reexports` warning from the parent `oauth.rs`'s
// `pub use types::*;` clashing with the sibling `mod provider;`
// (the `OAuthProviderConfig` impl directory) which shares the name.
pub(crate) mod claims;
pub(crate) mod client_credentials;
pub(crate) mod device_flow;
pub(crate) mod error;
pub(crate) mod fapi;
pub(crate) mod jwks_refresh;
pub(crate) mod login_options;
pub(crate) mod provider;

pub use claims::{OAuthClaims, UserInfoClaims};
pub use client_credentials::ClientCredentialsToken;
pub use device_flow::{DeviceAuthResponse, DeviceTokenOutcome};
pub use error::OAuthError;
pub use fapi::{DpopProof, FapiConfig, ParResponse, SenderConstraint};
pub use jwks_refresh::spawn_jwks_refresh;
pub use login_options::{OAuthLoginOptions, ResponseMode};
pub use provider::{AuthUrlResult, OAuthProvider};

// `provider::keys` is `pub(crate)`; re-export at the same visibility so
// callers inside `axess-core` that used `types::keys::*` keep resolving.
pub use provider::keys;
