//! Cross-instance reload notices, shared by every concern that reloads on a
//! running service.
//!
//! A [`ReloadCoordinator`] is one channel: an instance announces that its
//! state changed, and every subscriber (itself included) is told. The notice
//! is a hint with a label for logs; a receiver applies nothing from it and
//! re-reads its own source. The Cedar policy reload
//! ([`AuthzStore::follow_reloads`](crate::authz::AuthzStore::follow_reloads))
//! and the authentication provider reload
//! ([`AuthnService::follow_provider_reloads`](crate::authn::service::AuthnService::follow_provider_reloads))
//! each take their own coordinator value, so their notices never mix.

mod coordinator;
#[cfg(feature = "valkey")]
mod valkey;

use std::future::Future;
use std::pin::Pin;

pub use coordinator::{
    CoordinationError, InProcessCoordinator, ReloadCoordinator, ReloadNotice, ReloadReceiver,
};
#[cfg(feature = "valkey")]
#[cfg_attr(docsrs, doc(cfg(feature = "valkey")))]
pub use valkey::ValkeyReloadCoordinator;

/// A boxed, sendable future: the return type of the reload traits, which are
/// used as trait objects.
pub type ReloadFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
