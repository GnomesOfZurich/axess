//! The report of OAuth providers registered twice under one name.

use super::AuthnServiceBuilder;
use crate::authn::store::{FactorStore, IdentityStore};

impl<I, F> AuthnServiceBuilder<I, F>
where
    I: IdentityStore,
    F: FactorStore,
{
    /// Report each duplicate registration to the provider-registry sink, then
    /// refuse a debug build: a provider that silently replaced another is a
    /// misconfiguration worth stopping in development, while a release build
    /// keeps serving and leaves the count to the operator.
    pub(super) fn report_duplicate_providers(&self) {
        for _ in 0..self.duplicate_providers {
            self.metrics.registry.provider_duplicate_registration();
        }
        debug_assert!(
            self.duplicate_providers == 0,
            "duplicate OAuth provider name registered {} time(s); the earlier provider was \
             replaced (a release build keeps serving and counts it)",
            self.duplicate_providers
        );
    }
}
