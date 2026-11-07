//! Choosing the provider that verifies a logout token: by issuer, then by the
//! client id the token is addressed to, across the global registration and
//! the tenants' providers.

use super::{BackChannelLogoutHandler, ProviderEntry, addressed_to};
use crate::authn::ids::TenantId;
use std::sync::Arc;

/// Why no single provider could be chosen for a logout token.
#[derive(Debug, thiserror::Error)]
pub enum LogoutProviderError {
    /// More than one provider has the token's issuer and client id, so the
    /// token cannot be attributed to one of them. The token is refused.
    #[error(
        "back-channel logout: {} providers share the issuer and client id of the token \
         (global registration: {global}, tenants: {tenants:?})",
        tenants.len() + usize::from(*global)
    )]
    Ambiguous {
        /// Whether the global registration is one of the matches.
        global: bool,
        /// The tenants whose providers match.
        tenants: Vec<TenantId>,
    },
    /// The tenant source failed while looking for providers of the issuer.
    #[error("back-channel logout: the tenant provider source failed: {0}")]
    Source(#[from] axess_factors::oauth::OAuthError),
    /// The one provider with the token's issuer and client id is a tenant's
    /// that could not be built (its configuration does not open, or its
    /// discovery failed). The token is refused as retryable: the IdP resends
    /// it, and it verifies once the configuration is fixed. Other tenants of
    /// the issuer are not affected.
    #[error(
        "back-channel logout: the provider {name} of tenant {tenant} has the token's issuer and \
         client id but could not be built: {error}"
    )]
    Unavailable {
        /// The tenant whose provider it is.
        tenant: TenantId,
        /// The provider's name within the tenant.
        name: Arc<str>,
        /// Why it could not be built.
        error: axess_factors::oauth::OAuthError,
    },
}

impl BackChannelLogoutHandler {
    /// The provider that verifies a token of issuer `iss` addressed to the
    /// client ids in `unverified` (its unverified payload), or `None` when no
    /// provider of the issuer has a client id the token names.
    ///
    /// Errors: [`LogoutProviderError::Ambiguous`] when more than one provider
    /// (global or a tenant's) matches; [`LogoutProviderError::Unavailable`]
    /// when the one match is a tenant's provider that could not be built;
    /// [`LogoutProviderError::Source`] when the tenant source fails.
    pub(super) async fn entry_for(
        &self,
        iss: &str,
        unverified: &serde_json::Value,
    ) -> Result<Option<ProviderEntry>, LogoutProviderError> {
        // Providers can share an issuer; the one whose client id the token
        // is addressed to verifies it. The first global match stands for the
        // global registration, as before tenants existed.
        let global = self
            .providers_by_issuer
            .get(iss)
            .and_then(|entries| {
                entries
                    .iter()
                    .find(|e| addressed_to(unverified, &e.client_id))
            })
            .cloned();
        let Some(source) = &self.tenants else {
            return Ok(global);
        };
        let now = self.clock.now();
        // Read before asking, so a change while the source is read is not
        // mistaken for the state the miss was recorded in.
        let generation = source.generation();
        if global.is_none() && self.unknown_issuers.is_unknown(iss, now, generation) {
            return Ok(None);
        }
        let found = source.providers_for_issuer(iss).await?;
        if global.is_none() && found.providers.is_empty() && found.broken.is_empty() {
            self.unknown_issuers.remember(iss, now, generation);
        }
        let mut tenant_matches: Vec<ProviderEntry> = Vec::new();
        for built in found.providers {
            let Some(client_id) = built.provider.client_id().map(str::to_string) else {
                continue;
            };
            if addressed_to(unverified, &client_id) {
                tenant_matches.push(ProviderEntry {
                    client_id,
                    name: built.name,
                    provider: built.provider,
                    tenant: Some(built.tenant),
                });
            }
        }
        // A provider that could not be built still counts where the token is
        // addressed to it: it may be the one the IdP meant, so it neither
        // drops out of an ambiguity nor lets a token through to another.
        // Providers of the issuer the token is not addressed to do not matter.
        let broken: Vec<_> = found
            .broken
            .into_iter()
            .filter(|b| addressed_to(unverified, &b.client_id))
            .collect();
        for b in &broken {
            tracing::warn!(
                tenant = %b.tenant,
                provider = %b.name,
                error = %b.error,
                "back-channel logout: a tenant provider the token is addressed to could not be built"
            );
        }
        if usize::from(global.is_some()) + tenant_matches.len() + broken.len() > 1 {
            return Err(LogoutProviderError::Ambiguous {
                global: global.is_some(),
                tenants: tenant_matches
                    .iter()
                    .filter_map(|e| e.tenant)
                    .chain(broken.iter().map(|b| b.tenant))
                    .collect(),
            });
        }
        if let Some(b) = broken.into_iter().next() {
            return Err(LogoutProviderError::Unavailable {
                tenant: b.tenant,
                name: b.name,
                error: b.error,
            });
        }
        Ok(global.or_else(|| tenant_matches.pop()))
    }
}
