//! [`TenantOAuthRecords`]: the directory's records, read-only.

use crate::authn::ids::TenantId;
use crate::federation::oauth_tenant::{
    TenantOAuthProviderRecord, TenantOAuthProviderStore, TenantOAuthProviderStoreError,
};

/// The records of a
/// [`StoredTenantOAuthProviders`](super::StoredTenantOAuthProviders),
/// read-only, as its [`store`](super::StoredTenantOAuthProviders::store)
/// returns them. Nothing written through it skips the directory's checks,
/// because nothing can be written through it.
pub struct TenantOAuthRecords<'a, S> {
    store: &'a S,
}

impl<S> Clone for TenantOAuthRecords<'_, S> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<S> Copy for TenantOAuthRecords<'_, S> {}

impl<S> std::fmt::Debug for TenantOAuthRecords<'_, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TenantOAuthRecords").finish_non_exhaustive()
    }
}

impl<'a, S: TenantOAuthProviderStore> TenantOAuthRecords<'a, S> {
    pub(super) fn new(store: &'a S) -> Self {
        Self { store }
    }

    /// The record for `(tenant, name)`, if any.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub async fn get(
        &self,
        tenant: &TenantId,
        name: &str,
    ) -> Result<Option<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
        self.store.get(tenant, name).await
    }

    /// Every record of `tenant`, by name.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub async fn list(
        &self,
        tenant: &TenantId,
    ) -> Result<Vec<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
        self.store.list(tenant).await
    }

    /// Every record, of any tenant, whose issuer is exactly `issuer`.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub async fn list_by_issuer(
        &self,
        issuer: &str,
    ) -> Result<Vec<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
        self.store.list_by_issuer(issuer).await
    }

    /// Every record of every tenant, ordered by tenant and name.
    ///
    /// # Errors
    ///
    /// The store's error.
    pub async fn list_all(
        &self,
    ) -> Result<Vec<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
        self.store.list_all().await
    }
}
