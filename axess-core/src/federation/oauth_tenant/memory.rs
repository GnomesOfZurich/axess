//! In-memory [`TenantOAuthProviderStore`](super::TenantOAuthProviderStore).

use super::{TenantOAuthProviderRecord, TenantOAuthProviderStore, TenantOAuthProviderStoreError};
use crate::authn::ids::TenantId;
use std::collections::HashMap;
use std::sync::Mutex;

/// Records held in process memory: for tests, single-process tools and
/// deployments whose tenant list is fixed at start. Nothing survives a
/// restart.
#[derive(Default)]
pub struct MemoryTenantOAuthProviderStore {
    records: Mutex<HashMap<(TenantId, String), TenantOAuthProviderRecord>>,
}

impl MemoryTenantOAuthProviderStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(
        &self,
    ) -> std::sync::MutexGuard<'_, HashMap<(TenantId, String), TenantOAuthProviderRecord>> {
        self.records.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl TenantOAuthProviderStore for MemoryTenantOAuthProviderStore {
    async fn get(
        &self,
        tenant: &TenantId,
        name: &str,
    ) -> Result<Option<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
        Ok(self.lock().get(&(*tenant, name.to_string())).cloned())
    }

    async fn put(
        &self,
        mut record: TenantOAuthProviderRecord,
    ) -> Result<TenantOAuthProviderRecord, TenantOAuthProviderStoreError> {
        let mut records = self.lock();
        let key = (record.tenant_id, record.name.clone());
        record.revision = records.get(&key).map_or(1, |old| old.revision + 1);
        records.insert(key, record.clone());
        Ok(record)
    }

    async fn put_if_revision(
        &self,
        mut record: TenantOAuthProviderRecord,
        expected: u64,
    ) -> Result<Option<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
        let mut records = self.lock();
        let key = (record.tenant_id, record.name.clone());
        match records.get(&key) {
            Some(old) if old.revision == expected => {
                record.revision = expected + 1;
                records.insert(key, record.clone());
                Ok(Some(record))
            }
            _ => Ok(None),
        }
    }

    async fn delete(
        &self,
        tenant: &TenantId,
        name: &str,
    ) -> Result<bool, TenantOAuthProviderStoreError> {
        Ok(self.lock().remove(&(*tenant, name.to_string())).is_some())
    }

    async fn list_by_issuer(
        &self,
        issuer: &str,
    ) -> Result<Vec<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
        let mut found: Vec<_> = self
            .lock()
            .values()
            .filter(|r| r.issuer == issuer)
            .cloned()
            .collect();
        found.sort_by(|a, b| {
            (a.tenant_id.to_string(), &a.name).cmp(&(b.tenant_id.to_string(), &b.name))
        });
        Ok(found)
    }

    async fn list(
        &self,
        tenant: &TenantId,
    ) -> Result<Vec<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
        let mut found: Vec<_> = self
            .lock()
            .values()
            .filter(|r| r.tenant_id == *tenant)
            .cloned()
            .collect();
        found.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(found)
    }
}
