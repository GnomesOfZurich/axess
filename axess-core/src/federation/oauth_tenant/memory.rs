//! In-memory [`TenantOAuthProviderStore`](super::TenantOAuthProviderStore).

use super::{
    ReassignedPair, TenantOAuthProviderRecord, TenantOAuthProviderStore,
    TenantOAuthProviderStoreError,
};
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

/// Whether a record other than `record` itself holds its issuer and client id.
fn pair_held_by_another(
    records: &HashMap<(TenantId, String), TenantOAuthProviderRecord>,
    record: &TenantOAuthProviderRecord,
) -> bool {
    records.iter().any(|((tenant, name), other)| {
        (*tenant, name.as_str()) != (record.tenant_id, record.name.as_str())
            && other.issuer == record.issuer
            && other.client_id == record.client_id
    })
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
        if pair_held_by_another(&records, &record) {
            return Err(TenantOAuthProviderStoreError::pair_held());
        }
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
                if pair_held_by_another(&records, &record) {
                    return Err(TenantOAuthProviderStoreError::pair_held());
                }
                record.revision = expected + 1;
                records.insert(key, record.clone());
                Ok(Some(record))
            }
            _ => Ok(None),
        }
    }

    async fn reassign_pair(
        &self,
        mut record: TenantOAuthProviderRecord,
    ) -> Result<ReassignedPair, TenantOAuthProviderStoreError> {
        let mut records = self.lock();
        let key = (record.tenant_id, record.name.clone());
        let holders: Vec<_> = records
            .iter()
            .filter(|(other, held)| {
                **other != key && held.issuer == record.issuer && held.client_id == record.client_id
            })
            .map(|(other, _)| other.clone())
            .collect();
        let holders: Vec<_> = holders
            .iter()
            .filter_map(|holder| records.remove(holder))
            .collect();
        record.revision = records.get(&key).map_or(1, |old| old.revision + 1);
        records.insert(key, record.clone());
        Ok(ReassignedPair {
            stored: record,
            removed: holders,
        })
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

    async fn list_all(
        &self,
    ) -> Result<Vec<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
        let mut found: Vec<_> = self.lock().values().cloned().collect();
        found.sort_by(|a, b| {
            (a.tenant_id.to_string(), &a.name).cmp(&(b.tenant_id.to_string(), &b.name))
        });
        Ok(found)
    }
}
