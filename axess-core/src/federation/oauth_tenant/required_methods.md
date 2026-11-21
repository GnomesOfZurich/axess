# The conditional write and the full listing of `TenantOAuthProviderStore` are required

A store that implements every method compiles:

```rust
# use axess_core::authn::ids::TenantId;
# use axess_core::federation::oauth_tenant::{
#     ReassignedPair, TenantOAuthProviderRecord, TenantOAuthProviderStore,
#     TenantOAuthProviderStoreError,
# };
struct Store;

impl TenantOAuthProviderStore for Store {
#     async fn get(&self, tenant: &TenantId, name: &str) -> Result<Option<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
#         Ok(None)
#     }
#     async fn put(&self, record: TenantOAuthProviderRecord) -> Result<TenantOAuthProviderRecord, TenantOAuthProviderStoreError> {
#         Ok(record)
#     }
#     async fn reassign_pair(&self, record: TenantOAuthProviderRecord) -> Result<ReassignedPair, TenantOAuthProviderStoreError> {
#         Ok(ReassignedPair { stored: record, removed: Vec::new() })
#     }
    async fn put_if_revision(&self, record: TenantOAuthProviderRecord, expected: u64) -> Result<Option<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
        Ok(None)
    }
#     async fn delete(&self, tenant: &TenantId, name: &str) -> Result<bool, TenantOAuthProviderStoreError> {
#         Ok(false)
#     }
#     async fn list_by_issuer(&self, issuer: &str) -> Result<Vec<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
#         Ok(Vec::new())
#     }
#     async fn list(&self, tenant: &TenantId) -> Result<Vec<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
#         Ok(Vec::new())
#     }
    async fn list_all(&self) -> Result<Vec<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
        Ok(Vec::new())
    }
}
# fn main() {}
```

Without `put_if_revision` it does not compile: a store whose conditional write did nothing would let the start-up pass report a move it never made.

```rust,compile_fail,E0046
# use axess_core::authn::ids::TenantId;
# use axess_core::federation::oauth_tenant::{
#     ReassignedPair, TenantOAuthProviderRecord, TenantOAuthProviderStore,
#     TenantOAuthProviderStoreError,
# };
struct Store;

impl TenantOAuthProviderStore for Store {
#     async fn get(&self, tenant: &TenantId, name: &str) -> Result<Option<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
#         Ok(None)
#     }
#     async fn put(&self, record: TenantOAuthProviderRecord) -> Result<TenantOAuthProviderRecord, TenantOAuthProviderStoreError> {
#         Ok(record)
#     }
#     async fn reassign_pair(&self, record: TenantOAuthProviderRecord) -> Result<ReassignedPair, TenantOAuthProviderStoreError> {
#         Ok(ReassignedPair { stored: record, removed: Vec::new() })
#     }
#     async fn delete(&self, tenant: &TenantId, name: &str) -> Result<bool, TenantOAuthProviderStoreError> {
#         Ok(false)
#     }
#     async fn list_by_issuer(&self, issuer: &str) -> Result<Vec<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
#         Ok(Vec::new())
#     }
#     async fn list(&self, tenant: &TenantId) -> Result<Vec<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
#         Ok(Vec::new())
#     }
    async fn list_all(&self) -> Result<Vec<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
        Ok(Vec::new())
    }
}
# fn main() {}
```

Without `list_all` it does not compile: a store the start-up pass cannot list would leave earlier-binding credentials where the pass never reaches them.

```rust,compile_fail,E0046
# use axess_core::authn::ids::TenantId;
# use axess_core::federation::oauth_tenant::{
#     ReassignedPair, TenantOAuthProviderRecord, TenantOAuthProviderStore,
#     TenantOAuthProviderStoreError,
# };
struct Store;

impl TenantOAuthProviderStore for Store {
#     async fn get(&self, tenant: &TenantId, name: &str) -> Result<Option<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
#         Ok(None)
#     }
#     async fn put(&self, record: TenantOAuthProviderRecord) -> Result<TenantOAuthProviderRecord, TenantOAuthProviderStoreError> {
#         Ok(record)
#     }
#     async fn reassign_pair(&self, record: TenantOAuthProviderRecord) -> Result<ReassignedPair, TenantOAuthProviderStoreError> {
#         Ok(ReassignedPair { stored: record, removed: Vec::new() })
#     }
    async fn put_if_revision(&self, record: TenantOAuthProviderRecord, expected: u64) -> Result<Option<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
        Ok(None)
    }
#     async fn delete(&self, tenant: &TenantId, name: &str) -> Result<bool, TenantOAuthProviderStoreError> {
#         Ok(false)
#     }
#     async fn list_by_issuer(&self, issuer: &str) -> Result<Vec<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
#         Ok(Vec::new())
#     }
#     async fn list(&self, tenant: &TenantId) -> Result<Vec<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
#         Ok(Vec::new())
#     }
}
# fn main() {}
```
