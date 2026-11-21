# The passkey credential-id methods of `FactorStore` are required

A store that implements every method compiles:

```rust
# use axess_core::authn::factor::{FactorConfig, FactorKind};
# use axess_core::authn::ids::{TenantId, UserId};
# use axess_core::authn::store::{AuthMethod, FactorStore, Fido2CredentialClaim, ResolvedFactor};
# use axess_core::authn::types::AuthnScope;
# #[derive(Debug)]
# struct Never;
# impl std::fmt::Display for Never {
#     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("never") }
# }
# impl std::error::Error for Never {}
struct Store;

impl FactorStore for Store {
    type Error = Never;
#     async fn resolve_factor(&self, scope: &AuthnScope, kind: FactorKind) -> Result<Option<ResolvedFactor>, Never> {
#         Ok(None)
#     }
#     async fn load_factor(&self, scope: &AuthnScope, kind: FactorKind) -> Result<Option<FactorConfig>, Never> {
#         Ok(None)
#     }
#     async fn save_factor(&self, scope: &AuthnScope, config: FactorConfig) -> Result<(), Never> {
#         Ok(())
#     }
#     async fn compare_and_save_factor(&self, scope: &AuthnScope, prior: &FactorConfig, updated: FactorConfig) -> Result<bool, Never> {
#         Ok(false)
#     }
#     async fn insert_factor_if_absent(&self, scope: &AuthnScope, config: FactorConfig) -> Result<bool, Never> {
#         Ok(false)
#     }
#     async fn available_methods(&self, user_id: &UserId, tenant_id: &TenantId) -> Result<Vec<AuthMethod>, Never> {
#         Ok(Vec::new())
#     }
#     async fn save_method(&self, scope: &AuthnScope, method: AuthMethod) -> Result<(), Never> {
#         Ok(())
#     }
#     async fn remove_method(&self, scope: &AuthnScope, name: &str) -> Result<(), Never> {
#         Ok(())
#     }
#     async fn set_method_enabled(&self, scope: &AuthnScope, name: &str, enabled: bool) -> Result<bool, Never> {
#         Ok(false)
#     }
    async fn claim_fido2_credential(&self, tenant_id: &TenantId, user_id: &UserId, credential_id: &[u8]) -> Result<Fido2CredentialClaim, Never> {
        Ok(Fido2CredentialClaim::Refused)
    }
    async fn release_fido2_credential(&self, tenant_id: &TenantId, user_id: &UserId, credential_id: &[u8]) -> Result<(), Never> {
        Ok(())
    }
}
# fn main() {}
```

Without `claim_fido2_credential` it does not compile: a store without an atomic claim does not compile.

```rust,compile_fail,E0046
# use axess_core::authn::factor::{FactorConfig, FactorKind};
# use axess_core::authn::ids::{TenantId, UserId};
# use axess_core::authn::store::{AuthMethod, FactorStore, Fido2CredentialClaim, ResolvedFactor};
# use axess_core::authn::types::AuthnScope;
# #[derive(Debug)]
# struct Never;
# impl std::fmt::Display for Never {
#     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("never") }
# }
# impl std::error::Error for Never {}
struct Store;

impl FactorStore for Store {
    type Error = Never;
#     async fn resolve_factor(&self, scope: &AuthnScope, kind: FactorKind) -> Result<Option<ResolvedFactor>, Never> {
#         Ok(None)
#     }
#     async fn load_factor(&self, scope: &AuthnScope, kind: FactorKind) -> Result<Option<FactorConfig>, Never> {
#         Ok(None)
#     }
#     async fn save_factor(&self, scope: &AuthnScope, config: FactorConfig) -> Result<(), Never> {
#         Ok(())
#     }
#     async fn compare_and_save_factor(&self, scope: &AuthnScope, prior: &FactorConfig, updated: FactorConfig) -> Result<bool, Never> {
#         Ok(false)
#     }
#     async fn insert_factor_if_absent(&self, scope: &AuthnScope, config: FactorConfig) -> Result<bool, Never> {
#         Ok(false)
#     }
#     async fn available_methods(&self, user_id: &UserId, tenant_id: &TenantId) -> Result<Vec<AuthMethod>, Never> {
#         Ok(Vec::new())
#     }
#     async fn save_method(&self, scope: &AuthnScope, method: AuthMethod) -> Result<(), Never> {
#         Ok(())
#     }
#     async fn remove_method(&self, scope: &AuthnScope, name: &str) -> Result<(), Never> {
#         Ok(())
#     }
#     async fn set_method_enabled(&self, scope: &AuthnScope, name: &str, enabled: bool) -> Result<bool, Never> {
#         Ok(false)
#     }
    async fn release_fido2_credential(&self, tenant_id: &TenantId, user_id: &UserId, credential_id: &[u8]) -> Result<(), Never> {
        Ok(())
    }
}
# fn main() {}
```

Without `release_fido2_credential` it does not compile: a store that never releases a claim does not compile.

```rust,compile_fail,E0046
# use axess_core::authn::factor::{FactorConfig, FactorKind};
# use axess_core::authn::ids::{TenantId, UserId};
# use axess_core::authn::store::{AuthMethod, FactorStore, Fido2CredentialClaim, ResolvedFactor};
# use axess_core::authn::types::AuthnScope;
# #[derive(Debug)]
# struct Never;
# impl std::fmt::Display for Never {
#     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("never") }
# }
# impl std::error::Error for Never {}
struct Store;

impl FactorStore for Store {
    type Error = Never;
#     async fn resolve_factor(&self, scope: &AuthnScope, kind: FactorKind) -> Result<Option<ResolvedFactor>, Never> {
#         Ok(None)
#     }
#     async fn load_factor(&self, scope: &AuthnScope, kind: FactorKind) -> Result<Option<FactorConfig>, Never> {
#         Ok(None)
#     }
#     async fn save_factor(&self, scope: &AuthnScope, config: FactorConfig) -> Result<(), Never> {
#         Ok(())
#     }
#     async fn compare_and_save_factor(&self, scope: &AuthnScope, prior: &FactorConfig, updated: FactorConfig) -> Result<bool, Never> {
#         Ok(false)
#     }
#     async fn insert_factor_if_absent(&self, scope: &AuthnScope, config: FactorConfig) -> Result<bool, Never> {
#         Ok(false)
#     }
#     async fn available_methods(&self, user_id: &UserId, tenant_id: &TenantId) -> Result<Vec<AuthMethod>, Never> {
#         Ok(Vec::new())
#     }
#     async fn save_method(&self, scope: &AuthnScope, method: AuthMethod) -> Result<(), Never> {
#         Ok(())
#     }
#     async fn remove_method(&self, scope: &AuthnScope, name: &str) -> Result<(), Never> {
#         Ok(())
#     }
#     async fn set_method_enabled(&self, scope: &AuthnScope, name: &str, enabled: bool) -> Result<bool, Never> {
#         Ok(false)
#     }
    async fn claim_fido2_credential(&self, tenant_id: &TenantId, user_id: &UserId, credential_id: &[u8]) -> Result<Fido2CredentialClaim, Never> {
        Ok(Fido2CredentialClaim::Refused)
    }
}
# fn main() {}
```

A claim that answers a `bool` does not compile: a refusal names its holder, or says that it names none, in the claim's own answer. The store is the first one above with only the claim's answer changed.

```rust,compile_fail,E0271
# use axess_core::authn::factor::{FactorConfig, FactorKind};
# use axess_core::authn::ids::{TenantId, UserId};
# use axess_core::authn::store::{AuthMethod, FactorStore, Fido2CredentialClaim, ResolvedFactor};
# use axess_core::authn::types::AuthnScope;
# #[derive(Debug)]
# struct Never;
# impl std::fmt::Display for Never {
#     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("never") }
# }
# impl std::error::Error for Never {}
struct Store;

impl FactorStore for Store {
    type Error = Never;
#     async fn resolve_factor(&self, scope: &AuthnScope, kind: FactorKind) -> Result<Option<ResolvedFactor>, Never> {
#         Ok(None)
#     }
#     async fn load_factor(&self, scope: &AuthnScope, kind: FactorKind) -> Result<Option<FactorConfig>, Never> {
#         Ok(None)
#     }
#     async fn save_factor(&self, scope: &AuthnScope, config: FactorConfig) -> Result<(), Never> {
#         Ok(())
#     }
#     async fn compare_and_save_factor(&self, scope: &AuthnScope, prior: &FactorConfig, updated: FactorConfig) -> Result<bool, Never> {
#         Ok(false)
#     }
#     async fn insert_factor_if_absent(&self, scope: &AuthnScope, config: FactorConfig) -> Result<bool, Never> {
#         Ok(false)
#     }
#     async fn available_methods(&self, user_id: &UserId, tenant_id: &TenantId) -> Result<Vec<AuthMethod>, Never> {
#         Ok(Vec::new())
#     }
#     async fn save_method(&self, scope: &AuthnScope, method: AuthMethod) -> Result<(), Never> {
#         Ok(())
#     }
#     async fn remove_method(&self, scope: &AuthnScope, name: &str) -> Result<(), Never> {
#         Ok(())
#     }
#     async fn set_method_enabled(&self, scope: &AuthnScope, name: &str, enabled: bool) -> Result<bool, Never> {
#         Ok(false)
#     }
    async fn claim_fido2_credential(&self, tenant_id: &TenantId, user_id: &UserId, credential_id: &[u8]) -> Result<bool, Never> {
        Ok(false)
    }
    async fn release_fido2_credential(&self, tenant_id: &TenantId, user_id: &UserId, credential_id: &[u8]) -> Result<(), Never> {
        Ok(())
    }
}
# fn main() {}
```
