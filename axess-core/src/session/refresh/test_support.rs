//! Shared fixtures for the `refresh` sibling test modules.
//!
//! Hosts the `MockRng` / `MemoryRefreshTokenStore` / per-test fixture
//! helpers consumed by `basics`, `atomic_rotation`, `device_cascade`,
//! and `status_check`. Kept in a dedicated submodule so the per-scenario
//! test files stay focused on assertions rather than scaffolding.

use super::*;

pub(super) fn test_config() -> RefreshTokenConfig {
    RefreshTokenConfig {
        ttl: Duration::days(30),
        max_per_user: 3,
        rotation: true,
        hash_pepper: None,
    }
}

pub(super) fn now() -> DateTime<Utc> {
    Utc::now()
}

pub(super) fn fixture_user() -> UserId {
    axess_identity::testing::user("user-1")
}

pub(super) fn fixture_tenant() -> TenantId {
    axess_identity::testing::tenant("tenant-1")
}
