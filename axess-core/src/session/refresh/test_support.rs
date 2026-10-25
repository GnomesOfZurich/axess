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

/// The fixed instant the refresh tests run at.
pub(super) fn now() -> DateTime<Utc> {
    use chrono::TimeZone;
    Utc.with_ymd_and_hms(2031, 3, 1, 12, 0, 0).unwrap()
}

/// A store whose clock is [`now`], so row expiry does not depend on when the
/// test runs.
pub(super) fn store() -> crate::testing::MemoryRefreshTokenStore {
    crate::testing::MemoryRefreshTokenStore::new().with_clock(std::sync::Arc::new(
        axess_clock::testing::MockClock::at(now()),
    ))
}

pub(super) fn fixture_user() -> UserId {
    axess_identity::testing::user("user-1")
}

pub(super) fn fixture_tenant() -> TenantId {
    axess_identity::testing::tenant("tenant-1")
}
