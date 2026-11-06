//! Shared fixtures for the `refresh` `*_tests` modules: the config, clock
//! and store every scenario starts from, and a forwarding spy store. Kept
//! in a dedicated submodule so the per-scenario test files stay focused on
//! assertions rather than scaffolding.

use super::*;

pub(super) fn test_config() -> RefreshTokenConfig {
    RefreshTokenConfig {
        ttl: Duration::days(30),
        max_per_user: 3,
        rotation: true,
        hash_pepper: None,
        // Most scenarios bind a device string without keying the digest.
        allow_unkeyed_hashes: true,
        ..Default::default()
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

/// A refresh store that forwards every call to an in-memory store and
/// counts the compromise hook's calls. [`without_device_index`]
/// (Self::without_device_index) makes it a store that cannot revoke by
/// device, as one written before that method existed.
#[cfg(feature = "device")]
pub(super) struct SpyRefreshStore {
    inner: crate::testing::MemoryRefreshTokenStore,
    compromises: std::sync::atomic::AtomicUsize,
    device_index: bool,
}

#[cfg(feature = "device")]
impl SpyRefreshStore {
    /// A spy over [`store`].
    pub(super) fn new() -> Self {
        Self {
            inner: store(),
            compromises: std::sync::atomic::AtomicUsize::new(0),
            device_index: true,
        }
    }

    /// Answer `revoke_device_tokens` as the trait's provided body does.
    pub(super) fn without_device_index(mut self) -> Self {
        self.device_index = false;
        self
    }

    /// How often the compromise hook ran.
    pub(super) fn compromises(&self) -> usize {
        self.compromises.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(feature = "device")]
impl RefreshTokenStore for SpyRefreshStore {
    type Error = std::convert::Infallible;

    async fn store_token(&self, t: &RefreshToken) -> Result<(), Self::Error> {
        self.inner.store_token(t).await
    }

    async fn find_token(&self, h: &str) -> Result<Option<RefreshToken>, Self::Error> {
        self.inner.find_token(h).await
    }

    async fn revoke_token(&self, id: &RefreshTokenId) -> Result<(), Self::Error> {
        self.inner.revoke_token(id).await
    }

    async fn revoke_user_tokens(&self, u: &UserId) -> Result<(), Self::Error> {
        self.inner.revoke_user_tokens(u).await
    }

    async fn revoke_device_tokens(
        &self,
        t: &TenantId,
        d: &crate::authn::ids::DeviceId,
    ) -> Result<DeviceTokenRevocation, Self::Error> {
        if !self.device_index {
            return Ok(DeviceTokenRevocation::Unsupported);
        }
        self.inner.revoke_device_tokens(t, d).await
    }

    async fn active_tokens(&self, u: &UserId) -> Result<Vec<RefreshToken>, Self::Error> {
        self.inner.active_tokens(u).await
    }

    async fn revoke_family(&self, u: &UserId, f: &TokenFamilyId) -> Result<(), Self::Error> {
        self.inner.revoke_family(u, f).await
    }

    async fn issue_capped(&self, t: &RefreshToken, max: usize) -> Result<(), Self::Error> {
        self.inner.issue_capped(t, max).await
    }

    async fn rotate_token(
        &self,
        p: &RefreshTokenId,
        t: &RefreshToken,
    ) -> Result<RotationOutcome, Self::Error> {
        self.inner.rotate_token(p, t).await
    }

    async fn on_token_compromise(
        &self,
        u: &UserId,
        f: &TokenFamilyId,
        devices: &[(TenantId, crate::authn::ids::DeviceId)],
    ) {
        self.compromises
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.on_token_compromise(u, f, devices).await;
    }
}
