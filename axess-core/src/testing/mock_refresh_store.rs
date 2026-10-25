//! In-memory [`RefreshTokenStore`] for unit tests and single-node
//! development.
//!
//! Backed by the shared [`crate::store::MemoryStore`]. `store_token`
//! delegates to `MemoryStore::put` with `ttl = (token.expires_at -
//! clock.now()).max(ZERO)`, where `clock` is the store's injected clock
//! ([`with_clock`](MemoryRefreshTokenStore::with_clock), default the system
//! clock), so entries auto-evict at `expires_at`. The
//! secondary-index operations (`find_token`, `active_tokens`,
//! `revoke_*`) use the backend's `snapshot()` + `update()` helpers
//! because the `Store<K, V>` trait carries no iteration primitive.
//!
//! **Not suitable for production.** The lookup path is a linear scan
//! over the snapshot (leaking timing information), there's no
//! persistence across restarts, and contents are not encrypted at
//! rest. Matches the positioning of the other `mock_*` doubles in
//! this module.

use crate::authn::ids::UserId;
use crate::session::refresh::{
    RefreshToken, RefreshTokenId, RefreshTokenStore, RotationOutcome, TokenFamilyId,
};
use crate::store::{MemoryStore, Store};
use axess_clock::Clock;
use std::sync::Arc;
use std::time::Duration;

/// In-memory refresh token store backed by [`MemoryStore`].
#[derive(Clone, Default)]
pub struct MemoryRefreshTokenStore {
    inner: MemoryStore<RefreshTokenId, RefreshToken>,
}

/// Infallible error for the in-memory refresh token store. Aliased to
/// `std::convert::Infallible` so the empty error type behaves the
/// canonical way in `?`-propagation and exhaustive matches.
pub type MemoryRefreshStoreError = std::convert::Infallible;

impl MemoryRefreshTokenStore {
    /// Create an empty in-memory refresh token store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Drive row expiry from `clock` instead of the system clock, so a test
    /// outlives a token by advancing a mock clock.
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.inner = self.inner.with_clock(clock);
        self
    }
}

impl RefreshTokenStore for MemoryRefreshTokenStore {
    type Error = MemoryRefreshStoreError;

    async fn store_token(&self, token: &RefreshToken) -> Result<(), Self::Error> {
        // TTL = expires_at - the store's now, saturating at zero. An
        // expired-on-arrival token is stored with TTL=0 → invisible to
        // every subsequent `get`. The store is infallible so the
        // `unwrap_or` is hit on negative chrono durations only.
        let ttl = (token.expires_at - self.inner.clock().now())
            .to_std()
            .unwrap_or(Duration::ZERO);
        self.inner.put(&token.id, token, ttl).await
    }

    async fn find_token(&self, token_hash: &str) -> Result<Option<RefreshToken>, Self::Error> {
        // Linear scan over the snapshot; fine for tests; production
        // backends index by `token_hash` directly.
        let found = self
            .inner
            .snapshot()
            .into_iter()
            .find(|(_, t)| t.token_hash == token_hash)
            .map(|(_, t)| t);
        Ok(found)
    }

    async fn revoke_token(&self, token_id: &RefreshTokenId) -> Result<(), Self::Error> {
        self.inner.update(token_id, |t| t.revoked = true);
        Ok(())
    }

    async fn revoke_user_tokens(&self, user_id: &UserId) -> Result<(), Self::Error> {
        for (id, token) in self.inner.snapshot() {
            if &token.user_id == user_id {
                self.inner.update(&id, |t| t.revoked = true);
            }
        }
        Ok(())
    }

    async fn revoke_family(
        &self,
        user_id: &UserId,
        family_id: &TokenFamilyId,
    ) -> Result<(), Self::Error> {
        for (id, token) in self.inner.snapshot() {
            if &token.user_id == user_id && token.family_id.as_ref() == Some(family_id) {
                self.inner.update(&id, |t| t.revoked = true);
            }
        }
        Ok(())
    }

    async fn active_tokens(&self, user_id: &UserId) -> Result<Vec<RefreshToken>, Self::Error> {
        let mut tokens: Vec<RefreshToken> = self
            .inner
            .snapshot()
            .into_iter()
            .filter(|(_, t)| &t.user_id == user_id && !t.revoked)
            .map(|(_, t)| t)
            .collect();
        tokens.sort_by_key(|t| t.issued_at);
        Ok(tokens)
    }

    // ── Required transactional methods ──────────────────────────────────
    //
    // The in-memory store is single-process and infallible, so atomicity
    // is trivially satisfied: each individual `update`/`put` call holds
    // the shared map lock for the duration of its mutation, and the
    // observable end state matches a transactional revoke+insert.

    async fn issue_with_eviction(
        &self,
        evict_ids: &[RefreshTokenId],
        new_token: &RefreshToken,
    ) -> Result<(), Self::Error> {
        for id in evict_ids {
            self.revoke_token(id).await?;
        }
        self.store_token(new_token).await
    }

    async fn rotate_token(
        &self,
        parent_id: &RefreshTokenId,
        new_token: &RefreshToken,
    ) -> Result<RotationOutcome, Self::Error> {
        // Conditional, as the contract requires: the parent is revoked only
        // if it was not already, and that test-and-set happens under the
        // map's per-entry lock. A parent already revoked (or gone) means a
        // parallel refresh won, and nothing is stored.
        let mut won = false;
        let existed = self.inner.update(parent_id, |t| {
            if !t.revoked {
                t.revoked = true;
                won = true;
            }
        });
        if !(existed && won) {
            return Ok(RotationOutcome::ParentAlreadyRevoked);
        }
        self.store_token(new_token).await?;
        Ok(RotationOutcome::Rotated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::refresh::RefreshTokenId;
    use axess_rng::testing::MockRng;
    use chrono::Utc;
    use std::sync::Arc;

    fn token(rng: &MockRng, user: UserId, hash: &str) -> RefreshToken {
        let now = Utc::now();
        RefreshToken {
            id: RefreshTokenId::new(rng),
            user_id: user,
            tenant_id: axess_identity::testing::tenant("t1"),
            token_hash: hash.to_string(),
            issued_at: now,
            expires_at: now + chrono::Duration::days(1),
            revoked: false,
            device_info: None,
            family_id: None,
            device_id: None,
            authn_time: None,
        }
    }

    /// Row expiry follows the injected clock: a token is visible until the
    /// mock clock passes its `expires_at`, whatever the real date is.
    #[tokio::test]
    async fn rows_expire_on_the_injected_clock() {
        use chrono::TimeZone;
        let origin = Utc.with_ymd_and_hms(2031, 3, 1, 12, 0, 0).unwrap();
        let clock = axess_clock::testing::MockClock::at(origin);
        let store = MemoryRefreshTokenStore::new().with_clock(Arc::new(clock.clone()));
        let mut t = token(&MockRng::new(3), axess_identity::testing::user("u1"), "h");
        t.issued_at = origin;
        t.expires_at = origin + chrono::Duration::days(1);
        store.store_token(&t).await.unwrap();

        clock.advance(chrono::Duration::hours(23));
        assert!(store.find_token("h").await.unwrap().is_some());
        clock.advance(chrono::Duration::hours(2));
        assert!(store.find_token("h").await.unwrap().is_none());
    }

    /// Of N parallel rotations of one parent, exactly one stores a child.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn parallel_rotations_of_one_parent_yield_one_child() {
        let rng = MockRng::new(1);
        let user = axess_identity::testing::user("u1");
        for round in 0..200 {
            let store = Arc::new(MemoryRefreshTokenStore::new());
            let parent = token(&rng, user, &format!("parent-{round}"));
            store.store_token(&parent).await.unwrap();
            let tasks: Vec<_> = (0..8)
                .map(|i| {
                    let store = store.clone();
                    let child = token(&rng, user, &format!("child-{round}-{i}"));
                    let parent_id = parent.id;
                    tokio::spawn(
                        async move { store.rotate_token(&parent_id, &child).await.unwrap() },
                    )
                })
                .collect();
            let mut rotated = 0;
            for task in tasks {
                if matches!(task.await.unwrap(), RotationOutcome::Rotated) {
                    rotated += 1;
                }
            }
            assert_eq!(rotated, 1, "round {round}: {rotated} rotations won");
            assert_eq!(store.active_tokens(&user).await.unwrap().len(), 1);
        }
    }
}
