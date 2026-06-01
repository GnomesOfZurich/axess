//! In-memory [`RefreshTokenStore`] for unit tests and single-node
//! development.
//!
//! Backed by the shared [`crate::store::MemoryStore`]. `store_token`
//! delegates to `MemoryStore::put` with `ttl = (token.expires_at -
//! Utc::now()).max(ZERO)` so entries auto-evict at `expires_at`. The
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
use crate::session::refresh::{RefreshToken, RefreshTokenId, RefreshTokenStore, TokenFamilyId};
use crate::store::{MemoryStore, Store};
use chrono::Utc;
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
}

impl RefreshTokenStore for MemoryRefreshTokenStore {
    type Error = MemoryRefreshStoreError;

    async fn store_token(&self, token: &RefreshToken) -> Result<(), Self::Error> {
        // TTL = expires_at - now, saturating at zero. An
        // expired-on-arrival token is stored with TTL=0 → invisible to
        // every subsequent `get`. The store is infallible so the
        // `unwrap_or` is hit on negative chrono durations only.
        let ttl = (token.expires_at - Utc::now())
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
    ) -> Result<(), Self::Error> {
        self.revoke_token(parent_id).await?;
        self.store_token(new_token).await
    }
}
