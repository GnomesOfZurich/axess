//! Regression: a backend whose `rotate_token` fails atomically
//! (revokes nothing, inserts nothing) leaves the parent token usable so
//! the user is not silently logged out of every device.

use super::test_support::{fixture_tenant, fixture_user, now, store, test_config};
use super::*;
use crate::authn::ids::DeviceId;
use crate::testing::{MemoryRefreshTokenStore, mock_random::MockRng};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Wraps `MemoryRefreshTokenStore` with an injectable `rotate_token`
/// failure that does NOT touch the underlying store. Models a
/// production transactional backend whose BEGIN…ROLLBACK leaves no
/// changes behind on commit failure.
struct AtomicRotateStore {
    inner: MemoryRefreshTokenStore,
    fail_rotate: AtomicBool,
    fail_revoke_family: AtomicBool,
    compromise_calls: AtomicUsize,
}

impl AtomicRotateStore {
    fn new() -> Self {
        Self {
            inner: store(),
            fail_rotate: AtomicBool::new(false),
            fail_revoke_family: AtomicBool::new(false),
            compromise_calls: AtomicUsize::new(0),
        }
    }

    fn arm_rotate_failure(&self) {
        self.fail_rotate.store(true, Ordering::SeqCst);
    }
}

impl RefreshTokenStore for AtomicRotateStore {
    type Error = std::io::Error;

    async fn store_token(&self, token: &RefreshToken) -> Result<(), Self::Error> {
        self.inner
            .store_token(token)
            .await
            .map_err(std::io::Error::other)
    }

    async fn find_token(&self, token_hash: &str) -> Result<Option<RefreshToken>, Self::Error> {
        self.inner
            .find_token(token_hash)
            .await
            .map_err(std::io::Error::other)
    }

    async fn revoke_token(&self, token_id: &RefreshTokenId) -> Result<(), Self::Error> {
        self.inner
            .revoke_token(token_id)
            .await
            .map_err(std::io::Error::other)
    }

    async fn revoke_user_tokens(&self, user_id: &UserId) -> Result<(), Self::Error> {
        self.inner
            .revoke_user_tokens(user_id)
            .await
            .map_err(std::io::Error::other)
    }

    async fn revoke_family(
        &self,
        user_id: &UserId,
        family_id: &TokenFamilyId,
    ) -> Result<(), Self::Error> {
        if self.fail_revoke_family.load(Ordering::SeqCst) {
            return Err(std::io::Error::other("simulated revoke failure"));
        }
        self.inner
            .revoke_family(user_id, family_id)
            .await
            .map_err(std::io::Error::other)
    }

    async fn active_tokens(&self, user_id: &UserId) -> Result<Vec<RefreshToken>, Self::Error> {
        self.inner
            .active_tokens(user_id)
            .await
            .map_err(std::io::Error::other)
    }

    async fn rotate_token(
        &self,
        parent_id: &RefreshTokenId,
        new_token: &RefreshToken,
    ) -> Result<RotationOutcome, Self::Error> {
        if self.fail_rotate.load(Ordering::SeqCst) {
            // Atomic failure; touch nothing, just like a transaction
            // that hits a constraint violation and is ROLLBACK'd.
            return Err(std::io::Error::other("simulated commit failure"));
        }
        // Otherwise the production-correct atomic path, delegated to the
        // memory store, whose revoke is conditional on the parent being live.
        self.inner
            .rotate_token(parent_id, new_token)
            .await
            .map_err(std::io::Error::other)
    }

    async fn on_token_compromise(
        &self,
        _user_id: &UserId,
        _family_id: &TokenFamilyId,
        _compromised_devices: &[(TenantId, DeviceId)],
    ) {
        self.compromise_calls.fetch_add(1, Ordering::SeqCst);
    }

    async fn issue_capped(
        &self,
        new_token: &RefreshToken,
        max_per_user: usize,
    ) -> Result<(), Self::Error> {
        self.inner
            .issue_capped(new_token, max_per_user)
            .await
            .map_err(std::io::Error::other)
    }
}

#[tokio::test]
async fn atomic_rotate_failure_keeps_parent_usable() {
    let store = AtomicRotateStore::new();
    let config = test_config();
    let rng = MockRng::new(123);
    let ts = now();

    let (parent_plaintext, _) = issue_refresh_token(
        IssueRequest {
            user_id: &fixture_user(),
            tenant_id: &fixture_tenant(),
            device_info: None,
            family_id: None,
            device_id: None,
        },
        &config,
        &store,
        &rng,
        ts,
    )
    .await
    .unwrap();

    // Arm rotate to fail atomically.
    store.arm_rotate_failure();

    let result = refresh_session(&parent_plaintext, &store, &config, &rng, ts, None).await;
    assert!(matches!(result, Err(RefreshError::Store(_))));

    // The parent must still be active; atomic failure means the
    // revoke didn't happen either. Disarm and retry to confirm the
    // user can still authenticate from the same token.
    store.fail_rotate.store(false, Ordering::SeqCst);
    let (session, new_token) = refresh_session(&parent_plaintext, &store, &config, &rng, ts, None)
        .await
        .expect("post-failure retry must succeed: silent-logout regression");
    assert!(session.auth_state.is_authenticated());
    assert!(new_token.is_some());
}

#[tokio::test]
async fn rotate_token_on_memory_store_revokes_parent_and_stores_child() {
    // `MemoryRefreshTokenStore::rotate_token` is single-process and
    // infallible, so the revoke + insert pair is observably atomic.
    // This test pins the post-rotation state: the parent record is
    // marked revoked and the active set carries only the new child.
    let store = store();
    let config = test_config();
    let rng = MockRng::new(456);
    let ts = now();

    let (parent_plaintext, parent_record) = issue_refresh_token(
        IssueRequest {
            user_id: &fixture_user(),
            tenant_id: &fixture_tenant(),
            device_info: None,
            family_id: None,
            device_id: None,
        },
        &config,
        &store,
        &rng,
        ts,
    )
    .await
    .unwrap();

    let (_, new_token) = refresh_session(&parent_plaintext, &store, &config, &rng, ts, None)
        .await
        .unwrap();
    let (_, new_record) = new_token.unwrap();

    // Parent is revoked, child is active.
    let active = store.active_tokens(&fixture_user()).await.unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].id, new_record.id);
    assert_ne!(active[0].id, parent_record.id);
}

/// Two rotations of one parent: the second finds it revoked, stores nothing
/// and answers `ParentAlreadyRevoked`, which the caller treats as reuse.
/// Before, both succeeded and two live children existed.
#[tokio::test]
async fn second_rotation_of_the_same_parent_is_refused() {
    let store = AtomicRotateStore::new();
    let config = test_config();
    let rng = MockRng::new(457);
    let ts = now();
    let user = fixture_user();
    let tenant = fixture_tenant();
    let mut issued = Vec::with_capacity(3);
    for _ in 0..3 {
        let request = IssueRequest {
            user_id: &user,
            tenant_id: &tenant,
            device_info: None,
            family_id: None,
            device_id: None,
        };
        let (_, record) = issue_refresh_token(request, &config, &store, &rng, ts)
            .await
            .unwrap();
        issued.push(record);
    }
    let (parent, child_a, child_b) = (&issued[0], &issued[1], &issued[2]);

    assert_eq!(
        store.rotate_token(&parent.id, child_a).await.unwrap(),
        RotationOutcome::Rotated
    );
    assert_eq!(
        store.rotate_token(&parent.id, child_b).await.unwrap(),
        RotationOutcome::ParentAlreadyRevoked,
        "a parent already revoked is a lost race, not a second rotation"
    );
}

/// The caller maps a lost race to a reuse: the second refresh with one token
/// is refused as revoked, and the family is revoked with it.
#[tokio::test]
async fn second_refresh_with_one_token_is_refused_as_reuse() {
    let store = AtomicRotateStore::new();
    let config = test_config();
    let rng = MockRng::new(458);
    let ts = now();
    let (plaintext, _parent) = issue_refresh_token(
        IssueRequest {
            user_id: &fixture_user(),
            tenant_id: &fixture_tenant(),
            device_info: None,
            family_id: None,
            device_id: None,
        },
        &config,
        &store,
        &rng,
        ts,
    )
    .await
    .unwrap();
    assert!(
        refresh_session(&plaintext, &store, &config, &rng, ts, None)
            .await
            .is_ok()
    );
    let second = refresh_session(&plaintext, &store, &config, &rng, ts, None).await;
    assert!(
        matches!(second, Err(RefreshError::Revoked)),
        "the second use of one token is a reuse: {second:?}"
    );
    assert!(
        store
            .active_tokens(&fixture_user())
            .await
            .unwrap()
            .is_empty(),
        "reuse revokes the whole family"
    );
}

/// When revoking the family of a reused token fails, the caller gets the
/// store's error rather than `Revoked`, and the compromise hook does not run:
/// the hook's contract is "called after `revoke_family` has revoked the
/// family", and reporting `Revoked` would tell the caller a compromise was
/// handled when the family is still live. The reused token itself is refused
/// either way (an `Err`, never a session).
#[tokio::test]
async fn failed_family_revoke_on_reuse_is_a_store_error_and_not_a_handled_compromise() {
    let store = AtomicRotateStore::new();
    let config = test_config();
    let rng = MockRng::new(459);
    let ts = now();
    let (plaintext, _parent) = issue_refresh_token(
        IssueRequest {
            user_id: &fixture_user(),
            tenant_id: &fixture_tenant(),
            device_info: None,
            family_id: None,
            device_id: None,
        },
        &config,
        &store,
        &rng,
        ts,
    )
    .await
    .unwrap();
    refresh_session(&plaintext, &store, &config, &rng, ts, None)
        .await
        .unwrap();

    store.fail_revoke_family.store(true, Ordering::SeqCst);
    let reuse = refresh_session(&plaintext, &store, &config, &rng, ts, None).await;
    assert!(
        matches!(reuse, Err(RefreshError::Store(_))),
        "a failed revoke is reported as the store error it is: {reuse:?}"
    );
    assert_eq!(
        store.compromise_calls.load(Ordering::SeqCst),
        0,
        "the hook runs only after the family was revoked"
    );

    store.fail_revoke_family.store(false, Ordering::SeqCst);
    let retry = refresh_session(&plaintext, &store, &config, &rng, ts, None).await;
    assert!(matches!(retry, Err(RefreshError::Revoked)));
    assert_eq!(store.compromise_calls.load(Ordering::SeqCst), 1);
}
