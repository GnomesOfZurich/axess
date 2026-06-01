//! `refresh_session_with_status_check` gates rotation on the
//! caller's status predicate.

use super::test_support::{fixture_tenant, fixture_user, now, test_config};
use super::*;
use crate::testing::{MemoryRefreshTokenStore, mock_random::MockRng};

/// Predicate returns `true` → behaves identically to bare
/// [`refresh_session`]: rotation succeeds, new token is issued.
#[tokio::test]
async fn status_check_true_allows_rotation() {
    let store = MemoryRefreshTokenStore::new();
    let config = test_config();
    let rng = MockRng::new(331);
    let ts = now();

    let (plaintext, _) = issue_refresh_token(
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

    let (session, new_token) = refresh_session_with_status_check(
        &plaintext,
        &store,
        &config,
        &rng,
        ts,
        None,
        |_user_id| async { true },
    )
    .await
    .expect("status=true must allow refresh");

    assert!(session.auth_state.is_authenticated());
    assert!(
        new_token.is_some(),
        "rotation must run when status check passes"
    );
}

/// Predicate returns `false` → returns `RefreshError::AccountInactive`
/// AND the original token stays unrotated. This is load-bearing for
/// the status-check contract: the legitimate user's family must survive
/// a transient `false` (e.g. a momentary suspend) so unsuspension
/// restores access without forcing a full re-login.
#[tokio::test]
async fn status_check_false_refuses_and_preserves_token() {
    let store = MemoryRefreshTokenStore::new();
    let config = test_config();
    let rng = MockRng::new(332);
    let ts = now();

    let (plaintext, original_record) = issue_refresh_token(
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

    let err = refresh_session_with_status_check(
        &plaintext,
        &store,
        &config,
        &rng,
        ts,
        None,
        |_user_id| async { false },
    )
    .await
    .expect_err("status=false must refuse refresh");

    assert!(
        matches!(err, RefreshError::AccountInactive),
        "expected AccountInactive, got {err:?}"
    );

    // Original token must still be present and not revoked; the
    // refusal is non-destructive so a later un-suspension can use
    // the same family.
    let token_hash = hash_token(&plaintext, config.hash_pepper.as_deref());
    let still_there = store
        .find_token(&token_hash)
        .await
        .unwrap()
        .expect("refused refresh must NOT consume the token");
    assert!(
        !still_there.revoked,
        "refused refresh must NOT revoke the token"
    );
    // The record id is unchanged; no rotation happened.
    assert_eq!(still_there.id, original_record.id);
}

/// A revoked-token reuse takes priority over the status
/// check: the family-revocation cascade must run regardless of
/// account status (a stolen token from a still-active account is
/// the worst case the cascade exists for, and a stolen token from
/// an already-suspended account should still trip the cascade so
/// SOC sees the compromise signal).
#[tokio::test]
async fn revoked_token_bypasses_status_check() {
    let store = MemoryRefreshTokenStore::new();
    let config = test_config();
    let rng = MockRng::new(333);
    let ts = now();

    let (plaintext, _) = issue_refresh_token(
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

    // Rotate once (revokes the parent).
    let _ = refresh_session(&plaintext, &store, &config, &rng, ts, None)
        .await
        .unwrap();

    // Replay the original; should hit the family-revocation path,
    // returning `RefreshError::Revoked`, NOT `AccountInactive`,
    // even though the status check would have refused.
    let err = refresh_session_with_status_check(
        &plaintext,
        &store,
        &config,
        &rng,
        ts,
        None,
        |_user_id| async { false },
    )
    .await
    .expect_err("revoked token must error");

    assert!(
        matches!(err, RefreshError::Revoked),
        "revoked-token compromise signal must take priority over status check, got {err:?}"
    );
}
