//! Rotating the refresh-token hash pepper without logging everyone out.

use super::test_support::{fixture_tenant, fixture_user, now, store, test_config};
use super::*;
use crate::testing::mock_random::MockRng;

fn peppered(pepper: &[u8]) -> RefreshTokenConfig {
    RefreshTokenConfig {
        hash_pepper: Some(Zeroizing::new(pepper.to_vec())),
        ..test_config()
    }
}

fn rotated_to(new: &[u8], old: &[u8]) -> RefreshTokenConfig {
    RefreshTokenConfig {
        previous_hash_pepper: Some(Zeroizing::new(old.to_vec())),
        ..peppered(new)
    }
}

async fn issue_under(
    config: &RefreshTokenConfig,
    store: &crate::testing::MemoryRefreshTokenStore,
    rng: &MockRng,
) -> String {
    issue_refresh_token(
        IssueRequest {
            user_id: &fixture_user(),
            tenant_id: &fixture_tenant(),
            device_info: None,
            family_id: None,
            device_id: None,
        },
        config,
        store,
        rng,
        now(),
    )
    .await
    .expect("issue")
    .0
}

#[tokio::test]
async fn a_token_hashed_under_the_retired_pepper_refreshes_and_moves_to_the_new_one() {
    let store = store();
    let rng = MockRng::new(11);
    let plaintext = issue_under(&peppered(b"old"), &store, &rng).await;

    let config = rotated_to(b"new", b"old");
    let (session, next) = refresh_session_with_status_check(
        &plaintext,
        &store,
        &config,
        &rng,
        now(),
        None,
        |_| async { true },
    )
    .await
    .expect("the retired pepper is still accepted");
    assert!(session.auth_state.is_authenticated());
    let (next_plain, _) = next.expect("a replacement token");

    let under_new = hash_token(&next_plain, Some(b"new"));
    assert!(
        store.find_token(&under_new).await.unwrap().is_some(),
        "the replacement is stored under the current pepper"
    );

    // From here on the current pepper alone serves it.
    let only_new = peppered(b"new");
    refresh_session_with_status_check(
        &next_plain,
        &store,
        &only_new,
        &rng,
        now(),
        None,
        |_| async { true },
    )
    .await
    .expect("no previous pepper needed any more");
}

#[tokio::test]
async fn without_a_previous_pepper_a_changed_pepper_loses_the_token() {
    let store = store();
    let rng = MockRng::new(12);
    let plaintext = issue_under(&peppered(b"old"), &store, &rng).await;

    let result = refresh_session_with_status_check(
        &plaintext,
        &store,
        &peppered(b"new"),
        &rng,
        now(),
        None,
        |_| async { true },
    )
    .await;
    assert!(matches!(result, Err(RefreshError::NotFound)));
}

#[tokio::test]
async fn a_token_on_the_retired_pepper_is_rotated_even_when_rotation_is_off() {
    let store = store();
    let rng = MockRng::new(13);
    let plaintext = issue_under(&peppered(b"old"), &store, &rng).await;

    let config = RefreshTokenConfig {
        rotation: false,
        ..rotated_to(b"new", b"old")
    };
    let (_, next) = refresh_session_with_status_check(
        &plaintext,
        &store,
        &config,
        &rng,
        now(),
        None,
        |_| async { true },
    )
    .await
    .expect("refresh");
    let (next_plain, _) = next.expect("re-stored under the current pepper despite rotation off");
    assert!(
        store
            .find_token(&hash_token(&next_plain, Some(b"new")))
            .await
            .unwrap()
            .is_some()
    );

    // A token already on the current pepper is left alone with rotation off.
    let (_, again) = refresh_session_with_status_check(
        &next_plain,
        &store,
        &config,
        &rng,
        now(),
        None,
        |_| async { true },
    )
    .await
    .expect("refresh");
    assert!(again.is_none());
}

#[tokio::test]
async fn replaying_a_rotated_out_retired_pepper_token_is_still_reuse() {
    let store = store();
    let rng = MockRng::new(14);
    let plaintext = issue_under(&peppered(b"old"), &store, &rng).await;
    let config = rotated_to(b"new", b"old");

    let (_, next) = refresh_session_with_status_check(
        &plaintext,
        &store,
        &config,
        &rng,
        now(),
        None,
        |_| async { true },
    )
    .await
    .expect("first use");
    let (next_plain, _) = next.expect("child");

    let replay = refresh_session_with_status_check(
        &plaintext,
        &store,
        &config,
        &rng,
        now(),
        None,
        |_| async { true },
    )
    .await;
    assert!(matches!(replay, Err(RefreshError::Revoked)), "{replay:?}");
    let child = store
        .find_token(&hash_token(&next_plain, Some(b"new")))
        .await
        .unwrap()
        .expect("child row");
    assert!(child.revoked, "the family is revoked on reuse");
}

#[tokio::test]
async fn logout_finds_a_token_on_the_retired_pepper() {
    let store = store();
    let rng = MockRng::new(15);
    let plaintext = issue_under(&peppered(b"old"), &store, &rng).await;
    let config = rotated_to(b"new", b"old");

    revoke_refresh_token(&plaintext, &store, &config)
        .await
        .expect("found under the previous pepper");
    let row = store
        .find_token(&hash_token(&plaintext, Some(b"old")))
        .await
        .unwrap()
        .expect("row");
    assert!(row.revoked);
}

#[tokio::test]
async fn a_status_checked_refresh_also_reads_the_retired_pepper() {
    let store = store();
    let rng = MockRng::new(16);
    let plaintext = issue_under(&peppered(b"old"), &store, &rng).await;
    let config = rotated_to(b"new", b"old");

    let (_, next) = refresh_session_with_status_check(
        &plaintext,
        &store,
        &config,
        &rng,
        now(),
        None,
        |_| async { true },
    )
    .await
    .expect("refresh");
    assert!(next.is_some());
}

#[test]
fn an_empty_previous_pepper_is_refused_and_both_peppers_are_redacted() {
    let config = RefreshTokenConfig {
        previous_hash_pepper: Some(Zeroizing::new(Vec::new())),
        ..peppered(b"new")
    };
    assert!(config.validate().is_err());

    let shown = format!("{:?}", rotated_to(b"new-secret", b"old-secret"));
    assert!(!shown.contains("old-secret") && !shown.contains("new-secret"));
    assert!(shown.contains("previous_hash_pepper: Some(<redacted 10 bytes>)"));
}
