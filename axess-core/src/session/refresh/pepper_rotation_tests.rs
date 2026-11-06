//! Rotating the refresh-token hash pepper without logging everyone out.

use super::test_support::{fixture_tenant, fixture_user, now, store, test_config};
use super::*;
use crate::authn::ids::DeviceId;
use crate::testing::mock_random::MockRng;

fn peppered(pepper: &[u8]) -> RefreshTokenConfig {
    RefreshTokenConfig {
        hash_pepper: Some(Zeroizing::new(pepper.to_vec())),
        ..test_config()
    }
}

fn rotated_to(new: &[u8], old: &[u8]) -> RefreshTokenConfig {
    RefreshTokenConfig {
        previous_hash_pepper: Some(PreviousPepper::keyed(old)),
        ..peppered(new)
    }
}

async fn issue_under(
    config: &RefreshTokenConfig,
    store: &crate::testing::MemoryRefreshTokenStore,
    rng: &MockRng,
) -> String {
    issue_bound_under(config, store, rng, None, None).await
}

/// Issue a token bound to `device_info` for `device`.
async fn issue_bound_under(
    config: &RefreshTokenConfig,
    store: &crate::testing::MemoryRefreshTokenStore,
    rng: &MockRng,
    device_info: Option<&str>,
    device_id: Option<DeviceId>,
) -> String {
    issue_refresh_token(
        IssueRequest {
            user_id: &fixture_user(),
            tenant_id: &fixture_tenant(),
            device_info: device_info.map(str::to_owned),
            family_id: None,
            device_id,
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
    let (session, next) = Refresh::any_tenant(&plaintext, |_| async { true })
        .run(&store, &config, &rng, now())
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
    Refresh::any_tenant(&next_plain, |_| async { true })
        .run(&store, &only_new, &rng, now())
        .await
        .expect("no previous pepper needed any more");
}

#[tokio::test]
async fn without_a_previous_pepper_a_changed_pepper_loses_the_token() {
    let store = store();
    let rng = MockRng::new(12);
    let plaintext = issue_under(&peppered(b"old"), &store, &rng).await;

    let result = Refresh::any_tenant(&plaintext, |_| async { true })
        .run(&store, &peppered(b"new"), &rng, now())
        .await;
    assert!(matches!(result, Err(RefreshError::NotFound)));
}

/// A client that does not rotate keeps its token across a pepper rotation:
/// the refresh re-stores the same token under the current pepper and hands
/// back no replacement, so presenting the same token again is not reuse.
#[tokio::test]
async fn a_non_rotating_client_keeps_its_token_across_a_pepper_rotation() {
    let store = store();
    let rng = MockRng::new(13);
    let plaintext = issue_under(&peppered(b"old"), &store, &rng).await;

    let config = RefreshTokenConfig {
        rotation: false,
        ..rotated_to(b"new", b"old")
    };
    let (_, next) = Refresh::any_tenant(&plaintext, |_| async { true })
        .run(&store, &config, &rng, now())
        .await
        .expect("refresh");
    assert!(next.is_none(), "a non-rotating client gets no new token");
    let moved = store
        .find_token(&hash_token(&plaintext, Some(b"new")))
        .await
        .unwrap()
        .expect("the same token is stored under the current pepper");
    assert!(!moved.revoked);

    // The same token again, during the window and after it closes.
    for cfg in [
        &config,
        &RefreshTokenConfig {
            rotation: false,
            ..peppered(b"new")
        },
    ] {
        let again = Refresh::any_tenant(&plaintext, |_| async { true })
            .run(&store, cfg, &rng, now())
            .await;
        assert!(
            matches!(again, Ok((_, None))),
            "the client's own token is not reuse: {again:?}"
        );
    }
}

#[tokio::test]
async fn replaying_a_rotated_out_retired_pepper_token_is_still_reuse() {
    let store = store();
    let rng = MockRng::new(14);
    let plaintext = issue_under(&peppered(b"old"), &store, &rng).await;
    let config = rotated_to(b"new", b"old");

    let (_, next) = Refresh::any_tenant(&plaintext, |_| async { true })
        .run(&store, &config, &rng, now())
        .await
        .expect("first use");
    let (next_plain, _) = next.expect("child");

    let replay = Refresh::any_tenant(&plaintext, |_| async { true })
        .run(&store, &config, &rng, now())
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

    let (_, next) = Refresh::any_tenant(&plaintext, |_| async { true })
        .run(&store, &config, &rng, now())
        .await
        .expect("refresh");
    assert!(next.is_some());
}

/// A deployment that ran without a pepper names the unkeyed state as the
/// previous pepper, so none of its tokens is lost on the move to a pepper.
#[tokio::test]
async fn a_token_hashed_without_a_pepper_moves_to_the_new_one_through_the_unkeyed_marker() {
    let store = store();
    let rng = MockRng::new(13);
    let unkeyed = test_config();
    assert!(unkeyed.hash_pepper.is_none());
    let plaintext = issue_under(&unkeyed, &store, &rng).await;

    let config = RefreshTokenConfig {
        previous_hash_pepper: Some(PreviousPepper::Unkeyed),
        ..peppered(b"new")
    };
    let (_, next) = Refresh::any_tenant(&plaintext, |_| async { true })
        .run(&store, &config, &rng, now())
        .await
        .expect("the unkeyed hash is accepted as the previous one");
    let (next_plain, _) = next.expect("a replacement token");
    assert!(
        store
            .find_token(&hash_token(&next_plain, Some(b"new")))
            .await
            .unwrap()
            .is_some(),
        "the replacement is stored under the current pepper"
    );
    Refresh::any_tenant(&next_plain, |_| async { true })
        .run(&store, &peppered(b"new"), &rng, now())
        .await
        .expect("no previous pepper needed any more");
}

#[tokio::test]
async fn without_the_unkeyed_marker_a_new_pepper_loses_an_unkeyed_token() {
    let store = store();
    let rng = MockRng::new(14);
    let plaintext = issue_under(&test_config(), &store, &rng).await;
    let result = Refresh::any_tenant(&plaintext, |_| async { true })
        .run(&store, &peppered(b"new"), &rng, now())
        .await;
    assert!(matches!(result, Err(RefreshError::NotFound)));
}

#[test]
fn the_unkeyed_marker_needs_a_current_pepper_and_prints_without_bytes() {
    let config = RefreshTokenConfig {
        previous_hash_pepper: Some(PreviousPepper::Unkeyed),
        ..test_config()
    };
    assert!(config.validate().is_err());
    let keyed = RefreshTokenConfig {
        previous_hash_pepper: Some(PreviousPepper::Unkeyed),
        ..peppered(b"new")
    };
    assert_eq!(keyed.validate(), Ok(()));
    assert!(format!("{keyed:?}").contains("previous_hash_pepper: Some(Unkeyed)"));
}

#[test]
fn an_empty_previous_pepper_is_refused_and_both_peppers_are_redacted() {
    let config = RefreshTokenConfig {
        previous_hash_pepper: Some(PreviousPepper::keyed(Vec::new())),
        ..peppered(b"new")
    };
    assert!(config.validate().is_err());

    let shown = format!("{:?}", rotated_to(b"new-secret", b"old-secret"));
    assert!(!shown.contains("old-secret") && !shown.contains("new-secret"));
    assert!(shown.contains("previous_hash_pepper: Some(<redacted 10 bytes>)"));
}

/// Device-bound tokens across a pepper rotation, on every refresh path.
#[cfg(feature = "device")]
mod device_bound {
    use super::*;
    use crate::device::{DeviceStore, MemoryDeviceStore};

    fn laptop() -> DeviceId {
        axess_identity::testing::device("laptop")
    }

    /// A device-bound token hashed under the retired pepper is verified under
    /// that pepper and re-bound under the current one, on every refresh path.
    #[tokio::test]
    async fn a_device_bound_token_survives_a_pepper_rotation() {
        for (seed, path) in [(21u64, "plain"), (22, "status"), (23, "device")] {
            let store = store();
            let rng = MockRng::new(seed);
            let devices = MemoryDeviceStore::new();
            let plaintext =
                issue_bound_under(&peppered(b"old"), &store, &rng, Some("fp"), Some(laptop()))
                    .await;
            let config = rotated_to(b"new", b"old");

            // A wrong device string is still a mismatch.
            let other = refresh_on(
                path,
                &plaintext,
                &store,
                &config,
                &rng,
                Some("other"),
                &devices,
            )
            .await;
            assert!(
                matches!(other, Err(RefreshError::DeviceMismatch)),
                "{path}: {other:?}"
            );

            let (_, next) = refresh_on(
                path,
                &plaintext,
                &store,
                &config,
                &rng,
                Some("fp"),
                &devices,
            )
            .await
            .unwrap_or_else(|e| {
                panic!("{path}: the device-bound token refreshes after a pepper rotation: {e:?}")
            });
            let (next_plain, child) = next.expect("a replacement token");
            assert_eq!(
                child.device_info.as_deref(),
                Some(device_binding::bind("fp", Some(&laptop()), Some(b"new")).as_str()),
                "{path}: the child is bound under the current pepper"
            );

            // The previous pepper is retired; the child still refreshes.
            let only_new = peppered(b"new");
            let again = refresh_on(
                path,
                &next_plain,
                &store,
                &only_new,
                &rng,
                Some("fp"),
                &devices,
            )
            .await;
            assert!(again.is_ok(), "{path}: {again:?}");
            let again = refresh_on(
                path,
                &next_plain,
                &store,
                &only_new,
                &rng,
                Some("other"),
                &devices,
            )
            .await;
            assert!(
                matches!(
                    again,
                    Err(RefreshError::Revoked | RefreshError::DeviceMismatch)
                ),
                "{path}: {again:?}"
            );
        }
    }

    /// One refresh through the named path.
    async fn refresh_on(
        path: &str,
        plaintext: &str,
        store: &crate::testing::MemoryRefreshTokenStore,
        config: &RefreshTokenConfig,
        rng: &MockRng,
        device_info: Option<&str>,
        devices: &MemoryDeviceStore,
    ) -> Result<
        (SessionData, Option<(String, RefreshToken)>),
        RefreshError<crate::testing::MemoryRefreshStoreError>,
    > {
        match path {
            "plain" => {
                Refresh::new(plaintext, &fixture_tenant(), |_| async { true })
                    .device_info(device_info)
                    .run(store, config, rng, now())
                    .await
            }
            "status" => {
                Refresh::any_tenant(plaintext, |_| async { true })
                    .device_info(device_info)
                    .run(store, config, rng, now())
                    .await
            }
            "device" => {
                devices
                    .save(&bound_device(), crate::device::test_now())
                    .await
                    .expect("save");
                Refresh::any_tenant(plaintext, |_| async { true })
                    .device_info(device_info)
                    .device_store(devices)
                    .run(store, config, rng, now())
                    .await
            }
            other => panic!("unknown path {other}"),
        }
    }

    fn bound_device() -> crate::device::Device {
        crate::device::Device {
            id: laptop(),
            tenant_id: fixture_tenant(),
            user_id: Some(fixture_user()),
            trust_level: crate::device::DeviceTrustLevel::Trusted,
            fingerprint_hash: crate::device::FingerprintHash::from_bytes([7; 32]),
            first_seen_at: now(),
            last_seen_at: now(),
            revoked_at: None,
            demoted_at: None,
            bindings: Vec::new(),
        }
    }
}

/// Re-storing a token under the current pepper is a change of key, not a new
/// grant: a token that does not rotate still ends when it was due to.
#[tokio::test]
async fn a_non_rotating_token_moved_to_the_new_pepper_keeps_its_expiry() {
    let store = store();
    let rng = MockRng::new(15);
    let plaintext = issue_under(&peppered(b"old"), &store, &rng).await;
    let issued = store
        .find_token(&hash_token(&plaintext, Some(b"old")))
        .await
        .unwrap()
        .expect("issued row");

    let config = RefreshTokenConfig {
        rotation: false,
        ..rotated_to(b"new", b"old")
    };
    let later = now() + Duration::days(10);
    Refresh::any_tenant(&plaintext, |_| async { true })
        .run(&store, &config, &rng, later)
        .await
        .expect("refresh");

    let moved = store
        .find_token(&hash_token(&plaintext, Some(b"new")))
        .await
        .unwrap()
        .expect("the same token is stored under the current pepper");
    assert_eq!(
        moved.expires_at, issued.expires_at,
        "the move must not extend the token's life"
    );
}
