//! Configuration and cap guarantees of `issue_refresh_token`.

use super::test_support::{fixture_tenant, fixture_user, now, store, test_config};
use super::*;
use crate::testing::mock_random::MockRng;
use std::sync::Arc;
use zeroize::Zeroizing;

fn request<'a>(user: &'a UserId, tenant: &'a TenantId) -> IssueRequest<'a> {
    IssueRequest {
        user_id: user,
        tenant_id: tenant,
        device_info: None,
        family_id: None,
        device_id: None,
    }
}

/// An empty pepper is refused instead of silently hashing without a key, and
/// nothing is stored.
#[tokio::test]
async fn an_empty_pepper_is_refused_before_anything_is_stored() {
    let store = store();
    let config = RefreshTokenConfig {
        hash_pepper: Some(Zeroizing::new(Vec::new())),
        ..test_config()
    };
    let (user, tenant) = (fixture_user(), fixture_tenant());
    let issued = issue_refresh_token(
        request(&user, &tenant),
        &config,
        &store,
        &MockRng::new(1),
        now(),
    )
    .await;
    assert!(
        matches!(issued, Err(RefreshError::InvalidConfig(_))),
        "{issued:?}"
    );
    assert!(store.active_tokens(&user).await.unwrap().is_empty());

    let refreshed = refresh_session_with_status_check(
        "anything",
        &store,
        &config,
        &MockRng::new(2),
        now(),
        None,
        |_| async { true },
    )
    .await;
    assert!(matches!(refreshed, Err(RefreshError::InvalidConfig(_))));
    let checked = refresh_session_with_status_check(
        "anything",
        &store,
        &config,
        &MockRng::new(3),
        now(),
        None,
        |_| async { true },
    )
    .await;
    assert!(matches!(checked, Err(RefreshError::InvalidConfig(_))));
}

/// A cap of zero is refused up front: the existing tokens are not revoked
/// and no token is issued.
#[tokio::test]
async fn a_cap_of_zero_revokes_nothing_and_issues_nothing() {
    let store = store();
    let (user, tenant) = (fixture_user(), fixture_tenant());
    let rng = MockRng::new(4);
    let (_, kept) =
        issue_refresh_token(request(&user, &tenant), &test_config(), &store, &rng, now())
            .await
            .unwrap();

    let zero = RefreshTokenConfig {
        max_per_user: 0,
        ..test_config()
    };
    let refused = issue_refresh_token(request(&user, &tenant), &zero, &store, &rng, now()).await;
    assert!(
        matches!(refused, Err(RefreshError::InvalidConfig(_))),
        "{refused:?}"
    );

    let active = store.active_tokens(&user).await.unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].id, kept.id);
}

#[test]
fn validate_accepts_the_defaults_and_a_keyed_config() {
    assert_eq!(RefreshTokenConfig::default().validate(), Ok(()));
    let keyed = RefreshTokenConfig {
        hash_pepper: Some(Zeroizing::new(b"pepper".to_vec())),
        ..RefreshTokenConfig::default()
    };
    assert_eq!(keyed.validate(), Ok(()));
}

/// Concurrent issues for one user end at the cap, not above it: the store
/// counts and evicts in the same step as the insert.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_issues_for_one_user_never_exceed_the_cap() {
    let config = test_config();
    for round in 0..20u64 {
        let store = Arc::new(store());
        let user = fixture_user();
        let tenant = fixture_tenant();
        let mut tasks = Vec::new();
        for n in 0..12u64 {
            let (store, user, tenant, config) = (store.clone(), user, tenant, config.clone());
            tasks.push(tokio::spawn(async move {
                let rng = MockRng::new(1000 * round + n);
                let at = now() + chrono::Duration::milliseconds(i64::try_from(n).unwrap());
                issue_refresh_token(request(&user, &tenant), &config, &*store, &rng, at)
                    .await
                    .unwrap();
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        let active = store.active_tokens(&user).await.unwrap();
        assert_eq!(
            active.len(),
            config.max_per_user,
            "round {round}: exactly the cap must remain active"
        );
    }
}
