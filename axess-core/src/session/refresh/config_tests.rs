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

    let refreshed = Refresh::any_tenant("anything", |_| async { true })
        .run(&store, &config, &MockRng::new(2), now())
        .await;
    assert!(matches!(refreshed, Err(RefreshError::InvalidConfig(_))));
    let checked = Refresh::any_tenant("anything", |_| async { true })
        .run(&store, &config, &MockRng::new(3), now())
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

/// A ttl of zero or less issues tokens that are born expired.
#[test]
fn validate_refuses_a_ttl_that_is_not_positive() {
    for ttl in [chrono::Duration::zero(), chrono::Duration::seconds(-1)] {
        let config = RefreshTokenConfig {
            ttl,
            ..RefreshTokenConfig::default()
        };
        assert!(config.validate().is_err(), "ttl {ttl} must be refused");
    }
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

/// A refresh family ends 90 days after the authentication it descends from,
/// unless the cap is lifted.
#[test]
fn the_default_caps_a_family_at_ninety_days() {
    assert_eq!(
        RefreshTokenConfig::default().max_lifetime,
        Some(Duration::days(90))
    );
}

/// A device string stored without a pepper is an unkeyed digest a reader of
/// the store can confirm a guess against; the config refuses it by name.
#[tokio::test]
async fn a_device_string_without_a_pepper_is_an_invalid_config() {
    let config = RefreshTokenConfig::default();
    assert!(config.hash_pepper.is_none());
    let result = issue_refresh_token(
        IssueRequest {
            user_id: &fixture_user(),
            tenant_id: &fixture_tenant(),
            device_info: Some("laptop".to_owned()),
            family_id: None,
            device_id: None,
        },
        &config,
        &store(),
        &MockRng::new(3),
        now(),
    )
    .await;
    assert!(
        matches!(result, Err(RefreshError::InvalidConfig(_))),
        "got {result:?}"
    );
}

#[tokio::test]
async fn a_refresh_presenting_a_device_string_without_a_pepper_is_an_invalid_config() {
    let config = RefreshTokenConfig::default();
    let result = Refresh::any_tenant("any-token", |_| async { true })
        .device_info(Some("laptop"))
        .run(&store(), &config, &MockRng::new(4), now())
        .await;
    assert!(
        matches!(result, Err(RefreshError::InvalidConfig(_))),
        "got {result:?}"
    );
}

#[tokio::test]
async fn allow_unkeyed_hashes_and_a_pepper_each_permit_a_device_string() {
    for config in [
        RefreshTokenConfig::default().allow_unkeyed_hashes(),
        RefreshTokenConfig {
            hash_pepper: Some(Zeroizing::new(b"pepper".to_vec())),
            ..RefreshTokenConfig::default()
        },
    ] {
        issue_refresh_token(
            IssueRequest {
                user_id: &fixture_user(),
                tenant_id: &fixture_tenant(),
                device_info: Some("laptop".to_owned()),
                family_id: None,
                device_id: None,
            },
            &config,
            &store(),
            &MockRng::new(3),
            now(),
        )
        .await
        .expect("issue");
    }
}

#[test]
fn with_max_lifetime_none_lifts_the_cap() {
    let config = RefreshTokenConfig::default().with_max_lifetime(None);
    assert_eq!(config.max_lifetime, None);
    assert_eq!(config.validate(), Ok(()));
}
