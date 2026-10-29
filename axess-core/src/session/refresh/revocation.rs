//! Revocation reasons, the absolute family lifetime, family-less tokens and
//! tenant-scoped refresh.

use super::test_support::{fixture_tenant, fixture_user, now, store, test_config};
use super::*;
use crate::testing::mock_random::MockRng;

async fn issue(
    store: &crate::testing::MemoryRefreshTokenStore,
    config: &RefreshTokenConfig,
    rng: &MockRng,
    at: DateTime<Utc>,
) -> (String, RefreshToken) {
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
        at,
    )
    .await
    .unwrap()
}

// ── absolute lifetime ───────────────────────────────────────────────────

/// A family rotated every 20 days with a 30 day ttl and a 60 day cap: every
/// child expires no later than day 60, and the first refresh at or after day
/// 60 is `Expired`. Without the cap the chain would run for ever.
#[tokio::test]
async fn max_lifetime_caps_a_family_that_rotates_before_its_ttl() {
    let store = store();
    let config = RefreshTokenConfig {
        max_lifetime: Some(Duration::days(60)),
        ..test_config()
    };
    let rng = MockRng::new(11);
    let start = now();
    let end = start + Duration::days(60);
    let (mut plaintext, first) = issue(&store, &config, &rng, start).await;
    assert!(first.expires_at <= end);

    for day in [20, 40] {
        let at = start + Duration::days(day);
        let (_, next) = refresh_session_with_status_check(
            &plaintext,
            &store,
            &config,
            &rng,
            at,
            None,
            |_| async { true },
        )
        .await
        .unwrap();
        let (next_plain, record) = next.unwrap();
        assert!(
            record.expires_at <= end,
            "day {day}: expires_at {} passes the cap {end}",
            record.expires_at
        );
        plaintext = next_plain;
    }
    // Day 40's child would have lived to day 70 under the sliding ttl; the
    // cap clamped it to day 60.
    let (_, last) = store
        .find_token(&hash_token(&plaintext, None))
        .await
        .map(|r| ((), r.unwrap()))
        .unwrap();
    assert_eq!(last.expires_at, end);

    let at_cap = refresh_session_with_status_check(
        &plaintext,
        &store,
        &config,
        &rng,
        end,
        None,
        |_| async { true },
    )
    .await;
    assert!(matches!(at_cap, Err(RefreshError::Expired)), "{at_cap:?}");
}

/// The status-checked path enforces the cap too, before the predicate runs.
#[tokio::test]
async fn max_lifetime_is_enforced_on_the_status_checked_path() {
    let store = store();
    let config = RefreshTokenConfig {
        max_lifetime: Some(Duration::days(30)),
        ..test_config()
    };
    let rng = MockRng::new(12);
    let (plaintext, mut record) = issue(&store, &config, &rng, now()).await;
    // A row written before the cap existed: its own expiry is later.
    record.expires_at = now() + Duration::days(90);
    store.store_token(&record).await.unwrap();
    let at = now() + Duration::days(31);
    let result =
        refresh_session_with_status_check(&plaintext, &store, &config, &rng, at, None, |_| async {
            panic!("the predicate must not run for an expired family")
        })
        .await;
    assert!(matches!(result, Err(RefreshError::Expired)), "{result:?}");
}

#[test]
fn max_lifetime_below_ttl_or_zero_is_refused() {
    let below = RefreshTokenConfig {
        max_lifetime: Some(Duration::days(29)),
        ..test_config()
    };
    assert!(below.validate().is_err());
    let zero = RefreshTokenConfig {
        max_lifetime: Some(Duration::zero()),
        ..test_config()
    };
    assert!(zero.validate().is_err());
    let ok = RefreshTokenConfig {
        max_lifetime: Some(Duration::days(30)),
        ..test_config()
    };
    assert!(ok.validate().is_ok());
    assert!(test_config().validate().is_ok(), "the default is no cap");
}

// ── revocation reasons ──────────────────────────────────────────────────

/// A token the cap evicted, presented later by a stale client, is refused
/// without revoking the family it belongs to or running the compromise hook.
#[tokio::test]
async fn an_evicted_token_is_refused_without_a_family_revocation() {
    let store = store();
    let config = RefreshTokenConfig {
        max_per_user: 1,
        ..test_config()
    };
    let rng = MockRng::new(13);
    let (old_plain, old) = issue(&store, &config, &rng, now()).await;
    let (_new_plain, newer) = issue(&store, &config, &rng, now() + Duration::seconds(1)).await;

    let evicted = store.find_token(&old.token_hash).await.unwrap().unwrap();
    assert_eq!(evicted.revoked_reason, Some(RevocationReason::Evicted));

    let result = refresh_session_with_status_check(
        &old_plain,
        &store,
        &config,
        &rng,
        now(),
        None,
        |_| async { true },
    )
    .await;
    assert!(matches!(result, Err(RefreshError::Revoked)), "{result:?}");
    let live = store.active_tokens(&fixture_user()).await.unwrap();
    assert_eq!(live.len(), 1, "the newer login is not collateral damage");
    assert_eq!(live[0].id, newer.id);
}

/// A logged-out token presented again is refused and revokes nothing else.
#[tokio::test]
async fn a_logged_out_token_reused_does_not_revoke_its_family() {
    let store = store();
    let config = test_config();
    let rng = MockRng::new(14);
    let (plaintext, _) = issue(&store, &config, &rng, now()).await;
    let (_, rotated) = refresh_session_with_status_check(
        &plaintext,
        &store,
        &config,
        &rng,
        now(),
        None,
        |_| async { true },
    )
    .await
    .unwrap();
    let (child_plain, _) = rotated.unwrap();
    // Log out the live child; a sibling in the same family stays live.
    revoke_refresh_token(&child_plain, &store, &config)
        .await
        .unwrap();
    let record = store
        .find_token(&hash_token(&child_plain, None))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.revoked_reason, Some(RevocationReason::Explicit));

    let (other_plain, other) = issue(&store, &config, &rng, now()).await;
    let again = refresh_session_with_status_check(
        &child_plain,
        &store,
        &config,
        &rng,
        now(),
        None,
        |_| async { true },
    )
    .await;
    assert!(matches!(again, Err(RefreshError::Revoked)));
    let still = store.find_token(&other.token_hash).await.unwrap().unwrap();
    assert!(!still.revoked, "an unrelated family is untouched");
    assert!(
        refresh_session_with_status_check(
            &other_plain,
            &store,
            &config,
            &rng,
            now(),
            None,
            |_| async { true }
        )
        .await
        .is_ok()
    );
}

/// A rotated-out token reused after the grace window is theft; inside it, a
/// parallel refresh that revokes nothing.
#[tokio::test]
async fn reuse_inside_the_grace_window_is_concurrent_and_outside_is_theft() {
    let store = store();
    let config = RefreshTokenConfig {
        reuse_grace: Duration::seconds(5),
        ..test_config()
    };
    let rng = MockRng::new(15);
    let (plaintext, _) = issue(&store, &config, &rng, now()).await;
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
    .unwrap();
    let (_, child) = next.unwrap();

    let soon = now() + Duration::seconds(2);
    let parallel = refresh_session_with_status_check(
        &plaintext,
        &store,
        &config,
        &rng,
        soon,
        None,
        |_| async { true },
    )
    .await;
    assert!(
        matches!(parallel, Err(RefreshError::ConcurrentRefresh)),
        "{parallel:?}"
    );
    let child_row = store.find_token(&child.token_hash).await.unwrap().unwrap();
    assert!(!child_row.revoked, "nothing was revoked inside the grace");

    let late = now() + Duration::seconds(30);
    let theft = refresh_session_with_status_check(
        &plaintext,
        &store,
        &config,
        &rng,
        late,
        None,
        |_| async { true },
    )
    .await;
    assert!(matches!(theft, Err(RefreshError::Revoked)), "{theft:?}");
    let child_row = store.find_token(&child.token_hash).await.unwrap().unwrap();
    assert!(child_row.revoked, "the family is revoked after the grace");
}

/// With the default (zero) grace, any reuse of a rotated token is theft.
#[tokio::test]
async fn default_grace_treats_an_immediate_reuse_as_theft() {
    let store = store();
    let config = test_config();
    let rng = MockRng::new(16);
    let (plaintext, _) = issue(&store, &config, &rng, now()).await;
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
    .unwrap();
    let (_, child) = next.unwrap();
    let again = refresh_session_with_status_check(
        &plaintext,
        &store,
        &config,
        &rng,
        now(),
        None,
        |_| async { true },
    )
    .await;
    assert!(matches!(again, Err(RefreshError::Revoked)));
    assert!(
        store
            .find_token(&child.token_hash)
            .await
            .unwrap()
            .unwrap()
            .revoked
    );
}

#[test]
fn revocation_reason_spellings_round_trip() {
    for reason in [
        RevocationReason::Rotated,
        RevocationReason::Explicit,
        RevocationReason::Evicted,
        RevocationReason::Compromise,
    ] {
        assert_eq!(RevocationReason::parse(reason.as_str()), Some(reason));
    }
    assert_eq!(RevocationReason::parse("nonsense"), None);
}

// ── family-less tokens ──────────────────────────────────────────────────

/// A token stored without a family (a row from before families existed)
/// rotates into a child whose family is the parent's id, and reusing the
/// parent revokes that child. Before, the reuse revoked nothing.
#[tokio::test]
async fn reuse_of_a_family_less_token_revokes_its_descendants() {
    let store = store();
    let config = test_config();
    let rng = MockRng::new(17);
    let (plaintext, mut legacy) = issue(&store, &config, &rng, now()).await;
    legacy.family_id = None;
    store.store_token(&legacy).await.unwrap();

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
    .unwrap();
    let (_, child) = next.unwrap();
    assert_eq!(
        child.family_id.map(|f| f.to_string()),
        Some(legacy.id.to_string()),
        "the child's family is the parent's id"
    );

    let reuse = refresh_session_with_status_check(
        &plaintext,
        &store,
        &config,
        &rng,
        now(),
        None,
        |_| async { true },
    )
    .await;
    assert!(matches!(reuse, Err(RefreshError::Revoked)));
    assert!(
        store
            .find_token(&child.token_hash)
            .await
            .unwrap()
            .unwrap()
            .revoked,
        "the descendant of a family-less token is revoked on reuse"
    );
}

// ── tenant scope ────────────────────────────────────────────────────────

/// A token presented against another tenant is `NotFound` and is neither
/// rotated nor revoked; against its own tenant it refreshes.
#[tokio::test]
async fn refresh_in_tenant_refuses_a_foreign_token_without_rotating() {
    let store = store();
    let config = test_config();
    let rng = MockRng::new(18);
    let (plaintext, record) = issue(&store, &config, &rng, now()).await;
    let other = axess_identity::testing::tenant("tenant-2");

    let foreign =
        refresh_session_in_tenant(&plaintext, &other, &store, &config, &rng, now(), None).await;
    assert!(
        matches!(foreign, Err(RefreshError::NotFound)),
        "{foreign:?}"
    );
    let row = store.find_token(&record.token_hash).await.unwrap().unwrap();
    assert!(!row.revoked, "the foreign attempt rotated nothing");

    let status_checked = refresh_session_with_status_check_in_tenant(
        &plaintext,
        RefreshScope {
            tenant: &other,
            device_info: None,
        },
        &store,
        &config,
        &rng,
        now(),
        |_| async { panic!("the predicate must not run for a foreign tenant") },
    )
    .await;
    assert!(matches!(status_checked, Err(RefreshError::NotFound)));

    let own = refresh_session_in_tenant(
        &plaintext,
        &fixture_tenant(),
        &store,
        &config,
        &rng,
        now(),
        None,
    )
    .await;
    assert!(own.is_ok());
}
