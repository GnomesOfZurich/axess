//! Top-level rotation, expiry, family, and device-binding tests for
//! the `refresh` module. Lives alongside the production module so the
//! private helpers `hash_token` and `collect_family_device_targets`
//! remain in scope.

use super::test_support::{fixture_tenant, fixture_user, now, test_config};
use super::*;
use crate::testing::{MemoryRefreshTokenStore, mock_random::MockRng};

/// Pins the `expires_at = issued_at + ttl` invariant on freshly issued
/// tokens. `expired_token_rejected` does not pin this: a `+`-to-`-`
/// sign flip in the impl produces tokens that are immediately expired,
/// but `expired_token_rejected`'s `now >= record.expires_at` check
/// still trips on the past expiry and the test passes. This direct
/// invariant assertion closes that gap.
#[tokio::test]
async fn issued_token_expires_after_issuance() {
    let store = MemoryRefreshTokenStore::new();
    let config = test_config();
    let rng = MockRng::new(123);
    let ts = now();

    let (_, record) = issue_refresh_token(
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
        record.expires_at > record.issued_at,
        "expires_at ({}) must be after issued_at ({}); a sign-flip in \
         build_refresh_token would invert this and silently produce \
         tokens that are dead on arrival",
        record.expires_at,
        record.issued_at,
    );
    assert_eq!(
        record.expires_at - record.issued_at,
        config.ttl,
        "expires_at - issued_at must equal the configured ttl exactly; \
         this pins the additive shape against an offset / multiplier \
         drift mutation"
    );
}

#[tokio::test]
async fn issue_and_refresh_roundtrip() {
    let store = MemoryRefreshTokenStore::new();
    let config = test_config();
    let rng = MockRng::new(42);
    let ts = now();

    let (plaintext, record) = issue_refresh_token(
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

    assert!(!plaintext.is_empty());
    assert_eq!(record.user_id, fixture_user());
    assert_eq!(record.tenant_id, fixture_tenant());
    assert!(!record.revoked);

    // Use the plaintext to refresh; should produce a new session.
    let (session, new_token) = refresh_session(&plaintext, &store, &config, &rng, ts, None)
        .await
        .unwrap();

    assert!(session.auth_state.is_authenticated());
    assert_eq!(session.auth_state.user_id(), Some(&fixture_user()));
    // Rotation enabled; should have a new token.
    assert!(new_token.is_some());
}

#[tokio::test]
async fn expired_token_rejected() {
    let store = MemoryRefreshTokenStore::new();
    let config = RefreshTokenConfig {
        ttl: Duration::seconds(1),
        ..test_config()
    };
    let rng = MockRng::new(99);
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

    // Advance time past expiry.
    let future = ts + Duration::seconds(2);
    let result = refresh_session(&plaintext, &store, &config, &rng, future, None).await;

    assert!(matches!(result, Err(RefreshError::Expired)));
}

#[tokio::test]
async fn revoked_token_rejected() {
    let store = MemoryRefreshTokenStore::new();
    let config = RefreshTokenConfig {
        rotation: false,
        ..test_config()
    };
    let rng = MockRng::new(77);
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

    // Revoke it.
    revoke_refresh_token(&plaintext, &store, &config)
        .await
        .unwrap();

    let result = refresh_session(&plaintext, &store, &config, &rng, ts, None).await;
    assert!(matches!(result, Err(RefreshError::Revoked)));
}

#[tokio::test]
async fn rotation_invalidates_old_token() {
    let store = MemoryRefreshTokenStore::new();
    let config = RefreshTokenConfig {
        rotation: true,
        ..test_config()
    };
    let rng = MockRng::new(55);
    let ts = now();

    let (plaintext_v1, _) = issue_refresh_token(
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

    // First refresh: v1 is consumed, v2 is issued.
    let (_, new_token) = refresh_session(&plaintext_v1, &store, &config, &rng, ts, None)
        .await
        .unwrap();
    let (plaintext_v2, _) = new_token.unwrap();

    // v1 should now be revoked.
    let result = refresh_session(&plaintext_v1, &store, &config, &rng, ts, None).await;
    assert!(matches!(result, Err(RefreshError::Revoked)));

    // v1 reuse triggered family revocation; v2 is also revoked (correct
    // security behavior: token theft detected → entire family invalidated).
    let result = refresh_session(&plaintext_v2, &store, &config, &rng, ts, None).await;
    assert!(matches!(result, Err(RefreshError::Revoked)));
}

/// Cover the `hash_token` pepper-conditional branch.
/// Mutation-testing baseline surfaced three live mutants
/// at `hash_token`'s `match guard !pep.is_empty()`: the conditional
/// pepper path was never exercised by tests. This test asserts:
///
/// 1. **`Some(empty)` falls through to SHA-256.** An empty pepper
///    must produce the same hash as `None`. Kills the
///    `replace match guard with true` mutant (which would HMAC
///    with an empty key instead of falling back).
/// 2. **`Some(non_empty)` uses HMAC, not SHA-256.** A populated
///    pepper must produce a different hash than `None`. Kills the
///    `replace match guard with false` mutant (which would never
///    take the HMAC path) and the `delete !` mutant (which inverts
///    the guard).
/// 3. **Different peppers produce different hashes.** A pepper
///    rotation invalidates old hashes: confirms the HMAC key is
///    actually mixed in, not constant-folded.
///
/// Driven through the public `issue_refresh_token` so the test
/// asserts the contract of the on-the-wire `RefreshTokenRecord`,
/// not just the private helper. The shared `MockRng` seed pins
/// the random plaintext so the only thing varying between runs
/// is the pepper.
#[tokio::test]
async fn hash_token_pepper_branch_covered() {
    let user = fixture_user();
    let tenant = fixture_tenant();
    let ts = now();
    const SEED: u64 = 0xA1FF;

    async fn hash_with(
        pepper: Option<Vec<u8>>,
        seed: u64,
        user: &UserId,
        tenant: &TenantId,
        ts: DateTime<Utc>,
    ) -> String {
        let store = MemoryRefreshTokenStore::new();
        let config = RefreshTokenConfig {
            hash_pepper: pepper,
            ..test_config()
        };
        let rng = MockRng::new(seed);
        let (_plaintext, record) = issue_refresh_token(
            IssueRequest {
                user_id: user,
                tenant_id: tenant,
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
        record.token_hash
    }

    let h_none = hash_with(None, SEED, &user, &tenant, ts).await;
    let h_empty = hash_with(Some(Vec::new()), SEED, &user, &tenant, ts).await;
    let h_pepper_a = hash_with(Some(b"pepper-a".to_vec()), SEED, &user, &tenant, ts).await;
    let h_pepper_b = hash_with(Some(b"pepper-b".to_vec()), SEED, &user, &tenant, ts).await;

    // (1) Some(empty) must equal None; both fall through to SHA-256.
    assert_eq!(
        h_none, h_empty,
        "Some(empty) pepper must take the same SHA-256 fallback as None",
    );
    // (2) Some(non_empty) must differ from None.
    assert_ne!(
        h_none, h_pepper_a,
        "Some(non-empty) pepper must take the HMAC path, not the SHA-256 fallback",
    );
    // (3) Different peppers produce different hashes.
    assert_ne!(
        h_pepper_a, h_pepper_b,
        "Different peppers must produce different HMAC outputs",
    );
}

/// Explicit multi-client threat-model test for the
/// family-revoke-on-reuse contract. The setup mirrors a real
/// stolen-refresh-token scenario:
///
/// 1. **Alice's browser** issues a refresh token (`alice_v1`) and
///    rotates it to `alice_v2` on the next call. From Alice's
///    perspective, everything is normal: `alice_v2` works.
/// 2. **Eve** has previously copied `alice_v1` (e.g. via XSS,
///    backup leak, or a logged HTTPS request). She tries to use
///    it after Alice's rotation.
/// 3. **Eve's request must fail**: `alice_v1` was rotated out
///    and is now revoked. That alone is straightforward.
/// 4. **Alice's `alice_v2` must ALSO fail**: the reuse-detection
///    contract says any reuse of a rotated-out token revokes the
///    entire family, so Alice gets logged out across every device
///    sharing this family. This is the security trade-off:
///    Alice's session dies, but Eve's stolen token is neutralised
///    and Alice will notice and re-authenticate (likely changing
///    her password while she's at it).
///
/// This duplicates `rotation_invalidates_old_token` at the
/// behaviour level on purpose: that test is named after the
/// rotation mechanic, not the threat model. This test name makes
/// the threat model findable when SOC engineers grep the codebase.
#[tokio::test]
async fn replayed_rotated_token_revokes_entire_family() {
    let store = MemoryRefreshTokenStore::new();
    let config = RefreshTokenConfig {
        rotation: true,
        ..test_config()
    };
    let rng = MockRng::new(0xA1);
    let ts = now();

    // Step 1: Alice issues v1.
    let (alice_v1, _) = issue_refresh_token(
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

    // Step 1 (cont.): Alice's browser rotates v1 → v2.
    let (_, alice_rotation) = refresh_session(&alice_v1, &store, &config, &rng, ts, None)
        .await
        .unwrap();
    let (alice_v2, _) = alice_rotation.expect("rotation must mint v2 when rotation=true");

    // Step 2 + 3: Eve replays the rotated-out v1. Must fail.
    let eve_replay = refresh_session(&alice_v1, &store, &config, &rng, ts, None).await;
    assert!(
        matches!(eve_replay, Err(RefreshError::Revoked)),
        "Eve's replay of rotated-out v1 must fail with Revoked, got {eve_replay:?}",
    );

    // Step 4: Alice's still-current v2 must ALSO fail; the family
    // is now revoked. This is the contract that distinguishes axess
    // from naive "revoke just the replayed token" implementations.
    let alice_followup = refresh_session(&alice_v2, &store, &config, &rng, ts, None).await;
    assert!(
        matches!(alice_followup, Err(RefreshError::Revoked)),
        "Alice's v2 must be invalidated by family-revoke after Eve's replay, got {alice_followup:?}",
    );
}

#[tokio::test]
async fn max_per_user_enforced() {
    let store = MemoryRefreshTokenStore::new();
    let config = RefreshTokenConfig {
        max_per_user: 2,
        rotation: false,
        ..test_config()
    };
    let rng = MockRng::new(10);
    let ts = now();

    // Issue 3 tokens with max_per_user = 2.
    // Use increasing timestamps so `active_tokens` ordering is deterministic.
    let t1 = ts;
    let t2 = ts + Duration::seconds(1);
    let t3 = ts + Duration::seconds(2);

    let (pt1, _) = issue_refresh_token(
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
        t1,
    )
    .await
    .unwrap();
    let (_pt2, _) = issue_refresh_token(
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
        t2,
    )
    .await
    .unwrap();
    let (_pt3, _) = issue_refresh_token(
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
        t3,
    )
    .await
    .unwrap();

    // The first token should have been auto-revoked.
    let result = refresh_session(&pt1, &store, &config, &rng, ts, None).await;
    assert!(matches!(result, Err(RefreshError::Revoked)));

    // Should have exactly 2 active tokens.
    let active = store.active_tokens(&fixture_user()).await.unwrap();
    assert_eq!(active.len(), 2);
}

#[tokio::test]
async fn revoke_user_tokens_clears_all() {
    let store = MemoryRefreshTokenStore::new();
    let config = RefreshTokenConfig {
        rotation: false,
        ..test_config()
    };
    let rng = MockRng::new(33);
    let ts = now();

    let (pt1, _) = issue_refresh_token(
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
    let (pt2, _) = issue_refresh_token(
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

    // Revoke all.
    store.revoke_user_tokens(&fixture_user()).await.unwrap();

    let result1 = refresh_session(&pt1, &store, &config, &rng, ts, None).await;
    let result2 = refresh_session(&pt2, &store, &config, &rng, ts, None).await;

    assert!(matches!(result1, Err(RefreshError::Revoked)));
    assert!(matches!(result2, Err(RefreshError::Revoked)));

    let active = store.active_tokens(&fixture_user()).await.unwrap();
    assert_eq!(active.len(), 0);
}

#[tokio::test]
async fn device_binding_mismatch_rejected() {
    let store = MemoryRefreshTokenStore::new();
    let config = RefreshTokenConfig {
        rotation: false,
        ..test_config()
    };
    let rng = MockRng::new(88);
    let ts = now();

    let (plaintext, _) = issue_refresh_token(
        IssueRequest {
            user_id: &fixture_user(),
            tenant_id: &fixture_tenant(),
            device_info: Some("iPhone/16".to_string()),
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

    // Refresh from a different device.
    let result = refresh_session(&plaintext, &store, &config, &rng, ts, Some("Android/15")).await;
    assert!(matches!(result, Err(RefreshError::DeviceMismatch)));

    // Correct device works.
    let (session, _) = refresh_session(&plaintext, &store, &config, &rng, ts, Some("iPhone/16"))
        .await
        .unwrap();
    assert!(session.auth_state.is_authenticated());
}
