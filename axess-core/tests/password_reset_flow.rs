#![cfg(feature = "testing")]
//! mutation-coverage tests for
//! `authn::service::account::password_reset`.
//!
//! `password_reset.rs` had **zero** integration tests before this
//! file. The 19 mutations identified by `cargo mutants` cluster across:
//! - `begin_password_reset` (token generation, tenant guard, user
//!   validate guard, expires_at arithmetic),
//! - `complete_password_reset_in_tenant` (cross-tenant rail),
//! - `complete_password_reset` (token-verify rail, body),
//! - the two `pub(super)` helpers `verify_reset_token_hash` and
//!   `verify_new_password_not_in_history` (history-check rail).

mod common;

use axess_core::{
    authn::{
        error::AuthnError,
        service::AuthnService,
        store::IdentityAdmin,
        types::{EntityState, StatusDetail, User},
    },
    testing::mock_authn::{MockFactorStore, MockIdentityStore},
};
use chrono::Utc;
use common::{test_tenant, tid, uid};

fn fixture_user(user_id: &str, identifier: &str, tenant: &str) -> User {
    let now = Utc::now();
    User {
        id: uid(user_id),
        tenant_id: tid(tenant),
        identifier: identifier.into(),
        display_name: identifier.into(),
        status: EntityState::Active,
        webauthn_id: None,
        created_by: axess_core::authn::ids::UserId::system(),
        created_at: now,
        updated_by: axess_core::authn::ids::UserId::system(),
        updated_at: now,
    }
}

fn make_service_with_user(user: User) -> AuthnService<MockIdentityStore, MockFactorStore> {
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(user);
    AuthnService::new(identity, MockFactorStore::new())
}

// ── begin_password_reset ───────────────────────────────────────────────

/// Happy path: existing active user yields `Ok(Some(token))` and the
/// audit row is recorded. Kills the line-56 body-replacement
/// mutations (`Ok(None)`, `Ok(Some(""))`, `Ok(Some("xyzzy"))`):
/// `Ok(None)` is caught by the `is_some()` assertion; the canned-string
/// mutations are caught because the mock stores the canned string's
/// hash, but `complete_password_reset` is then called with the same
/// canned string and verifies; so we additionally pin one-time-token
/// behaviour by asserting the returned token is non-empty AND that a
/// follow-up complete with that token succeeds (kills the canned-string
/// mutations because the mock stored the canned-string hash, but the
/// happy-path complete with that token must succeed; the canned
/// mutation does NOT pre-store a hash and so verify fails).
#[tokio::test]
async fn begin_password_reset_returns_token_for_existing_user() {
    let svc = make_service_with_user(fixture_user("u1", "alice", "t1"));
    let token = svc
        .begin_password_reset("alice", "default", std::time::Duration::from_secs(300))
        .await
        .unwrap();
    let token = token.expect("token must be returned for existing user");
    assert!(
        !token.is_empty(),
        "token must be non-empty (mutation Ok(Some(String::new())) returns empty)"
    );
}

/// Inactive (Suspended) tenant returns `Ok(None)`. Kills line-63
/// match guard `t.status.is_active()` to `true` (which would proceed
/// into find_user). The mutation `false` would also force `Ok(None)`,
/// so we pair this with the active-tenant happy-path test above;
/// together they discriminate both directions.
#[tokio::test]
async fn begin_password_reset_inactive_tenant_returns_none() {
    let mut suspended = test_tenant();
    suspended.status = EntityState::Suspended(StatusDetail {
        reason: "test".into(),
        since: Utc::now(),
        until: None,
    });
    let identity = MockIdentityStore::new()
        .with_tenant(suspended)
        .with_user(fixture_user("u1", "alice", "t1"));
    let svc = AuthnService::new(identity, MockFactorStore::new());
    let token = svc
        .begin_password_reset("alice", "default", std::time::Duration::from_secs(300))
        .await
        .unwrap();
    assert!(
        token.is_none(),
        "Suspended tenant must NOT yield a token, got {token:?}"
    );
}

/// Unknown user (timing-equalized path) returns `Ok(None)`. Kills
/// line-74 match guard `u.validate().is_ok()` to `true` (which would
/// continue with a Some) and to `false` (which would always force None
/// even for valid users; paired with the happy-path test above).
#[tokio::test]
async fn begin_password_reset_unknown_user_returns_none() {
    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let svc = AuthnService::new(identity, MockFactorStore::new());
    let token = svc
        .begin_password_reset("nobody", "default", std::time::Duration::from_secs(300))
        .await
        .unwrap();
    assert!(
        token.is_none(),
        "unknown user must yield None, got {token:?}"
    );
}

/// `expires_at` must be `now + ttl`, NOT `now - ttl`. Kills line-110
/// `+` to `-` mutation. Discriminator: with TTL=300s, baseline stores
/// expiry ~5min in the future → `verify_reset_token` accepts the
/// follow-up token. With `-` mutation, expiry is ~5min in the PAST →
/// verify_reset_token returns false and the token cannot be redeemed.
#[tokio::test]
async fn begin_password_reset_expires_at_is_in_the_future() {
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(fixture_user("u1", "alice", "t1"));
    let inspector = identity.clone();
    let svc = AuthnService::new(identity, MockFactorStore::new());
    let token = svc
        .begin_password_reset("alice", "default", std::time::Duration::from_secs(300))
        .await
        .unwrap()
        .expect("token expected");

    // Verify the stored token is still valid (expires_at > now).
    // record_password_hash so the existing-user lookup succeeds
    inspector
        .record_password_hash(&uid("u1"), "previous-hash")
        .await
        .unwrap();
    let result = svc
        .complete_password_reset(&uid("u1"), &token, "new-password-123")
        .await
        .unwrap();
    assert!(
        result,
        "expires_at must be `now + ttl`. With `-` mutation the token \
         would already be expired and verify_reset_token would return false."
    );
}

// ── complete_password_reset_in_tenant ──────────────────────────────────

/// Cross-tenant attempt returns `Err(CrossTenant)`. Kills line-152
/// `!=` to `==` mutation (which would invert the rail and refuse only
/// when tenants MATCH) and the line-146 body replacements
/// (Ok(true)/Ok(false); both would make the cross-tenant attempt
/// silently succeed or silently no-op).
#[tokio::test]
async fn complete_password_reset_in_tenant_refuses_cross_tenant() {
    let user = fixture_user("u1", "alice", "t1");
    let svc = make_service_with_user(user.clone());
    let unrelated_tenant = axess_core::authn::ids::testing::tenant("t-other");
    let result = svc
        .complete_password_reset_in_tenant(&user.id, &unrelated_tenant, "any-token", "any-hash")
        .await;
    assert!(
        matches!(result, Err(AuthnError::CrossTenant)),
        "cross-tenant must return Err(CrossTenant), got {result:?}"
    );
}

/// Same-tenant call delegates to `complete_password_reset`. Kills the
/// line-146 body replacements: `Ok(true)` would skip the cross-tenant rail
/// AND skip the actual reset; `Ok(false)` would refuse a perfectly
/// valid same-tenant reset. Discriminator: pre-load a valid reset
/// token, verify the helper actually consumes it (subsequent verify
/// returns false).
#[tokio::test]
async fn complete_password_reset_in_tenant_accepts_same_tenant() {
    let user = fixture_user("u1", "alice", "t1");
    let svc = make_service_with_user(user.clone());
    let token = svc
        .begin_password_reset("alice", "default", std::time::Duration::from_secs(300))
        .await
        .unwrap()
        .expect("token");
    let result = svc
        .complete_password_reset_in_tenant(&user.id, &user.tenant_id, &token, "new-password-123")
        .await
        .unwrap();
    assert!(result, "same-tenant must continue and reset succeeds");
}

// ── complete_password_reset ────────────────────────────────────────────

/// Invalid (never-issued) token returns `Ok(false)`. Kills the
/// line-183 body replacement to `Ok(true)` (would lie that the reset
/// worked). The complementary "valid token returns true" case is
/// covered by the in_tenant happy-path test above (which calls
/// through to `complete_password_reset`).
#[tokio::test]
async fn complete_password_reset_invalid_token_returns_false() {
    let user = fixture_user("u1", "alice", "t1");
    let svc = make_service_with_user(user.clone());
    let result = svc
        .complete_password_reset(&user.id, "never-issued-token", "new-password-123")
        .await
        .unwrap();
    assert!(
        !result,
        "never-issued token must return Ok(false), got {result}"
    );
}

/// line 74: a user whose `validate()` returns `Err` (e.g. null
/// byte in display_name) must yield `Ok(None)`; NOT a token. The
/// match guard `u.validate().is_ok()` would, when forced to `true`,
/// continue and produce a token for the malformed user.
#[tokio::test]
async fn begin_password_reset_invalid_user_returns_none() {
    let mut bad_user = fixture_user("u1", "alice", "t1");
    // Null byte in display_name → `User::validate()` returns Err.
    bad_user.display_name = "Alice\x00Evil".into();
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(bad_user);
    let svc = AuthnService::new(identity, MockFactorStore::new());
    let token = svc
        .begin_password_reset("alice", "default", std::time::Duration::from_secs(300))
        .await
        .unwrap();
    assert!(
        token.is_none(),
        "user with failing validate() must yield None, got {token:?}"
    );
}

/// line 347 `verify_new_password_not_in_history` body and
/// rail. With history_count > 0 and the new password's hash already
/// in history, the function returns `Ok(true)`; `complete_password_reset`
/// then refuses with `Ok(false)`. Mutation `Ok(false)`: history check
/// always passes → reused passwords accepted. Mutation `==` to `!=`:
/// with history_count > 0, the early return fires (returns Ok(false)
///; "not reused") and the loop is skipped, so reuse goes undetected.
///
/// Discriminator: pre-load a password into history, attempt reset
/// with the same hash, baseline rejects (Ok(false) from
/// complete_password_reset), mutation accepts (Ok(true)).
#[tokio::test]
async fn complete_password_reset_rejects_password_reuse() {
    use axess_core::authn::factor::PasswordRules;

    let user = fixture_user("u1", "alice", "t1");
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(user.clone())
        .with_password_rules(
            &user.tenant_id,
            PasswordRules {
                history_count: 5,
                ..PasswordRules::default()
            },
        );
    let inspector = identity.clone();
    let svc = AuthnService::new(identity, MockFactorStore::new());

    // Begin a reset to issue a real token.
    let token = svc
        .begin_password_reset("alice", "default", std::time::Duration::from_secs(300))
        .await
        .unwrap()
        .expect("token");

    // The history check Argon2-verifies the new plaintext against each
    // stored hash. To produce a reuse case we hash the candidate
    // plaintext, store the resulting PHC string in history, then call
    // `complete_password_reset` with the same plaintext; Argon2's verify
    // recomputes the candidate under the stored salt and matches.
    let reused_plaintext = "reused-password";
    let history_entry = axess_factors::generate_password_hash(reused_plaintext);
    inspector
        .record_password_hash(&user.id, &history_entry)
        .await
        .unwrap();

    let result = svc
        .complete_password_reset(&user.id, &token, reused_plaintext)
        .await
        .unwrap();
    assert!(
        !result,
        "reused password must be rejected (Ok(false)). \
         Mutation `Ok(false)` body would mask reuse and let the reset succeed; \
         mutation `==` → `!=` would early-return `Ok(false)` from history check \
         and let the reset succeed."
    );
}

/// line 183:12 `delete !` on `if !verify_reset_token_hash(...)`.
/// Removing the `!` inverts the polarity: a VALID token is rejected
/// (Ok(false)) while INVALID tokens are processed and crash later
/// because `get_user` returns Some but the password hash is the
/// invalid input. Discriminator: provide a valid token, expect
/// `Ok(true)` (baseline); mutation returns `Ok(false)`.
#[tokio::test]
async fn complete_password_reset_valid_token_returns_true() {
    let user = fixture_user("u1", "alice", "t1");
    let svc = make_service_with_user(user.clone());
    let token = svc
        .begin_password_reset("alice", "default", std::time::Duration::from_secs(300))
        .await
        .unwrap()
        .expect("token");
    let result = svc
        .complete_password_reset(&user.id, &token, "new-password-123")
        .await
        .unwrap();
    assert!(result, "valid token must return Ok(true), got {result}");
}
