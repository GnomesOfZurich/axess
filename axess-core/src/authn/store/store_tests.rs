//! Pin trait-default behaviours and `AuthMethod` accessors
//! against body-replacement and equality-flip mutations.
use super::*;
use crate::authn::factor::{FactorKind, FactorStep};
use crate::testing::mock_authn::MockIdentityStore;

fn fixture_user_id() -> UserId {
    axess_identity::testing::user("u-store")
}

fn fixture_tenant_id() -> TenantId {
    axess_identity::testing::tenant("t-store")
}

fn other_tenant_id() -> TenantId {
    axess_identity::testing::tenant("t-other")
}

fn build_user(user_id: &UserId, tenant_id: &TenantId) -> User {
    let now = chrono::Utc::now();
    User {
        id: *user_id,
        tenant_id: *tenant_id,
        identifier: "u-store".into(),
        display_name: "u-store".into(),
        status: EntityState::Active,
        webauthn_id: None,
        created_by: UserId::system(),
        created_at: now,
        updated_by: UserId::system(),
        updated_at: now,
    }
}

// ── get_user_in_tenant (line 132) ────────────────────────────────

/// Kills line 132 `with true` / `with false` and `== → !=`:
/// when the user's stored tenant matches `expected_tenant`,
/// `get_user_in_tenant` returns Some.
#[tokio::test]
async fn get_user_in_tenant_matching_tenant_returns_some() {
    let user_id = fixture_user_id();
    let tenant_id = fixture_tenant_id();
    let store = MockIdentityStore::new().with_user(build_user(&user_id, &tenant_id));

    let result = store
        .get_user_in_tenant(&user_id, &tenant_id)
        .await
        .expect("store call succeeds");
    assert!(result.is_some(), "user in expected tenant must return Some");
}

/// Companion: when the user's stored tenant DIFFERS from
/// `expected_tenant`, the function must return None. Kills the
/// `with true` mutation (which would always return Some) and
/// `== → !=` (which inverts the guard).
#[tokio::test]
async fn get_user_in_tenant_mismatched_tenant_returns_none() {
    let user_id = fixture_user_id();
    let tenant_id = fixture_tenant_id();
    let store = MockIdentityStore::new().with_user(build_user(&user_id, &tenant_id));

    let result = store
        .get_user_in_tenant(&user_id, &other_tenant_id())
        .await
        .expect("store call succeeds");
    assert!(
        result.is_none(),
        "user NOT in expected tenant must return None; \
         IDOR mitigation depends on this"
    );
}

// ── AuthMethod::factors() (line 601) ─────────────────────────────

/// Kills line 601 `-> vec![]`: a method with concrete factor
/// steps must produce a non-empty kinds list.
#[test]
fn auth_method_factors_extracts_kinds_from_required_steps() {
    let method = AuthMethod::sequential(
        "totp-pw",
        vec![FactorKind::Password, FactorKind::Totp],
        AuthnScope::Global,
    );
    let kinds = method.factors();
    assert_eq!(
        kinds,
        vec![FactorKind::Password, FactorKind::Totp],
        "factors() must surface the configured kinds in order; \
         `vec![]` mutation would collapse to empty"
    );
}

/// AnyOf-step handling: the first choice of each AnyOf is
/// returned. Defends the AnyOf arm against being dropped or
/// reordered with the empty-vec mutation.
#[test]
fn auth_method_factors_picks_first_anyof_choice() {
    let method = AuthMethod {
        name: "anyof".into(),
        steps: vec![FactorStep::AnyOf(vec![
            FactorKind::Totp,
            FactorKind::Password,
        ])],
        scope: AuthnScope::Global,
    };
    let kinds = method.factors();
    assert_eq!(kinds, vec![FactorKind::Totp]);
}
