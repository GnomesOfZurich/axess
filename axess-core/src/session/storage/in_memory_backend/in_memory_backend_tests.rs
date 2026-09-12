//! `in_memory_backend_tests`: extracted from `in_memory_backend.rs` per the
//! 200-LoC inline-test rule in AGENTS.md.

//! Drive each delegation through observable behavior so that a
//! `Default::default()` / `Ok(None)` / `Ok(())` mutation at the
//! wrapper level changes a downstream assertion.
use super::*;
use crate::authn::event::{AuthEvent, AuthEventBuilder, AuthEventStatus, AuthEventType};
use crate::authn::store::{IdentityAdmin, IdentityAuthnLog, IdentityLookup};
use crate::authn::types::StatusDetail;
use chrono::Utc;

fn t() -> TenantId {
    axess_identity::testing::tenant("default")
}

fn u() -> UserId {
    axess_identity::testing::user("alice")
}

fn user_scope() -> AuthnScope {
    AuthnScope::User {
        tenant_id: t(),
        user_id: u(),
    }
}

fn populated_backend() -> InMemoryBackend {
    InMemoryBackend::new()
        .with_default_tenant("default", "Default Tenant")
        .with_user_password("alice", "default", "Gnomes2+")
}

#[tokio::test]
async fn with_default_tenant_persists_through_find_tenant_and_default_tenant() {
    // Kills `with_default_tenant -> Default::default()` (which
    // would erase the tenant and produce an empty backend).
    let backend = InMemoryBackend::new().with_default_tenant("default", "Default Tenant");
    let found = backend.find_tenant("default").await.unwrap();
    assert!(
        found.is_some(),
        "find_tenant must surface the registered tenant"
    );
    let default = backend.default_tenant().await.unwrap();
    assert_eq!(default.id, t());
}

#[tokio::test]
async fn with_user_password_registers_user_factor_and_method() {
    // Kills `with_user_password -> Default::default()` plus the
    // delegations exercised below.
    let backend = populated_backend();

    // find_user / get_user; kills both `Ok(None)` mutations.
    let found = backend.find_user("alice", &t()).await.unwrap();
    assert!(found.is_some(), "find_user must locate the registered user");
    let got = backend.get_user(&u()).await.unwrap();
    assert!(got.is_some(), "get_user must locate the registered user");

    // load_factor; kills `Ok(None)` mutation.
    let factor = backend
        .load_factor(&user_scope(), FactorKind::Password)
        .await
        .unwrap();
    assert!(
        factor.is_some(),
        "load_factor must surface the seeded password factor"
    );

    // available_methods; kills `Ok(vec![])`.
    let methods = backend.available_methods(&u(), &t()).await.unwrap();
    assert!(
        methods.iter().any(|m| m.name.as_ref() == "password"),
        "available_methods must contain the seeded `password` method"
    );
}

#[tokio::test]
async fn account_status_is_active_after_registration() {
    // Kills `account_status -> Ok(Default::default())`. Default
    // for EntityState is Guest; the seeded user is Active.
    let backend = populated_backend();
    let status = backend.account_status(&u()).await.unwrap();
    assert_eq!(status, EntityState::Active);
}

#[tokio::test]
async fn record_failed_attempt_increments_and_reset_zeroes_count() {
    // Kills `record_failed_attempt -> Ok(0)` and `Ok(1)` (both
    // would give the same value across calls), and
    // `reset_failed_attempts -> Ok(())` (which would skip the
    // reset side effect; verified via the inner mock's
    // `failed_attempts_for`).
    let backend = populated_backend();
    let first = backend.record_failed_attempt(&u()).await.unwrap();
    let second = backend.record_failed_attempt(&u()).await.unwrap();
    assert!(
        second > first,
        "record_failed_attempt must increment (got {first} -> {second})"
    );
    assert_eq!(
        backend.identity_store().failed_attempts_for("alice"),
        second
    );

    backend.reset_failed_attempts(&u()).await.unwrap();
    assert_eq!(
        backend.identity_store().failed_attempts_for("alice"),
        0,
        "reset_failed_attempts must zero the inner counter"
    );
}

#[tokio::test]
async fn record_event_persists_to_inner_store() {
    // Kills `record_event -> Ok(())` (which would skip the side
    // effect; verified via the inner mock's `events()`).
    let backend = populated_backend();
    let event: AuthEvent =
        AuthEventBuilder::unattributed(AuthEventType::LoginAttempt, AuthEventStatus::Success)
            .build();
    backend.record_event(event).await.unwrap();
    let recorded = backend.identity_store().events();
    assert_eq!(
        recorded.len(),
        1,
        "record_event must forward to MockIdentityStore::record_event"
    );
}

#[tokio::test]
async fn create_tenant_and_create_user_persist() {
    // Kills `create_tenant -> Ok(())` and `create_user -> Ok(())`
    // (both would skip the side effect; observable via the next
    // find_tenant / get_user call).
    let backend = InMemoryBackend::new();
    let now = Utc::now();
    let tenant = Tenant {
        id: axess_identity::testing::tenant("acme"),
        identifier: "acme".into(),
        display_name: "ACME".into(),
        status: EntityState::Active,
        created_by: UserId::system(),
        created_at: now,
        updated_by: UserId::system(),
        updated_at: now,
    };
    backend.create_tenant(tenant).await.unwrap();
    assert!(backend.find_tenant("acme").await.unwrap().is_some());

    let user = User {
        id: axess_identity::testing::user("bob"),
        tenant_id: axess_identity::testing::tenant("acme"),
        identifier: "bob".into(),
        display_name: "Bob".into(),
        status: EntityState::Active,
        webauthn_id: None,
        created_by: UserId::system(),
        created_at: now,
        updated_by: UserId::system(),
        updated_at: now,
    };
    backend.create_user(user).await.unwrap();
    assert!(
        backend
            .get_user(&axess_identity::testing::user("bob"))
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn suspend_and_activate_user_change_account_status() {
    // Kills `suspend_user -> Ok(())` and `activate_user -> Ok(())`.
    let backend = populated_backend();
    let detail = StatusDetail {
        reason: "ax-028 test".into(),
        since: Utc::now(),
        until: None,
    };
    backend.suspend_user(&u(), detail).await.unwrap();
    let suspended = backend.account_status(&u()).await.unwrap();
    assert!(
        matches!(suspended, EntityState::Suspended(_)),
        "suspend_user must transition account_status (got {suspended:?})"
    );
    backend.activate_user(&u()).await.unwrap();
    assert_eq!(
        backend.account_status(&u()).await.unwrap(),
        EntityState::Active,
        "activate_user must restore Active"
    );
}

#[tokio::test]
async fn save_factor_overwrites_existing_password_factor() {
    // Kills `save_factor -> Ok(())` and `compare_and_save_factor
    // -> Ok(true)` / `Ok(false)`.
    let backend = populated_backend();
    let original = backend
        .load_factor(&user_scope(), FactorKind::Password)
        .await
        .unwrap()
        .expect("seeded factor present");

    let replacement = FactorConfig::Password(PasswordConfig {
        hash: ZeroizedString::new("REPLACEMENT-HASH"),
        rules: PasswordRules::default(),
    });
    backend
        .save_factor(&user_scope(), replacement.clone())
        .await
        .unwrap();

    let loaded = backend
        .load_factor(&user_scope(), FactorKind::Password)
        .await
        .unwrap()
        .expect("factor present after save");
    match loaded {
        FactorConfig::Password(ref pc) => {
            assert_eq!(&*pc.hash, "REPLACEMENT-HASH", "save_factor must overwrite");
        }
        _ => panic!("expected Password factor"),
    }

    // CAS: prior matches loaded, update to a third value should succeed.
    let next = FactorConfig::Password(PasswordConfig {
        hash: ZeroizedString::new("CAS-WIN"),
        rules: PasswordRules::default(),
    });
    let cas_ok = backend
        .compare_and_save_factor(&user_scope(), &loaded, next.clone())
        .await
        .unwrap();
    assert!(cas_ok, "compare_and_save with matching prior must succeed");

    // CAS: prior is now stale (matches `loaded`, not the latest),
    // so this must fail.
    let losing = FactorConfig::Password(PasswordConfig {
        hash: ZeroizedString::new("CAS-LOSE"),
        rules: PasswordRules::default(),
    });
    let cas_fail = backend
        .compare_and_save_factor(&user_scope(), &original, losing)
        .await
        .unwrap();
    assert!(
        !cas_fail,
        "compare_and_save with stale prior must NOT succeed"
    );
}

#[tokio::test]
async fn save_method_remove_method_and_set_enabled_drive_available_methods() {
    // Kills `save_method -> Ok(())`, `remove_method -> Ok(())`,
    // and `set_method_enabled -> Ok(true|false)`.
    //
    // `MockFactorStore` rejects `AuthnScope::System` for these
    // CRUD calls (returns `InvalidSystemMethod`). User-scope and
    // Tenant-scope rows are stored in a separate `scoped_methods`
    // map and surface alongside the seeded user-id-keyed methods
    // in `available_methods`.
    let backend = populated_backend();

    let scope = user_scope();
    let totp = AuthMethod::sequential("totp", vec![FactorKind::Totp], scope.clone());

    backend.save_method(&scope, totp).await.unwrap();
    let methods = backend.available_methods(&u(), &t()).await.unwrap();
    assert!(
        methods.iter().any(|m| m.name.as_ref() == "totp"),
        "save_method must publish into available_methods (got {:?})",
        methods
            .iter()
            .map(|m| m.name.to_string())
            .collect::<Vec<_>>()
    );

    // Toggle: disable the user-scoped method, it must drop from
    // `available_methods` (filtered to enabled-only).
    let was_enabled = backend
        .set_method_enabled(&scope, "totp", false)
        .await
        .unwrap();
    assert!(
        was_enabled,
        "set_method_enabled must report the prior enabled state (true)"
    );
    let after_disable = backend.available_methods(&u(), &t()).await.unwrap();
    assert!(
        !after_disable.iter().any(|m| m.name.as_ref() == "totp"),
        "set_method_enabled(false) must drop method from available_methods"
    );

    // Re-enable.
    backend
        .set_method_enabled(&scope, "totp", true)
        .await
        .unwrap();
    let after_reenable = backend.available_methods(&u(), &t()).await.unwrap();
    assert!(
        after_reenable.iter().any(|m| m.name.as_ref() == "totp"),
        "set_method_enabled(true) must restore method to available_methods"
    );

    backend.remove_method(&scope, "totp").await.unwrap();
    let after_remove = backend.available_methods(&u(), &t()).await.unwrap();
    assert!(
        !after_remove.iter().any(|m| m.name.as_ref() == "totp"),
        "remove_method must drop the method"
    );
}

#[tokio::test]
async fn identity_store_and_factor_store_accessors_return_inner() {
    // Kills `identity_store -> Box::leak(...)` and
    // `factor_store -> Box::leak(...)`. The mutated bodies leak a
    // fresh empty store; the registered tenant / user / method
    // would not appear via those accessors.
    let backend = populated_backend();
    let identity_events_before = backend.identity_store().events();
    assert_eq!(
        identity_events_before.len(),
        0,
        "fresh backend must have no events; if mutated, accessor would still return empty (this case is informational)"
    );
    // After registering, the accessor must point at the populated
    // inner store; verify by inspecting failed_attempts_for "alice"
    // after recording an attempt (drives both delegation and the
    // accessor).
    backend.record_failed_attempt(&u()).await.unwrap();
    assert_eq!(
        backend.identity_store().failed_attempts_for("alice"),
        1,
        "identity_store accessor must yield the populated MockIdentityStore"
    );

    // factor_store: confirm the seeded factor is present via the
    // accessor (kills the leak-fresh-Default mutant).
    let factor = backend
        .factor_store()
        .load_factor(&user_scope(), FactorKind::Password)
        .await
        .unwrap();
    assert!(
        factor.is_some(),
        "factor_store accessor must yield the populated MockFactorStore"
    );
}

#[tokio::test]
async fn record_password_hash_appears_in_password_history() {
    // Together kills:
    //   - `record_password_hash -> Ok(())` (skips the push; history would be empty)
    //   - `password_history     -> Ok(vec![])` (would return empty even after a push)
    //   - `password_history     -> Ok(vec![String::new()])` (would return [""])
    //   - `password_history     -> Ok(vec!["xyzzy".into()])` (would return ["xyzzy"])
    let backend = populated_backend();
    let user_id = u();

    backend
        .record_password_hash(&user_id, "argon2$first")
        .await
        .unwrap();
    backend
        .record_password_hash(&user_id, "argon2$second")
        .await
        .unwrap();

    let recent = backend.password_history(&user_id, 2).await.unwrap();
    // MockIdentityStore returns most-recent-first.
    assert_eq!(
        recent,
        vec!["argon2$second".to_string(), "argon2$first".to_string()],
        "password_history must surface both recorded hashes in reverse insertion order"
    );
}

#[tokio::test]
async fn reset_token_round_trip_through_backend() {
    // Together kills:
    //   - `store_reset_token   -> Ok(())` (skips the insert; subsequent verify would be false)
    //   - `verify_reset_token  -> Ok(true)`  (would accept a wrong hash)
    //   - `verify_reset_token  -> Ok(false)` (would reject a correct hash)
    let backend = populated_backend();
    let user_id = u();
    let token_hash = "sha256$abc123";
    let wrong_hash = "sha256$wrong";
    let expires_at = Utc::now() + chrono::Duration::minutes(15);

    // Wrong hash before anything is stored; must be false.
    let pre = backend
        .verify_reset_token(&user_id, wrong_hash)
        .await
        .unwrap();
    assert!(
        !pre,
        "verify_reset_token must be false when no token is stored"
    );

    backend
        .store_reset_token(&user_id, token_hash, expires_at)
        .await
        .unwrap();

    // Wrong hash against a stored token; still false (kills `Ok(true)`).
    let bad = backend
        .verify_reset_token(&user_id, wrong_hash)
        .await
        .unwrap();
    assert!(!bad, "verify_reset_token must reject a non-matching hash");

    // Correct hash; true (kills `Ok(false)` and `store_reset_token -> Ok(())`).
    let ok = backend
        .verify_reset_token(&user_id, token_hash)
        .await
        .unwrap();
    assert!(
        ok,
        "verify_reset_token must accept the matching hash before expiry"
    );
}
