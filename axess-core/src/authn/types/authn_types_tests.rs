//! `authn_types_tests`: extracted from `types.rs` per the
//! 200-LoC inline-test rule in AGENTS.md.

use super::*;
use crate::authn::ids::UserId;

/// `EntityState::is_active` returns true ONLY for the
/// `Active` variant. A `-> true` body mutation would silently
/// allow login on every `Suspended`/`Terminated`/`Archived`/
/// `Candidate` account.
#[test]
fn entity_state_is_active_only_for_active() {
    assert!(EntityState::Active.is_active());
    assert!(
        !EntityState::Suspended(StatusDetail {
            reason: "test".into(),
            since: chrono::Utc::now(),
            until: None,
        })
        .is_active()
    );
    assert!(
        !EntityState::Terminated(StatusDetail {
            reason: "test".into(),
            since: chrono::Utc::now(),
            until: None,
        })
        .is_active()
    );
    assert!(
        !EntityState::Archived(StatusDetail {
            reason: "test".into(),
            since: chrono::Utc::now(),
            until: None,
        })
        .is_active()
    );
    assert!(!EntityState::Candidate.is_active());
}

/// `resolution_chain` must return a non-empty ordered chain
/// for each scope, terminating at [`AuthnScope::System`]. The mutation
/// `-> vec![]` would silently drop every fall-through branch:
/// factor-config and method-resolution would only ever look at
/// the most-specific row, never the tenant or system default.
#[test]
fn resolution_chain_returns_non_empty_terminated_chain_per_scope() {
    // System → exactly [System].
    let system = AuthnScope::System.resolution_chain();
    assert_eq!(system, vec![AuthnScope::System]);

    // Tenant → tenant row, then system fallback.
    let tenant = axess_identity::testing::tenant("t1");
    let tenant_chain = AuthnScope::Tenant(tenant).resolution_chain();
    assert_eq!(
        tenant_chain,
        vec![AuthnScope::Tenant(tenant), AuthnScope::System]
    );

    // User → user row, tenant row, system fallback.
    let user = axess_identity::testing::user("u1");
    let user_chain = AuthnScope::User {
        tenant_id: tenant,
        user_id: user,
    }
    .resolution_chain();
    assert_eq!(
        user_chain,
        vec![
            AuthnScope::User {
                tenant_id: tenant,
                user_id: user,
            },
            AuthnScope::Tenant(tenant),
            AuthnScope::System,
        ]
    );
}

/// Storage projection: `tenant_id` is always populated (SYSTEM for
/// the `System` scope); `user_id` is populated only for `User`.
#[test]
fn as_columns_always_populates_tenant() {
    let sys = AuthnScope::System.as_columns();
    assert_eq!(sys.tenant_id, TenantId::SYSTEM);
    assert!(sys.user_id.is_none());

    let t = axess_identity::testing::tenant("t1");
    let tenant = AuthnScope::Tenant(t).as_columns();
    assert_eq!(tenant.tenant_id, t);
    assert!(tenant.user_id.is_none());

    let u = axess_identity::testing::user("u1");
    let user = AuthnScope::User {
        tenant_id: t,
        user_id: u,
    }
    .as_columns();
    assert_eq!(user.tenant_id, t);
    assert_eq!(user.user_id, Some(u));
}

fn make_user_with_identifier(identifier: &str, display_name: &str) -> User {
    let now = chrono::Utc::now();
    User {
        id: axess_identity::testing::user("u-validate"),
        tenant_id: axess_identity::testing::tenant("t-validate"),
        identifier: identifier.into(),
        display_name: display_name.into(),
        status: EntityState::Active,
        webauthn_id: None,
        created_by: UserId::system(),
        created_at: now,
        updated_by: UserId::system(),
        updated_at: now,
    }
}

fn make_tenant_with_identifier(identifier: &str) -> Tenant {
    let now = chrono::Utc::now();
    Tenant {
        id: axess_identity::testing::tenant("t-validate"),
        identifier: identifier.into(),
        display_name: "Display".into(),
        status: EntityState::Active,
        created_by: UserId::system(),
        created_at: now,
        updated_by: UserId::system(),
        updated_at: now,
    }
}

/// Kill the `User::validate -> Ok(())` body replacement.
/// The function must reject invalid identifiers and display names.
#[test]
fn user_validate_rejects_invalid_inputs() {
    // Empty identifier
    assert!(
        make_user_with_identifier("", "Display").validate().is_err(),
        "empty identifier must fail validation"
    );
    // Identifier with control character
    assert!(
        make_user_with_identifier("ab\nc", "Display")
            .validate()
            .is_err(),
        "control characters in identifier must fail validation"
    );
    // Display name with null byte
    assert!(
        make_user_with_identifier("alice", "bad\0name")
            .validate()
            .is_err(),
        "null byte in display_name must fail validation"
    );
    // Happy path: valid inputs pass
    assert!(
        make_user_with_identifier("alice", "Alice")
            .validate()
            .is_ok()
    );
}

/// Kill the `Tenant::validate -> Ok(())` body replacement.
#[test]
fn tenant_validate_rejects_invalid_inputs() {
    assert!(
        make_tenant_with_identifier("").validate().is_err(),
        "empty identifier must fail"
    );
    assert!(
        make_tenant_with_identifier("acme\nplc").validate().is_err(),
        "control character must fail"
    );
    assert!(make_tenant_with_identifier("acme").validate().is_ok());
}

/// Kill the `AuthnScope::key -> String::new()` and
/// `-> "xyzzy".into()` body replacements. The key must:
/// 1. Be non-empty for every variant (kills String::new()).
/// 2. Match the documented prefix for each variant (kills
///    "xyzzy".into(); a fixed wrong value would lose the
///    `global` / `tenant:` / `user:` prefixes).
/// 3. Interpolate the tenant/user ids (kills any fixed-string
///    mutation that ignores the variant data).
#[test]
fn authn_scope_key_per_variant_format() {
    let tenant = axess_identity::testing::tenant("t-key");
    let user = axess_identity::testing::user("u-key");

    assert_eq!(AuthnScope::System.key(), "system");

    let tenant_key = AuthnScope::Tenant(tenant).key();
    assert!(
        tenant_key.starts_with("tenant:"),
        "Tenant key must start with `tenant:`, got {tenant_key:?}"
    );
    assert!(
        tenant_key.contains(&tenant.to_string()),
        "Tenant key must interpolate the tenant id, got {tenant_key:?}"
    );

    let user_key = AuthnScope::User {
        tenant_id: tenant,
        user_id: user,
    }
    .key();
    assert!(
        user_key.starts_with("user:"),
        "User key must start with `user:`, got {user_key:?}"
    );
    assert!(
        user_key.contains(&tenant.to_string()) && user_key.contains(&user.to_string()),
        "User key must interpolate both ids, got {user_key:?}"
    );
}

fn policy(allow: &[&str], deny: &[&str]) -> IpPolicy {
    IpPolicy {
        allow: allow.iter().map(|s| (*s).into()).collect(),
        deny: deny.iter().map(|s| (*s).into()).collect(),
    }
}

#[test]
fn ipv4_mapped_ipv6_is_judged_as_its_ipv4_address() {
    let deny = policy(&[], &["10.0.0.0/8"]);
    assert!(!deny.is_allowed("::ffff:10.1.2.3".parse().unwrap()));
    assert!(deny.is_allowed("::ffff:172.16.0.1".parse().unwrap()));

    let allow = policy(&["10.0.0.0/8"], &[]);
    assert!(allow.is_allowed("::ffff:10.1.2.3".parse().unwrap()));
    assert!(!allow.is_allowed("::ffff:11.1.2.3".parse().unwrap()));
}

#[test]
fn mapped_notation_in_an_entry_names_the_ipv4_network() {
    let deny = policy(&[], &["::ffff:10.0.0.0/104"]);
    assert!(!deny.is_allowed("10.9.9.9".parse().unwrap()));
    assert!(deny.is_allowed("11.9.9.9".parse().unwrap()));
}

#[test]
fn a_malformed_deny_entry_denies_everyone() {
    for bad in ["10.0.0.0/33", "not-an-ip", "10.0.0.0/x", "10.0.0.256", ""] {
        let deny = policy(&[], &["192.0.2.0/24", bad]);
        assert!(
            !deny.is_allowed("203.0.113.1".parse().unwrap()),
            "deny entry {bad:?} is unreadable and must fail closed"
        );
    }
}

#[test]
fn a_malformed_allow_entry_matches_nothing() {
    let allow = policy(&["10.0.0.0/33", "bogus"], &[]);
    assert!(!allow.is_allowed("10.0.0.1".parse().unwrap()));
}

#[test]
fn suspension_ends_when_until_passes() {
    use chrono::TimeZone;
    let now = Utc.with_ymd_and_hms(2026, 6, 1, 12, 0, 0).unwrap();
    let detail = |until| {
        EntityState::Suspended(StatusDetail {
            reason: "lockout".into(),
            since: now - chrono::Duration::hours(1),
            until,
        })
    };
    assert!(
        detail(Some(now - chrono::Duration::seconds(1)))
            .effective_at(now)
            .allows_login()
    );
    assert!(detail(Some(now)).effective_at(now).allows_login());
    assert!(
        !detail(Some(now + chrono::Duration::seconds(1)))
            .effective_at(now)
            .allows_login()
    );
    assert!(!detail(None).effective_at(now).allows_login());
    assert!(
        !EntityState::Terminated(StatusDetail {
            reason: "x".into(),
            since: now,
            until: Some(now - chrono::Duration::days(1)),
        })
        .effective_at(now)
        .allows_login()
    );
}
