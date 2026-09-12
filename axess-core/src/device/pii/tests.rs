//! `tests`: extracted from `pii.rs` per the
//! 200-LoC inline-test rule in AGENTS.md.

use super::*;

fn user(s: &str) -> UserId {
    axess_identity::testing::user(s)
}

fn tenant(s: &str) -> TenantId {
    axess_identity::testing::tenant(s)
}

/// Token wire format is `"pii:<uuid-hyphenated>"` and
/// round-trips through `parse`. This is the documented canonical
/// shape compatible with `gov-core::pii::PiiToken`; changing it is
/// a wire-break.
#[test]
fn token_wire_format_is_pii_colon_uuid() {
    let uuid = Uuid::nil();
    let token = PiiToken::from_uuid(uuid);
    assert_eq!(token.as_str(), "pii:00000000-0000-0000-0000-000000000000");

    let parsed = PiiToken::parse(token.as_str()).expect("round-trip parse");
    assert_eq!(parsed, token);
}

/// `is_well_formed` rejects shapes that wouldn't round-trip
/// through `new`. Stable rejection set so callers can use it as a
/// pre-store validation gate.
#[test]
fn is_well_formed_rejects_malformed() {
    // Missing prefix.
    assert!(!PiiToken::is_well_formed(
        "00000000-0000-0000-0000-000000000000"
    ));
    // Wrong prefix.
    assert!(!PiiToken::is_well_formed(
        "pii_00000000-0000-0000-0000-000000000000"
    ));
    // Non-UUID body.
    assert!(!PiiToken::is_well_formed("pii:not-a-uuid"));
    // Empty.
    assert!(!PiiToken::is_well_formed(""));
    assert!(!PiiToken::is_well_formed("pii:"));
    // Right shape.
    assert!(PiiToken::is_well_formed(
        "pii:00000000-0000-0000-0000-000000000000"
    ));
}

/// `record` → `resolve` round-trips the value plaintext;
/// the returned token is the same token now stored. Pins the
/// Memory backend's basic contract.
#[tokio::test]
async fn record_then_resolve_round_trips_value() {
    let store = MemoryDevicePiiStore::new();
    let now = Utc::now();
    let token = store
        .record(
            &user("u1"),
            &tenant("t1"),
            DevicePiiCategory::DisplayName,
            "Alice's iPhone".to_string(),
            now,
        )
        .await
        .unwrap();
    assert!(PiiToken::is_well_formed(token.as_str()));
    let value = store.resolve(&token, &tenant("t1")).await.unwrap();
    assert_eq!(value.as_deref(), Some("Alice's iPhone"));
}

/// Structural tenant rail. A mapping recorded under tenant
/// A is invisible to a resolve issued from tenant B, even when
/// the caller has the right token. Same shape as missing.
/// Without this rail, a multi-tenant deployment can leak PII via
/// token-guessing across tenants.
#[tokio::test]
async fn resolve_refuses_cross_tenant_lookup() {
    let store = MemoryDevicePiiStore::new();
    let token = store
        .record(
            &user("u1"),
            &tenant("alpha"),
            DevicePiiCategory::IpAddress,
            "203.0.113.42".to_string(),
            Utc::now(),
        )
        .await
        .unwrap();

    // Same-tenant resolve hits.
    let same = store.resolve(&token, &tenant("alpha")).await.unwrap();
    assert_eq!(same.as_deref(), Some("203.0.113.42"));

    // Cross-tenant resolve returns None; same as a missing token.
    let cross = store.resolve(&token, &tenant("beta")).await.unwrap();
    assert!(
        cross.is_none(),
        "cross-tenant lookup must be invisible, not leak the value"
    );
}

/// `erase_subject` deletes every mapping for the
/// `(subject, tenant)` pair, leaves other subjects' mappings
/// alone, and returns the count erased. Subsequent `resolve` of
/// an erased token returns `None` (forms the basis of the
/// `RedactedResolver` post-erasure contract).
#[tokio::test]
async fn erase_subject_removes_only_target_subject_mappings() {
    let store = MemoryDevicePiiStore::new();
    let now = Utc::now();
    let t = tenant("t1");

    // Two mappings for the target user across two categories.
    let alice_dn = store
        .record(
            &user("alice"),
            &t,
            DevicePiiCategory::DisplayName,
            "Alice".into(),
            now,
        )
        .await
        .unwrap();
    let alice_ip = store
        .record(
            &user("alice"),
            &t,
            DevicePiiCategory::IpAddress,
            "203.0.113.1".into(),
            now,
        )
        .await
        .unwrap();
    // One mapping for a different user that must NOT be touched.
    let bob_dn = store
        .record(
            &user("bob"),
            &t,
            DevicePiiCategory::DisplayName,
            "Bob".into(),
            now,
        )
        .await
        .unwrap();

    let erased = store.erase_subject(&user("alice"), &t).await.unwrap();
    assert_eq!(erased, 2, "must erase exactly Alice's 2 rows");

    // Alice's tokens no longer resolve.
    assert!(store.resolve(&alice_dn, &t).await.unwrap().is_none());
    assert!(store.resolve(&alice_ip, &t).await.unwrap().is_none());

    // Bob's mapping survives; erasure is per-subject, not per-tenant.
    assert_eq!(
        store.resolve(&bob_dn, &t).await.unwrap().as_deref(),
        Some("Bob"),
    );
}

/// `erase_subject` is also tenant-scoped. Erasing a
/// `(subject, tenantA)` pair must NOT touch a same-named subject
/// in `tenantB`: different tenants are different data subjects
/// from the controller's perspective.
#[tokio::test]
async fn erase_subject_is_tenant_scoped() {
    let store = MemoryDevicePiiStore::new();
    let alice_alpha = store
        .record(
            &user("alice"),
            &tenant("alpha"),
            DevicePiiCategory::DisplayName,
            "Alice@alpha".into(),
            Utc::now(),
        )
        .await
        .unwrap();
    let alice_beta = store
        .record(
            &user("alice"),
            &tenant("beta"),
            DevicePiiCategory::DisplayName,
            "Alice@beta".into(),
            Utc::now(),
        )
        .await
        .unwrap();

    let erased = store
        .erase_subject(&user("alice"), &tenant("alpha"))
        .await
        .unwrap();
    assert_eq!(erased, 1);

    assert!(
        store
            .resolve(&alice_alpha, &tenant("alpha"))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .resolve(&alice_beta, &tenant("beta"))
            .await
            .unwrap()
            .as_deref(),
        Some("Alice@beta"),
        "erasure in tenant alpha must not touch tenant beta"
    );
}

/// `list_for_subject` drives the Art 20 portability export.
/// Returns every mapping for the `(subject, tenant)` pair, no
/// others. Tenant-scoped (mirrors erase_subject's scoping).
#[tokio::test]
async fn list_for_subject_returns_all_mappings_in_tenant() {
    let store = MemoryDevicePiiStore::new();
    let t = tenant("t1");
    let now = Utc::now();
    store
        .record(
            &user("alice"),
            &t,
            DevicePiiCategory::DisplayName,
            "Alice".into(),
            now,
        )
        .await
        .unwrap();
    store
        .record(
            &user("alice"),
            &t,
            DevicePiiCategory::UserAgentString,
            "Mozilla/5.0".into(),
            now,
        )
        .await
        .unwrap();
    store
        .record(
            &user("bob"),
            &t,
            DevicePiiCategory::DisplayName,
            "Bob".into(),
            now,
        )
        .await
        .unwrap();

    let alice_rows = store.list_for_subject(&user("alice"), &t).await.unwrap();
    assert_eq!(
        alice_rows.len(),
        2,
        "portability export must include all of Alice's mappings"
    );
    assert!(
        alice_rows.iter().all(|m| m.subject_id == user("alice")),
        "list_for_subject must not leak other subjects' rows"
    );
}

/// The auto-impl of `DevicePiiResolver` for
/// `DevicePiiStore` collapses missing mappings to the canonical
/// `[redacted]` placeholder. Same shape regardless of whether the
/// row was erased, never existed, or is cross-tenant.
#[tokio::test]
async fn resolver_returns_redacted_for_missing_token() {
    let store = MemoryDevicePiiStore::new();
    let bogus = PiiToken::new();
    let resolved = store
        .resolve_or_redacted(&bogus, &tenant("t1"))
        .await
        .unwrap();
    assert_eq!(resolved, REDACTED_PLACEHOLDER);
}

/// The auto-impl of `DevicePiiResolver` returns the real
/// value when present. Pins that the redacted-on-missing
/// behaviour is conditional, not unconditional.
#[tokio::test]
async fn resolver_returns_real_value_when_present() {
    let store = MemoryDevicePiiStore::new();
    let token = store
        .record(
            &user("u1"),
            &tenant("t1"),
            DevicePiiCategory::DisplayName,
            "Alice".into(),
            Utc::now(),
        )
        .await
        .unwrap();
    let resolved = store
        .resolve_or_redacted(&token, &tenant("t1"))
        .await
        .unwrap();
    assert_eq!(resolved, "Alice");
}

/// `RedactedResolver` always returns the placeholder,
/// regardless of whether the token would resolve in some other
/// store. Pins the post-erasure / fail-safe contract.
#[tokio::test]
async fn redacted_resolver_unconditionally_returns_placeholder() {
    let resolver = RedactedResolver;
    let token = PiiToken::new();
    let resolved = resolver
        .resolve_or_redacted(&token, &tenant("t1"))
        .await
        .unwrap();
    assert_eq!(resolved, REDACTED_PLACEHOLDER);
}

/// `DevicePiiCategory::as_str` wire strings are stable.
/// Pinned for the same reason `AuthEventType` strings are pinned:
/// SQL backends and SOC dashboards key off these exact strings.
#[test]
fn category_wire_strings_are_stable() {
    for (variant, expected) in [
        (DevicePiiCategory::DisplayName, "display_name"),
        (DevicePiiCategory::UserAgentString, "user_agent_string"),
        (DevicePiiCategory::AcceptLanguage, "accept_language"),
        (DevicePiiCategory::IpAddress, "ip_address"),
        (DevicePiiCategory::ScreenMetrics, "screen_metrics"),
        (DevicePiiCategory::Other, "other"),
    ] {
        assert_eq!(variant.as_str(), expected);
    }
}

#[test]
fn pii_token_display_matches_as_str() {
    let token = PiiToken::new();
    assert_eq!(format!("{token}"), token.as_str());
}

#[tokio::test]
async fn memory_store_len_and_is_empty_track_inserts() {
    let store = MemoryDevicePiiStore::new();
    assert_eq!(store.len(), 0);
    assert!(store.is_empty());

    let token = PiiToken::new();
    let mapping = DevicePiiMapping {
        token: token.clone(),
        subject_id: axess_identity::testing::user("u-pii"),
        tenant_id: axess_identity::testing::tenant("t-pii"),
        category: DevicePiiCategory::IpAddress,
        value: "1.2.3.4".to_string(),
        created_at: chrono::Utc::now(),
    };
    store.mappings.insert(token, mapping);
    assert_eq!(store.len(), 1);
    assert!(!store.is_empty());
}
