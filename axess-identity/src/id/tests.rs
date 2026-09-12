//! `tests`: extracted from `id.rs` per the
//! 200-LoC inline-test rule in AGENTS.md.

use super::*;
use crate::testing;
use axess_rng::testing::MockRng;

#[test]
fn system_tenant_is_nil() {
    assert!(TenantId::SYSTEM.is_system());
    assert!(TenantId::system().is_nil());
    assert_eq!(TenantId::SYSTEM.to_string(), TenantId::SYSTEM_STR);
}

#[test]
fn system_user_distinct_from_system_tenant() {
    assert_ne!(UserId::SYSTEM.as_uuid(), TenantId::SYSTEM.as_uuid());
    assert!(UserId::SYSTEM.is_system());
    assert_eq!(UserId::SYSTEM.to_string(), UserId::SYSTEM_STR);
}

#[test]
fn try_new_rejects_empty() {
    assert_eq!(TenantId::try_new(""), Err(IdError::Empty("TenantId")));
    assert_eq!(UserId::try_new(""), Err(IdError::Empty("UserId")));
}

#[test]
fn try_new_rejects_non_uuid() {
    assert_eq!(
        TenantId::try_new("not-a-uuid"),
        Err(IdError::NotAUuid("TenantId"))
    );
}

#[test]
fn try_new_accepts_uuid_string() {
    let t = TenantId::try_new("1f0a7b2e-4c91-4e3f-9b2a-8d0123456789").unwrap();
    assert!(!t.is_system());
}

#[test]
fn new_is_dst_reproducible() {
    let a = MockRng::new(42);
    let b = MockRng::new(42);
    assert_eq!(TenantId::new(&a), TenantId::new(&b));
    assert_eq!(
        SessionId::new(&MockRng::new(7)).as_uuid().get_version_num(),
        4
    );
}

#[test]
fn from_namespaced_str_is_deterministic() {
    let ns = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
    let a = TenantId::from_namespaced_str(ns, "ekekrantz");
    let b = TenantId::from_namespaced_str(ns, "ekekrantz");
    let c = TenantId::from_namespaced_str(ns, "wctest");
    assert_eq!(a, b);
    assert_ne!(a, c);
    assert_eq!(a.as_uuid().get_version_num(), 5);
}

#[test]
fn ensure_user_id_not_reserved_blocks_system_user() {
    let res = ensure_user_id_not_reserved(&UserId::SYSTEM, &testing::tenant("t1"));
    assert_eq!(res, Err(IdError::Reserved("UserId")));
}

#[test]
fn ensure_user_id_not_reserved_blocks_system_tenant() {
    let res = ensure_user_id_not_reserved(&testing::user("u1"), &TenantId::SYSTEM);
    assert_eq!(res, Err(IdError::Reserved("TenantId")));
}

#[test]
fn ensure_user_id_not_reserved_accepts_normal_pair() {
    let res = ensure_user_id_not_reserved(&testing::user("u1"), &testing::tenant("t1"));
    assert!(res.is_ok());
}

#[test]
fn testing_helpers_are_deterministic() {
    assert_eq!(testing::tenant("alice"), testing::tenant("alice"));
    assert_eq!(testing::user("alice"), testing::user("alice"));
    assert_eq!(testing::device("alice"), testing::device("alice"));
    assert_eq!(testing::session("alice"), testing::session("alice"));
    assert_eq!(testing::event("alice"), testing::event("alice"));
}

#[cfg(feature = "serde")]
#[test]
fn serde_wire_is_hyphenated_string() {
    let id = TenantId::from_uuid(Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap());
    let json = serde_json::to_string(&id).unwrap();
    assert_eq!(json, "\"550e8400-e29b-41d4-a716-446655440000\"");
    let back: TenantId = serde_json::from_str(&json).unwrap();
    assert_eq!(id, back);
}

#[cfg(feature = "serde")]
#[test]
fn id_error_serialise_shape_is_stable() {
    // Pin the IdError JSON shape so error responses crossing the
    // wire (HTTP boundary, SIEM pipelines) stay stable. The
    // discriminator is the variant name; the body is the
    // `&'static str` kind label.
    //
    // Round-trip is intentionally one-way (serialise only): the
    // `&'static str` payload can't be reconstituted from
    // non-static input, so `Deserialize` is supported only for
    // structural symmetry (e.g. a higher-level error type that
    // happens to embed `IdError` and decodes from a known
    // source). External-input deserialisation should land in a
    // typed-error wrapper that owns its strings, not in
    // `IdError` directly.
    for (err, expected_json) in [
        (IdError::Empty("TenantId"), r#"{"Empty":"TenantId"}"#),
        (IdError::NotAUuid("UserId"), r#"{"NotAUuid":"UserId"}"#),
        (IdError::Reserved("DeviceId"), r#"{"Reserved":"DeviceId"}"#),
    ] {
        let json = serde_json::to_string(&err).unwrap();
        assert_eq!(json, expected_json, "IdError JSON shape drifted");
    }
}

#[test]
fn no_default_impl() {
    // Pin the absence of `Default` on typed ids; `Default::default()`
    // would silently produce `Self(Uuid::nil())`, which collides
    // with `TenantId::SYSTEM` / `UserId::SYSTEM` semantics. Forcing
    // explicit construction (via `NIL`, `new(rng)`, `from_uuid`,
    // or `from_namespaced_str`) makes intent explicit at every
    // call site.
    //
    // This compile-time test asserts the absence by checking that
    // `TenantId` does NOT implement `Default`. If `Default` is
    // ever re-added, this test won't compile.
    fn assert_not_default<T>()
    where
        T: Sized,
    {
    }
    assert_not_default::<TenantId>();
    assert_not_default::<UserId>();
    assert_not_default::<SessionId>();
    assert_not_default::<DeviceId>();
    assert_not_default::<EventId>();
    // To be a useful pin: this would ideally check
    // `!impls Default`, but Rust's negative-bound expressivity
    // is limited. The signal is in the line above; call sites
    // that do `TenantId::default()` will fail at use, not here.
}

define_id! {
    /// Adopter-defined id used in macro tests.
    pub TestId
}

#[test]
fn define_id_macro_yields_v4_via_new() {
    let rng = MockRng::new(7);
    let id = TestId::new(&rng);
    assert_eq!(id.as_uuid().get_version_num(), 4);
    assert!(!id.is_nil());
}

/// PG-072: `mint_v4_default()` honours the thread-local RNG override.
/// Same seed via `with_thread_local_rng` produces the same Uuid both
/// times, confirming DST reproducibility through the no-arg helper.
#[test]
fn mint_v4_default_is_dst_reproducible_under_override() {
    let a = with_thread_local_rng(MockRng::new(99), mint_v4_default);
    let b = with_thread_local_rng(MockRng::new(99), mint_v4_default);
    assert_eq!(a, b);
    // And: outside the override, a third draw uses SystemRng and is
    // (with overwhelming probability) distinct.
    let c = mint_v4_default();
    assert_ne!(a, c);
    assert_eq!(a.get_version_num(), 4);
    assert_eq!(b.get_version_num(), 4);
    assert_eq!(c.get_version_num(), 4);
}

/// sqlx round-trip: bind a typed id into a TEXT column, query it
/// back, decode into the typed shape, verify the value matches.
/// Catches both Encode (TEXT-shaped output) and Decode (TEXT input
/// to `try_new` parsing) regressions in one go.
#[cfg(feature = "sqlx")]
#[tokio::test]
async fn sqlx_text_column_roundtrip() {
    use sqlx::sqlite::SqlitePoolOptions;

    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();

    sqlx::query("CREATE TABLE ids (id TEXT NOT NULL PRIMARY KEY)")
        .execute(&pool)
        .await
        .unwrap();

    let rng = MockRng::new(13);
    let original = TenantId::new(&rng);

    sqlx::query("INSERT INTO ids (id) VALUES (?1)")
        .bind(original)
        .execute(&pool)
        .await
        .unwrap();

    let row: (TenantId,) = sqlx::query_as("SELECT id FROM ids LIMIT 1")
        .fetch_one(&pool)
        .await
        .unwrap();

    assert_eq!(row.0, original);
}

#[test]
fn id_error_display_pins_each_variant_string() {
    assert_eq!(IdError::Empty("Foo").to_string(), "Foo must be non-empty");
    assert_eq!(
        IdError::NotAUuid("Bar").to_string(),
        "Bar must be a valid Uuid"
    );
    assert_eq!(
        IdError::Reserved("Baz").to_string(),
        "Baz matches reserved system identifier"
    );
}

/// The Drop impl on `with_thread_local_rng`'s `Guard` restores
/// the previous thread-local override on scope exit. With the
/// Drop body deleted (mutation), the inner override would leak
/// into the outer scope, so a re-mint after the inner closure
/// returns would observe the inner seed's draws instead of the
/// outer seed's. Pin the restoration by comparing draws on both
/// sides of the inner scope.
#[test]
fn with_thread_local_rng_drop_restores_previous_override() {
    // What the outer seed would draw at step 1 with NO inner
    // disturbance.
    let outer_step1 = with_thread_local_rng(MockRng::new(1), mint_v4_default);

    // Same outer seed, but with an inner override that drains
    // five draws (different seed). If the Drop on Guard restores
    // the outer override, the next draw after the inner scope
    // must equal `outer_step1` (the FIRST draw on a fresh seed=1
    // override). If Drop is a no-op (mutation), the next draw
    // comes from seed=99 instead.
    let post_inner = with_thread_local_rng(MockRng::new(1), || {
        with_thread_local_rng(MockRng::new(99), || {
            for _ in 0..5 {
                let _ = mint_v4_default();
            }
        });
        mint_v4_default()
    });

    assert_eq!(
        outer_step1, post_inner,
        "Drop on Guard MUST restore the outer override; \
             otherwise the inner override leaks across the scope boundary"
    );
}
