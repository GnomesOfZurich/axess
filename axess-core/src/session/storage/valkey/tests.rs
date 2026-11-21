//! Unit tests for the Valkey session backend.
//!
//! Pins the pure functions and the inherent-method bodies that can be
//! told apart from the test thread without a live Valkey instance. A
//! wrong body in the `SessionStore` / `SessionRegistry` impls
//! (load/save/cycle/…) shows only in an actual Valkey round-trip, which
//! is what the `valkey_integration` `#[ignore]` test below is for.

use super::internal::{
    CYCLE_SCRIPT, DEFAULT_MAX_PAYLOAD_BYTES, ValkeyStoreError, oldest_first,
    revocation_session_channel, revocation_user_channel, script_unavailable, session_row_key,
    user_keys,
};
use super::registry::ValkeySessionRegistry;
use super::store::ValkeySessionStore;
use super::subscriber::connection_name;
use super::watch_tests::{connect, eventually, subscriber_connections};
use crate::authn::ids::UserId;
use crate::session::crypto::{BoundFormat, SessionCrypto};
use crate::session::data::SessionData;
use crate::session::id::{SessionId, SessionKey};
use crate::session::storage::session_codec::SessionCodec;
use crate::session::store::{CutOff, CycleOutcome, SessionRegistry, SessionStore};
use crate::testing::valkey_sweep::Swept;
use axess_rng::SystemRng;
use fred::prelude::*;
use std::time::Duration;

/// A fixed session id, and the key a store names its session by.
const TEST_ID: &str = "00000000-0000-4000-8000-000000000001";

fn test_id() -> SessionKey {
    SessionKey::of(&TEST_ID.parse().expect("fixed test id"))
}

// The previous `encrypt_decrypt_roundtrip` /
// `key_rotation_decrypt_with_previous` / `decrypt_wrong_key_fails`
// tests duplicated `session::crypto::tests`: they exercised the
// inline `encrypt` / `decrypt` Valkey helpers which now route
// through the shared `SessionCrypto`. The crypto-primitive
// round-trip + rotation + wrong-key tests live there.

/// Unit test: encode/decode round-trip through the shared codec
/// with encryption configured the way `ValkeySessionStore::new`
/// configures it. Pins that the codec produces bytes that
/// round-trip back to the same `SessionData`.
#[test]
fn store_encode_decode_encrypted() {
    let key = crate::testing::test_key(99);
    let codec = SessionCodec::encrypted(SessionCrypto::new(key));
    let data = SessionData::default();
    let bytes = codec.encode_bytes(&test_id(), &data).expect("encode_bytes");
    let restored = codec
        .decode_bytes(&test_id(), &bytes)
        .expect("decode_bytes");
    assert_eq!(
        serde_json::to_string(&data).unwrap(),
        serde_json::to_string(&restored).unwrap(),
    );
}

/// Unit test: payload size limit is enforced.
#[test]
fn encode_rejects_oversized_payload() {
    let config = Config::from_url("redis://127.0.0.1:6379").expect("parse url");
    let client = Client::new(config, None, None, None);

    // Create a store with a limit smaller than any possible serialized SessionData.
    let store = ValkeySessionStore::plaintext_insecure(client).with_max_payload(1);

    let data = SessionData::default();
    let result = store.encode(&test_id(), &data);

    assert!(
        matches!(result, Err(ValkeyStoreError::PayloadTooLarge { .. })),
        "expected PayloadTooLarge, got: {result:?}"
    );
}

/// Unit test: payload within limit succeeds.
#[test]
fn encode_accepts_payload_within_limit() {
    let config = Config::from_url("redis://127.0.0.1:6379").expect("parse url");
    let client = Client::new(config, None, None, None);

    // Default limit (64 KiB): default SessionData is tiny.
    let store = ValkeySessionStore::plaintext_insecure(client);
    let data = SessionData::default();
    assert!(store.encode(&test_id(), &data).is_ok());
}

// ── pinning tests ───────────────────────────────────────

fn dummy_client() -> Client {
    let config = Config::from_url("redis://127.0.0.1:6379").expect("parse url");
    Client::new(config, None, None, None)
}

/// A fred `Client` configured so commands fail fast when no
/// connection is established. Without this, commands wait
/// indefinitely for a connection to come up. Used by the
/// SessionStore / SessionRegistry impl-method pinning tests to
/// observe an `Err` deterministically.
fn unreachable_client() -> Client {
    // Port 1 is IANA-reserved; ECONNREFUSED is immediate.
    let mut config = Config::from_url("redis://127.0.0.1:1/").expect("parse url");
    // Disable reconnects so the call returns Err on first failure.
    let connection = fred::types::config::ConnectionConfig {
        max_command_attempts: 1,
        internal_command_timeout: Duration::from_millis(50),
        ..Default::default()
    };
    let perf = fred::types::config::PerformanceConfig {
        default_command_timeout: Duration::from_millis(200),
        ..Default::default()
    };
    // Don't auto-pipeline: we want each command to surface its own
    // error rather than queueing.
    config.fail_fast = true;
    Client::new(config, Some(perf), Some(connection), None)
}

/// Pin every key-helper format string against the
/// observed mutations: `-> String::new()` (empty) and
/// `-> "xyzzy".into()` (fixed wrong string).
#[test]
fn key_helpers_produce_expected_strings() {
    let rng = SystemRng;
    let session = SessionId::new(&rng);
    let id = SessionKey::of(&session);
    let id_s = id.to_string();

    // The name holds the 64 characters of the key and nothing of the id.
    assert_eq!(id_s.len(), 64);
    assert_eq!(session_row_key("axess", &id), format!("axess:sess:{id_s}"));
    assert!(!session_row_key("axess", &id).contains(&session.to_string()));
    let keys = user_keys("axess", &UserId::NIL).expect("one slot");
    assert_eq!(
        keys.registry,
        "axess:reg:{00000000-0000-0000-0000-000000000000}"
    );
    assert_eq!(
        keys.registered_at,
        "axess:reg-at:{00000000-0000-0000-0000-000000000000}"
    );
    assert_eq!(
        keys.forward,
        "axess:fwd:{00000000-0000-0000-0000-000000000000}"
    );
    assert_eq!(
        keys.forward_order,
        "axess:fwd-at:{00000000-0000-0000-0000-000000000000}"
    );
    assert_eq!(
        revocation_session_channel("axess", "s-1"),
        "axess:revoked-session:s-1"
    );
    assert_eq!(
        revocation_user_channel("axess", "u-1"),
        "axess:revoked-user:u-1"
    );

    // Prefix is interpolated, not hard-coded: discriminates a body
    // replacement that returns a constant ignoring `prefix`.
    assert_eq!(
        session_row_key("other", &id),
        format!("other:sess:{id_s}"),
        "session_row_key must interpolate the prefix argument"
    );
}

/// Pin `DEFAULT_MAX_PAYLOAD_BYTES = 64 * 1024` against
/// `replace * with +` (yields 1088) and `replace * with /`
/// (yields 0, which would make every encode reject).
#[test]
fn default_max_payload_bytes_is_64_kib() {
    assert_eq!(DEFAULT_MAX_PAYLOAD_BYTES, 64 * 1024);
    assert_eq!(DEFAULT_MAX_PAYLOAD_BYTES, 65_536);
}

/// Encode at exactly the configured cap succeeds and one
/// byte over rejects. This discriminates `>` from `==` and `>=`
/// (which would reject at exactly the cap) and from `<` (which
/// would accept any size).
#[test]
fn encode_size_boundary_is_strict_greater_than() {
    let store = ValkeySessionStore::plaintext_insecure(dummy_client());
    let data = SessionData::default();

    // Find the natural encoded size by measuring with a huge cap.
    let baseline = store
        .clone()
        .with_max_payload(usize::MAX)
        .encode(&test_id(), &data)
        .expect("baseline encode")
        .len();

    // Exactly at cap: original (`>`) returns Ok; `==` and `>=` reject.
    let ok_at_cap = store
        .clone()
        .with_max_payload(baseline)
        .encode(&test_id(), &data);
    assert!(
        ok_at_cap.is_ok(),
        "encode at exactly the cap must succeed (> not >= or ==): {ok_at_cap:?}"
    );

    // One under cap: original rejects, `<` mutant accepts.
    let under_cap = store
        .clone()
        .with_max_payload(baseline - 1)
        .encode(&test_id(), &data);
    assert!(
        matches!(under_cap, Err(ValkeyStoreError::PayloadTooLarge { .. })),
        "encode one byte under cap must reject (discriminates < mutant): {under_cap:?}"
    );
}

/// Encode → decode round-trip pins the encode body against
/// `Ok(vec![])`, `Ok(vec![0])`, `Ok(vec![1])` (all of which would
/// fail to decode back to `SessionData::default()`).
/// Also covers the symmetric `decode` body replacement
/// `Ok(Default::default())`: only if `data != default`, which
/// `SessionData::default()` satisfies trivially (default ≡ default,
/// so that mutation is equivalent for this specific payload).
/// We therefore use a non-default payload via the public
/// `set_custom` mutator path (write through a synthetic
/// `SessionData` with one custom byte).
#[test]
fn store_encode_decode_roundtrip_pins_bodies() {
    let store = ValkeySessionStore::plaintext_insecure(dummy_client());

    // `SessionData::default()` has `custom: Value::Null`. The
    // `decode -> Ok(Default::default())` mutation is observable
    // only when the encoded value diverges from the default; we
    // overwrite `custom` with a real Object so the assertion
    // can distinguish "decoded matches encoded" from "decoded
    // dropped back to Default".
    let data = SessionData {
        custom: serde_json::json!({"k": "v"}),
        ..SessionData::default()
    };

    let bytes = store.encode(&test_id(), &data).expect("encode");
    assert!(
        !bytes.is_empty(),
        "encode must produce a non-empty payload: kills Ok(vec![])"
    );
    assert!(
        bytes.len() > 1,
        "encode must produce > 1 byte for non-trivial payload: kills Ok(vec![0/1])"
    );

    let decoded = store.decode(&test_id(), &bytes).expect("decode");
    assert_eq!(
        serde_json::to_string(&data).unwrap(),
        serde_json::to_string(&decoded).unwrap(),
        "encode/decode must round-trip: kills Ok(Default::default()) on decode"
    );
    // Sanity check that the payload really did diverge from
    // default: if it didn't, the decode-mutant test above is
    // trivially satisfied (default → default).
    let default_json = serde_json::to_string(&SessionData::default()).unwrap();
    let actual_json = serde_json::to_string(&data).unwrap();
    assert_ne!(
        default_json, actual_json,
        "test payload must differ from default for the decode mutation test to be meaningful"
    );
}

/// Pin every `From<X> for ValkeyStoreError` impl variant.
/// Codec errors flow through the shared `SqlStoreError`.
#[test]
fn from_impls_preserve_source_variant() {
    // Connection error path.
    let fred_err: ValkeyStoreError =
        fred::error::Error::new(fred::error::ErrorKind::IO, "x").into();
    assert!(matches!(fred_err, ValkeyStoreError::Connection(_)));

    // Codec error path: synthesize via rmp_serde decode failure
    // wrapped into SqlStoreError, then into ValkeyStoreError.
    let decode_err: Result<SessionData, _> = rmp_serde::from_slice(&[0xFF, 0xFF, 0xFF]);
    if let Err(e) = decode_err {
        let sql_err: crate::session::storage::session_codec::SqlStoreError = e.into();
        let wrapped: ValkeyStoreError = sql_err.into();
        assert!(matches!(wrapped, ValkeyStoreError::Codec(_)));
    }
}

// The `decrypt_size_guard_boundaries` test that lived here
// duplicated `session::crypto::tests::short_data_fails`. The
// 12-byte nonce + 16-byte AEAD tag boundary is now pinned in the
// shared `SessionCrypto::decrypt` test surface.

/// Every `SessionStore`/`SessionRegistry` impl-method body
/// propagates a fred error from an unreachable-pool client;
/// mutations that replace the body with `Ok(...)` flip Err→Ok
/// and are caught.
#[tokio::test]
async fn load_propagates_error_against_unreachable_valkey() {
    let store = ValkeySessionStore::plaintext_insecure(unreachable_client());
    let rng = SystemRng;
    let id = SessionId::new(&rng);
    let result =
        tokio::time::timeout(Duration::from_secs(3), store.load(&SessionKey::of(&id))).await;
    assert!(
        matches!(result, Ok(Err(_))),
        "load must return Err quickly against unreachable Valkey: {result:?}"
    );
}

#[tokio::test]
async fn save_propagates_error_against_unreachable_valkey() {
    let store = ValkeySessionStore::plaintext_insecure(unreachable_client());
    let rng = SystemRng;
    let id = SessionId::new(&rng);
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        store.save(
            &SessionKey::of(&id),
            &SessionData::default(),
            Duration::from_secs(60),
        ),
    )
    .await;
    assert!(
        matches!(result, Ok(Err(_))),
        "save must return Err: {result:?}"
    );
}

#[tokio::test]
async fn delete_propagates_error_against_unreachable_valkey() {
    let store = ValkeySessionStore::plaintext_insecure(unreachable_client());
    let rng = SystemRng;
    let id = SessionId::new(&rng);
    let result =
        tokio::time::timeout(Duration::from_secs(3), store.delete(&SessionKey::of(&id))).await;
    assert!(
        matches!(result, Ok(Err(_))),
        "delete must return Err: {result:?}"
    );
}

#[tokio::test]
async fn cycle_propagates_error_against_unreachable_valkey() {
    let store = ValkeySessionStore::plaintext_insecure(unreachable_client());
    let rng = SystemRng;
    let old = SessionId::new(&rng);
    let new = SessionId::new(&rng);
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        store.cycle(
            &SessionKey::of(&old),
            &SessionKey::of(&new),
            &SessionData::default(),
            Duration::from_secs(60),
            true,
        ),
    )
    .await;
    assert!(
        matches!(result, Ok(Err(_))),
        "cycle must return Err: {result:?}"
    );
}

/// A registry on a client that cannot connect, built past the constructors'
/// checks (which would refuse it), so each method's own error is seen.
fn unreachable_registry() -> ValkeySessionRegistry {
    ValkeySessionRegistry::assembled(
        unreachable_client(),
        "axess".into(),
        Duration::from_secs(60),
    )
}

#[tokio::test]
async fn register_propagates_error_against_unreachable_valkey() {
    let registry = unreachable_registry();
    let user = axess_identity::testing::user("u");
    let rng = SystemRng;
    let sid = SessionKey::of(&SessionId::new(&rng));
    let result = tokio::time::timeout(Duration::from_secs(3), registry.register(&user, &sid)).await;
    assert!(
        matches!(result, Ok(Err(_))),
        "register must return Err: {result:?}"
    );
}

#[tokio::test]
async fn is_valid_propagates_error_against_unreachable_valkey() {
    let registry = unreachable_registry();
    let user = axess_identity::testing::user("u");
    let rng = SystemRng;
    let sid = SessionKey::of(&SessionId::new(&rng));
    let result = tokio::time::timeout(Duration::from_secs(3), registry.is_valid(&user, &sid)).await;
    assert!(
        matches!(result, Ok(Err(_))),
        "is_valid must return Err: kills Ok(true)/Ok(false) mutants: {result:?}"
    );
}

#[tokio::test]
async fn invalidate_user_propagates_error_against_unreachable_valkey() {
    let registry = unreachable_registry();
    let user = axess_identity::testing::user("u");
    let result =
        tokio::time::timeout(Duration::from_secs(3), registry.invalidate_user(&user)).await;
    assert!(
        matches!(result, Ok(Err(_))),
        "invalidate_user must return Err: {result:?}"
    );
}

#[tokio::test]
async fn invalidate_session_propagates_error_against_unreachable_valkey() {
    let registry = unreachable_registry();
    let user = axess_identity::testing::user("u");
    let rng = SystemRng;
    let sid = SessionKey::of(&SessionId::new(&rng));
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        registry.invalidate_session(&user, &sid),
    )
    .await;
    assert!(
        matches!(result, Ok(Err(_))),
        "invalidate_session must return Err: {result:?}"
    );
}

#[tokio::test]
async fn active_sessions_propagates_error_against_unreachable_valkey() {
    let registry = unreachable_registry();
    let user = axess_identity::testing::user("u");
    let result =
        tokio::time::timeout(Duration::from_secs(3), registry.active_sessions(&user)).await;
    assert!(
        matches!(result, Ok(Err(_))),
        "active_sessions must return Err: kills Ok(vec![]) AND the \
         `delete -` mutation on `-1i64` (both flip the awaited result \
         from Err to Ok): {result:?}"
    );
}

// `watch_revocation` has no test in this file. Its body only performs
// side effects (subscribing, awaiting a message) and returns `()`, so an
// empty body returns the same value; what tells them apart is the
// subscriber connection the production path opens, which the
// `fred::Client` surface gives no way to mock. The live tests in
// `watch_tests.rs` observe that connection.

/// Pin `prune_expired` against the `Ok(1)` mutation:
/// the Valkey trait surface explicitly returns `Ok(0)` because
/// Redis evicts expired keys natively, and the doc-comment on
/// the method makes that an intentional contract.
#[tokio::test]
async fn prune_expired_returns_zero_per_native_expiry_contract() {
    let store = ValkeySessionStore::plaintext_insecure(dummy_client());
    let count = store.prune_expired().await.expect("Ok per contract");
    assert_eq!(
        count, 0,
        "Valkey relies on native key expiry: prune_expired contract is Ok(0)"
    );
}

// The `ValkeySessionStore::plaintext` constructor also emits a
// tracing::warn: exercise it via the existing `dummy_client()`
// call sites above. The body-replacement mutation on the function
// signature is UNVIABLE (no `Default` impl on `ValkeySessionStore`),
// so no separate pinning test is needed. The Postgres analogue
// covers the equivalent warn-on-plaintext path; this comment
// documents the symmetry without introducing a TracingCapture-based
// test that is flaky under parallel execution (per-thread default
// subscriber appears to interact with fred client construction).

/// Integration test: full store + registry round-trip against a live Valkey.
///
/// Requires a running Valkey instance at `127.0.0.1:6379`.
/// Run with: `cargo test --features valkey -- --ignored valkey_integration`
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_integration() {
    let config = Config::from_url(&live_client_url()).expect("parse redis URL");
    let client = Client::new(config, None, None, None);
    client.init().await.expect("connect to Valkey");
    let sweep = crate::testing::valkey_sweep::on_node("integration");

    let encryption_key = crate::testing::test_key(77);
    let store =
        ValkeySessionStore::encrypted(client.clone(), encryption_key).with_prefix(sweep.prefix());
    let registry = ValkeySessionRegistry::with_options(
        client.clone(),
        sweep.prefix(),
        Duration::from_secs(60),
    )
    .await
    .expect("a registry");

    let rng = SystemRng;
    let sid = SessionId::new(&rng);
    let data = SessionData::default();
    let ttl = Duration::from_secs(30);

    // Store: save -> load -> matches.
    store
        .save(&SessionKey::of(&sid), &data, ttl)
        .await
        .expect("save");
    let loaded = store.load(&SessionKey::of(&sid)).await.expect("load");
    assert!(loaded.is_some(), "session should exist after save");

    // Store: cycle -> old gone, new exists.
    let new_sid = SessionId::new(&rng);
    assert_eq!(
        store
            .cycle(
                &SessionKey::of(&sid),
                &SessionKey::of(&new_sid),
                &data,
                ttl,
                true
            )
            .await
            .expect("cycle"),
        CycleOutcome::Rotated
    );
    assert!(
        store
            .load(&SessionKey::of(&sid))
            .await
            .expect("load old")
            .is_none()
    );
    assert!(
        store
            .load(&SessionKey::of(&new_sid))
            .await
            .expect("load new")
            .is_some()
    );

    // Store: delete -> gone.
    store
        .delete(&SessionKey::of(&new_sid))
        .await
        .expect("delete");
    assert!(
        store
            .load(&SessionKey::of(&new_sid))
            .await
            .expect("load deleted")
            .is_none()
    );

    // Registry: register -> is_valid -> invalidate.
    let user_id = axess_identity::testing::user("test-user-integration");
    let user_id = &user_id;
    let reg_sid = SessionId::new(&rng);
    registry
        .register(user_id, &SessionKey::of(&reg_sid))
        .await
        .expect("register");
    assert!(
        registry
            .is_valid(user_id, &SessionKey::of(&reg_sid))
            .await
            .expect("is_valid"),
        "session should be valid after register"
    );

    // Registry: invalidate single session.
    registry
        .invalidate_session(user_id, &SessionKey::of(&reg_sid))
        .await
        .expect("invalidate_session");
    assert!(
        !registry
            .is_valid(user_id, &SessionKey::of(&reg_sid))
            .await
            .expect("is_valid after invalidate"),
    );

    // Registry: invalidate all sessions for user.
    let sid_a = SessionId::new(&rng);
    let sid_b = SessionId::new(&rng);
    registry
        .register(user_id, &SessionKey::of(&sid_a))
        .await
        .expect("reg a");
    registry
        .register(user_id, &SessionKey::of(&sid_b))
        .await
        .expect("reg b");
    registry
        .invalidate_user(user_id)
        .await
        .expect("invalidate_user");
    assert!(
        !registry
            .is_valid(user_id, &SessionKey::of(&sid_a))
            .await
            .expect("a")
    );
    assert!(
        !registry
            .is_valid(user_id, &SessionKey::of(&sid_b))
            .await
            .expect("b")
    );

    // Key rotation: save with old key, load with new key + old as fallback.
    let old_key = crate::testing::test_key(77);
    let new_key = crate::testing::test_key(88);
    let old_store =
        ValkeySessionStore::encrypted(client.clone(), old_key).with_prefix(sweep.prefix());
    let rotation_store =
        ValkeySessionStore::encrypted_with_rotation(client.clone(), new_key, old_key)
            .with_prefix(sweep.prefix());

    let rot_sid = SessionId::new(&rng);
    old_store
        .save(&SessionKey::of(&rot_sid), &data, ttl)
        .await
        .expect("save with old key");
    let loaded = rotation_store
        .load(&SessionKey::of(&rot_sid))
        .await
        .expect("load with rotation");
    assert!(
        loaded.is_some(),
        "should decrypt with previous key fallback"
    );

    // Cleanup.
    old_store
        .delete(&SessionKey::of(&rot_sid))
        .await
        .expect("cleanup");

    client.quit().await.expect("disconnect");
}

/// The cycle script checks the old key first, writes the new key before it
/// touches the old one, and only deletes the old key when it differs from the
/// new one.
#[test]
fn cycle_script_checks_then_sets_then_deletes_and_spares_a_same_key_cycle() {
    let check = CYCLE_SCRIPT.find("'EXISTS', KEYS[1]").expect("EXISTS old");
    let set = CYCLE_SCRIPT.find("'SET', KEYS[2]").expect("SET new");
    let guard = CYCLE_SCRIPT
        .find("KEYS[1] ~= KEYS[2]")
        .expect("same-key guard");
    let del = CYCLE_SCRIPT.find("'DEL', KEYS[1]").expect("DEL old");
    assert!(check < set && set < guard && guard < del);
}

/// Only "this deployment cannot run the script" errors take the sequenced
/// fallback; a failed write or a dead connection does not.
#[test]
fn only_script_unavailability_selects_the_fallback() {
    use fred::error::{Error, ErrorKind};
    for text in [
        "CROSSSLOT Keys in request don't hash to the same slot",
        "ERR unknown command 'EVAL'",
        "NOPERM this user has no permissions to run the 'eval' command",
        "NOSCRIPT No matching script",
    ] {
        assert!(
            script_unavailable(&Error::new(ErrorKind::Unknown, text)),
            "{text}"
        );
    }
    // A cluster error from the client is not the script being unavailable:
    // keys on two nodes never reach the client's own check, because the
    // route is decided from their slots before a script is sent.
    for text in [
        "Missing server for hash slot 42",
        "All keys must belong to the same cluster node.",
    ] {
        assert!(
            !script_unavailable(&Error::new(ErrorKind::Cluster, text)),
            "{text}"
        );
    }
    for text in [
        "ERR invalid expire time in 'set' command",
        "connection reset",
    ] {
        assert!(
            !script_unavailable(&Error::new(ErrorKind::Unknown, text)),
            "{text}"
        );
    }
}

/// On a cluster, keys in two hash slots take the sequenced form before
/// anything is sent, whatever a client would answer; keys under one hash tag,
/// and any keys on a single node, run the script.
#[test]
fn the_script_route_is_decided_by_the_key_slots() {
    use super::internal::{ScriptRoute, script_route};
    use fred::util::redis_keyslot;
    let old = "axess:sess:old-id";
    let new = "axess:sess:new-id";
    assert_ne!(redis_keyslot(old.as_bytes()), redis_keyslot(new.as_bytes()));
    assert_eq!(script_route(true, [old, new]), ScriptRoute::Sequenced);
    assert_eq!(script_route(false, [old, new]), ScriptRoute::Script);
    assert_eq!(
        script_route(true, ["{axess}:sess:old-id", "{axess}:sess:new-id"]),
        ScriptRoute::Script
    );
    assert_eq!(script_route(true, [old, old]), ScriptRoute::Script);
}

fn live_client_url() -> String {
    std::env::var("VALKEY_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into())
}

/// A rotation whose SET fails leaves the old session readable; a good
/// rotation moves it; cycling to the same id keeps it.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_session_cycle_is_atomic() {
    let client = Client::new(
        Config::from_url(&live_client_url()).unwrap(),
        None,
        None,
        None,
    );
    client.init().await.expect("connect");
    let sweep = crate::testing::valkey_sweep::on_node("cycle");
    let store = ValkeySessionStore::plaintext_insecure(client.clone()).with_prefix(sweep.prefix());
    let rng = SystemRng;
    let (old, new) = (SessionId::new(&rng), SessionId::new(&rng));
    let data = SessionData::default();
    store
        .save(&SessionKey::of(&old), &data, Duration::from_secs(60))
        .await
        .unwrap();

    // A client that may not SET makes the SET inside the script fail. Its
    // user is named for this run, so two runs at once do not share it, and
    // is removed when the test ends, also when it fails.
    let (noset, restricted) =
        super::registry_tests::client_denied(&client, &format!("{}_noset", sweep.prefix()), "-set")
            .await;
    let failed = ValkeySessionStore::plaintext_insecure(restricted)
        .with_prefix(sweep.prefix())
        .cycle(
            &SessionKey::of(&old),
            &SessionKey::of(&new),
            &data,
            Duration::from_secs(60),
            true,
        )
        .await;
    noset.remove(&client).await;
    assert!(failed.is_err());
    assert!(
        store.load(&SessionKey::of(&old)).await.unwrap().is_some(),
        "old row survives a failed SET"
    );
    assert!(store.load(&SessionKey::of(&new)).await.unwrap().is_none());

    assert_eq!(
        store
            .cycle(
                &SessionKey::of(&old),
                &SessionKey::of(&new),
                &data,
                Duration::from_secs(60),
                true
            )
            .await
            .unwrap(),
        CycleOutcome::Rotated
    );
    assert!(store.load(&SessionKey::of(&old)).await.unwrap().is_none());
    assert!(store.load(&SessionKey::of(&new)).await.unwrap().is_some());

    assert_eq!(
        store
            .cycle(
                &SessionKey::of(&new),
                &SessionKey::of(&new),
                &data,
                Duration::from_secs(60),
                true
            )
            .await
            .unwrap(),
        CycleOutcome::Rotated
    );
    assert!(
        store.load(&SessionKey::of(&new)).await.unwrap().is_some(),
        "same-id cycle keeps the session"
    );
    store.delete(&SessionKey::of(&new)).await.unwrap();
}

/// The shared "an ended session stays ended" checks against a live Valkey,
/// through the cycle script and `SET ... XX`.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_store_never_revives_an_ended_session() {
    let client = Client::new(
        Config::from_url(&live_client_url()).unwrap(),
        None,
        None,
        None,
    );
    client.init().await.expect("connect");
    let sweep = crate::testing::valkey_sweep::on_node("revival");
    let store = ValkeySessionStore::plaintext_insecure(client).with_prefix(sweep.prefix());
    crate::session::store::revival_tests::run_all(&store).await;
}

/// The same checks with the encrypted codec.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_encrypted_store_never_revives_an_ended_session() {
    let client = Client::new(
        Config::from_url(&live_client_url()).unwrap(),
        None,
        None,
        None,
    );
    client.init().await.expect("connect");
    let sweep = crate::testing::valkey_sweep::on_node("revival_enc");
    let store =
        ValkeySessionStore::new(client, crate::testing::test_key(11)).with_prefix(sweep.prefix());
    crate::session::store::revival_tests::run_all(&store).await;
}

/// A blob that carries no row binding is refused and left as it is, whatever
/// legacy policy the crypto of the store carries; the next save of the
/// session writes the current form and gives the key its expiry.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_refuses_an_unbound_blob_and_the_next_save_seals_the_current_form() {
    let client = Client::new(
        Config::from_url(&live_client_url()).unwrap(),
        None,
        None,
        None,
    );
    client.init().await.expect("connect");
    let key = crate::testing::test_key(13);
    let sweep = crate::testing::valkey_sweep::on_node("unbound");
    let prefix = sweep.prefix().to_owned();
    let store = ValkeySessionStore::new(client.clone(), key).with_prefix(prefix.clone());
    let id = SessionKey::of(&SessionId::new(&SystemRng));
    let redis_key = format!("{prefix}:sess:{id}");
    let unbound = SessionCrypto::new(key)
        .encrypt_unbound(&rmp_serde::to_vec_named(&SessionData::default()).unwrap())
        .unwrap();
    client
        .set::<(), _, _>(
            &redis_key,
            unbound.clone(),
            Some(Expiration::EX(600)),
            None,
            false,
        )
        .await
        .unwrap();

    assert!(
        store.load(&id).await.is_err(),
        "the unbound blob is refused"
    );
    let untouched: Vec<u8> = client.get(&redis_key).await.unwrap();
    assert_eq!(untouched, unbound, "a refused blob is left as it is");

    store
        .save(&id, &SessionData::default(), Duration::from_secs(600))
        .await
        .unwrap();
    let after: Vec<u8> = client.get(&redis_key).await.unwrap();
    assert!(BoundFormat::SESSION.marks(&after), "sealed by the save");
    assert_eq!(after[..4], [0x41, 0x58, 0x53, 0x82]);
    let ttl: i64 = client.ttl(&redis_key).await.unwrap();
    assert!((1..=600).contains(&ttl), "the key has its expiry: {ttl}");
    assert!(store.load(&id).await.unwrap().is_some());
    store.delete(&id).await.unwrap();
}

/// The compare-and-swap contract against a live Valkey, encrypted and not.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_update_if_revision_keeps_the_contract() {
    let config = Config::from_url(&live_client_url()).expect("parse redis URL");
    let client = Client::new(config, None, None, None);
    client.init().await.expect("connect to Valkey");
    let sweep = crate::testing::valkey_sweep::on_node("cas");
    let encrypted = ValkeySessionStore::encrypted(client.clone(), crate::testing::test_key(5))
        .with_prefix(format!("{}_sealed", sweep.prefix()));
    crate::testing::store_contract::assert_update_if_revision_contract(&encrypted).await;
    let plain = ValkeySessionStore::plaintext_insecure(client)
        .with_prefix(format!("{}_plain", sweep.prefix()));
    crate::testing::store_contract::assert_update_if_revision_contract(&plain).await;
}

/// A zero TTL stores nothing, as in every other store: a conditional write
/// against the stored revision removes the key and reports the session gone
/// (against another revision it conflicts and removes nothing), and a
/// rotation removes both keys and reports the session gone whether or not
/// the old key was required.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_zero_ttl_writes_store_nothing() {
    let client = Client::new(
        Config::from_url(&live_client_url()).unwrap(),
        None,
        None,
        None,
    );
    client.init().await.expect("connect");
    let sweep = crate::testing::valkey_sweep::on_node("zero");
    let prefix = sweep.prefix().to_owned();
    let store = ValkeySessionStore::plaintext_insecure(client.clone()).with_prefix(prefix.clone());
    let exists = |id: SessionKey| {
        let client = client.clone();
        let prefix = prefix.clone();
        async move {
            client
                .exists::<i64, _>(session_row_key(&prefix, &id))
                .await
                .unwrap()
                == 1
        }
    };
    let data = SessionData {
        revision: 3,
        ..SessionData::default()
    };
    let ttl = Duration::from_secs(60);

    let id = SessionKey::of(&SessionId::new(&SystemRng));
    store.save(&id, &data, ttl).await.unwrap();
    assert_eq!(
        store
            .update_if_revision(&id, 9, &data, Duration::ZERO)
            .await
            .unwrap(),
        crate::session::store::ConditionalUpdate::Conflict
    );
    assert!(exists(id).await, "a conflict removes nothing");
    assert_eq!(
        store
            .update_if_revision(&id, 3, &data, Duration::ZERO)
            .await
            .unwrap(),
        crate::session::store::ConditionalUpdate::Gone
    );
    assert!(
        !exists(id).await,
        "update_if_revision: no key is left behind"
    );

    for require_old in [false, true] {
        let (old, new) = (
            SessionKey::of(&SessionId::new(&SystemRng)),
            SessionKey::of(&SessionId::new(&SystemRng)),
        );
        store.save(&old, &data, ttl).await.unwrap();
        assert_eq!(
            store
                .cycle(&old, &new, &data, Duration::ZERO, require_old)
                .await
                .unwrap(),
            CycleOutcome::SessionGone,
            "require_old={require_old}: nothing is stored, so nothing rotated"
        );
        assert!(
            !exists(old).await && !exists(new).await,
            "cycle: no key is left behind"
        );

        // A key already stored under the new id goes too, and a rotation
        // onto the same id removes its one key.
        store.save(&old, &data, ttl).await.unwrap();
        store.save(&new, &data, ttl).await.unwrap();
        assert_eq!(
            store
                .cycle(&old, &new, &data, Duration::ZERO, require_old)
                .await
                .unwrap(),
            CycleOutcome::SessionGone
        );
        assert!(
            !exists(old).await && !exists(new).await,
            "cycle: a stored new key is not left behind"
        );
        store.save(&old, &data, ttl).await.unwrap();
        assert_eq!(
            store
                .cycle(&old, &old, &data, Duration::ZERO, require_old)
                .await
                .unwrap(),
            CycleOutcome::SessionGone
        );
        assert!(
            !exists(old).await,
            "cycle onto the same id: the key is gone"
        );
    }
}

/// A store lifetime beyond the server's expiry range still saves: the key's
/// expiry is capped instead of being rejected as an invalid expire time.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_save_with_an_enormous_ttl_still_stores() {
    let client = Client::new(
        Config::from_url(&live_client_url()).unwrap(),
        None,
        None,
        None,
    );
    client.init().await.expect("connect");
    let sweep = crate::testing::valkey_sweep::on_node("hugettl");
    let store = ValkeySessionStore::plaintext_insecure(client).with_prefix(sweep.prefix());
    let id = test_id();
    store
        .save(&id, &SessionData::default(), Duration::MAX)
        .await
        .unwrap();
    assert!(store.load(&id).await.unwrap().is_some());
}

/// A debug log line of the store names a session by the first eight
/// characters of its key, never by the whole key and never by the id.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn a_logged_session_is_the_first_eight_characters_of_its_key() {
    let capture = axess_testing::mock_tracing::TracingCapture::install();
    let client = Client::new(
        Config::from_url(&live_client_url()).unwrap(),
        None,
        None,
        None,
    );
    client.init().await.expect("connect");
    let sweep = crate::testing::valkey_sweep::on_node("logform");
    let store = ValkeySessionStore::plaintext_insecure(client).with_prefix(sweep.prefix());
    let ids = [SessionId::new(&SystemRng), SessionId::new(&SystemRng)];
    let [key, next] = ids.map(|id| SessionKey::of(&id));
    let data = SessionData::default();
    let ttl = Duration::from_secs(60);

    // Every line of the store that names a session: saved, loaded, not
    // found, cycled (old and new), deleted.
    store.save(&key, &data, ttl).await.unwrap();
    assert!(store.load(&key).await.unwrap().is_some());
    assert!(store.load(&next).await.unwrap().is_none());
    assert_eq!(
        store.cycle(&key, &next, &data, ttl, true).await.unwrap(),
        CycleOutcome::Rotated
    );
    store.delete(&next).await.unwrap();

    // The store's own lines, each with its fields as `name=value`.
    let lines: Vec<String> = capture
        .events()
        .into_iter()
        .filter(|event| event.target.ends_with("valkey::store"))
        .map(|event| event.message)
        .collect();
    for message in [
        "session saved to valkey",
        "session loaded from valkey",
        "session not found in valkey",
        "session cycled in valkey",
        "session deleted from valkey",
    ] {
        assert!(
            lines.iter().any(|line| line.contains(message)),
            "no line says {message:?}: {lines:#?}"
        );
    }
    let logged = lines.join("\n");
    for (key, id) in [(key, ids[0]), (next, ids[1])] {
        let text = key.to_string();
        assert_eq!(key.prefix().to_string(), format!("{}...", &text[..8]));
        assert!(logged.contains(&key.prefix().to_string()));
        assert!(!logged.contains(&text[..9]), "more than eight characters");
        assert!(!logged.contains(&id.to_string()), "the session id");
        assert!(
            !logged.contains(&id.to_string()[..8]),
            "the start of the id"
        );
    }
}

/// An encrypted Valkey store returns a session's assurance record as it
/// was saved.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn a_session_carrying_assurance_round_trips() {
    let client = Client::new(
        Config::from_url(&live_client_url()).unwrap(),
        None,
        None,
        None,
    );
    client.init().await.expect("connect");
    let sweep = crate::testing::valkey_sweep::on_node("assured");
    let store =
        ValkeySessionStore::new(client, crate::testing::test_key(9)).with_prefix(sweep.prefix());
    let id = SessionId::new(&SystemRng);
    let data = crate::session::data::assured_fixture::assured_session();
    store
        .save(&SessionKey::of(&id), &data, Duration::from_secs(60))
        .await
        .unwrap();
    let back = store
        .load(&SessionKey::of(&id))
        .await
        .unwrap()
        .expect("stored");
    assert_eq!(back.auth_state, data.auth_state);
    store.delete(&SessionKey::of(&id)).await.unwrap();
}

/// The eviction order is the order of registration: a session used since
/// (its score moved forward) still sorts by when it was registered.
#[test]
fn oldest_first_orders_by_registration_not_by_last_use() {
    // A was registered at 0 and used at 7; B was registered at 1 and not used.
    let live = vec![("B".to_string(), 1.0), ("A".to_string(), 7.0)];
    let registered = [Some(1.0), Some(0.0)];
    assert_eq!(oldest_first(live, &registered), vec!["A", "B"]);
}

/// A member registered before the registration set existed is ordered by
/// its score, and ties break on the member.
#[test]
fn oldest_first_falls_back_to_the_score_and_breaks_ties_on_the_member() {
    let live = vec![
        ("c".to_string(), 5.0),
        ("b".to_string(), 5.0),
        ("a".to_string(), 9.0),
    ];
    assert_eq!(
        oldest_first(live, &[None, None, Some(1.0)]),
        vec!["a", "b", "c"]
    );
    assert!(oldest_first(Vec::new(), &[]).is_empty());
}

/// A registry on the live server under a prefix no other run has used,
/// held with the sweep that removes its keys when the test ends, also when
/// it fails.
async fn live_registry(tag: &str, ttl: Duration) -> Swept<ValkeySessionRegistry> {
    let sweep = crate::testing::valkey_sweep::on_node(tag);
    let registry = live_registry_under(sweep.prefix().to_owned(), ttl).await;
    sweep.hold(registry)
}

/// A registry on the live server under `prefix`.
async fn live_registry_under(prefix: String, ttl: Duration) -> ValkeySessionRegistry {
    let client = Client::new(
        Config::from_url(&live_client_url()).unwrap(),
        None,
        None,
        None,
    );
    client.init().await.expect("connect");
    ValkeySessionRegistry::with_options(client, prefix, ttl)
        .await
        .expect("a registry")
}

/// Ending the other sessions keeps the one named, returns the rest, leaves
/// another user alone, and ends nothing around a session the registry does
/// not hold for the user.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_registry_ends_every_session_but_the_one_kept() {
    let registry = live_registry("keepone", Duration::from_secs(60)).await;
    let (alice, bob) = (
        axess_identity::testing::user("keep-one-alice"),
        axess_identity::testing::user("keep-one-bob"),
    );
    let rng = SystemRng;
    let sessions: Vec<SessionKey> = (0..4)
        .map(|_| SessionKey::of(&SessionId::new(&rng)))
        .collect();
    for s in &sessions {
        registry.register(&alice, s).await.unwrap();
    }
    let bobs = SessionKey::of(&SessionId::new(&rng));
    registry.register(&bob, &bobs).await.unwrap();

    // Another user's session, and one never registered, are not Alice's to
    // keep: nothing is ended around them.
    for keep in [bobs, SessionKey::of(&SessionId::new(&rng))] {
        assert_eq!(
            registry
                .invalidate_other_sessions(&alice, &keep)
                .await
                .unwrap(),
            CutOff::NotHeld
        );
        assert_eq!(registry.active_sessions(&alice).await.unwrap().len(), 4);
    }

    let CutOff::KeptOne(mut ended) = registry
        .invalidate_other_sessions(&alice, &sessions[1])
        .await
        .unwrap()
    else {
        panic!("the session to keep is held");
    };
    ended.sort_by_key(ToString::to_string);
    let mut others = vec![sessions[0], sessions[2], sessions[3]];
    others.sort_by_key(ToString::to_string);
    assert_eq!(ended, others);
    assert_eq!(
        registry.active_sessions(&alice).await.unwrap(),
        vec![sessions[1]]
    );
    for s in &others {
        assert!(!registry.is_valid(&alice, s).await.unwrap());
    }
    assert!(registry.is_valid(&alice, &sessions[1]).await.unwrap());
    assert_eq!(registry.active_sessions(&bob).await.unwrap(), vec![bobs]);

    // The one kept is alone now, and a session registered afterwards is a
    // later sign-in the step did not touch.
    assert_eq!(
        registry
            .invalidate_other_sessions(&alice, &sessions[1])
            .await
            .unwrap(),
        CutOff::KeptOne(Vec::new())
    );
    let later = SessionKey::of(&SessionId::new(&rng));
    registry.register(&alice, &later).await.unwrap();
    assert!(registry.is_valid(&alice, &later).await.unwrap());
}

/// A session to keep whose member has lapsed is not held: nothing is ended
/// around it.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_registry_ends_nothing_around_a_lapsed_session() {
    let clock = axess_clock::testing::MockClock::at_reference();
    let registry = Swept::map(
        live_registry("keeplapsed", Duration::from_secs(60)).await,
        |registry| registry.with_clock(std::sync::Arc::new(clock.clone())),
    );
    let alice = axess_identity::testing::user("keep-lapsed-alice");
    let rng = SystemRng;
    let (lapsed, other) = (
        SessionKey::of(&SessionId::new(&rng)),
        SessionKey::of(&SessionId::new(&rng)),
    );
    registry.register(&alice, &lapsed).await.unwrap();
    registry.register(&alice, &other).await.unwrap();
    assert_eq!(
        registry
            .invalidate_other_sessions(&alice, &lapsed)
            .await
            .unwrap(),
        CutOff::KeptOne(vec![other]),
        "the control: while it is live, the session is kept and the other ended"
    );
    registry.register(&alice, &other).await.unwrap();
    clock.advance_secs(61);

    assert_eq!(
        registry
            .invalidate_other_sessions(&alice, &lapsed)
            .await
            .unwrap(),
        CutOff::NotHeld
    );
}

/// The watchers of an ended session are told, and the kept session's are
/// not.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_registry_tells_the_watchers_of_the_ended_sessions_only() {
    let serial = super::SUBSCRIBER_TESTS.lock().await;
    let sweep = crate::testing::valkey_sweep::on_node("keepwatch");
    let prefix = sweep.prefix().to_owned();
    let connection = connection_name(&prefix);
    let registry = live_registry_under(prefix.clone(), Duration::from_secs(60)).await;
    let admin = connect().await;
    let alice = axess_identity::testing::user("keep-watch-alice");
    let bob = axess_identity::testing::user("keep-watch-bob");
    let rng = SystemRng;
    let (keep, other, last) = (
        SessionKey::of(&SessionId::new(&rng)),
        SessionKey::of(&SessionId::new(&rng)),
        SessionKey::of(&SessionId::new(&rng)),
    );
    registry.register(&alice, &keep).await.unwrap();
    registry.register(&alice, &other).await.unwrap();
    registry.register(&bob, &last).await.unwrap();
    let watch = |user, session| {
        let registry = registry.clone();
        tokio::spawn(async move { registry.watch_revocation(&user, &session).await })
    };
    let watching_other = watch(alice, other);
    let watching_keep = watch(alice, keep);
    let watching_last = watch(bob, last);
    // The watchers hold their places and their one connection is subscribed
    // before the step runs, so what the step publishes is routed to them.
    eventually("the three watchers joined", || async {
        registry.subscriber.watcher_count() == 3
    })
    .await;
    eventually("the watchers' connection is subscribed", || async {
        subscriber_connections(&admin, &connection).await == 1
    })
    .await;

    assert!(matches!(
        registry
            .invalidate_other_sessions(&alice, &keep)
            .await
            .unwrap(),
        CutOff::KeptOne(_)
    ));

    tokio::time::timeout(Duration::from_secs(5), watching_other)
        .await
        .expect("the ended session's watcher is told")
        .unwrap();
    // A revocation of another user's session is published by hand after
    // the step, and its registry entry stays: that watcher's own check of
    // the registry answers "live", so only the message can wake it. The one
    // connection the watchers share delivers in order: once its watcher is
    // told, a message for the kept session would have been routed to the
    // kept session's watcher already.
    let _: i64 = admin
        .publish(revocation_session_channel(&prefix, &last.to_string()), "1")
        .await
        .expect("PUBLISH");
    tokio::time::timeout(Duration::from_secs(5), watching_last)
        .await
        .expect("the watcher is told")
        .unwrap();
    assert!(
        registry.is_valid(&bob, &last).await.unwrap(),
        "the entry of the session published for stays"
    );
    assert!(
        !watching_keep.is_finished(),
        "the kept session's watcher was told its session ended"
    );
    watching_keep.abort();
    drop(serial);
}
