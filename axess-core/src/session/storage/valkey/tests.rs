//! Unit tests for the Valkey session backend.
//!
//! Pins pure-function behaviour and inherent-method bodies that
//! cargo-mutants can attack from the test thread without a live
//! Valkey instance. The body-replacement mutations on the
//! `SessionStore` / `SessionRegistry` impls (load/save/cycle/…) are
//! distinguishable from the originals only via an actual Valkey
//! round-trip, so they remain covered by the `valkey_integration`
//! `#[ignore]` test below.

use super::internal::{
    DEFAULT_MAX_PAYLOAD_BYTES, ValkeyStoreError, registry_key, revocation_session_channel,
    revocation_user_channel, session_key,
};
use super::registry::ValkeySessionRegistry;
use super::store::ValkeySessionStore;
use crate::session::crypto::SessionCrypto;
use crate::session::data::SessionData;
use crate::session::id::SessionId;
use crate::session::storage::session_codec::SessionCodec;
use crate::session::store::{SessionRegistry, SessionStore};
use axess_rng::SystemRng;
use fred::prelude::*;
use std::time::Duration;

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
    let key = [99u8; 32];
    let codec = SessionCodec::encrypted(SessionCrypto::new(key));
    let data = SessionData::default();
    let bytes = codec.encode_bytes(&data).expect("encode_bytes");
    let restored = codec.decode_bytes(&bytes).expect("decode_bytes");
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
    let store = ValkeySessionStore::plaintext(client).with_max_payload(1);

    let data = SessionData::default();
    let result = store.encode(&data);

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
    let store = ValkeySessionStore::plaintext(client);
    let data = SessionData::default();
    assert!(store.encode(&data).is_ok());
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
    let id = SessionId::new(&rng);
    let id_s = id.to_string();

    assert_eq!(session_key("axess", &id), format!("axess:sess:{id_s}"));
    assert_eq!(registry_key("axess", "u-1"), "axess:reg:u-1");
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
        session_key("other", &id),
        format!("other:sess:{id_s}"),
        "session_key must interpolate the prefix argument"
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
    let store = ValkeySessionStore::plaintext(dummy_client());
    let data = SessionData::default();

    // Find the natural encoded size by measuring with a huge cap.
    let baseline = store
        .clone()
        .with_max_payload(usize::MAX)
        .encode(&data)
        .expect("baseline encode")
        .len();

    // Exactly at cap: original (`>`) returns Ok; `==` and `>=` reject.
    let ok_at_cap = store.clone().with_max_payload(baseline).encode(&data);
    assert!(
        ok_at_cap.is_ok(),
        "encode at exactly the cap must succeed (> not >= or ==): {ok_at_cap:?}"
    );

    // One under cap: original rejects, `<` mutant accepts.
    let under_cap = store.clone().with_max_payload(baseline - 1).encode(&data);
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
    let store = ValkeySessionStore::plaintext(dummy_client());

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

    let bytes = store.encode(&data).expect("encode");
    assert!(
        !bytes.is_empty(),
        "encode must produce a non-empty payload: kills Ok(vec![])"
    );
    assert!(
        bytes.len() > 1,
        "encode must produce > 1 byte for non-trivial payload: kills Ok(vec![0/1])"
    );

    let decoded = store.decode(&bytes).expect("decode");
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
    let store = ValkeySessionStore::plaintext(unreachable_client());
    let rng = SystemRng;
    let id = SessionId::new(&rng);
    let result = tokio::time::timeout(Duration::from_secs(3), store.load(&id)).await;
    assert!(
        matches!(result, Ok(Err(_))),
        "load must return Err quickly against unreachable Valkey: {result:?}"
    );
}

#[tokio::test]
async fn save_propagates_error_against_unreachable_valkey() {
    let store = ValkeySessionStore::plaintext(unreachable_client());
    let rng = SystemRng;
    let id = SessionId::new(&rng);
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        store.save(&id, &SessionData::default(), Duration::from_secs(60)),
    )
    .await;
    assert!(
        matches!(result, Ok(Err(_))),
        "save must return Err: {result:?}"
    );
}

#[tokio::test]
async fn delete_propagates_error_against_unreachable_valkey() {
    let store = ValkeySessionStore::plaintext(unreachable_client());
    let rng = SystemRng;
    let id = SessionId::new(&rng);
    let result = tokio::time::timeout(Duration::from_secs(3), store.delete(&id)).await;
    assert!(
        matches!(result, Ok(Err(_))),
        "delete must return Err: {result:?}"
    );
}

#[tokio::test]
async fn cycle_propagates_error_against_unreachable_valkey() {
    let store = ValkeySessionStore::plaintext(unreachable_client());
    let rng = SystemRng;
    let old = SessionId::new(&rng);
    let new = SessionId::new(&rng);
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        store.cycle(&old, &new, &SessionData::default(), Duration::from_secs(60)),
    )
    .await;
    assert!(
        matches!(result, Ok(Err(_))),
        "cycle must return Err: {result:?}"
    );
}

fn unreachable_registry() -> ValkeySessionRegistry {
    ValkeySessionRegistry::new(unreachable_client())
}

#[tokio::test]
async fn register_propagates_error_against_unreachable_valkey() {
    let registry = unreachable_registry();
    let user = axess_identity::testing::user("u");
    let rng = SystemRng;
    let sid = SessionId::new(&rng);
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
    let sid = SessionId::new(&rng);
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
    let sid = SessionId::new(&rng);
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

// Note on `watch_revocation`: the mutation replaces the
// entire body with `()`. Because the original body itself only
// performs side effects (subscribing, awaiting a message) and
// returns `()`, the mutation produces the same return value. Any
// distinguishing behaviour would have to be observable through
// a separate channel: but the production path opens a new
// subscriber connection, which is impossible to mock under the
// current `fred::Client` surface. This mutant is documented as
// equivalent at the public API level; it would only matter if a
// future refactor moves `watch_revocation` to a return-value
// contract.
//
// The historical `decrypt` size-guard mutant note was deleted:
// the `decrypt` helper now lives in
// `session::crypto::SessionCrypto` and its mutant surface is
// pinned by the tests there.

/// Pin `prune_expired` against the `Ok(1)` mutation:
/// the Valkey trait surface explicitly returns `Ok(0)` because
/// Redis evicts expired keys natively, and the doc-comment on
/// the method makes that an intentional contract.
#[tokio::test]
async fn prune_expired_returns_zero_per_native_expiry_contract() {
    let store = ValkeySessionStore::plaintext(dummy_client());
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
#[ignore = "requires a running Valkey instance at 127.0.0.1:6379"]
async fn valkey_integration() {
    let config = Config::from_url("redis://127.0.0.1:6379").expect("parse redis URL");
    let client = Client::new(config, None, None, None);
    client.init().await.expect("connect to Valkey");

    let encryption_key = [77u8; 32];
    let store =
        ValkeySessionStore::encrypted(client.clone(), encryption_key).with_prefix("axess_test");
    let registry =
        ValkeySessionRegistry::with_options(client.clone(), "axess_test", Duration::from_secs(60));

    let rng = SystemRng;
    let sid = SessionId::new(&rng);
    let data = SessionData::default();
    let ttl = Duration::from_secs(30);

    // Store: save -> load -> matches.
    store.save(&sid, &data, ttl).await.expect("save");
    let loaded = store.load(&sid).await.expect("load");
    assert!(loaded.is_some(), "session should exist after save");

    // Store: cycle -> old gone, new exists.
    let new_sid = SessionId::new(&rng);
    store
        .cycle(&sid, &new_sid, &data, ttl)
        .await
        .expect("cycle");
    assert!(store.load(&sid).await.expect("load old").is_none());
    assert!(store.load(&new_sid).await.expect("load new").is_some());

    // Store: delete -> gone.
    store.delete(&new_sid).await.expect("delete");
    assert!(store.load(&new_sid).await.expect("load deleted").is_none());

    // Registry: register -> is_valid -> invalidate.
    let user_id = axess_identity::testing::user("test-user-integration");
    let user_id = &user_id;
    let reg_sid = SessionId::new(&rng);
    registry
        .register(user_id, &reg_sid)
        .await
        .expect("register");
    assert!(
        registry
            .is_valid(user_id, &reg_sid)
            .await
            .expect("is_valid"),
        "session should be valid after register"
    );

    // Registry: invalidate single session.
    registry
        .invalidate_session(user_id, &reg_sid)
        .await
        .expect("invalidate_session");
    assert!(
        !registry
            .is_valid(user_id, &reg_sid)
            .await
            .expect("is_valid after invalidate"),
    );

    // Registry: invalidate all sessions for user.
    let sid_a = SessionId::new(&rng);
    let sid_b = SessionId::new(&rng);
    registry.register(user_id, &sid_a).await.expect("reg a");
    registry.register(user_id, &sid_b).await.expect("reg b");
    registry
        .invalidate_user(user_id)
        .await
        .expect("invalidate_user");
    assert!(!registry.is_valid(user_id, &sid_a).await.expect("a"));
    assert!(!registry.is_valid(user_id, &sid_b).await.expect("b"));

    // Key rotation: save with old key, load with new key + old as fallback.
    let old_key = [77u8; 32];
    let new_key = [88u8; 32];
    let old_store =
        ValkeySessionStore::encrypted(client.clone(), old_key).with_prefix("axess_test");
    let rotation_store =
        ValkeySessionStore::encrypted_with_rotation(client.clone(), new_key, old_key)
            .with_prefix("axess_test");

    let rot_sid = SessionId::new(&rng);
    old_store
        .save(&rot_sid, &data, ttl)
        .await
        .expect("save with old key");
    let loaded = rotation_store
        .load(&rot_sid)
        .await
        .expect("load with rotation");
    assert!(
        loaded.is_some(),
        "should decrypt with previous key fallback"
    );

    // Cleanup.
    old_store.delete(&rot_sid).await.expect("cleanup");

    client.quit().await.expect("disconnect");
}
