//! Property-based tests for security-critical paths.
//!
//! Each module targets one invariant the security model relies on. The
//! generators stay deterministic; proptest's RNG is seeded; so any
//! falsifying input is reproducible from the printed seed.
//!
//! Targets:
//!
//! * `session_data_codec`; `SessionData` survives `rmp_serde::to_vec_named`
//!   ➜ `from_slice` round-trips with the same wire bytes.
//! * `hmac_constant_time`; HMAC-SHA256 + `ConstantTimeEq` correctly
//!   distinguish equal from non-equal tags (the cookie HMAC verify path).
//! * `pkce_alphabet`; RFC 7636 §4.1 `code_verifier` predicate behaves
//!   correctly under random valid and invalid inputs.
//!
//! `pkce_alphabet` re-implements the spec inline. Each property test
//! body asserts the spec holds for proptest-generated inputs; if axess
//! ever exposes a public `pkce` utility, swap the inline check for that.

use axess_core::session::data::{AuthState, SessionData};
use axess_factors::pkce;
use hmac::{Hmac, KeyInit, Mac};
use proptest::prelude::*;
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

// ── SessionData rmp_serde round-trip ─────────────────────────────────────────

/// A `SessionData` encoded with `rmp_serde::to_vec_named` then
/// decoded with `rmp_serde::from_slice` must re-encode to byte-identical
/// output. Any drift would be a silent corruption on the SQL session
/// store path that swapped to MessagePack.
fn arb_session_data() -> impl Strategy<Value = SessionData> {
    // Constrain the custom payload to JSON values that round-trip
    // through MessagePack without ambiguity. `serde_json::Value` is
    // a superset of MessagePack's data model in some edge cases
    // (numeric precision); we keep the generator within MessagePack's
    // safe subset to test the codec, not numeric quirks.
    let leaf = prop_oneof![
        Just(serde_json::Value::Null),
        any::<bool>().prop_map(serde_json::Value::Bool),
        any::<i64>().prop_map(serde_json::Value::from),
        ".*".prop_map(serde_json::Value::String),
    ];

    let custom = leaf.prop_recursive(
        3,  // max depth
        16, // approximate max nodes
        4,  // child count per branch
        |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..4).prop_map(serde_json::Value::Array),
                prop::collection::hash_map(".*", inner, 0..4)
                    .prop_map(|m| serde_json::Value::Object(m.into_iter().collect())),
            ]
        },
    );

    let fingerprint = prop::option::of(any::<String>());

    (custom, fingerprint).prop_map(|(custom, fingerprint)| SessionData {
        version: 1,
        auth_state: AuthState::Guest,
        fingerprint,
        device_id: None,
        custom,
    })
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        // Seed printed on failure; rerun with PROPTEST_REPLAY=<seed>.
        ..ProptestConfig::default()
    })]

    #[test]
    fn session_data_msgpack_roundtrip(data in arb_session_data()) {
        let bytes = rmp_serde::to_vec_named(&data).expect("encode");
        let decoded: SessionData = rmp_serde::from_slice(&bytes).expect("decode");
        let bytes2 = rmp_serde::to_vec_named(&decoded).expect("re-encode");
        prop_assert_eq!(bytes, bytes2, "msgpack round-trip not byte-stable");
    }

    /// Migration safety: a row written before the MessagePack switch
    /// (JSON) must still decode after the read-side fallback. Encode
    /// via `serde_json::to_vec`, then assert `rmp_serde::from_slice`
    /// rejects it AND `serde_json::from_slice` accepts it.
    #[test]
    fn legacy_json_decodes_via_serde_json_only(data in arb_session_data()) {
        let json = serde_json::to_vec(&data).expect("json encode");
        let mp_attempt = rmp_serde::from_slice::<SessionData>(&json);
        // JSON bytes are not valid MessagePack; fallback path must exist.
        prop_assert!(mp_attempt.is_err(), "json bytes happened to parse as msgpack");
        let _: SessionData = serde_json::from_slice(&json).expect("json decode");
    }
}

// ── HMAC-SHA256 + ConstantTimeEq ─────────────────────────────────────────────

/// The cookie verify path computes an HMAC over the raw session id
/// bytes and compares with `ct_eq`. Properties:
///
/// * `sign(k, m) == sign(k, m)`; determinism.
/// * `sign(k, m).ct_eq(sign(k, m')) == false` whenever `m != m'`.
/// * `sign(k, m).ct_eq(sign(k', m)) == false` whenever `k != k'`.
///
/// `ct_eq` is a constant-time comparator; these tests verify the
/// *correctness* property, not the timing property. The timing
/// property is provided by `subtle` itself.
fn sign(key: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 512,
        ..ProptestConfig::default()
    })]

    #[test]
    fn hmac_signing_is_deterministic(
        key in any::<[u8; 32]>(),
        msg in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let a = sign(&key, &msg);
        let b = sign(&key, &msg);
        prop_assert!(bool::from(a.ct_eq(&b)));
    }

    #[test]
    fn hmac_distinct_messages_produce_distinct_tags(
        key in any::<[u8; 32]>(),
        msg in prop::collection::vec(any::<u8>(), 1..256),
        idx in any::<prop::sample::Index>(),
    ) {
        // Flip exactly one bit in the message; the tag must change.
        let pos = idx.index(msg.len());
        let mut other = msg.clone();
        other[pos] ^= 0x01;
        let a = sign(&key, &msg);
        let b = sign(&key, &other);
        prop_assert!(!bool::from(a.ct_eq(&b)),
            "HMAC collision on single-bit flip: {msg:?} vs {other:?}");
    }

    #[test]
    fn hmac_distinct_keys_produce_distinct_tags(
        key in any::<[u8; 32]>(),
        msg in prop::collection::vec(any::<u8>(), 0..256),
        idx in any::<prop::sample::Index>(),
    ) {
        let pos = idx.index(32);
        let mut other_key = key;
        other_key[pos] ^= 0x80;
        let a = sign(&key, &msg);
        let b = sign(&other_key, &msg);
        prop_assert!(!bool::from(a.ct_eq(&b)),
            "HMAC collision on single-bit key flip");
    }
}

// ── PKCE code_verifier (RFC 7636 §4.1) ───────────────────────────────────────

/// Routes through the library's RFC 7636 §4.1 predicate so a future
/// regression in `pkce::is_valid_verifier` is caught by this proptest.
fn pkce_spec(verifier: &str) -> bool {
    pkce::is_valid_verifier(verifier)
}

const PKCE_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 512,
        ..ProptestConfig::default()
    })]

    #[test]
    fn valid_verifier_lengths_accepted(
        len in 43usize..=128,
        seed in any::<[u8; 32]>(),
    ) {
        // Build a verifier of the requested length by indexing the
        // PKCE alphabet with bytes derived from the seed. Deterministic
        // and always produces an in-alphabet verifier.
        let v: String = (0..len)
            .map(|i| PKCE_ALPHABET[(seed[i % 32] as usize) % PKCE_ALPHABET.len()] as char)
            .collect();
        prop_assert!(pkce_spec(&v),
            "in-spec verifier rejected: len={len}, sample='{v}'");
    }

    #[test]
    fn too_short_or_too_long_rejected(
        bad_len in prop_oneof![0usize..=42, 129usize..=200],
        seed in any::<[u8; 32]>(),
    ) {
        let v: String = (0..bad_len)
            .map(|i| PKCE_ALPHABET[(seed[i % 32] as usize) % PKCE_ALPHABET.len()] as char)
            .collect();
        prop_assert!(!pkce_spec(&v),
            "out-of-window length accepted: len={bad_len}");
    }

    #[test]
    fn out_of_alphabet_byte_rejected(
        len in 43usize..=128,
        seed in any::<[u8; 32]>(),
        // Pick an in-alphabet position to corrupt and a bad byte to
        // insert. The corrupting byte must not itself be in the
        // alphabet; proptest's `any::<u8>()` is filtered.
        idx in any::<prop::sample::Index>(),
        bad in any::<u8>().prop_filter(
            "bad byte must not be in PKCE alphabet",
            |b| !(b.is_ascii_alphanumeric()
                || *b == b'-' || *b == b'.' || *b == b'_' || *b == b'~'),
        ),
    ) {
        let mut v: Vec<u8> = (0..len)
            .map(|i| PKCE_ALPHABET[(seed[i % 32] as usize) % PKCE_ALPHABET.len()])
            .collect();
        let pos = idx.index(v.len());
        v[pos] = bad;
        // The corrupted verifier may not be valid UTF-8; only feed
        // the predicate when it is; UTF-8 invalidity is a stronger
        // rejection than the spec check anyway.
        if let Ok(s) = std::str::from_utf8(&v) {
            prop_assert!(!pkce_spec(s),
                "out-of-alphabet byte 0x{bad:02x} accepted at position {pos}");
        }
    }
}
