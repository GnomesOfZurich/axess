// Fuzz the device-key proof parser,
// `axess_factors::key_proof::parse_key_proof`, which reads a value any client
// can post to the refresh path before anything is verified.
//
// The target calls the library function and holds it to an independent
// statement of the contract: a proof is parsed only when it is within the
// size bound, has exactly three dot-separated segments whose first two are
// URL-safe base64 of JSON objects, names `ES256` as its `alg` and its shape's
// `typ` and carries no `crit`; and the challenge the parsed proof reports is
// the shape's claim as a string, or none.
//
// Every proof that parses is then put through the three verifications
// (under the key it carries, under a stored key, and as a request proof
// under each, with a clock and a window drawn from the input). Each must
// return, and the two under the stored key must refuse: the fuzzer holds no
// key that signs for it.

#![no_main]

use axess_factors::key_proof::{
    APP_PROOF_TYP, KEY_PROOF_ALG, KeyProofShape, MAX_KEY_PROOF_BYTES, P256Key, ProofKey,
    ProofTarget, RequestProofCheck, browser_draft, parse_key_proof,
};
use base64::Engine as _;
use libfuzzer_sys::fuzz_target;

fn object(segment: &str) -> Option<serde_json::Value> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segment)
        .ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    value.is_object().then_some(value)
}

/// The challenge a well-formed proof reports, written without the library's
/// code: `None` for a proof the contract refuses, `Some(None)` for one with
/// no challenge claim.
fn expected(jws: &str, shape: KeyProofShape) -> Option<Option<String>> {
    if jws.len() > MAX_KEY_PROOF_BYTES {
        return None;
    }
    let segments: Vec<&str> = jws.split('.').collect();
    let [head, body, _] = segments.as_slice() else {
        return None;
    };
    let (header, claims) = (object(head)?, object(body)?);
    if header.get("crit").is_some() {
        return None;
    }
    let (typ, claim) = match shape {
        KeyProofShape::Browser => (
            browser_draft::PROOF_TYP,
            browser_draft::PROOF_CHALLENGE_CLAIM,
        ),
        KeyProofShape::App => (APP_PROOF_TYP, "nonce"),
    };
    if header.get("alg").and_then(|v| v.as_str()) != Some(KEY_PROOF_ALG)
        || header.get("typ").and_then(|v| v.as_str()) != Some(typ)
    {
        return None;
    }
    Some(
        claims
            .get(claim)
            .and_then(|v| v.as_str())
            .map(str::to_owned),
    )
}

const TARGET: ProofTarget<'static> = ProofTarget {
    method: "POST",
    url: "https://app.example/axess/device-key",
};

/// The key the stored-key verifications run under: the base point of the
/// curve. No input is signed for it.
const STORED: P256Key = P256Key {
    x: [
        0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
        0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98,
        0xc2, 0x96,
    ],
    y: [
        0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e,
        0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf,
        0x51, 0xf5,
    ],
};

/// A number from the input, so the clock and the window vary with it.
fn number(data: &[u8], at: usize) -> i64 {
    let mut bytes = [0u8; 8];
    for (slot, byte) in bytes.iter_mut().zip(data.iter().skip(at)) {
        *slot = *byte;
    }
    i64::from_le_bytes(bytes)
}

fuzz_target!(|data: &[u8]| {
    let Ok(jws) = std::str::from_utf8(data) else {
        return;
    };
    for shape in [KeyProofShape::Browser, KeyProofShape::App] {
        let outcome = parse_key_proof(jws, shape);
        let parsed = outcome
            .as_ref()
            .ok()
            .map(|proof| proof.challenge().map(str::to_owned));
        assert_eq!(parsed, expected(jws, shape), "{shape:?}");
        let Ok(proof) = outcome else {
            continue;
        };
        // Under the key the proof carries: it must return, whatever it says.
        std::hint::black_box(proof.verify(TARGET, ProofKey::Embedded).is_ok());
        assert!(
            proof.verify(TARGET, ProofKey::Stored(&STORED)).is_err(),
            "{shape:?}: verified under a key nobody signed with"
        );
        let check = RequestProofCheck {
            target: TARGET,
            now_unix: number(data, 0),
            max_age: std::time::Duration::from_secs(number(data, 8).unsigned_abs()),
            max_ahead: std::time::Duration::from_secs(number(data, 16).unsigned_abs()),
            key: ProofKey::Stored(&STORED),
        };
        assert!(
            proof.verify_request(check).is_err(),
            "{shape:?}: a request proof verified under a key nobody signed with"
        );
        // As a request proof under the key it carries, which is how a request
        // is read before any store is asked: it must return.
        let carried = RequestProofCheck {
            key: ProofKey::Embedded,
            ..check
        };
        std::hint::black_box(proof.verify_request(carried).is_ok());
    }
});
