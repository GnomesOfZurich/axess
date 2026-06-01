//! Benchmarks for the session layer; the per-request cost every handler pays.
//!
//! Gated via `required-features = ["memory"]` in `axess-core/Cargo.toml`,
//! so cargo skips this bench cleanly when the feature is off.

use axess_core::SystemRng;
use axess_core::session::{
    crypto::SessionCrypto,
    data::SessionData,
    id::SessionId,
    store::{MemorySessionStore, SessionStore},
};
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::time::Duration;

/// HMAC-SHA256 cookie signing + verification roundtrip.
fn bench_hmac_sign_verify(c: &mut Criterion) {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    use subtle::ConstantTimeEq;

    type HmacSha256 = Hmac<Sha256>;

    let key = [42u8; 32];
    let session_id = SessionId::new(&SystemRng);
    let id_bytes = session_id.as_bytes();

    c.bench_function("hmac_sign_cookie", |b| {
        b.iter(|| {
            let mut mac = HmacSha256::new_from_slice(&key).unwrap();
            mac.update(black_box(id_bytes));
            let tag = mac.finalize().into_bytes();
            let id_b64 = URL_SAFE_NO_PAD.encode(id_bytes);
            let tag_b64 = URL_SAFE_NO_PAD.encode(tag);
            black_box(format!("{id_b64}.{tag_b64}"));
        })
    });

    // Pre-sign a cookie for the verify benchmark.
    let mut mac = HmacSha256::new_from_slice(&key).unwrap();
    mac.update(id_bytes);
    let tag = mac.finalize().into_bytes();
    let expected_tag = tag.to_vec();

    c.bench_function("hmac_verify_cookie", |b| {
        b.iter(|| {
            let mut mac = HmacSha256::new_from_slice(&key).unwrap();
            mac.update(black_box(id_bytes));
            let computed = mac.finalize().into_bytes();
            let valid: bool = computed.as_slice().ct_eq(black_box(&expected_tag)).into();
            black_box(valid);
        })
    });
}

/// Session fingerprint computation (HMAC-SHA256 of User-Agent).
fn bench_fingerprint(c: &mut Criterion) {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let key = [42u8; 32];
    let user_agent = b"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36";

    c.bench_function("fingerprint_hmac_sha256", |b| {
        b.iter(|| {
            let mut mac = HmacSha256::new_from_slice(&key).unwrap();
            mac.update(black_box(user_agent));
            let result = mac.finalize();
            black_box(URL_SAFE_NO_PAD.encode(result.into_bytes()));
        })
    });
}

/// Session data JSON serialization/deserialization (SQLite store path).
fn bench_session_json_serde(c: &mut Criterion) {
    let data = SessionData::default();

    c.bench_function("session_json_serialize", |b| {
        b.iter(|| {
            black_box(serde_json::to_string(black_box(&data)).unwrap());
        })
    });

    let json = serde_json::to_string(&data).unwrap();

    c.bench_function("session_json_deserialize", |b| {
        b.iter(|| {
            black_box(serde_json::from_str::<SessionData>(black_box(&json)).unwrap());
        })
    });
}

/// AES-256-GCM encrypt/decrypt roundtrip (encrypted SQLite/Valkey store path).
fn bench_session_crypto(c: &mut Criterion) {
    let crypto = SessionCrypto::new([42u8; 32]);
    let data = SessionData::default();
    let plaintext = serde_json::to_vec(&data).unwrap();

    c.bench_function("session_encrypt_aes256gcm", |b| {
        b.iter(|| {
            black_box(crypto.encrypt(black_box(&plaintext)).unwrap());
        })
    });

    let encrypted = crypto.encrypt(&plaintext).unwrap();

    c.bench_function("session_decrypt_aes256gcm", |b| {
        b.iter(|| {
            black_box(crypto.decrypt(black_box(&encrypted)).unwrap());
        })
    });
}

/// In-memory session store load/save (baseline; no I/O).
fn bench_memory_store(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let store = MemorySessionStore::new();
    let rng = SystemRng;
    let id = SessionId::new(&rng);
    let data = SessionData::default();
    let ttl = Duration::from_secs(3600);

    // Pre-populate.
    rt.block_on(store.save(&id, &data, ttl)).unwrap();

    c.bench_function("memory_store_load", |b| {
        b.to_async(&rt).iter(|| async {
            black_box(store.load(black_box(&id)).await.unwrap());
        })
    });

    c.bench_function("memory_store_save", |b| {
        b.to_async(&rt).iter(|| async {
            store
                .save(black_box(&id), black_box(&data), ttl)
                .await
                .unwrap();
        })
    });

    c.bench_function("memory_store_cycle", |b| {
        b.to_async(&rt).iter(|| async {
            // Cycle deletes the old ID and inserts under the new one; measures
            // the full session fixation prevention cost.
            let new_id = SessionId::new(&SystemRng);
            store
                .cycle(black_box(&id), black_box(&new_id), black_box(&data), ttl)
                .await
                .unwrap();
            black_box(new_id);
        })
    });
}

criterion_group!(
    benches,
    bench_hmac_sign_verify,
    bench_fingerprint,
    bench_session_json_serde,
    bench_session_crypto,
    bench_memory_store,
);
criterion_main!(benches);
