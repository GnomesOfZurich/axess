//! Benchmarks for the session layer; the per-request cost every handler pays.
//!
//! Gated via `required-features = ["memory", "sqlite"]` in
//! `axess-core/Cargo.toml`: `session::crypto` is compiled only with a store
//! feature, so cargo skips this bench cleanly when either is off.

use axess_core::session::{
    crypto::SessionCrypto,
    data::SessionData,
    id::{SessionId, SessionKey},
    store::{MemorySessionStore, SessionStore},
};
use axess_core::{SqliteSessionStore, SystemRng};
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

/// Session data MessagePack encoding and decoding: the encoding every
/// session store writes and the only one it reads.
fn bench_session_msgpack_serde(c: &mut Criterion) {
    let data = SessionData::default();

    c.bench_function("session_msgpack_serialize", |b| {
        b.iter(|| {
            black_box(rmp_serde::to_vec_named(black_box(&data)).unwrap());
        })
    });

    let bytes = rmp_serde::to_vec_named(&data).unwrap();

    c.bench_function("session_msgpack_deserialize", |b| {
        b.iter(|| {
            black_box(rmp_serde::from_slice::<SessionData>(black_box(&bytes)).unwrap());
        })
    });
}

/// AES-256-GCM encrypt/decrypt roundtrip (encrypted SQLite/Valkey store path).
fn bench_session_crypto(c: &mut Criterion) {
    let crypto = SessionCrypto::new(axess_core::testing::test_key(42));
    let data = SessionData::default();
    let plaintext = rmp_serde::to_vec_named(&data).unwrap();

    c.bench_function("session_encrypt_aes256gcm", |b| {
        b.iter(|| {
            black_box(
                crypto
                    .encrypt_with_aad(b"bench", black_box(&plaintext))
                    .unwrap(),
            );
        })
    });

    let encrypted = crypto.encrypt_with_aad(b"bench", &plaintext).unwrap();

    c.bench_function("session_decrypt_aes256gcm", |b| {
        b.iter(|| {
            black_box(
                crypto
                    .decrypt_with_aad(b"bench", black_box(&encrypted))
                    .unwrap(),
            );
        })
    });
}

/// In-memory session store load/save (baseline; no I/O).
fn bench_memory_store(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let store = MemorySessionStore::new();
    let rng = SystemRng;
    let id = SessionKey::of(&SessionId::new(&rng));
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
            let new_id = SessionKey::of(&SessionId::new(&SystemRng));
            let outcome = store
                .cycle(
                    black_box(&id),
                    black_box(&new_id),
                    black_box(&data),
                    ttl,
                    false,
                )
                .await
                .unwrap();
            assert_eq!(outcome, axess_core::session::CycleOutcome::Rotated);
            black_box(new_id);
        })
    });
}

/// A session carrying a 2 KiB value, saved to and loaded from SQLite in
/// memory by a store that keeps it in plaintext and by one that encrypts
/// it. The encrypting store seals each row under a subkey derived for that
/// record, so what lies between the two `save` figures is the cost of that
/// seal on the path a request takes, and between the two `load` figures the
/// cost of the open.
fn bench_sqlite_store_sealed(c: &mut Criterion) {
    use sqlx::sqlite::SqlitePoolOptions;

    let rt = tokio::runtime::Runtime::new().unwrap();
    let pool = || async {
        SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap()
    };
    let (plain, sealed) = rt.block_on(async {
        let plain = SqliteSessionStore::plaintext_insecure(pool().await);
        plain.init_schema().await.unwrap();
        let crypto = SessionCrypto::new(axess_core::testing::test_key(42));
        let sealed = SqliteSessionStore::new(pool().await, crypto);
        sealed.init_schema().await.unwrap();
        (plain, sealed)
    });

    let id = SessionKey::of(&SessionId::new(&SystemRng));
    let data = SessionData {
        custom: serde_json::json!({ "payload": "x".repeat(2048) }),
        ..SessionData::default()
    };
    let ttl = Duration::from_secs(3600);

    for (name, store) in [("plaintext", &plain), ("sealed", &sealed)] {
        c.bench_function(&format!("sqlite_store_save_2k_{name}"), |b| {
            b.to_async(&rt).iter(|| async {
                store
                    .save(black_box(&id), black_box(&data), ttl)
                    .await
                    .unwrap();
            })
        });
        c.bench_function(&format!("sqlite_store_load_2k_{name}"), |b| {
            b.to_async(&rt).iter(|| async {
                black_box(store.load(black_box(&id)).await.unwrap());
            })
        });
    }
}

criterion_group!(
    benches,
    bench_hmac_sign_verify,
    bench_fingerprint,
    bench_session_msgpack_serde,
    bench_session_crypto,
    bench_memory_store,
    bench_sqlite_store_sealed,
);
criterion_main!(benches);
