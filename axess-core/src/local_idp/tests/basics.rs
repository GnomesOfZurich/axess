//! Foundation tests for the production `LocalIdp`.
//!
//! Covers `from_key_store`, `mint`, `mint_with_header`, `with_max_ttl`,
//! `with_issuance_listener`, `with_clock`, and the `verifier_algorithms` /
//! `jwks_handle` / `jwks_json` / `algorithm` / `issuer` / `max_ttl`
//! accessors.

use std::sync::Arc;

use super::super::*;
use super::support::CustomClaims;
use crate::testing::MockClock;
use axess_factors::jwt::verifier::JwtVerifier;
use chrono::{Duration, Utc};
use jsonwebtoken::Header;

fn one_hour_from_now() -> chrono::DateTime<Utc> {
    Utc::now() + Duration::hours(1)
}

/// Fallible key store that always errors on `load_all`. Used to
/// confirm `from_key_store` surfaces backend errors through
/// `IssuanceError::KeyStore` with the original error type preserved.
#[derive(Clone)]
struct FailingKeyStore;

#[derive(Debug, thiserror::Error)]
#[error("intentional load failure for test")]
struct LoadFailure;

impl LocalIdpKeyStore for FailingKeyStore {
    type Error = LoadFailure;

    async fn load_all(&self) -> Result<LoadedKeys, Self::Error> {
        Err(LoadFailure)
    }

    async fn rotate(&self, new_current: LocalIdpSigningKey) -> Result<(), Self::Error> {
        drop(new_current);
        Err(LoadFailure)
    }
}

#[tokio::test]
async fn from_key_store_rsa_mint_roundtrips_through_verifier() {
    let key = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-1");
    let store = MemoryLocalIdpKeyStore::with_current(key);
    let idp = LocalIdp::from_key_store("https://idp.local", store)
        .await
        .expect("load");

    let token = idp
        .mint(
            &MintClaims::new("worker-1", one_hour_from_now())
                .with_audience("https://api")
                .with_issued_at(Utc::now()),
        )
        .await
        .expect("mint");

    let verifier = JwtVerifier::new(idp.jwks_handle().await)
        .with_issuer("https://idp.local")
        .with_audience("https://api")
        .with_algorithms(idp.verifier_algorithms().await);
    let verified = verifier
        .verify::<CustomClaims>(&token)
        .await
        .expect("verify");
    assert_eq!(verified.sub.as_deref(), Some("worker-1"));
    assert_eq!(verified.iss.as_deref(), Some("https://idp.local"));
}

#[tokio::test]
async fn from_key_store_es256_mint_roundtrips_through_verifier() {
    let key = LocalIdpSigningKey::generate_es256().with_key_id("ec-1");
    let store = MemoryLocalIdpKeyStore::with_current(key);
    let idp = LocalIdp::from_key_store("https://idp.local", store)
        .await
        .expect("load");

    let token = idp
        .mint(
            &MintClaims::new("worker-2", one_hour_from_now())
                .with_audience("https://api")
                .with_issued_at(Utc::now()),
        )
        .await
        .expect("mint");

    let verifier = JwtVerifier::new(idp.jwks_handle().await)
        .with_audience("https://api")
        .with_algorithms(idp.verifier_algorithms().await);
    let verified = verifier
        .verify::<CustomClaims>(&token)
        .await
        .expect("ES256 verify");
    assert_eq!(verified.sub.as_deref(), Some("worker-2"));
}

#[tokio::test]
async fn key_store_load_failure_surfaces_as_issuance_error_keystore() {
    let result: Result<LocalIdp<FailingKeyStore>, IssuanceError<LoadFailure>> =
        LocalIdp::from_key_store("https://idp.local", FailingKeyStore).await;
    let err =
        result.expect_err("FailingKeyStore::load_all errors → from_key_store must return Err");
    assert!(
        matches!(err, IssuanceError::KeyStore(LoadFailure)),
        "expected IssuanceError::KeyStore(LoadFailure), got {err:?}"
    );
}

#[tokio::test]
async fn mint_exceeding_max_ttl_returns_error_does_not_panic() {
    let key = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-1");
    let idp = LocalIdp::from_key_store(
        "https://idp.local",
        MemoryLocalIdpKeyStore::with_current(key),
    )
    .await
    .expect("load")
    .with_max_ttl(Duration::minutes(5));

    let now = Utc::now();
    let result = idp
        .mint(&MintClaims::new("worker-1", now + Duration::hours(2)).with_issued_at(now))
        .await;
    match result {
        Err(IssuanceError::LifetimeExceedsCap { observed, max }) => {
            assert_eq!(max, Duration::minutes(5));
            assert!(observed > max, "observed {observed} must exceed cap {max}");
        }
        other => panic!("expected LifetimeExceedsCap, got {other:?}"),
    }
}

#[tokio::test]
async fn mint_within_max_ttl_succeeds() {
    let key = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-1");
    let idp = LocalIdp::from_key_store(
        "https://idp.local",
        MemoryLocalIdpKeyStore::with_current(key),
    )
    .await
    .expect("load")
    .with_max_ttl(Duration::minutes(10));

    let now = Utc::now();
    idp.mint(&MintClaims::new("worker-1", now + Duration::minutes(5)).with_issued_at(now))
        .await
        .expect("mint within cap");
}

#[tokio::test]
async fn mint_at_exact_max_ttl_boundary_succeeds() {
    let key = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-1");
    let idp = LocalIdp::from_key_store(
        "https://idp.local",
        MemoryLocalIdpKeyStore::with_current(key),
    )
    .await
    .expect("load")
    .with_max_ttl(Duration::minutes(10));

    let now = Utc::now();
    idp.mint(&MintClaims::new("worker-1", now + Duration::minutes(10)).with_issued_at(now))
        .await
        .expect("boundary mint succeeds (<= not <)");
}

#[tokio::test]
async fn mint_fires_issuance_listener_with_event_fields_populated() {
    let key = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-1");
    let recorder = Arc::new(MockIssuanceListener::new());
    let idp = LocalIdp::from_key_store(
        "https://idp.local",
        MemoryLocalIdpKeyStore::with_current(key),
    )
    .await
    .expect("load")
    .with_issuance_listener(recorder.clone());

    let now = Utc::now();
    idp.mint(
        &MintClaims::new("worker-1", now + Duration::hours(1))
            .with_audience("https://api")
            .with_issued_at(now)
            .with_jwt_id("jti-prod-1"),
    )
    .await
    .expect("mint");

    let events = recorder.events();
    assert_eq!(events.len(), 1);
    let e = &events[0];
    assert_eq!(e.subject, "worker-1");
    assert_eq!(e.issuer, "https://idp.local");
    assert_eq!(e.key_id, "rsa-1");
    assert_eq!(e.audience, vec!["https://api".to_string()]);
    assert_eq!(e.jwt_id.as_deref(), Some("jti-prod-1"));
}

#[tokio::test]
async fn issuance_listener_does_not_fire_when_max_ttl_violated() {
    let key = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-1");
    let recorder = Arc::new(MockIssuanceListener::new());
    let idp = LocalIdp::from_key_store(
        "https://idp.local",
        MemoryLocalIdpKeyStore::with_current(key),
    )
    .await
    .expect("load")
    .with_max_ttl(Duration::minutes(5))
    .with_issuance_listener(recorder.clone());

    let now = Utc::now();
    let _ = idp
        .mint(&MintClaims::new("worker-1", now + Duration::hours(2)).with_issued_at(now))
        .await;
    assert_eq!(
        recorder.count(),
        0,
        "listener must not see refused mints (production parity with fixture)"
    );
}

#[tokio::test]
async fn mint_with_header_fires_issuance_listener_and_returns_token() {
    let key = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-1");
    let recorder = Arc::new(MockIssuanceListener::new());
    let idp = LocalIdp::from_key_store(
        "https://idp.local",
        MemoryLocalIdpKeyStore::with_current(key),
    )
    .await
    .expect("load")
    .with_issuance_listener(recorder.clone());

    let now = Utc::now();
    let header = Header {
        typ: Some("custom-typ".to_string()),
        ..Header::default()
    };
    let token = idp
        .mint_with_header(
            &MintClaims::new("worker-1", now + Duration::hours(1))
                .with_audience("https://api")
                .with_issued_at(now),
            header,
        )
        .await
        .expect("mint_with_header");
    assert!(!token.is_empty());

    let decoded = jsonwebtoken::decode_header(&token).expect("decode header");
    assert_eq!(decoded.typ.as_deref(), Some("custom-typ"));
    assert_eq!(decoded.kid.as_deref(), Some("rsa-1"));
    assert_eq!(recorder.count(), 1);
}

#[tokio::test]
async fn with_clock_drives_max_ttl_reference_when_iat_unset() {
    let key = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-1");
    // Stable clock anchored in the past so the test does not depend on
    // wall-clock progress.
    let anchor = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let clock = Arc::new(MockClock::at(anchor));
    let idp = LocalIdp::from_key_store(
        "https://idp.local",
        MemoryLocalIdpKeyStore::with_current(key),
    )
    .await
    .expect("load")
    .with_max_ttl(Duration::minutes(10))
    .with_clock(clock);

    // No iat: the production code uses now-from-clock as reference.
    // exp = anchor + 5 min → lifetime = 5 min ≤ 10 min cap → mint OK.
    idp.mint(&MintClaims::new("worker-1", anchor + Duration::minutes(5)))
        .await
        .expect("mint within injected-clock TTL");

    // exp = anchor + 30 min → lifetime = 30 min > 10 min cap → error.
    let result = idp
        .mint(&MintClaims::new("worker-1", anchor + Duration::minutes(30)))
        .await;
    assert!(
        matches!(result, Err(IssuanceError::LifetimeExceedsCap { .. })),
        "injected clock must drive TTL reference, got {result:?}"
    );
}

#[tokio::test]
async fn verifier_algorithms_returns_current_then_historical() {
    let rsa = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-1");
    let ec = LocalIdpSigningKey::generate_es256().with_key_id("ec-1");
    let store = MemoryLocalIdpKeyStore::with_keys(rsa, vec![ec]);
    let idp = LocalIdp::from_key_store("https://idp.local", store)
        .await
        .expect("load");

    let algs = idp.verifier_algorithms().await;
    assert_eq!(algs[0], Algorithm::RS256, "current first");
    assert!(algs.contains(&Algorithm::ES256), "historical included");
    assert_eq!(algs.len(), 2, "deduplicated");
}

#[tokio::test]
async fn jwks_handle_returns_current_and_historical_kids() {
    let rsa = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-1");
    let ec = LocalIdpSigningKey::generate_es256().with_key_id("ec-1");
    let store = MemoryLocalIdpKeyStore::with_keys(rsa, vec![ec]);
    let idp = LocalIdp::from_key_store("https://idp.local", store)
        .await
        .expect("load");

    let handle = idp.jwks_handle().await;
    let jwks = handle.read().unwrap();
    let kids: Vec<_> = jwks
        .keys
        .iter()
        .filter_map(|k| k.common.key_id.as_deref())
        .collect();
    assert!(kids.contains(&"rsa-1"));
    assert!(kids.contains(&"ec-1"));
    assert_eq!(jwks.keys.len(), 2);
}

#[tokio::test]
async fn jwks_json_is_well_formed_and_omits_private_material() {
    let key = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-1");
    let idp = LocalIdp::from_key_store(
        "https://idp.local",
        MemoryLocalIdpKeyStore::with_current(key),
    )
    .await
    .expect("load");

    let json = idp.jwks_json().await;
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");
    let keys = parsed["keys"].as_array().expect("keys array");
    assert_eq!(keys.len(), 1);
    let k = &keys[0];
    assert_eq!(k["kty"], "RSA");
    assert!(k.get("n").is_some());
    assert!(k.get("e").is_some());
    assert!(k.get("d").is_none(), "private exponent must not leak");
}

#[tokio::test]
async fn local_idp_clone_shares_state_across_handles() {
    // LocalIdp is Arc-shared internally. Cloning it then minting from
    // both handles must produce two tokens that verify against the
    // *same* JWKS, and the listener (if installed on one handle) must
    // see mints from the cloned handle too.
    let key = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-1");
    let recorder = Arc::new(MockIssuanceListener::new());
    let idp_a = LocalIdp::from_key_store(
        "https://idp.local",
        MemoryLocalIdpKeyStore::with_current(key),
    )
    .await
    .expect("load")
    .with_issuance_listener(recorder.clone());
    let idp_b = idp_a.clone();

    let now = Utc::now();
    let claims = MintClaims::new("worker-1", now + Duration::hours(1))
        .with_audience("https://api")
        .with_issued_at(now);

    idp_a.mint(&claims).await.expect("mint via handle A");
    idp_b.mint(&claims).await.expect("mint via handle B");

    assert_eq!(
        recorder.count(),
        2,
        "listener installed on A must fire for mints via cloned B"
    );
}

#[tokio::test]
async fn algorithm_accessor_returns_current_signing_alg() {
    let ec = LocalIdpSigningKey::generate_es256().with_key_id("ec-1");
    let idp = LocalIdp::from_key_store(
        "https://idp.local",
        MemoryLocalIdpKeyStore::with_current(ec),
    )
    .await
    .expect("load");
    assert_eq!(idp.algorithm().await, Algorithm::ES256);
}

#[tokio::test]
async fn issuer_accessor_returns_configured_string() {
    let key = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-1");
    let idp = LocalIdp::from_key_store(
        "https://idp.local",
        MemoryLocalIdpKeyStore::with_current(key),
    )
    .await
    .expect("load");
    assert_eq!(idp.issuer(), "https://idp.local");
}

#[tokio::test]
async fn max_ttl_accessor_returns_none_by_default_and_value_after_set() {
    let key = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-1");
    let idp = LocalIdp::from_key_store(
        "https://idp.local",
        MemoryLocalIdpKeyStore::with_current(key),
    )
    .await
    .expect("load");
    assert_eq!(idp.max_ttl(), None);

    let idp = idp.with_max_ttl(Duration::minutes(15));
    assert_eq!(idp.max_ttl(), Some(Duration::minutes(15)));
}
