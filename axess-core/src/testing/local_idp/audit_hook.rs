use axess_clock::testing::Shift;
use std::sync::{Arc, Mutex};

use super::*;
use crate::testing::MockClock;
use axess_factors::jwt::verifier::JwtVerifier;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct CustomClaims {}

// ── Issuance audit hook ──────────────────────────────────────────────

#[tokio::test]
async fn issuance_listener_fires_per_mint() {
    let clock = MockClock::at_reference();
    let recorder = Arc::new(MockIssuanceListener::new());
    let idp = LocalIdpFixture::new("https://idp")
        .with_clock(clock.clone())
        .with_issuance_listener(recorder.clone());

    let now = axess_clock::testing::MockClock::reference_time();
    idp.mint(
        &MintClaims::new("alice", now.plus(SignedDuration::hours(1)))
            .with_audience("https://api")
            .with_issued_at(now),
    );
    idp.mint(
        &MintClaims::new("bob", now.plus(SignedDuration::hours(1)))
            .with_audience("https://api")
            .with_issued_at(now),
    );

    assert_eq!(recorder.count(), 2);
    let events = recorder.events();
    assert_eq!(events[0].subject, "alice");
    assert_eq!(events[1].subject, "bob");
    assert_eq!(events[0].issuer, "https://idp");
    assert_eq!(events[0].key_id, idp.key_id());
    assert_eq!(events[0].algorithm, idp.algorithm());
    assert_eq!(events[0].audience, vec!["https://api".to_string()]);
}

#[tokio::test]
async fn issuance_listener_captures_optional_claims() {
    let clock = MockClock::at_reference();
    let recorder = Arc::new(MockIssuanceListener::new());
    let idp = LocalIdpFixture::new("https://idp")
        .with_clock(clock.clone())
        .with_issuance_listener(recorder.clone());

    let now = axess_clock::testing::MockClock::reference_time();
    idp.mint(
        &MintClaims::new("alice", now.plus(SignedDuration::hours(1)))
            .with_audience("https://api")
            .with_issued_at(now)
            .with_not_before(now)
            .with_jwt_id("jti-42"),
    );

    let event = recorder.events().pop().expect("one event recorded");
    assert!(event.issued_at.is_some());
    assert!(event.not_before.is_some());
    assert_eq!(event.jwt_id.as_deref(), Some("jti-42"));
}

#[tokio::test]
async fn issuance_listener_captures_multi_audience() {
    let clock = MockClock::at_reference();
    let recorder = Arc::new(MockIssuanceListener::new());
    let idp = LocalIdpFixture::new("https://idp")
        .with_clock(clock.clone())
        .with_issuance_listener(recorder.clone());

    let now = axess_clock::testing::MockClock::reference_time();
    idp.mint(
        &MintClaims::new("alice", now.plus(SignedDuration::hours(1)))
            .with_audiences(["https://api", "https://other"])
            .with_issued_at(now),
    );

    let event = recorder.events().pop().expect("one event recorded");
    assert_eq!(
        event.audience,
        vec!["https://api".to_string(), "https://other".to_string()]
    );
}

#[tokio::test]
async fn issuance_listener_records_kid_after_rotation() {
    let clock = MockClock::at_reference();
    let recorder = Arc::new(MockIssuanceListener::new());
    let k1 = LocalIdpSigningKey::generate_es256().with_key_id("k1");
    let k2 = LocalIdpSigningKey::generate_es256().with_key_id("k2");
    let idp = LocalIdpFixture::with_signing_key("https://idp", k1)
        .with_clock(clock.clone())
        .with_issuance_listener(recorder.clone());

    let now = axess_clock::testing::MockClock::reference_time();
    let claims = MintClaims::new("alice", now.plus(SignedDuration::hours(1)))
        .with_audience("https://api")
        .with_issued_at(now);
    idp.mint(&claims);

    let rotated = idp.rotate_signing_key(k2);
    rotated.mint(&claims);

    let events = recorder.events();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].key_id, "k1");
    assert_eq!(events[1].key_id, "k2");
}

#[tokio::test]
#[should_panic(expected = "max_ttl")]
async fn issuance_listener_does_not_fire_when_max_ttl_violated() {
    let clock = MockClock::at_reference();
    let recorder = Arc::new(MockIssuanceListener::new());
    let idp = LocalIdpFixture::new("https://idp")
        .with_clock(clock.clone())
        .with_max_ttl(std::time::Duration::from_mins(5))
        .with_issuance_listener(recorder.clone());
    let now = axess_clock::testing::MockClock::reference_time();
    let _ =
        idp.mint(&MintClaims::new("alice", now.plus(SignedDuration::hours(2))).with_issued_at(now));
}

#[tokio::test]
async fn issuance_listener_replaced_on_second_call() {
    let clock = MockClock::at_reference();
    let first = Arc::new(MockIssuanceListener::new());
    let second = Arc::new(MockIssuanceListener::new());
    let idp = LocalIdpFixture::new("https://idp")
        .with_clock(clock.clone())
        .with_issuance_listener(first.clone())
        .with_issuance_listener(second.clone());

    let now = axess_clock::testing::MockClock::reference_time();
    idp.mint(&MintClaims::new("alice", now.plus(SignedDuration::hours(1))).with_issued_at(now));

    assert_eq!(first.count(), 0, "replaced listener must not be invoked");
    assert_eq!(second.count(), 1, "current listener captures the mint");
}

#[tokio::test]
async fn recording_issuance_listener_clear_resets_count() {
    let clock = MockClock::at_reference();
    let recorder = Arc::new(MockIssuanceListener::new());
    let idp = LocalIdpFixture::new("https://idp")
        .with_clock(clock.clone())
        .with_issuance_listener(recorder.clone());
    let now = axess_clock::testing::MockClock::reference_time();
    let claims = MintClaims::new("alice", now.plus(SignedDuration::hours(1))).with_issued_at(now);
    idp.mint(&claims);
    idp.mint(&claims);
    assert_eq!(recorder.count(), 2);
    recorder.clear();
    assert_eq!(recorder.count(), 0);
}

#[tokio::test]
async fn issuance_listener_accessor_returns_installed() {
    let recorder = Arc::new(MockIssuanceListener::new());
    let idp = LocalIdpFixture::new("https://idp").with_issuance_listener(recorder.clone());
    assert!(idp.issuance_listener().is_some());
    assert!(
        LocalIdpFixture::new("https://idp")
            .issuance_listener()
            .is_none()
    );
}

#[tokio::test]
async fn issuance_listener_survives_with_historical_signing_key() {
    let clock = MockClock::at_reference();
    let recorder = Arc::new(MockIssuanceListener::new());
    let key = LocalIdpSigningKey::generate_es256();
    let idp = LocalIdpFixture::new("https://idp")
        .with_clock(clock.clone())
        .with_issuance_listener(recorder.clone())
        .with_historical_signing_key(key);
    let now = axess_clock::testing::MockClock::reference_time();
    idp.mint(&MintClaims::new("alice", now.plus(SignedDuration::hours(1))).with_issued_at(now));
    assert_eq!(recorder.count(), 1);
}

#[tokio::test]
async fn issuance_listener_survives_with_extra_public_jwk() {
    let clock = MockClock::at_reference();
    let recorder = Arc::new(MockIssuanceListener::new());
    let foreign = LocalIdpSigningKey::generate_es256().with_key_id("foreign");
    let idp = LocalIdpFixture::new("https://idp")
        .with_clock(clock.clone())
        .with_issuance_listener(recorder.clone())
        .with_extra_public_jwk(foreign.jwk().clone());
    let now = axess_clock::testing::MockClock::reference_time();
    idp.mint(&MintClaims::new("alice", now.plus(SignedDuration::hours(1))).with_issued_at(now));
    assert_eq!(recorder.count(), 1);
}

#[tokio::test]
async fn issuance_listener_survives_with_max_ttl() {
    let clock = MockClock::at_reference();
    let recorder = Arc::new(MockIssuanceListener::new());
    let idp = LocalIdpFixture::new("https://idp")
        .with_clock(clock.clone())
        .with_issuance_listener(recorder.clone())
        .with_max_ttl(std::time::Duration::from_hours(2));
    let now = axess_clock::testing::MockClock::reference_time();
    idp.mint(&MintClaims::new("alice", now.plus(SignedDuration::hours(1))).with_issued_at(now));
    assert_eq!(recorder.count(), 1);
}

#[tokio::test]
async fn issuance_listener_survives_with_key_id() {
    let clock = MockClock::at_reference();
    let recorder = Arc::new(MockIssuanceListener::new());
    let idp = LocalIdpFixture::new("https://idp")
        .with_clock(clock.clone())
        .with_issuance_listener(recorder.clone())
        .with_key_id("custom");
    let now = axess_clock::testing::MockClock::reference_time();
    idp.mint(&MintClaims::new("alice", now.plus(SignedDuration::hours(1))).with_issued_at(now));
    assert_eq!(recorder.count(), 1);
    assert_eq!(recorder.events()[0].key_id, "custom");
}

#[tokio::test]
async fn issuance_listener_fires_for_mint_jwt_svid() {
    let recorder = Arc::new(MockIssuanceListener::new());
    let idp = LocalIdpFixture::new("https://idp").with_issuance_listener(recorder.clone());
    let _ = idp.mint_jwt_svid(
        "test.example.org",
        "worker",
        "acme",
        "https://api",
        SignedDuration::minutes(5),
    );
    let event = recorder.events().pop().expect("one event recorded");
    assert_eq!(event.subject, "spiffe://test.example.org/worker/acme");
    assert_eq!(event.audience, vec!["https://api".to_string()]);
}

#[tokio::test]
async fn issuance_listener_fires_for_mint_with_header() {
    let clock = MockClock::at_reference();
    let recorder = Arc::new(MockIssuanceListener::new());
    let idp = LocalIdpFixture::new("https://idp")
        .with_clock(clock.clone())
        .with_issuance_listener(recorder.clone());
    let now = axess_clock::testing::MockClock::reference_time();
    let claims = MintClaims::new("alice", now.plus(SignedDuration::hours(1)))
        .with_audience("https://api")
        .with_issued_at(now);
    let mut header = jsonwebtoken::Header::new(idp.algorithm());
    header.x5t = Some("custom-thumbprint".to_string());
    let _ = idp.mint_with_header(&claims, &mut header);

    let event = recorder.events().pop().expect("one event recorded");
    assert_eq!(event.subject, "alice");
    assert_eq!(event.key_id, idp.key_id());
}

#[derive(Default)]
struct CountingListener {
    count: Mutex<usize>,
}

impl CountingListener {
    fn count(&self) -> usize {
        *self.count.lock().expect("CountingListener mutex poisoned")
    }
}

impl IssuanceListener for CountingListener {
    fn on_mint(&self, event: &IssuanceEvent<'_>) {
        tracing::trace!(?event, "CountingListener: bumping counter");
        *self.count.lock().expect("CountingListener mutex poisoned") += 1;
    }
}

#[tokio::test]
async fn custom_issuance_listener_implementation_works() {
    let clock = MockClock::at_reference();
    let counter = Arc::new(CountingListener::default());
    let idp = LocalIdpFixture::new("https://idp")
        .with_clock(clock.clone())
        .with_issuance_listener(counter.clone());
    let now = axess_clock::testing::MockClock::reference_time();
    let claims = MintClaims::new("alice", now.plus(SignedDuration::hours(1))).with_issued_at(now);
    idp.mint(&claims);
    idp.mint(&claims);
    idp.mint(&claims);
    assert_eq!(counter.count(), 3);
}

// ── Additional coverage ──────────────────────────────────────────────

#[tokio::test]
async fn from_ec_pem_accepts_sec1_pem() {
    let clock = MockClock::at_reference();
    use p256::SecretKey;

    let secret = SecretKey::from_slice(&[0x22; 32]).expect("a scalar below the curve order");
    let sec1_pem = secret
        .to_sec1_pem(p256::pkcs8::LineEnding::LF)
        .expect("SEC1 PEM encode")
        .to_string();
    assert!(sec1_pem.starts_with("-----BEGIN EC PRIVATE KEY-----"));

    let key = LocalIdpSigningKey::from_ec_pem(&sec1_pem, "sec1-pem-kid", Algorithm::ES256)
        .expect("SEC1 PEM parses");
    assert_eq!(key.key_id(), "sec1-pem-kid");
    assert_eq!(key.algorithm(), Algorithm::ES256);

    let idp = LocalIdpFixture::with_signing_key("https://idp", key).with_clock(clock.clone());
    let now = axess_clock::testing::MockClock::reference_time();
    let token = idp.mint(
        &MintClaims::new("alice", now.plus(SignedDuration::hours(1)))
            .with_audience("https://api")
            .with_issued_at(now),
    );
    let verifier = JwtVerifier::new(idp.jwks_handle())
        .with_clock(Arc::new(clock.clone()))
        .with_audience("https://api")
        .allow_any_issuer()
        .with_algorithms(idp.verifier_algorithms());
    verifier
        .verify::<CustomClaims>(&token)
        .await
        .expect("SEC1-PEM-loaded ES256 key mints verifiable token");
}

#[tokio::test]
async fn mint_with_header_fires_issuance_listener() {
    let clock = MockClock::at_reference();
    let recorder = Arc::new(MockIssuanceListener::new());
    let idp = LocalIdpFixture::new("https://idp")
        .with_clock(clock.clone())
        .with_issuance_listener(recorder.clone());

    let now = axess_clock::testing::MockClock::reference_time();
    let claims = MintClaims::new("alice", now.plus(SignedDuration::hours(1)))
        .with_audience("https://api")
        .with_issued_at(now);

    let mut header = jsonwebtoken::Header::new(idp.algorithm());
    header.typ = Some("custom-typ".to_string());
    drop(idp.mint_with_header(&claims, &mut header));

    assert_eq!(
        recorder.count(),
        1,
        "listener must fire on header-customized mint"
    );
    let event = recorder.events().pop().expect("one event");
    assert_eq!(event.subject, "alice");
}

#[tokio::test]
async fn max_ttl_survives_with_issuance_listener() {
    let recorder = Arc::new(MockIssuanceListener::new());
    let idp = LocalIdpFixture::new("https://idp")
        .with_max_ttl(std::time::Duration::from_mins(5))
        .with_issuance_listener(recorder.clone());
    assert_eq!(
        idp.max_ttl(),
        Some(std::time::Duration::from_mins(5)),
        "with_issuance_listener must preserve max_ttl"
    );
}
