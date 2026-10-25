use super::*;
use axess_factors::jwt::verifier::JwtVerifier;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct CustomClaims {}

// ── Max-TTL policy tests ─────────────────────────────────────────────

#[test]
fn max_ttl_accessor_returns_none_by_default() {
    let idp = LocalIdpFixture::new("https://idp");
    assert!(idp.max_ttl().is_none());
}

#[test]
fn with_max_ttl_records_cap() {
    let idp = LocalIdpFixture::new("https://idp").with_max_ttl(Duration::minutes(15));
    assert_eq!(idp.max_ttl(), Some(Duration::minutes(15)));
}

#[tokio::test]
async fn mint_within_max_ttl_succeeds() {
    let idp = LocalIdpFixture::new("https://idp").with_max_ttl(Duration::minutes(30));
    let now = Utc::now();
    let claims = MintClaims::new("alice", now + Duration::minutes(15))
        .with_audience("https://api")
        .with_issued_at(now);
    let token = idp.mint(&claims);
    let verifier = JwtVerifier::new(idp.jwks_handle()).with_audience("https://api");
    verifier
        .verify::<CustomClaims>(&token)
        .await
        .expect("within-cap mint must verify");
}

#[test]
#[should_panic(expected = "exceeding the fixture's max_ttl")]
fn mint_exceeding_max_ttl_panics() {
    let idp = LocalIdpFixture::new("https://idp").with_max_ttl(Duration::minutes(15));
    let now = Utc::now();
    let claims = MintClaims::new("alice", now + Duration::hours(2))
        .with_audience("https://api")
        .with_issued_at(now);
    let _ = idp.mint(&claims);
}

/// Without `iat`, the cap is enforced against `now`. Construct a
/// claim whose exp is far in the future to trigger the over-TTL
/// path even though no iat is set.
#[test]
#[should_panic(expected = "exceeding the fixture's max_ttl")]
fn mint_exceeding_max_ttl_without_iat_uses_now() {
    let idp = LocalIdpFixture::new("https://idp").with_max_ttl(Duration::seconds(60));
    let claims =
        MintClaims::new("alice", Utc::now() + Duration::hours(2)).with_audience("https://api");
    let _ = idp.mint(&claims);
}

/// `mint_jwt_svid` carries its own ttl arg; if it exceeds the
/// fixture's max_ttl, the policy still rejects.
#[test]
#[should_panic(expected = "exceeding the fixture's max_ttl")]
fn mint_jwt_svid_exceeding_max_ttl_panics() {
    let idp = LocalIdpFixture::new("https://idp").with_max_ttl(Duration::minutes(5));
    let _ = idp.mint_jwt_svid(
        "test.gnomes",
        "worker",
        "acme",
        "https://api",
        Duration::hours(1),
    );
}

#[tokio::test]
async fn mint_at_exact_max_ttl_boundary_succeeds() {
    let idp = LocalIdpFixture::new("https://idp").with_max_ttl(Duration::minutes(10));
    let now = Utc::now();
    let claims = MintClaims::new("alice", now + Duration::minutes(10))
        .with_audience("https://api")
        .with_issued_at(now);
    let token = idp.mint(&claims);
    let verifier = JwtVerifier::new(idp.jwks_handle()).with_audience("https://api");
    verifier
        .verify::<CustomClaims>(&token)
        .await
        .expect("boundary-exact mint must verify (<=, not <)");
}

#[tokio::test]
async fn max_ttl_survives_rotate_signing_key() {
    let idp = LocalIdpFixture::new("https://idp").with_max_ttl(Duration::minutes(5));
    let new_key = LocalIdpSigningKey::generate_rsa().with_key_id("rotated");
    let rotated = idp.rotate_signing_key(new_key);
    assert_eq!(rotated.max_ttl(), Some(Duration::minutes(5)));
}

#[tokio::test]
async fn max_ttl_survives_with_historical_signing_key() {
    let key = LocalIdpSigningKey::generate_rsa();
    let idp = LocalIdpFixture::new("https://idp")
        .with_max_ttl(Duration::minutes(5))
        .with_historical_signing_key(key);
    assert_eq!(idp.max_ttl(), Some(Duration::minutes(5)));
}

#[tokio::test]
async fn max_ttl_survives_with_key_id() {
    let idp = LocalIdpFixture::new("https://idp")
        .with_max_ttl(Duration::minutes(5))
        .with_key_id("custom");
    assert_eq!(idp.max_ttl(), Some(Duration::minutes(5)));
}

fn far_future() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2100-01-01T00:00:00Z")
        .expect("literal parses")
        .with_timezone(&Utc)
}

/// The cap is measured from the supplied instant: a five-minute token
/// anchored in 2100 is within a ten-minute cap, which the wall clock
/// would call seventy-odd years long.
#[test]
fn mint_at_measures_the_cap_from_the_given_instant() {
    let idp = LocalIdpFixture::new("https://idp").with_max_ttl(Duration::minutes(10));
    let now = far_future();
    let claims = MintClaims::new("alice", now + Duration::minutes(5)).with_audience("https://api");
    let _ = idp.mint_at(&claims, now);
}

#[test]
#[should_panic(expected = "exceeding the fixture's max_ttl")]
fn mint_at_rejects_a_lifetime_over_the_cap_from_the_given_instant() {
    let idp = LocalIdpFixture::new("https://idp").with_max_ttl(Duration::minutes(10));
    let now = far_future();
    let claims = MintClaims::new("alice", now + Duration::minutes(11)).with_audience("https://api");
    let _ = idp.mint_at(&claims, now);
}

/// `mint_jwt_svid_at` takes `iat`, `exp` and the cap from `now`.
#[tokio::test]
async fn mint_jwt_svid_at_uses_the_given_instant() {
    let idp = LocalIdpFixture::new("https://idp").with_max_ttl(Duration::minutes(10));
    let now = far_future();
    let token = idp.mint_jwt_svid_at(
        "test.gnomes",
        "worker",
        "acme",
        "https://api",
        Duration::minutes(5),
        now,
    );
    let clock = std::sync::Arc::new(crate::testing::MockClock::at(now));
    let verifier = JwtVerifier::new(idp.jwks_handle())
        .with_audience("https://api")
        .with_clock(clock);
    verifier
        .verify::<CustomClaims>(&token)
        .await
        .expect("token minted at the mock instant verifies at that instant");
    let payload = token.split('.').nth(1).expect("payload segment");
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, payload)
        .expect("payload decodes");
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("payload is JSON");
    assert_eq!(json["iat"], now.timestamp());
    assert_eq!(json["exp"], (now + Duration::minutes(5)).timestamp());
}
