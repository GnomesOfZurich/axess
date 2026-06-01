use super::*;
use axess_factors::jwt::verifier::JwtVerifier;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct CustomClaims {}

// ── Multi-key JWKS / rotation tests ──────────────────────────────────

/// `with_historical_signing_key` adds a key's public JWK to the JWKS
/// without using it for new mints. Verifier sees both kids and
/// dispatches per token's header.
#[tokio::test]
async fn historical_key_still_verifies_under_combined_jwks() {
    let now = Utc::now();
    let k_old = LocalIdpSigningKey::generate_rsa().with_key_id("k-old");
    let k_new = LocalIdpSigningKey::generate_rsa().with_key_id("k-new");

    // Snapshot fixture under the old key; mint a token.
    let old_idp = LocalIdpFixture::with_signing_key("https://idp", k_old.clone());
    let token_under_old = old_idp.mint(
        &MintClaims::new("alice", now + Duration::hours(1))
            .with_audience("https://api")
            .with_issued_at(now),
    );

    // Build a rotated fixture: current = k_new, historical = k_old.
    let rotated_idp =
        LocalIdpFixture::with_signing_key("https://idp", k_new).with_historical_signing_key(k_old);
    let token_under_new = rotated_idp.mint(
        &MintClaims::new("alice", now + Duration::hours(1))
            .with_audience("https://api")
            .with_issued_at(now),
    );

    // Confirm header kids reflect their actual signing key.
    assert_eq!(
        jsonwebtoken::decode_header(&token_under_old).unwrap().kid,
        Some("k-old".to_string()),
    );
    assert_eq!(
        jsonwebtoken::decode_header(&token_under_new).unwrap().kid,
        Some("k-new".to_string()),
    );

    // JWKS carries both keys.
    assert_eq!(rotated_idp.jwks().keys.len(), 2);

    // Verifier dispatches by header kid; both tokens succeed.
    let verifier = JwtVerifier::new(rotated_idp.jwks_handle()).with_audience("https://api");
    verifier
        .verify::<CustomClaims>(&token_under_old)
        .await
        .expect("historical-kid token must verify against multi-key JWKS");
    verifier
        .verify::<CustomClaims>(&token_under_new)
        .await
        .expect("current-kid token must verify against multi-key JWKS");
}

/// `rotate_signing_key` is the convenience over the manual
/// `with_historical_signing_key(old) + with_signing_key(new)` shape:
/// after rotation, the OLD current is in historical, and new mints
/// use NEW.
#[tokio::test]
async fn rotate_signing_key_moves_previous_current_to_historical() {
    let now = Utc::now();
    let k1 = LocalIdpSigningKey::generate_rsa().with_key_id("k1");
    let k2 = LocalIdpSigningKey::generate_rsa().with_key_id("k2");

    let idp_v1 = LocalIdpFixture::with_signing_key("https://idp", k1);
    let token_v1 = idp_v1.mint(
        &MintClaims::new("alice", now + Duration::hours(1))
            .with_audience("https://api")
            .with_issued_at(now),
    );

    let idp_v2 = idp_v1.rotate_signing_key(k2);
    assert_eq!(idp_v2.key_id(), "k2");
    assert_eq!(idp_v2.jwks().keys.len(), 2);

    let token_v2 = idp_v2.mint(
        &MintClaims::new("alice", now + Duration::hours(1))
            .with_audience("https://api")
            .with_issued_at(now),
    );
    assert_eq!(
        jsonwebtoken::decode_header(&token_v2).unwrap().kid,
        Some("k2".to_string()),
    );

    let verifier = JwtVerifier::new(idp_v2.jwks_handle()).with_audience("https://api");
    verifier
        .verify::<CustomClaims>(&token_v1)
        .await
        .expect("token from before rotation must still verify");
    verifier
        .verify::<CustomClaims>(&token_v2)
        .await
        .expect("token from after rotation must verify");
}

/// Repeated rotation pushes multiple keys onto the historical list,
/// all of which remain verifiable.
#[tokio::test]
async fn multiple_rotations_accumulate_historical_keys() {
    let now = Utc::now();
    let k1 = LocalIdpSigningKey::generate_rsa().with_key_id("k1");
    let k2 = LocalIdpSigningKey::generate_rsa().with_key_id("k2");
    let k3 = LocalIdpSigningKey::generate_rsa().with_key_id("k3");

    let idp = LocalIdpFixture::with_signing_key("https://idp", k1);
    let t1 = idp.mint(
        &MintClaims::new("alice", now + Duration::hours(1))
            .with_audience("https://api")
            .with_issued_at(now),
    );

    let idp = idp.rotate_signing_key(k2);
    let t2 = idp.mint(
        &MintClaims::new("alice", now + Duration::hours(1))
            .with_audience("https://api")
            .with_issued_at(now),
    );

    let idp = idp.rotate_signing_key(k3);
    let t3 = idp.mint(
        &MintClaims::new("alice", now + Duration::hours(1))
            .with_audience("https://api")
            .with_issued_at(now),
    );

    assert_eq!(
        idp.jwks().keys.len(),
        3,
        "three keys: k3 current, k1+k2 historical"
    );
    let verifier = JwtVerifier::new(idp.jwks_handle()).with_audience("https://api");
    for (label, token) in [("t1", &t1), ("t2", &t2), ("t3", &t3)] {
        verifier
            .verify::<CustomClaims>(token)
            .await
            .unwrap_or_else(|e| panic!("{label} must verify after two rotations: {e:?}"));
    }
}

/// `with_extra_public_jwk` adds an arbitrary JWK to the JWKS without
/// registering signing material. Models mixing this fixture's tokens
/// with another IdP's tokens through one `JwtVerifier`.
#[tokio::test]
async fn extra_public_jwk_appears_in_jwks_but_not_used_for_signing() {
    let now = Utc::now();
    let foreign_key = LocalIdpSigningKey::generate_rsa().with_key_id("foreign");
    let foreign_jwk = foreign_key.jwk().clone();
    // Construct a token from the foreign IdP (separate fixture, same
    // protocol shape).
    let foreign_idp = LocalIdpFixture::with_signing_key("https://foreign-idp", foreign_key);
    let foreign_token = foreign_idp.mint(
        &MintClaims::new("bob", now + Duration::hours(1))
            .with_audience("https://api")
            .with_issued_at(now),
    );

    let our_idp = LocalIdpFixture::new("https://our-idp").with_extra_public_jwk(foreign_jwk);
    assert_eq!(our_idp.jwks().keys.len(), 2);

    // A verifier configured with our combined JWKS accepts both the
    // foreign-issued token and our own.
    let our_token = our_idp.mint(
        &MintClaims::new("alice", now + Duration::hours(1))
            .with_audience("https://api")
            .with_issued_at(now),
    );
    let verifier = JwtVerifier::new(our_idp.jwks_handle()).with_audience("https://api");
    verifier
        .verify::<CustomClaims>(&our_token)
        .await
        .expect("our token must verify");
    verifier
        .verify::<CustomClaims>(&foreign_token)
        .await
        .expect("foreign-IdP token must verify against extra JWK");
}

/// `with_key_id` after rotation: the current key's kid is renamed, but
/// historical + extra entries survive intact.
#[tokio::test]
async fn with_key_id_preserves_historical_keys_and_extra_jwks() {
    let now = Utc::now();
    let k_old = LocalIdpSigningKey::generate_rsa().with_key_id("old");
    let foreign_jwk = LocalIdpSigningKey::generate_rsa()
        .with_key_id("foreign")
        .jwk()
        .clone();

    let idp = LocalIdpFixture::new("https://idp")
        .with_historical_signing_key(k_old)
        .with_extra_public_jwk(foreign_jwk)
        .with_key_id("renamed-current");

    assert_eq!(idp.key_id(), "renamed-current");
    assert_eq!(idp.jwks().keys.len(), 3, "current + historical + extra");
    let kids: Vec<&str> = idp
        .jwks()
        .keys
        .iter()
        .filter_map(|k| k.common.key_id.as_deref())
        .collect();
    assert!(kids.contains(&"renamed-current"));
    assert!(kids.contains(&"old"));
    assert!(kids.contains(&"foreign"));

    // Tokens still mint under the renamed current.
    let token = idp.mint(
        &MintClaims::new("alice", now + Duration::hours(1))
            .with_audience("https://api")
            .with_issued_at(now),
    );
    assert_eq!(
        jsonwebtoken::decode_header(&token).unwrap().kid,
        Some("renamed-current".to_string()),
    );
}
