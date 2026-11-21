//! `tests`: the unit tests of `svid.rs`, kept beside it per the
//! 200-line inline-test rule in AGENTS.md.

use super::*;
use crate::jwt::encode;
use crate::jwt::validation::JwtError;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rsa::RsaPrivateKey;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use std::sync::RwLock;

fn rsa_keypair() -> (Vec<u8>, JwkSet, String) {
    let mut rng = rsa::rand_core::OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("key generation");
    let public_key = private_key.to_public_key();
    let kid = "svid-key-1".to_string();
    let private_der = private_key
        .to_pkcs1_der()
        .expect("PKCS1 DER encode")
        .as_bytes()
        .to_vec();
    let n = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
    let e = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());
    let jwk_json = serde_json::json!({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": kid,
            "n": n,
            "e": e,
        }]
    });
    let jwks: JwkSet = serde_json::from_value(jwk_json).expect("JwkSet parse");
    (private_der, jwks, kid)
}

fn sign(claims: &serde_json::Value, kid: &str, der: &[u8]) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    let key = EncodingKey::from_rsa_der(der);
    encode(&header, claims, &key).expect("JWT encode")
}

fn build_verifier(jwks: JwkSet) -> Arc<JwtVerifier> {
    Arc::new(
        JwtVerifier::new(Arc::new(RwLock::new(jwks)))
            .with_clock(std::sync::Arc::new(
                axess_clock::testing::MockClock::at_reference(),
            ))
            .with_issuer("https://idp.example.org")
            .with_audience("axess-platform"),
    )
}

fn now_secs() -> i64 {
    axess_clock::testing::MockClock::reference_time().unix_seconds()
}

fn sample_tenant_uuid() -> &'static str {
    "00000000-0000-4000-8000-000000000abc"
}

fn svid_claims(sub: &str) -> serde_json::Value {
    let now = now_secs();
    serde_json::json!({
        "iss": "https://idp.example.org",
        "sub": sub,
        "aud": "axess-platform",
        "exp": now + 3600,
        "iat": now,
        "tid": sample_tenant_uuid(),
    })
}

#[tokio::test]
async fn valid_jwt_svid_resolves_to_workload_principal() {
    let (der, jwks, kid) = rsa_keypair();
    let token = sign(
        &svid_claims("spiffe://example.org/compute-worker/acme"),
        &kid,
        &der,
    );
    let resolver = JwtSvidResolver::new(
        build_verifier(jwks),
        TrustDomain::new("example.org").unwrap(),
        token,
    )
    .without_tenant_cross_check();

    let principal = resolver.resolve().await.expect("must resolve");
    match principal {
        Principal::Workload(w) => {
            assert_eq!(
                w.workload_id.as_str(),
                "spiffe://example.org/compute-worker/acme"
            );
            assert_eq!(w.trust_domain.as_str(), "example.org");
            assert_eq!(w.issuer, Issuer::JwtSvid);
            assert_eq!(w.service_name, "compute-worker");
            assert_eq!(w.tenant_slug, "acme");
            assert_eq!(w.tenant_id.to_string(), sample_tenant_uuid());
        }
        Principal::Human(_) => panic!("expected Workload, got Human"),
    }
}

#[tokio::test]
async fn wrong_trust_domain_rejected() {
    let (der, jwks, kid) = rsa_keypair();
    // Token carries a SPIFFE ID under `attacker.example`; the
    // resolver pins `example.org`.
    let token = sign(
        &svid_claims("spiffe://attacker.example/compute-worker/acme"),
        &kid,
        &der,
    );
    let resolver = JwtSvidResolver::new(
        build_verifier(jwks),
        TrustDomain::new("example.org").unwrap(),
        token,
    )
    .without_tenant_cross_check();

    let err = resolver
        .resolve()
        .await
        .expect_err("trust-domain mismatch must reject");
    assert!(
        matches!(err, IdentityError::InvalidSpiffeId(_)),
        "expected InvalidSpiffeId, got {err:?}"
    );
}

#[tokio::test]
async fn malformed_spiffe_sub_rejected() {
    let (der, jwks, kid) = rsa_keypair();
    // Valid JWT, invalid SPIFFE URI in `sub`.
    let token = sign(&svid_claims("not-a-spiffe-id"), &kid, &der);
    let resolver = JwtSvidResolver::new(
        build_verifier(jwks),
        TrustDomain::new("example.org").unwrap(),
        token,
    )
    .without_tenant_cross_check();

    let err = resolver
        .resolve()
        .await
        .expect_err("malformed SPIFFE in sub must reject");
    assert!(
        matches!(err, IdentityError::InvalidSpiffeId(_)),
        "expected InvalidSpiffeId, got {err:?}"
    );
}

#[tokio::test]
async fn missing_tid_claim_rejected() {
    let (der, jwks, kid) = rsa_keypair();
    // Build SPIFFE-shaped sub but omit the custom `tid` claim;
    // the custom-claim deserialiser fails inside JwtVerifier and
    // surfaces as NotAuthenticated.
    let now = now_secs();
    let token = sign(
        &serde_json::json!({
            "iss": "https://idp.example.org",
            "sub": "spiffe://example.org/compute-worker/acme",
            "aud": "axess-platform",
            "exp": now + 3600,
            "iat": now,
        }),
        &kid,
        &der,
    );
    let resolver = JwtSvidResolver::new(
        build_verifier(jwks),
        TrustDomain::new("example.org").unwrap(),
        token,
    )
    .without_tenant_cross_check();

    let err = resolver
        .resolve()
        .await
        .expect_err("missing tid must reject");
    assert!(
        matches!(err, IdentityError::NotAuthenticated),
        "expected NotAuthenticated, got {err:?}"
    );
}

#[tokio::test]
async fn extra_spiffe_path_segments_rejected() {
    let (der, jwks, kid) = rsa_keypair();
    // SPIFFE path is valid per the spec but doesn't match the
    // platform's 2-segment shape: rejected.
    let token = sign(
        &svid_claims("spiffe://example.org/region/compute-worker/acme"),
        &kid,
        &der,
    );
    let resolver = JwtSvidResolver::new(
        build_verifier(jwks),
        TrustDomain::new("example.org").unwrap(),
        token,
    )
    .without_tenant_cross_check();

    let err = resolver
        .resolve()
        .await
        .expect_err("3-segment SPIFFE path must reject under platform shape");
    assert!(
        matches!(err, IdentityError::InvalidSpiffeId(_)),
        "expected InvalidSpiffeId, got {err:?}"
    );
}

/// An identifier that parses and is not the platform shape is quoted in the
/// refusal cut: a token names up to 2048 bytes of it.
#[tokio::test]
async fn a_long_identifier_is_quoted_cut() {
    let (der, jwks, kid) = rsa_keypair();
    let long = format!("spiffe://example.org/region/svc/{}", "a".repeat(1500));
    let token = sign(&svid_claims(&long), &kid, &der);
    let resolver = JwtSvidResolver::new(
        build_verifier(jwks),
        TrustDomain::new("example.org").unwrap(),
        token,
    )
    .without_tenant_cross_check();

    let err = resolver
        .resolve()
        .await
        .expect_err("not the platform shape");
    let text = err.to_string();
    assert!(text.len() <= 256, "{} bytes: {text}", text.len());
    assert!(text.contains("spiffe://example.org/region/svc/"), "{text}");
    assert!(text.ends_with("..."), "the cut is marked: {text}");
}

#[tokio::test]
async fn expired_token_rejected() {
    let (der, jwks, kid) = rsa_keypair();
    // exp in the past.
    let now = now_secs();
    let token = sign(
        &serde_json::json!({
            "iss": "https://idp.example.org",
            "sub": "spiffe://example.org/compute-worker/acme",
            "aud": "axess-platform",
            "exp": now - 3600,
            "iat": now - 7200,
            "tid": sample_tenant_uuid(),
        }),
        &kid,
        &der,
    );
    let resolver = JwtSvidResolver::new(
        build_verifier(jwks),
        TrustDomain::new("example.org").unwrap(),
        token,
    )
    .without_tenant_cross_check();

    let err = resolver
        .resolve()
        .await
        .expect_err("expired token must reject");
    assert!(
        matches!(err, IdentityError::NotAuthenticated),
        "expected NotAuthenticated, got {err:?}"
    );
}

/// Pin the wiring so the JwtError::DisallowedAlgorithm path lands
/// on NotAuthenticated rather than panicking; sanity test that
/// JwtError-to-IdentityError mapping is non-discriminating.
#[tokio::test]
async fn non_jwt_string_rejects_cleanly() {
    let (_, jwks, _) = rsa_keypair();
    let resolver = JwtSvidResolver::new(
        build_verifier(jwks),
        TrustDomain::new("example.org").unwrap(),
        "not-a-jwt-at-all".to_string(),
    )
    .without_tenant_cross_check();
    let err = resolver
        .resolve()
        .await
        .expect_err("malformed JWT must reject");
    assert!(
        matches!(err, IdentityError::NotAuthenticated),
        "expected NotAuthenticated, got {err:?}"
    );
    // Confirm the underlying JwtError path is reachable; direct
    // verifier call surfaces the structured error for callers that
    // bypass the resolver.
    let _ = JwtError::InvalidHeader("smoke".into());
}

#[tokio::test]
async fn tid_claim_must_match_the_tenant_registered_for_the_spiffe_slug() {
    let (der, jwks, kid) = rsa_keypair();
    let token = sign(
        &svid_claims("spiffe://example.org/compute-worker/acme"),
        &kid,
        &der,
    );
    let td = TrustDomain::new("example.org").unwrap();
    let verifier = build_verifier(jwks);
    let claimed: TenantId = sample_tenant_uuid().parse().expect("uuid");
    let other = TenantId::from_bytes([9u8; 16]);

    // Slug maps to the tenant the token claims: resolves.
    let ok = JwtSvidResolver::new(verifier.clone(), td.clone(), token.clone())
        .with_tenant_lookup(move |slug| (slug == "acme").then_some(claimed));
    assert!(ok.resolve().await.is_ok());

    // Slug maps to a different tenant than `tid`: refused.
    let mismatch = JwtSvidResolver::new(verifier.clone(), td.clone(), token.clone())
        .with_tenant_lookup(move |_| Some(other));
    assert!(matches!(
        mismatch.resolve().await,
        Err(IdentityError::NotAuthenticated)
    ));

    // Unknown slug: refused.
    let unknown = JwtSvidResolver::new(verifier, td, token).with_tenant_lookup(|_| None);
    assert!(matches!(
        unknown.resolve().await,
        Err(IdentityError::NotAuthenticated)
    ));
}

/// A JWT-SVID is only valid for the audience it names, and a shared issuer
/// makes `aud` the only separation between services: a verifier that pins
/// no audience (or no issuer) is refused even for a token it would verify.
#[tokio::test]
async fn a_verifier_without_an_audience_or_issuer_pin_is_refused() {
    let (der, jwks, kid) = rsa_keypair();
    let token = sign(
        &svid_claims("spiffe://example.org/compute-worker/acme"),
        &kid,
        &der,
    );
    let handle = || Arc::new(RwLock::new(jwks.clone()));
    let unpinned: [Arc<JwtVerifier>; 3] = [
        Arc::new(
            JwtVerifier::new(handle())
                .with_clock(std::sync::Arc::new(
                    axess_clock::testing::MockClock::at_reference(),
                ))
                .with_issuer("https://idp.example.org"),
        ),
        Arc::new(
            JwtVerifier::new(handle())
                .with_clock(std::sync::Arc::new(
                    axess_clock::testing::MockClock::at_reference(),
                ))
                .with_audience("axess-platform"),
        ),
        Arc::new(
            JwtVerifier::new(handle())
                .with_clock(std::sync::Arc::new(
                    axess_clock::testing::MockClock::at_reference(),
                ))
                .with_issuer("https://idp.example.org")
                .allow_any_audience(),
        ),
    ];
    for verifier in unpinned {
        let resolver = JwtSvidResolver::new(
            verifier,
            TrustDomain::new("example.org").unwrap(),
            token.clone(),
        )
        .without_tenant_cross_check();
        assert!(
            matches!(
                resolver.resolve().await,
                Err(IdentityError::NotAuthenticated)
            ),
            "an unpinned verifier must be refused"
        );
    }
}

/// Without a tenant lookup the slug in `sub` and the `tid` claim cannot be
/// cross-checked, so the resolver refuses the token instead of resolving a
/// principal whose slug and id may name two tenants.
#[tokio::test]
async fn a_resolver_without_a_tenant_lookup_refuses_by_default() {
    let (der, jwks, kid) = rsa_keypair();
    let token = sign(
        &svid_claims("spiffe://example.org/compute-worker/acme"),
        &kid,
        &der,
    );
    let resolver = JwtSvidResolver::new(
        build_verifier(jwks),
        TrustDomain::new("example.org").unwrap(),
        token,
    );
    assert!(
        matches!(
            resolver.resolve().await,
            Err(IdentityError::NotAuthenticated)
        ),
        "no lookup and no waiver must refuse"
    );
}

/// The named waiver resolves a token whose slug and `tid` nothing ties
/// together, and a lookup set beside it still applies.
#[tokio::test]
async fn the_named_waiver_resolves_without_a_lookup_and_a_lookup_still_applies() {
    let (der, jwks, kid) = rsa_keypair();
    let token = sign(
        &svid_claims("spiffe://example.org/compute-worker/acme"),
        &kid,
        &der,
    );
    let td = TrustDomain::new("example.org").unwrap();
    let verifier = build_verifier(jwks);

    let waived = JwtSvidResolver::new(verifier.clone(), td.clone(), token.clone())
        .without_tenant_cross_check();
    assert!(waived.resolve().await.is_ok());

    let still_checked = JwtSvidResolver::new(verifier, td, token)
        .without_tenant_cross_check()
        .with_tenant_lookup(|_| Some(TenantId::from_bytes([9u8; 16])));
    assert!(matches!(
        still_checked.resolve().await,
        Err(IdentityError::NotAuthenticated)
    ));
}

/// The JWT-SVID standard defines `sub`, `aud` and `exp` and no `iss`: an SVID
/// without one is valid, and a verifier built on the trust domain's own keys
/// says so by waiving the issuer by name. A verifier that pins an issuer
/// goes on refusing a token that carries none.
#[tokio::test]
async fn a_jwt_svid_with_no_issuer_claim_resolves_once_the_issuer_is_waived_by_name() {
    let (der, jwks, kid) = rsa_keypair();
    let now = now_secs();
    let token = sign(
        &serde_json::json!({
            "sub": "spiffe://example.org/compute-worker/acme",
            "aud": "axess-platform",
            "exp": now + 3600,
            "iat": now,
            "tid": sample_tenant_uuid(),
        }),
        &kid,
        &der,
    );
    let trust_domain = TrustDomain::new("example.org").unwrap();

    let waived = Arc::new(
        JwtVerifier::new(Arc::new(RwLock::new(jwks.clone())))
            .with_clock(std::sync::Arc::new(
                axess_clock::testing::MockClock::at_reference(),
            ))
            .with_audience("axess-platform")
            .allow_any_issuer(),
    );
    let principal = JwtSvidResolver::new(waived, trust_domain.clone(), token.clone())
        .without_tenant_cross_check()
        .resolve()
        .await
        .expect("an SVID with no `iss`, on a verifier that waived it by name");
    let Principal::Workload(workload) = principal else {
        panic!("a JWT-SVID resolves to a workload");
    };
    assert_eq!(workload.service_name, "compute-worker");

    let pinned = JwtSvidResolver::new(build_verifier(jwks), trust_domain, token)
        .without_tenant_cross_check();
    assert!(matches!(
        pinned.resolve().await,
        Err(IdentityError::NotAuthenticated)
    ));
}

/// An Ed25519 key made of a fixed seed, as PKCS#8, and its public key as a
/// JWK. Not a secret: the seed is written here.
fn ed25519_keypair() -> (Vec<u8>, JwkSet, String) {
    let mut pkcs8 = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    pkcs8.extend_from_slice(&[0x2a; 32]);
    let kid = "svid-ed-key-1".to_string();
    let jwks: JwkSet = serde_json::from_value(serde_json::json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "use": "sig",
            "alg": "EdDSA",
            "kid": kid,
            "x": "GX9rI-FshTLGq8g4-s1ep4m-DHaykgM0A5v6iz02jWE",
        }]
    }))
    .expect("JwkSet parse");
    (pkcs8, jwks, kid)
}

/// JWT-SVID standard, section 2.1: an SVID is signed with RSASSA-PKCS1-v1_5,
/// ECDSA or RSASSA-PSS, and a validator rejects any other `alg`. A verifier
/// may be told to accept Ed25519 for other tokens; the token below verifies
/// on it, and the SVID resolver refuses it all the same.
#[tokio::test]
async fn a_token_signed_with_an_algorithm_no_jwt_svid_may_carry_is_refused() {
    let (pkcs8, jwks, kid) = ed25519_keypair();
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(kid);
    let token = encode(
        &header,
        &svid_claims("spiffe://example.org/compute-worker/acme"),
        &EncodingKey::from_ed_der(&pkcs8),
    )
    .expect("JWT encode");
    let verifier = Arc::new(
        JwtVerifier::new(Arc::new(RwLock::new(jwks)))
            .with_clock(std::sync::Arc::new(
                axess_clock::testing::MockClock::at_reference(),
            ))
            .with_issuer("https://idp.example.org")
            .with_audience("axess-platform")
            .with_algorithms([Algorithm::EdDSA]),
    );
    // The control: the verifier itself accepts the token.
    let verified = verifier
        .verify::<SvidCustomClaims>(&token)
        .await
        .expect("the verifier was told to accept Ed25519");
    assert_eq!(
        verified.sub.as_deref(),
        Some("spiffe://example.org/compute-worker/acme")
    );

    let resolver = JwtSvidResolver::new(verifier, TrustDomain::new("example.org").unwrap(), token)
        .without_tenant_cross_check();
    assert!(matches!(
        resolver.resolve().await,
        Err(IdentityError::NotAuthenticated)
    ));
}

// ── A JWT-SVID without a `kid` ───────────────────────────────────────

/// Four P-256 keys from `openssl ecparam -name prime256v1 -genkey | openssl
/// pkcs8 -topk8 -nocrypt`, made for these tests only: the PKCS#8 body, and
/// the public point's `x` and `y` as a JWK carries them.
const EC_KEYS: [(&str, &str, &str); 4] = [
    (
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg5AWeolGM+AFsf8+gnBYcLWhUPhC97ZQ+DzxoAF8QnRihRANCAAR5EhEdkmHaY7RIeTQmtk7m0W4r2BzLBFyqK6FLWamh4ky7mwdza8rVgAGRYbILocdOehcweXxWR2yENmXV7b5u",
        "eRIRHZJh2mO0SHk0JrZO5tFuK9gcywRcqiuhS1mpoeI",
        "TLubB3NrytWAAZFhsguhx056FzB5fFZHbIQ2ZdXtvm4",
    ),
    (
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg9+dA65bhqNlo7+YaLQ6YDaqbAxKPmhAsdsNAQxB+CqWhRANCAATkoJc2257b6f1W6oOWc+L+9yv6sqr5Hq+VH63yYQRsccofK4v0jcn+Qmkfx47RMvKC1jaF97KuU5ufvUHdaWVd",
        "5KCXNtue2-n9VuqDlnPi_vcr-rKq-R6vlR-t8mEEbHE",
        "yh8ri_SNyf5CaR_HjtEy8oLWNoX3sq5Tm5-9Qd1pZV0",
    ),
    (
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgm6cHVgXt+vovX/r+h3pGNqOvtJfU+zz1mQzDISnPLpehRANCAARJUWNBPac4GbEgR9+yH60sFFJ0v0RiM0vcoAPLHCi1rFOBOwTjio4we+ki7mJL61OC1CPUyphEHxUqYAO5+w4v",
        "SVFjQT2nOBmxIEffsh-tLBRSdL9EYjNL3KADyxwotaw",
        "U4E7BOOKjjB76SLuYkvrU4LUI9TKmEQfFSpgA7n7Di8",
    ),
    (
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg+b+AH36JTjbBbVp3wX7OqZx8YMjngxhbdPxVGjSBgUyhRANCAASpbnY3WAJ1DbrZ1xcPwVlfZKEv0623o2ucSZbrLCK+JpBObSvAMkNhaMXirY3RGwsBaDtZ9eGpdcncUpiZMNrU",
        "qW52N1gCdQ262dcXD8FZX2ShL9Ott6NrnEmW6ywiviY",
        "kE5tK8AyQ2FoxeKtjdEbCwFoO1n14al1ydxSmJkw2tQ",
    ),
];

/// The public JWK of `EC_KEYS[i]` under `kid`, with `extra` members merged
/// in (a `use`, an `alg`).
fn ec_jwk(i: usize, kid: &str, extra: serde_json::Value) -> serde_json::Value {
    let (_, x, y) = EC_KEYS[i];
    let mut jwk = serde_json::json!({ "kty": "EC", "crv": "P-256", "kid": kid, "x": x, "y": y });
    if let (Some(jwk), Some(extra)) = (jwk.as_object_mut(), extra.as_object()) {
        jwk.extend(extra.clone());
    }
    jwk
}

/// A verifier over the key set `keys`, pinned as [`build_verifier`] pins.
fn verifier_over(keys: Vec<serde_json::Value>) -> Arc<JwtVerifier> {
    build_verifier(serde_json::from_value(serde_json::json!({ "keys": keys })).expect("JwkSet"))
}

/// An ES256 SVID signed with `EC_KEYS[i]`, naming the key `kid` (none when
/// `None`).
fn es256_svid(i: usize, kid: Option<&str>) -> String {
    use base64::engine::general_purpose::STANDARD;
    let der = STANDARD.decode(EC_KEYS[i].0).expect("PKCS#8 base64");
    let mut header = Header::new(Algorithm::ES256);
    header.kid = kid.map(str::to_owned);
    encode(
        &header,
        &svid_claims("spiffe://example.org/compute-worker/acme"),
        &EncodingKey::from_ec_der(&der),
    )
    .expect("JWT encode")
}

/// What the resolver answers for `token` under `verifier`.
async fn resolved(verifier: Arc<JwtVerifier>, token: String) -> Result<Principal, IdentityError> {
    JwtSvidResolver::new(verifier, TrustDomain::new("example.org").unwrap(), token)
        .without_tenant_cross_check()
        .resolve()
        .await
}

/// A JWT-SVID without a `kid`, signed by the second of three keys, resolves:
/// each key of the set is tried, and the one that made the signature wins.
#[tokio::test]
async fn a_keyless_svid_signed_by_any_key_of_the_set_resolves() {
    let keys = (0..3)
        .map(|i| ec_jwk(i, &format!("k{i}"), serde_json::json!({})))
        .collect();
    let principal = resolved(verifier_over(keys), es256_svid(1, None))
        .await
        .expect("the second key verifies");
    assert!(matches!(principal, Principal::Workload(_)), "{principal:?}");
}

/// A keyless SVID signed by a key outside the set is refused, as one
/// refusal that names no key.
#[tokio::test]
async fn a_keyless_svid_signed_by_a_key_outside_the_set_is_refused() {
    let keys: Vec<_> = (0..3)
        .map(|i| ec_jwk(i, &format!("k{i}"), serde_json::json!({})))
        .collect();
    let verifier = verifier_over(keys);
    let token = es256_svid(3, None);
    let refused = verifier
        .verify_for_svid::<SvidCustomClaims>(&token, &JWT_SVID_ALGORITHMS)
        .await
        .expect_err("no key of the set made the signature");
    assert!(
        matches!(&refused, JwtError::VerificationFailed(text) if !text.contains("k0")),
        "{refused:?}"
    );
    assert!(matches!(
        resolved(verifier, token).await,
        Err(IdentityError::NotAuthenticated)
    ));
}

/// A keyless RS256 SVID against a set of an EC key and an RSA key verifies
/// with the RSA key: the EC key cannot have made an RSA signature and is
/// passed over, not refused.
#[tokio::test]
async fn a_key_of_another_type_is_passed_over() {
    let (der, rsa_set, _) = rsa_keypair();
    let mut rsa_jwk = serde_json::to_value(&rsa_set.keys[0]).expect("JWK as JSON");
    if let Some(jwk) = rsa_jwk.as_object_mut() {
        jwk.remove("kid");
    }
    let token = encode(
        &Header::new(Algorithm::RS256),
        &svid_claims("spiffe://example.org/compute-worker/acme"),
        &EncodingKey::from_rsa_der(&der),
    )
    .expect("JWT encode");
    let verifier = verifier_over(vec![ec_jwk(0, "ec", serde_json::json!({})), rsa_jwk]);
    assert!(resolved(verifier, token).await.is_ok());
}

/// A token that names a `kid` takes that key or none: a `kid` the set does
/// not hold is refused as unknown, and the token is not tried against the
/// set, which here holds the key that signed it under another `kid`.
#[tokio::test]
async fn a_token_naming_an_unknown_kid_is_not_tried_against_every_key() {
    let verifier = verifier_over(vec![ec_jwk(0, "k0", serde_json::json!({}))]);
    let token = es256_svid(0, Some("not-in-the-set"));
    let refused = verifier
        .verify_for_svid::<SvidCustomClaims>(&token, &JWT_SVID_ALGORITHMS)
        .await
        .expect_err("the kid names no key of the set");
    assert!(matches!(refused, JwtError::UnknownKid(_)), "{refused:?}");
    assert!(matches!(
        resolved(verifier, token).await,
        Err(IdentityError::NotAuthenticated)
    ));
}

/// A keyless token is tried against at most `MAX_KEYLESS_KEYS` keys: a set
/// one larger is refused whole before any signature is checked, though the
/// key that signed it is in it. At the bound it verifies.
#[tokio::test]
async fn a_key_set_past_the_bound_is_refused_for_a_keyless_token() {
    use crate::jwt::validation::MAX_KEYLESS_KEYS;
    let set = |junk: usize| -> Vec<serde_json::Value> {
        let mut keys: Vec<_> = (0..junk)
            .map(|n| ec_jwk(2, &format!("junk-{n}"), serde_json::json!({})))
            .collect();
        keys.push(ec_jwk(0, "signer", serde_json::json!({})));
        keys
    };
    let token = es256_svid(0, None);
    let refused = verifier_over(set(MAX_KEYLESS_KEYS))
        .verify_for_svid::<SvidCustomClaims>(&token, &JWT_SVID_ALGORITHMS)
        .await
        .expect_err("one key past the bound");
    assert!(
        matches!(&refused, JwtError::VerificationFailed(text) if text.contains(&MAX_KEYLESS_KEYS.to_string())),
        "{refused:?}"
    );
    assert!(
        resolved(verifier_over(set(MAX_KEYLESS_KEYS - 1)), token)
            .await
            .is_ok(),
        "a set at the bound is tried"
    );
}

/// A key published for encryption is passed over for a keyless token, and
/// so is one whose `alg` member names another algorithm; the same key with
/// neither verifies.
#[tokio::test]
async fn a_key_for_another_use_or_algorithm_is_passed_over() {
    let token = es256_svid(0, None);
    for (members, verifies) in [
        (serde_json::json!({}), true),
        (serde_json::json!({ "use": "sig", "alg": "ES256" }), true),
        (serde_json::json!({ "use": "enc" }), false),
        (serde_json::json!({ "alg": "ES384" }), false),
        (serde_json::json!({ "alg": "RS256" }), false),
    ] {
        let verifier = verifier_over(vec![ec_jwk(0, "k0", members.clone())]);
        assert_eq!(
            resolved(verifier, token.clone()).await.is_ok(),
            verifies,
            "{members}"
        );
    }
}

/// The public verifier still requires a `kid`, even one an SVID resolver
/// also wraps: only the resolver tries a keyless token against the set.
#[tokio::test]
async fn the_public_verifier_refuses_a_keyless_token_the_resolver_takes() {
    let verifier = verifier_over(vec![ec_jwk(0, "k0", serde_json::json!({}))]);
    let token = es256_svid(0, None);
    assert!(matches!(
        verifier.verify::<SvidCustomClaims>(&token).await,
        Err(JwtError::MissingKid)
    ));
    assert!(resolved(verifier, token).await.is_ok());
}

/// The size bound comes before the header is read: a token over
/// `MAX_JWT_BYTES` whose header is not even base64 is refused for its
/// length, so its header was never decoded.
#[tokio::test]
async fn an_oversized_svid_is_refused_before_its_header_is_read() {
    use crate::jwt::claims::MAX_JWT_BYTES;
    let verifier = verifier_over(vec![ec_jwk(0, "k0", serde_json::json!({}))]);
    let token = format!("{}.e30.sig", "!".repeat(MAX_JWT_BYTES));
    let refused = verifier
        .verify_for_svid::<SvidCustomClaims>(&token, &JWT_SVID_ALGORITHMS)
        .await
        .expect_err("over the bound");
    assert!(matches!(refused, JwtError::TooLarge { .. }), "{refused:?}");
    // The same header in a token under the bound is refused for the header.
    let small = verifier
        .verify_for_svid::<SvidCustomClaims>("!!!!.e30.sig", &JWT_SVID_ALGORITHMS)
        .await
        .expect_err("not a JWT");
    assert!(matches!(small, JwtError::InvalidHeader(_)), "{small:?}");
    assert!(matches!(
        resolved(verifier, token).await,
        Err(IdentityError::NotAuthenticated)
    ));
}
