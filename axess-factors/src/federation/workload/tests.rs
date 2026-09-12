//! `tests`: extracted from `workload.rs` per the
//! 200-LoC inline-test rule in AGENTS.md.

use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rsa::RsaPrivateKey;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use serde::Deserialize;
use std::sync::RwLock;

/// Custom-claim shape emulating an Okta-style token: `azp` and
/// `service` carry the identity.
#[derive(Debug, Deserialize)]
struct OktaStyleClaims {
    azp: String,
    service: String,
    organization: String,
}

fn sample_tenant() -> TenantId {
    TenantId::from_bytes([13u8; 16])
}

fn rsa_keypair() -> (Vec<u8>, JwkSet, String) {
    let mut rng = rsa::rand_core::OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("key generation");
    let public_key = private_key.to_public_key();
    let kid = "oauth-rs-1".to_string();
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
            .with_issuer("https://gnomes.okta.com")
            .with_audience("axess-platform"),
    )
}

fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

fn okta_claims() -> serde_json::Value {
    let now = now_secs();
    serde_json::json!({
        "iss": "https://gnomes.okta.com",
        "sub": "okta-user-id-1",
        "aud": "axess-platform",
        "exp": now + 3600,
        "iat": now,
        "azp": "feed-worker",
        "service": "feed-worker",
        "organization": "ekekrantz",
    })
}

fn okta_mapper(
    trust_domain: TrustDomain,
) -> impl Fn(&VerifiedClaims<OktaStyleClaims>) -> Result<WorkloadMapping, IdentityError> {
    move |claims: &VerifiedClaims<OktaStyleClaims>| -> Result<WorkloadMapping, IdentityError> {
        let service = claims.custom.service.clone();
        let tenant_slug = claims.custom.organization.clone();
        let workload_id = WorkloadId::build(&trust_domain, &service, &tenant_slug)?;
        let mut attributes = BTreeMap::new();
        attributes.insert(
            "azp".to_string(),
            serde_json::Value::String(claims.custom.azp.clone()),
        );
        Ok(WorkloadMapping {
            workload_id,
            service_name: service,
            tenant_slug,
            attributes,
        })
    }
}

#[tokio::test]
async fn valid_token_resolves_via_custom_mapper() {
    let (der, jwks, kid) = rsa_keypair();
    let token = sign(&okta_claims(), &kid, &der);
    let trust = TrustDomain::new("okta.gnomes.local").unwrap();

    let resolver = WorkloadResolver::new(
        build_verifier(jwks),
        trust.clone(),
        sample_tenant(),
        Issuer::OAuth,
        token,
        okta_mapper(trust.clone()),
    );

    let principal = resolver.resolve().await.expect("must resolve");
    match principal {
        Principal::Workload(w) => {
            assert_eq!(
                w.workload_id.as_str(),
                "spiffe://okta.gnomes.local/feed-worker/ekekrantz"
            );
            assert_eq!(w.trust_domain, trust);
            assert_eq!(w.issuer, Issuer::OAuth);
            assert_eq!(w.tenant_id, sample_tenant());
            assert_eq!(w.service_name, "feed-worker");
            assert_eq!(w.tenant_slug, "ekekrantz");
            assert_eq!(
                w.attributes.get("azp"),
                Some(&serde_json::json!("feed-worker"))
            );
        }
        Principal::Human(_) => panic!("expected Workload, got Human"),
    }
}

#[tokio::test]
async fn wrong_iss_rejected_by_verifier() {
    let (der, jwks, kid) = rsa_keypair();
    let now = now_secs();
    // Wrong issuer; verifier rejects before mapper runs.
    let token = sign(
        &serde_json::json!({
            "iss": "https://attacker.example",
            "sub": "u1",
            "aud": "axess-platform",
            "exp": now + 3600,
            "iat": now,
            "azp": "feed-worker",
            "service": "feed-worker",
            "organization": "ekekrantz",
        }),
        &kid,
        &der,
    );
    let trust = TrustDomain::new("okta.gnomes.local").unwrap();
    let resolver = WorkloadResolver::new(
        build_verifier(jwks),
        trust.clone(),
        sample_tenant(),
        Issuer::OAuth,
        token,
        okta_mapper(trust),
    );
    let err = resolver.resolve().await.expect_err("wrong iss must reject");
    assert!(
        matches!(err, IdentityError::NotAuthenticated),
        "expected NotAuthenticated, got {err:?}"
    );
}

#[tokio::test]
async fn trust_domain_mismatch_rejected() {
    let (der, jwks, kid) = rsa_keypair();
    let token = sign(&okta_claims(), &kid, &der);
    // Resolver pins `okta.gnomes.local`; mapper synthesises
    // workload_id under a different domain.
    let resolver_trust = TrustDomain::new("okta.gnomes.local").unwrap();
    let attacker_trust = TrustDomain::new("attacker.example").unwrap();

    let resolver = WorkloadResolver::new(
        build_verifier(jwks),
        resolver_trust,
        sample_tenant(),
        Issuer::OAuth,
        token,
        okta_mapper(attacker_trust),
    );
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
async fn claim_mapper_error_propagated() {
    let (der, jwks, kid) = rsa_keypair();
    let token = sign(&okta_claims(), &kid, &der);
    let trust = TrustDomain::new("okta.gnomes.local").unwrap();

    // Mapper rejects every token unconditionally; simulates a
    // mapping precondition failure (missing required scope, etc.).
    let resolver = WorkloadResolver::new(
        build_verifier(jwks),
        trust,
        sample_tenant(),
        Issuer::OAuth,
        token,
        |_claims: &VerifiedClaims<OktaStyleClaims>| {
            Err(IdentityError::InvalidComponent(
                "missing required scope".to_string(),
            ))
        },
    );
    let err = resolver
        .resolve()
        .await
        .expect_err("mapper error must propagate");
    assert!(
        matches!(err, IdentityError::InvalidComponent(_)),
        "expected InvalidComponent, got {err:?}"
    );
}

#[tokio::test]
async fn custom_claim_deser_failure_rejected() {
    let (der, jwks, kid) = rsa_keypair();
    let now = now_secs();
    // Valid JWT, but custom claim shape doesn't match (missing
    // `service`). Custom-claim deserialisation fails inside the
    // verifier; surfaces as NotAuthenticated.
    let token = sign(
        &serde_json::json!({
            "iss": "https://gnomes.okta.com",
            "sub": "u1",
            "aud": "axess-platform",
            "exp": now + 3600,
            "iat": now,
            "azp": "feed-worker",
            "organization": "ekekrantz",
        }),
        &kid,
        &der,
    );
    let trust = TrustDomain::new("okta.gnomes.local").unwrap();
    let resolver = WorkloadResolver::new(
        build_verifier(jwks),
        trust.clone(),
        sample_tenant(),
        Issuer::OAuth,
        token,
        okta_mapper(trust),
    );
    let err = resolver
        .resolve()
        .await
        .expect_err("missing custom claim must reject");
    assert!(
        matches!(err, IdentityError::NotAuthenticated),
        "expected NotAuthenticated, got {err:?}"
    );
}

#[test]
fn issuer_oauth_wire_string_is_stable() {
    assert_eq!(Issuer::OAuth.as_str(), "oauth");
}
