//! End-to-end test for the Kubernetes service-account recipe.
//!
//! Mints an RSA-signed JWT carrying k8s-shape claims, drives the
//! generic `WorkloadResolver` with `k8s_sa_mapper`, and asserts the
//! produced `Principal::Workload` matches the claims.

mod common;

use axess_example_workload_identity::kubernetes::{K8sCustomClaims, k8s_sa_mapper};
use axess_factors::federation::workload::WorkloadResolver;
use axess_identity::{Issuer, Principal, PrincipalResolver, TenantId, TrustDomain};

const ISSUER: &str = "https://kubernetes.default.svc.cluster.local";
const AUDIENCE: &str = "axess-platform";
const TRUST_DOMAIN: &str = "cluster.local";

fn sample_tenant() -> TenantId {
    TenantId::from_bytes([7u8; 16])
}

fn k8s_claims(now: i64, exp: i64) -> serde_json::Value {
    serde_json::json!({
        "iss": ISSUER,
        "sub": "system:serviceaccount:tenant-acme:billing-api",
        "aud": [AUDIENCE],
        "exp": exp,
        "iat": now,
        "kubernetes.io": {
            "namespace": "tenant-acme",
            "serviceaccount": {
                "name": "billing-api",
                "uid": "11111111-2222-3333-4444-555555555555",
            },
            "pod": {
                "name": "billing-api-7d9bc6f5d8-x2k4q",
                "uid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            },
        },
    })
}

#[tokio::test]
async fn recipe_resolves_real_k8s_shape_token() {
    let (der, jwks) = common::rsa_keypair("k8s-1");
    let (now, exp) = common::now_and_exp();
    let token = common::sign(&k8s_claims(now, exp), "k8s-1", &der);
    let verifier = common::build_verifier(jwks, ISSUER, AUDIENCE);
    let trust = TrustDomain::new(TRUST_DOMAIN).unwrap();

    let resolver = WorkloadResolver::<K8sCustomClaims, _, _>::new(
        verifier,
        trust.clone(),
        sample_tenant(),
        Issuer::custom("kubernetes").unwrap(),
        token,
        k8s_sa_mapper(trust.clone()),
    );

    let principal = resolver.resolve().await.expect("recipe must resolve");
    let Principal::Workload(w) = principal else {
        panic!("expected Workload, got Human");
    };
    assert_eq!(
        w.workload_id.as_str(),
        "spiffe://cluster.local/billing-api/tenant-acme"
    );
    assert_eq!(w.trust_domain, trust);
    assert_eq!(w.issuer.as_str(), "kubernetes");
    assert_eq!(w.tenant_id, sample_tenant());
    assert_eq!(w.service_name, "billing-api");
    assert_eq!(w.tenant_slug, "tenant-acme");
    assert_eq!(
        w.attributes.get("sa_uid").and_then(|v| v.as_str()),
        Some("11111111-2222-3333-4444-555555555555")
    );
    assert_eq!(
        w.attributes.get("pod_name").and_then(|v| v.as_str()),
        Some("billing-api-7d9bc6f5d8-x2k4q")
    );
    assert_eq!(
        w.attributes.get("pod_uid").and_then(|v| v.as_str()),
        Some("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    );
}

#[tokio::test]
async fn recipe_resolves_minimal_token_without_pod_block() {
    // The pod block is optional in `K8sCustomClaims`. Tokens issued
    // by clusters that don't project pod info should still resolve.
    let (der, jwks) = common::rsa_keypair("k8s-min");
    let (now, exp) = common::now_and_exp();
    let token = common::sign(
        &serde_json::json!({
            "iss": ISSUER,
            "sub": "system:serviceaccount:default:lonely",
            "aud": [AUDIENCE],
            "exp": exp,
            "iat": now,
            "kubernetes.io": {
                "namespace": "default",
                "serviceaccount": { "name": "lonely" },
            },
        }),
        "k8s-min",
        &der,
    );
    let verifier = common::build_verifier(jwks, ISSUER, AUDIENCE);
    let trust = TrustDomain::new(TRUST_DOMAIN).unwrap();

    let resolver = WorkloadResolver::<K8sCustomClaims, _, _>::new(
        verifier,
        trust.clone(),
        sample_tenant(),
        Issuer::custom("kubernetes").unwrap(),
        token,
        k8s_sa_mapper(trust),
    );

    let Principal::Workload(w) = resolver
        .resolve()
        .await
        .expect("missing pod block must still resolve")
    else {
        panic!("expected Workload");
    };
    assert_eq!(
        w.workload_id.as_str(),
        "spiffe://cluster.local/lonely/default"
    );
    assert!(
        !w.attributes.contains_key("sa_uid"),
        "missing optional uid → no attr"
    );
    assert!(
        !w.attributes.contains_key("pod_name"),
        "missing pod block → no pod_name"
    );
}

#[tokio::test]
async fn wrong_issuer_rejected_before_mapper_runs() {
    // JWT carries the right shape but is signed by a different
    // issuer. `JwtVerifier` rejects on the `iss` check before the
    // mapper ever runs; defense at the right layer.
    let (der, jwks) = common::rsa_keypair("k8s-bad");
    let (now, exp) = common::now_and_exp();
    let mut claims = k8s_claims(now, exp);
    claims["iss"] = serde_json::json!("https://attacker.example");
    let token = common::sign(&claims, "k8s-bad", &der);
    let verifier = common::build_verifier(jwks, ISSUER, AUDIENCE);
    let trust = TrustDomain::new(TRUST_DOMAIN).unwrap();

    let resolver = WorkloadResolver::<K8sCustomClaims, _, _>::new(
        verifier,
        trust.clone(),
        sample_tenant(),
        Issuer::custom("kubernetes").unwrap(),
        token,
        k8s_sa_mapper(trust),
    );

    assert!(
        resolver.resolve().await.is_err(),
        "wrong iss must reject before mapper runs"
    );
}
