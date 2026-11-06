//! OpenShift and EKS bound service-account tokens through the Kubernetes
//! recipe, each from a recorded token (`tests/fixtures/{openshift,eks}.json`;
//! the fixtures name their source documents, date and whether they are real).
//! Every refusal reuses the one recorded token under a wrong expectation.

mod common;

use axess_example_workload_identity::kubernetes::{
    K8sCustomClaims, SaUidPins, k8s_sa_mapper_pinned,
};
use axess_example_workload_identity::{eks, openshift};
use axess_factors::federation::workload::WorkloadResolver;
use axess_identity::{IdentityError, Issuer, Principal, PrincipalResolver, TenantId, TrustDomain};

const UID: &str = "11111111-2222-3333-4444-555555555555";

fn pins() -> SaUidPins {
    SaUidPins::new().pin("tenant-acme", "billing-api", UID)
}

async fn resolve(
    fixture: &str,
    audience: Option<&str>,
    pins: SaUidPins,
) -> Result<Principal, IdentityError> {
    let f = common::fixture(fixture);
    let verifier = common::build_verifier(f.jwks, &f.issuer, audience.unwrap_or(&f.audience));
    let trust = TrustDomain::new("cluster.local").unwrap();
    WorkloadResolver::<K8sCustomClaims, _, _>::new(
        verifier,
        trust.clone(),
        |_slug: &str| Some(TenantId::from_bytes([7u8; 16])),
        Issuer::custom("kubernetes").unwrap(),
        f.token,
        k8s_sa_mapper_pinned(pins),
    )
    .resolve()
    .await
}

fn names(out: Result<Principal, IdentityError>, claim: &str) {
    let err = out.expect_err("must be refused").to_string();
    assert!(err.contains(&format!("`{claim}`")), "{err}");
}

async fn audience_refused(fixture: &str) {
    let out = resolve(fixture, Some(openshift::DEFAULT_AUDIENCE), pins()).await;
    assert!(out.is_err(), "{out:?}");
    // The resolver answers every verification failure alike; the verifier
    // underneath names the claim.
    let f = common::fixture(fixture);
    let verifier = common::build_verifier(f.jwks, &f.issuer, "https://kubernetes.default.svc");
    let err = verifier
        .verify::<K8sCustomClaims>(&f.token)
        .await
        .expect_err("audience must be refused")
        .to_string();
    assert!(err.to_lowercase().contains("audience"), "{err}");
}

#[tokio::test]
async fn openshift_token_resolves_with_the_default_issuer() {
    let f = common::fixture("openshift");
    assert_eq!(f.issuer, openshift::DEFAULT_ISSUER);
    assert!(f.source.contains("redhat.com"), "{}", f.source);
    assert_eq!(f.kind, "constructed");
    let Principal::Workload(w) = resolve("openshift", None, pins()).await.expect("resolves") else {
        panic!("expected Workload");
    };
    assert_eq!(
        w.workload_id.as_str(),
        "spiffe://cluster.local/billing-api/tenant-acme"
    );
}

#[tokio::test]
async fn openshift_wrong_namespace_wrong_uid_and_wrong_audience_are_refused() {
    let other_ns = SaUidPins::new().pin("tenant-other", "billing-api", UID);
    names(
        resolve("openshift", None, other_ns).await,
        "kubernetes.io.namespace",
    );
    let other_uid = SaUidPins::new().pin("tenant-acme", "billing-api", "ffff");
    names(
        resolve("openshift", None, other_uid).await,
        "kubernetes.io.serviceaccount.uid",
    );
    audience_refused("openshift").await;
}

#[tokio::test]
async fn eks_token_resolves_with_the_cluster_issuer() {
    let f = common::fixture("eks");
    assert_eq!(
        f.issuer,
        eks::issuer("eu-west-1", "A1B2C3D4E5F60718293A4B5C6D7E8F90")
    );
    assert!(f.source.contains("docs.aws.amazon.com"), "{}", f.source);
    assert_eq!(f.kind, "constructed");
    let Principal::Workload(w) = resolve("eks", None, pins()).await.expect("resolves") else {
        panic!("expected Workload");
    };
    assert_eq!(
        w.workload_id.as_str(),
        "spiffe://cluster.local/billing-api/tenant-acme"
    );
}

#[tokio::test]
async fn eks_wrong_namespace_wrong_uid_and_wrong_audience_are_refused() {
    let other_ns = SaUidPins::new().pin("tenant-other", "billing-api", UID);
    names(
        resolve("eks", None, other_ns).await,
        "kubernetes.io.namespace",
    );
    let other_uid = SaUidPins::new().pin("tenant-acme", "billing-api", "ffff");
    names(
        resolve("eks", None, other_uid).await,
        "kubernetes.io.serviceaccount.uid",
    );
    // The IRSA audience is for STS; a token for it is not a token for us.
    let out = resolve("eks", Some(eks::IRSA_AUDIENCE), pins()).await;
    assert!(out.is_err(), "{out:?}");
    audience_refused("eks").await;
}
