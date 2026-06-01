//! End-to-end test for the GitHub Actions recipe.
//!
//! Mints an RSA-signed JWT carrying GitHub-Actions-shape claims,
//! drives the generic `WorkloadResolver` with `github_actions_mapper`,
//! and asserts the produced `Principal::Workload` matches the claims.

mod common;

use std::collections::BTreeMap;

use axess_example_workload_identity::github_actions::{GitHubActionsClaims, github_actions_mapper};
use axess_factors::federation::workload::WorkloadResolver;
use axess_identity::{Issuer, Principal, PrincipalResolver, TenantId, TrustDomain};

const ISSUER: &str = "https://token.actions.githubusercontent.com";
const AUDIENCE: &str = "axess-platform";
const TRUST_DOMAIN: &str = "github.actions";

fn sample_tenant() -> TenantId {
    TenantId::from_bytes([42u8; 16])
}

fn github_claims(now: i64, exp: i64) -> serde_json::Value {
    serde_json::json!({
        "iss": ISSUER,
        "sub": "repo:gnomes/axess:ref:refs/heads/main",
        "aud": AUDIENCE,
        "exp": exp,
        "iat": now,
        "repository": "gnomes/axess",
        "repository_owner": "gnomes",
        "actor": "octocat",
        "workflow": "ci",
        "ref": "refs/heads/main",
        "sha": "deadbeefcafe",
        "event_name": "push",
    })
}

#[tokio::test]
async fn recipe_resolves_real_github_shape_token() {
    let (der, jwks) = common::rsa_keypair("gha-1");
    let (now, exp) = common::now_and_exp();
    let token = common::sign(&github_claims(now, exp), "gha-1", &der);
    let verifier = common::build_verifier(jwks, ISSUER, AUDIENCE);
    let trust = TrustDomain::new(TRUST_DOMAIN).unwrap();

    let resolver = WorkloadResolver::<GitHubActionsClaims, _, _>::new(
        verifier,
        trust.clone(),
        sample_tenant(),
        Issuer::custom("github_actions").unwrap(),
        token,
        github_actions_mapper(trust.clone()),
    );

    let principal = resolver.resolve().await.expect("recipe must resolve");
    let Principal::Workload(w) = principal else {
        panic!("expected Workload, got Human");
    };
    assert_eq!(
        w.workload_id.as_str(),
        "spiffe://github.actions/axess/gnomes"
    );
    assert_eq!(w.trust_domain, trust);
    assert_eq!(w.issuer.as_str(), "github_actions");
    assert_eq!(w.tenant_id, sample_tenant());
    assert_eq!(w.service_name, "axess");
    assert_eq!(w.tenant_slug, "gnomes");
    // All five attribute fields preserved.
    let expected: BTreeMap<String, serde_json::Value> = [
        ("actor", "octocat"),
        ("workflow", "ci"),
        ("ref", "refs/heads/main"),
        ("sha", "deadbeefcafe"),
        ("event_name", "push"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), serde_json::Value::String(v.to_string())))
    .collect();
    assert_eq!(w.attributes, expected);
}

#[tokio::test]
async fn recipe_rejects_repository_owner_mismatch() {
    // `repository_owner = "evil"` doesn't prefix `repository = "gnomes/axess"`.
    // The mapper should refuse to synthesise a workload id.
    let (der, jwks) = common::rsa_keypair("gha-bad");
    let (now, exp) = common::now_and_exp();
    let mut claims = github_claims(now, exp);
    claims["repository_owner"] = serde_json::json!("evil");
    let token = common::sign(&claims, "gha-bad", &der);
    let verifier = common::build_verifier(jwks, ISSUER, AUDIENCE);
    let trust = TrustDomain::new(TRUST_DOMAIN).unwrap();

    let resolver = WorkloadResolver::<GitHubActionsClaims, _, _>::new(
        verifier,
        trust.clone(),
        sample_tenant(),
        Issuer::custom("github_actions").unwrap(),
        token,
        github_actions_mapper(trust),
    );

    let err = resolver
        .resolve()
        .await
        .expect_err("owner/repo mismatch must reject");
    assert!(
        format!("{err}").contains("repository_owner"),
        "error should name the mismatched field, got: {err:?}"
    );
}

#[tokio::test]
async fn recipe_omits_missing_optional_attributes() {
    // Only `repository` + `repository_owner` set; the optional fields
    // are absent. Mapper should still resolve, with an empty attribute
    // map.
    let (der, jwks) = common::rsa_keypair("gha-min");
    let (now, exp) = common::now_and_exp();
    let token = common::sign(
        &serde_json::json!({
            "iss": ISSUER,
            "sub": "repo:gnomes/axess",
            "aud": AUDIENCE,
            "exp": exp,
            "iat": now,
            "repository": "gnomes/axess",
            "repository_owner": "gnomes",
        }),
        "gha-min",
        &der,
    );
    let verifier = common::build_verifier(jwks, ISSUER, AUDIENCE);
    let trust = TrustDomain::new(TRUST_DOMAIN).unwrap();

    let resolver = WorkloadResolver::<GitHubActionsClaims, _, _>::new(
        verifier,
        trust.clone(),
        sample_tenant(),
        Issuer::custom("github_actions").unwrap(),
        token,
        github_actions_mapper(trust),
    );

    let Principal::Workload(w) = resolver
        .resolve()
        .await
        .expect("minimal token must resolve")
    else {
        panic!("expected Workload");
    };
    assert!(w.attributes.is_empty(), "no optional fields → no attrs");
}
