//! End-to-end test for the GitHub Actions recipe.
//!
//! Mints an RSA-signed JWT carrying GitHub-Actions-shape claims,
//! drives the generic `WorkloadResolver` with `github_actions_mapper`,
//! and asserts the produced `Principal::Workload` matches the claims.

mod common;

use std::collections::BTreeMap;

use axess_example_workload_identity::github_actions::{
    GitHubActionsClaims, GitHubAllowlist, github_actions_mapper,
};
use axess_factors::federation::workload::WorkloadResolver;
use axess_identity::{Issuer, Principal, PrincipalResolver, TenantId, TrustDomain};

const ISSUER: &str = "https://token.actions.githubusercontent.com";
const AUDIENCE: &str = "axess-platform";
const TRUST_DOMAIN: &str = "github.actions";

fn allowlist() -> GitHubAllowlist {
    GitHubAllowlist::new().owner_id("123456")
}

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
        "repository_id": "987654321",
        "repository_owner_id": "123456",
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
        github_actions_mapper(trust.clone(), allowlist()),
    );

    let principal = resolver.resolve().await.expect("recipe must resolve");
    let Principal::Workload(w) = principal else {
        panic!("expected Workload, got Human");
    };
    assert_eq!(
        w.workload_id.as_str(),
        "spiffe://github.actions/987654321/123456"
    );
    assert_eq!(w.trust_domain, trust);
    assert_eq!(w.issuer.as_str(), "github_actions");
    assert_eq!(w.tenant_id, sample_tenant());
    assert_eq!(w.service_name, "987654321");
    assert_eq!(w.tenant_slug, "123456");
    // The names travel as attributes; the five optional fields are preserved.
    let expected: BTreeMap<String, serde_json::Value> = [
        ("repository", "gnomes/axess"),
        ("repository_owner", "gnomes"),
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
        github_actions_mapper(trust, allowlist()),
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
            "repository_id": "987654321",
            "repository_owner_id": "123456",
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
        github_actions_mapper(trust, allowlist()),
    );

    let Principal::Workload(w) = resolver
        .resolve()
        .await
        .expect("minimal token must resolve")
    else {
        panic!("expected Workload");
    };
    assert_eq!(
        w.attributes.keys().map(String::as_str).collect::<Vec<_>>(),
        vec!["repository", "repository_owner"],
        "no optional fields: only the audit names"
    );
}

async fn resolve_with(
    claims_edit: impl FnOnce(&mut serde_json::Value),
    allow: GitHubAllowlist,
) -> Result<Principal, axess_identity::IdentityError> {
    let (der, jwks) = common::rsa_keypair("gha-id");
    let (now, exp) = common::now_and_exp();
    let mut claims = github_claims(now, exp);
    claims_edit(&mut claims);
    let token = common::sign(&claims, "gha-id", &der);
    let verifier = common::build_verifier(jwks, ISSUER, AUDIENCE);
    let trust = TrustDomain::new(TRUST_DOMAIN).unwrap();
    WorkloadResolver::<GitHubActionsClaims, _, _>::new(
        verifier,
        trust.clone(),
        sample_tenant(),
        Issuer::custom("github_actions").unwrap(),
        token,
        github_actions_mapper(trust, allow),
    )
    .resolve()
    .await
}

/// A recycled organisation name carries a different owner id: the token has
/// the name the operator trusted and is still refused.
#[tokio::test]
async fn a_reused_owner_name_with_a_different_owner_id_is_refused() {
    let out = resolve_with(
        |c| c["repository_owner_id"] = serde_json::json!("999999"),
        allowlist(),
    )
    .await;
    assert!(out.is_err(), "{out:?}");
}

/// A token without the immutable ids is refused rather than falling back to names.
#[tokio::test]
async fn a_token_without_the_numeric_ids_is_refused() {
    let out = resolve_with(
        |c| {
            c.as_object_mut().unwrap().remove("repository_id");
        },
        allowlist(),
    )
    .await;
    assert!(out.is_err(), "{out:?}");
}

/// When repository ids are listed, a sibling repository of a trusted owner is refused.
#[tokio::test]
async fn a_repository_outside_the_listed_ids_is_refused() {
    let only_other = GitHubAllowlist::new().owner_id("123456").repository_id("1");
    assert!(resolve_with(|_| {}, only_other).await.is_err());
    let listed = GitHubAllowlist::new()
        .owner_id("123456")
        .repository_id("987654321");
    assert!(resolve_with(|_| {}, listed).await.is_ok());
}
