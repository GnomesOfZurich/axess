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
    GitHubAllowlist::new()
        .owner_id("123456")
        .git_ref("refs/heads/main")
        .event("push")
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
        |_slug: &str| Some(sample_tenant()),
        Issuer::custom("github_actions").unwrap(),
        token,
        github_actions_mapper(allowlist()),
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
        |_slug: &str| Some(sample_tenant()),
        Issuer::custom("github_actions").unwrap(),
        token,
        github_actions_mapper(allowlist()),
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
    // Only the required claims and the ref and event the allowlist needs
    // are set; the other optional fields are absent. Mapper should still resolve, with only those
    // attributes.
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
            "ref": "refs/heads/main",
            "event_name": "push",
        }),
        "gha-min",
        &der,
    );
    let verifier = common::build_verifier(jwks, ISSUER, AUDIENCE);
    let trust = TrustDomain::new(TRUST_DOMAIN).unwrap();

    let resolver = WorkloadResolver::<GitHubActionsClaims, _, _>::new(
        verifier,
        trust.clone(),
        |_slug: &str| Some(sample_tenant()),
        Issuer::custom("github_actions").unwrap(),
        token,
        github_actions_mapper(allowlist()),
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
        vec!["event_name", "ref", "repository", "repository_owner"],
        "no optional fields: the audit names and the run's ref and event"
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
        |_slug: &str| Some(sample_tenant()),
        Issuer::custom("github_actions").unwrap(),
        token,
        github_actions_mapper(allow),
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
    let only_other = allowlist().repository_id("1");
    assert!(resolve_with(|_| {}, only_other).await.is_err());
    let listed = allowlist().repository_id("987654321");
    assert!(resolve_with(|_| {}, listed).await.is_ok());
}

/// A run on a ref the allowlist does not name (a feature branch, a pull
/// request merge ref) is refused, and so is a run of a listed ref started by
/// an event that is not listed.
#[tokio::test]
async fn a_run_on_an_unlisted_ref_or_event_is_refused() {
    let out = resolve_with(
        |c| c["ref"] = serde_json::json!("refs/heads/feature"),
        allowlist(),
    )
    .await;
    assert!(out.is_err(), "feature branch admitted: {out:?}");
    let out = resolve_with(
        |c| c["event_name"] = serde_json::json!("pull_request"),
        allowlist(),
    )
    .await;
    assert!(out.is_err(), "pull_request event admitted: {out:?}");
}

/// A token that carries no ref and no event is refused: the allowlist fails
/// closed rather than skipping a check for a claim that is absent.
#[tokio::test]
async fn a_token_without_ref_or_event_is_refused() {
    let out = resolve_with(
        |c| {
            let o = c.as_object_mut().unwrap();
            o.remove("ref");
            o.remove("event_name");
        },
        allowlist(),
    )
    .await;
    assert!(out.is_err(), "{out:?}");
}

/// An allowlist that names only owners admits nothing.
#[tokio::test]
async fn an_allowlist_without_ref_or_event_rules_admits_nothing() {
    let owners_only = GitHubAllowlist::new().owner_id("123456");
    let out = resolve_with(|_| {}, owners_only).await;
    assert!(out.is_err(), "{out:?}");
}

/// A listed environment admits a run whose ref is not listed, for the listed
/// events; an unlisted environment does not.
#[tokio::test]
async fn a_listed_environment_admits_a_run_and_an_unlisted_one_does_not() {
    let by_environment = GitHubAllowlist::new()
        .owner_id("123456")
        .environment("production")
        .event("push");
    let edit = |env: &'static str| {
        move |c: &mut serde_json::Value| {
            c["ref"] = serde_json::json!("refs/heads/feature");
            c["environment"] = serde_json::json!(env);
        }
    };
    assert!(
        resolve_with(edit("production"), by_environment.clone())
            .await
            .is_ok()
    );
    assert!(resolve_with(edit("staging"), by_environment).await.is_err());
}

/// A run admitted through its environment records that environment, so the
/// audit trail says which rule let it in.
#[tokio::test]
async fn a_run_admitted_through_its_environment_records_it() {
    let by_environment = GitHubAllowlist::new()
        .owner_id("123456")
        .environment("production")
        .event("push");
    let Principal::Workload(w) = resolve_with(
        |c| {
            c["ref"] = serde_json::json!("refs/heads/feature");
            c["environment"] = serde_json::json!("production");
        },
        by_environment,
    )
    .await
    .expect("a listed environment admits the run") else {
        panic!("expected Workload");
    };
    assert_eq!(
        w.attributes.get("environment"),
        Some(&serde_json::Value::String("production".to_string()))
    );
}
