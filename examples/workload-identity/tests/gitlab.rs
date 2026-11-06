//! GitLab CI recipe against a recorded ID token (`tests/fixtures/gitlab.json`;
//! the fixture names its source document, date and whether it is real).
//! Every refusal reuses the one recorded token under a wrong expectation and
//! asserts the error names the claim.

mod common;

use axess_example_workload_identity::gitlab::{GitLabAllowlist, GitLabClaims, gitlab_mapper};
use axess_factors::federation::workload::WorkloadResolver;
use axess_identity::{IdentityError, Issuer, Principal, PrincipalResolver, TenantId, TrustDomain};

fn allowlist() -> GitLabAllowlist {
    GitLabAllowlist::new()
        .namespace_id("72")
        .project_id("20")
        .environment("production")
}

async fn resolve(
    audience: Option<&str>,
    allow: GitLabAllowlist,
) -> Result<Principal, IdentityError> {
    let f = common::fixture("gitlab");
    let verifier = common::build_verifier(f.jwks, &f.issuer, audience.unwrap_or(&f.audience));
    let trust = TrustDomain::new("gitlab.ci").unwrap();
    WorkloadResolver::<GitLabClaims, _, _>::new(
        verifier,
        trust.clone(),
        |_slug: &str| Some(TenantId::from_bytes([9u8; 16])),
        Issuer::custom("gitlab_ci").unwrap(),
        f.token,
        gitlab_mapper(allow),
    )
    .resolve()
    .await
}

async fn resolve_token(
    jwks: jsonwebtoken::jwk::JwkSet,
    token: String,
    allow: GitLabAllowlist,
    issuer: &str,
    audience: &str,
) -> Result<Principal, IdentityError> {
    let trust = TrustDomain::new("gitlab.ci").unwrap();
    WorkloadResolver::<GitLabClaims, _, _>::new(
        common::build_verifier(jwks, issuer, audience),
        trust.clone(),
        |_slug: &str| Some(TenantId::from_bytes([9u8; 16])),
        Issuer::custom("gitlab_ci").unwrap(),
        token,
        gitlab_mapper(allow),
    )
    .resolve()
    .await
}

fn names(out: Result<Principal, IdentityError>, claim: &str) {
    let err = out.expect_err("must be refused").to_string();
    assert!(err.contains(&format!("`{claim}`")), "{err}");
}

#[test]
fn the_fixture_names_its_source() {
    let f = common::fixture("gitlab");
    assert!(
        f.source.starts_with("https://docs.gitlab.com/"),
        "{}",
        f.source
    );
    assert_eq!(f.recorded, "2026-10-30");
    assert_eq!(f.kind, "constructed");
}

#[tokio::test]
async fn the_recorded_token_resolves_on_ids_not_paths() {
    let Principal::Workload(w) = resolve(None, allowlist()).await.expect("resolves") else {
        panic!("expected Workload");
    };
    assert_eq!(w.workload_id.as_str(), "spiffe://gitlab.ci/20/72");
    assert_eq!(w.service_name, "20");
    assert_eq!(w.tenant_slug, "72");
    assert_eq!(w.issuer.as_str(), "gitlab_ci");
    let attr = |k: &str| {
        w.attributes
            .get(k)
            .and_then(|v| v.as_str())
            .map(str::to_string)
    };
    assert_eq!(attr("project_path").as_deref(), Some("mygroup/myproject"));
    assert_eq!(attr("environment").as_deref(), Some("production"));
    assert_eq!(attr("ref").as_deref(), Some("main"));
}

#[tokio::test]
async fn a_wrong_project_id_is_refused_naming_project_id() {
    let only_others = GitLabAllowlist::new().namespace_id("72").project_id("21");
    names(resolve(None, only_others).await, "project_id");
}

#[tokio::test]
async fn a_wrong_namespace_id_is_refused_naming_namespace_id() {
    let other = GitLabAllowlist::new().namespace_id("73").project_id("20");
    names(resolve(None, other).await, "namespace_id");
    // The empty allowlist trusts nobody.
    names(resolve(None, GitLabAllowlist::new()).await, "namespace_id");
}

#[tokio::test]
async fn an_environment_outside_the_list_is_refused_naming_environment() {
    let staging = GitLabAllowlist::new()
        .namespace_id("72")
        .environment("staging");
    names(resolve(None, staging).await, "environment");
}

#[tokio::test]
async fn an_unprotected_ref_is_refused_unless_the_allowlist_opts_in() {
    // Same token; the protected-ref requirement is what the allowlist asks.
    // The recorded token is protected, so rewrite the claim by re-reading
    // through a mapper that sees `false`.
    let f = common::fixture("gitlab");
    let (der, jwks) = common::rsa_keypair("gl-unprot");
    let (now, exp) = common::now_and_exp();
    let claims = serde_json::json!({
        "iss": f.issuer, "aud": f.audience, "iat": now, "exp": exp,
        "namespace_id": "72", "project_id": "20",
        "ref": "feature", "ref_type": "branch", "ref_protected": "false",
    });
    let token = common::sign(&claims, "gl-unprot", &der);
    let run = |allow: GitLabAllowlist| {
        resolve_token(jwks.clone(), token.clone(), allow, &f.issuer, &f.audience)
    };
    names(
        run(GitLabAllowlist::new().namespace_id("72")).await,
        "ref_protected",
    );
    assert!(
        run(GitLabAllowlist::new()
            .namespace_id("72")
            .allow_unprotected_refs())
        .await
        .is_ok()
    );
}

#[tokio::test]
async fn a_job_without_an_environment_is_refused_when_environments_are_listed() {
    let f = common::fixture("gitlab");
    let (der, jwks) = common::rsa_keypair("gl-noenv");
    let (now, exp) = common::now_and_exp();
    let token = common::sign(
        &serde_json::json!({
            "iss": f.issuer, "aud": f.audience, "iat": now, "exp": exp,
            "namespace_id": "72", "project_id": "20", "ref_protected": "true",
        }),
        "gl-noenv",
        &der,
    );
    let out = resolve_token(jwks, token, allowlist(), &f.issuer, &f.audience).await;
    names(out, "environment");
}

#[tokio::test]
async fn a_wrong_audience_is_refused_and_the_verifier_names_aud() {
    let out = resolve(Some("https://other.example.com"), allowlist()).await;
    assert!(out.is_err(), "{out:?}");

    // The resolver answers every verification failure the same way; the
    // verifier underneath says which claim failed.
    let f = common::fixture("gitlab");
    let verifier = common::build_verifier(f.jwks, &f.issuer, "https://other.example.com");
    let err = verifier
        .verify::<GitLabClaims>(&f.token)
        .await
        .expect_err("audience must be refused")
        .to_string();
    assert!(err.to_lowercase().contains("audience"), "{err}");
}
