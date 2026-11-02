//! Rewrites `tests/fixtures/*.json`. Ignored: the fixtures are recorded
//! artefacts that the recipe tests read, and rewriting them mints a new test
//! key. Run with `cargo test -p axess-example-workload-identity --test
//! regenerate_fixtures -- --ignored`.
//!
//! None of these tokens was captured from a live issuer. Each is built from the
//! claim set its platform documents and signed with a throwaway test key whose
//! public half is stored beside it; the fixture says so in its `kind` field.

mod common;

use axess_example_workload_identity::eks;

const RECORDED: &str = "2026-10-30";

fn write(name: &str, source: &str, issuer: &str, audience: &str, claims: serde_json::Value) {
    let (der, jwks) = common::rsa_keypair("fixture-1");
    let token = common::sign(&claims, "fixture-1", &der);
    let body = serde_json::json!({
        "source": source,
        "recorded": RECORDED,
        "kind": "constructed",
        "issuer": issuer,
        "audience": audience,
        "jwks": jwks,
        "token": token,
    });
    let path = format!("{}/tests/fixtures/{name}.json", env!("CARGO_MANIFEST_DIR"));
    std::fs::write(path, serde_json::to_string_pretty(&body).unwrap() + "\n").unwrap();
}

#[test]
#[ignore = "rewrites the recorded fixtures with a new test key"]
fn regenerate() {
    // `--ignored` runs this generator too (the release preflight's
    // live-store step runs every ignored test), and it rewrote the three
    // fixtures with a fresh throwaway key on every run. It writes only when
    // asked by name; otherwise it says so and changes nothing.
    if std::env::var_os("REGENERATE_FIXTURES").is_none() {
        eprintln!(
            "regenerate_fixtures: NOT RUN (set REGENERATE_FIXTURES=1 to rewrite the fixtures)"
        );
        return;
    }

    let (now, exp) = common::now_and_exp();

    let gitlab_iss = "https://gitlab.example.com";
    let gitlab_aud = "https://axess.example.com";
    write(
        "gitlab",
        "https://docs.gitlab.com/ci/secrets/id_token_authentication/ (token payload section)",
        gitlab_iss,
        gitlab_aud,
        serde_json::json!({
            "iss": gitlab_iss,
            "sub": "project_path:mygroup/myproject:ref_type:branch:ref:main",
            "aud": gitlab_aud,
            "jti": "c82eeb0c-5c6f-4a33-abf5-4c474b92b558",
            "iat": now, "nbf": now, "exp": exp,
            "namespace_id": "72",
            "namespace_path": "mygroup",
            "project_id": "20",
            "project_path": "mygroup/myproject",
            "user_id": "1",
            "user_login": "sample-user",
            "pipeline_id": "574",
            "pipeline_source": "push",
            "job_id": "302",
            "ref": "main",
            "ref_type": "branch",
            "ref_path": "refs/heads/main",
            "ref_protected": "true",
            "environment": "production",
            "environment_protected": "true",
            "runner_environment": "self-hosted",
            "sha": "714a629c0b401fdce83e847fc9589983fc6f46bc",
        }),
    );

    let k8s_doc = "https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/#bound-service-account-tokens";
    let sa = |ns: &str| {
        serde_json::json!({
            "namespace": ns,
            "pod": { "name": "billing-api-7d9bc6f5d8-x2k4q", "uid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" },
            "serviceaccount": { "name": "billing-api", "uid": "11111111-2222-3333-4444-555555555555" },
        })
    };

    let ocp_iss = "https://kubernetes.default.svc";
    write(
        "openshift",
        &format!(
            "{k8s_doc}; OpenShift 4 default serviceAccountIssuer, https://docs.redhat.com/en/documentation/openshift_container_platform/4.18/html/authentication_and_authorization/bound-service-account-tokens"
        ),
        ocp_iss,
        "axess-platform",
        serde_json::json!({
            "iss": ocp_iss,
            "sub": "system:serviceaccount:tenant-acme:billing-api",
            "aud": ["axess-platform"],
            "iat": now, "nbf": now, "exp": exp,
            "kubernetes.io": sa("tenant-acme"),
        }),
    );

    let eks_iss = eks::issuer("eu-west-1", "A1B2C3D4E5F60718293A4B5C6D7E8F90");
    write(
        "eks",
        &format!(
            "{k8s_doc}; EKS issuer shape, https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html"
        ),
        &eks_iss,
        "axess-platform",
        serde_json::json!({
            "iss": eks_iss,
            "sub": "system:serviceaccount:tenant-acme:billing-api",
            "aud": ["axess-platform"],
            "iat": now, "nbf": now, "exp": exp,
            "kubernetes.io": sa("tenant-acme"),
        }),
    );
}
