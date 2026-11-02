//! The AWS walkthrough (`docs/workload-identity/aws.md`), compiled.
//!
//! Two exchanges through `AwsStsClient`: a CI job assumes a deploy role with
//! its ID token, and a service on EKS assumes its own role with the projected
//! service-account token (IAM roles for service accounts). The service is
//! called by a pipeline and protected by axess. STS is a wiremock server that
//! holds an IAM OIDC provider and two roles' trust policies, and answers the
//! way AWS documents when a token does not satisfy them, so each
//! misconfiguration the document names is reproduced here.
//!
//! The error codes and messages are the ones AWS documents for
//! `AssumeRoleWithWebIdentity` (`InvalidIdentityToken`, `AccessDenied`). The
//! mock was written from that documentation, not recorded from a live account.
//! The last hop of the walkthrough, `GetSecretValue`, needs a SigV4-signing
//! SDK that axess does not depend on; the document shows it and this file
//! stops at the credentials the SDK would be given.

mod common;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axess::workload::outbound::cloud_sts::aws::{
    AssumeRoleWithWebIdentityRequest, AssumeRoleWithWebIdentityResponse, AwsStsClient, AwsStsError,
};
use axess_factors::federation::workload::WorkloadResolver;
use axess_factors::jwt::verifier::JwtVerifier;
use axess_identity::{Issuer, PrincipalResolver, TenantId, TrustDomain};
use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, Request, StatusCode, header};
use axum::routing::get;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use tower::ServiceExt;
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request as MockRequest, Respond, ResponseTemplate};

// ANCHOR: inbound_recipe
// The caller's recipe: GitLab CI ID tokens, keyed on project and namespace id.
use axess_example_workload_identity::gitlab::{
    GitLabAllowlist as CallerAllowlist, GitLabClaims as CallerClaims,
    gitlab_mapper as caller_mapper,
};

const CALLER_ISSUER: &str = "https://gitlab.example.com";
const CALLER_AUDIENCE: &str = "axess-platform";

fn caller_allowlist() -> CallerAllowlist {
    CallerAllowlist::new()
        .namespace_id("1204")
        .project_id("4711")
        .environment("production")
}
// ANCHOR_END: inbound_recipe

const ACCOUNT: &str = "123456789012";
const STS_AUDIENCE: &str = "sts.amazonaws.com";
const GITHUB_HOST: &str = "token.actions.githubusercontent.com";
const EKS_HOST: &str = "oidc.eks.eu-central-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE";
const DEPLOY_ROLE: &str = "arn:aws:iam::123456789012:role/ledger-ci-deploy";
const READER_ROLE: &str = "arn:aws:iam::123456789012:role/ledger-secret-reader";
const JOB_SUBJECT: &str = "repo:gnomes/axess:ref:refs/heads/main";
const POD_SUBJECT: &str = "system:serviceaccount:payments:ledger";

// ANCHOR: service
/// What the service holds. Built once at startup.
#[derive(Clone)]
struct Service {
    verifier: Arc<JwtVerifier>,
    trust: TrustDomain,
    tenant: TenantId,
    sts: AwsStsClient,
    role_arn: String,
    web_identity_token_file: PathBuf,
}

impl Service {
    /// The variables the EKS pod identity webhook injects into a pod whose
    /// service account carries the `eks.amazonaws.com/role-arn` annotation.
    /// A regional STS endpoint keeps the call inside the cluster's region.
    fn sts_from_env(
        env: impl Fn(&str) -> Option<String>,
    ) -> Option<(AwsStsClient, String, PathBuf)> {
        let role_arn = env("AWS_ROLE_ARN")?;
        let token_file = PathBuf::from(env("AWS_WEB_IDENTITY_TOKEN_FILE")?);
        let region = env("AWS_REGION")?;
        let endpoint = Url::parse(&format!("https://sts.{region}.amazonaws.com/")).ok()?;
        Some((
            AwsStsClient::new().expect("client").with_endpoint(endpoint),
            role_arn,
            token_file,
        ))
    }
}

/// `GET /ready`: authenticate the caller, then prove the service can act as
/// its own role. The credentials go to the AWS SDK (see the document); this
/// handler answers with the role it was given.
async fn ready(
    State(svc): State<Service>,
    headers: HeaderMap,
) -> Result<String, (StatusCode, &'static str)> {
    // 1. Who is calling? The bearer token is the pipeline's ID token.
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or((StatusCode::UNAUTHORIZED, "bearer token required"))?;
    let resolver = WorkloadResolver::<CallerClaims, _, _>::new(
        svc.verifier.clone(),
        svc.trust.clone(),
        svc.tenant,
        Issuer::custom("pipeline").expect("issuer name"),
        bearer.to_string(),
        caller_mapper(svc.trust.clone(), caller_allowlist()),
    );
    resolver
        .resolve()
        .await
        .map_err(|_| (StatusCode::UNAUTHORIZED, "caller not recognised"))?;

    // 2. Exchange the service's own identity, never the caller's.
    let assumed = secret_reader_credentials(&svc).await.map_err(|e| {
        tracing::error!(error = %e, "STS refused the web identity");
        (StatusCode::BAD_GATEWAY, "upstream identity exchange failed")
    })?;
    Ok(assumed.assumed_role_arn.clone())
}

/// The exchange: the projected token in, credentials for the reader role out.
/// The file is read on every call because the kubelet rotates it.
async fn secret_reader_credentials(
    svc: &Service,
) -> Result<AssumeRoleWithWebIdentityResponse, AwsStsError> {
    let token = tokio::fs::read_to_string(&svc.web_identity_token_file)
        .await
        .map_err(|e| AwsStsError::Transport(format!("web identity token file: {e}")))?;
    let request = AssumeRoleWithWebIdentityRequest::new(&svc.role_arn, "ledger", token.trim())
        .with_duration_seconds(900);
    svc.sts.assume_role_with_web_identity(&request).await
}

fn router(svc: Service) -> Router {
    Router::new().route("/ready", get(ready)).with_state(svc)
}
// ANCHOR_END: service

// ANCHOR: job
/// What the CI job does after `id-token: write` gave it a token for
/// `sts.amazonaws.com`: assume the deploy role. In a workflow this is the
/// `aws-actions/configure-aws-credentials` step; this is the same call
/// through the adapter, for a job written in Rust.
async fn job_assumes_deploy_role(
    sts: &AwsStsClient,
    id_token: &str,
) -> Result<AssumeRoleWithWebIdentityResponse, AwsStsError> {
    let request = AssumeRoleWithWebIdentityRequest::new(DEPLOY_ROLE, "ci-deploy", id_token)
        .with_duration_seconds(900);
    sts.assume_role_with_web_identity(&request).await
}
// ANCHOR_END: job

// ── The mock STS ────────────────────────────────────────────────────────────

/// An IAM OIDC identity provider: the URL it was registered under (without
/// the scheme) and its client ID list, which AWS checks the token's `aud`
/// against.
struct IamOidcProvider {
    host: &'static str,
    client_ids: Vec<&'static str>,
}

/// One role's trust policy: which provider may federate in, and the
/// `StringEquals` conditions on `<host>:aud` and `<host>:sub`.
struct Trust {
    role_arn: &'static str,
    host: &'static str,
    aud: &'static str,
    sub: &'static str,
}

struct MockSts {
    providers: Vec<IamOidcProvider>,
    roles: Vec<Trust>,
}

fn sts_error(status: u16, code: &str, message: &str) -> ResponseTemplate {
    let body = format!(
        r#"<?xml version="1.0"?>
<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error>
    <Type>Sender</Type>
    <Code>{code}</Code>
    <Message>{message}</Message>
  </Error>
  <RequestId>0a1b2c3d-0000-4000-8000-0123456789ab</RequestId>
</ErrorResponse>
"#
    );
    ResponseTemplate::new(status).set_body_raw(body, "text/xml")
}

impl Respond for MockSts {
    fn respond(&self, req: &MockRequest) -> ResponseTemplate {
        let form: HashMap<String, String> = url::form_urlencoded::parse(&req.body)
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        let token = form.get("WebIdentityToken").cloned().unwrap_or_default();
        let role = form.get("RoleArn").cloned().unwrap_or_default();
        let claims: serde_json::Value = token
            .split('.')
            .nth(1)
            .and_then(|p| URL_SAFE_NO_PAD.decode(p).ok())
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let iss = claims["iss"].as_str().unwrap_or_default();
        let sub = claims["sub"].as_str().unwrap_or_default();
        let aud = claims["aud"].as_str().unwrap_or_default();
        let host = iss.strip_prefix("https://").unwrap_or(iss);

        // 1. The issuer must be a registered IAM OIDC provider.
        let Some(provider) = self.providers.iter().find(|p| p.host == host) else {
            return sts_error(
                400,
                "InvalidIdentityToken",
                &format!("No OpenIDConnect provider found in your account for {iss}"),
            );
        };
        // 2. The token's audience must be in the provider's client ID list.
        if !provider.client_ids.contains(&aud) {
            return sts_error(400, "InvalidIdentityToken", "Incorrect token audience");
        }
        // 3. The role's trust policy must admit this provider, audience and
        //    subject. Anything else is a plain denial.
        let admitted = self
            .roles
            .iter()
            .any(|t| t.role_arn == role && t.host == host && t.aud == aud && t.sub == sub);
        if !admitted {
            return sts_error(
                403,
                "AccessDenied",
                "Not authorized to perform sts:AssumeRoleWithWebIdentity",
            );
        }
        let name = form.get("RoleSessionName").cloned().unwrap_or_default();
        let role_name = role.rsplit('/').next().unwrap_or_default();
        ResponseTemplate::new(200).set_body_raw(
            format!(
                r#"<?xml version="1.0"?>
<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <SubjectFromWebIdentityToken>{sub}</SubjectFromWebIdentityToken>
    <Audience>{aud}</Audience>
    <AssumedRoleUser>
      <Arn>arn:aws:sts::{ACCOUNT}:assumed-role/{role_name}/{name}</Arn>
      <AssumedRoleId>AROAEXAMPLE:{name}</AssumedRoleId>
    </AssumedRoleUser>
    <Provider>arn:aws:iam::{ACCOUNT}:oidc-provider/{host}</Provider>
    <Credentials>
      <SessionToken>session-token-value</SessionToken>
      <SecretAccessKey>secret-access-key-value</SecretAccessKey>
      <AccessKeyId>ASIAEXAMPLEKEY</AccessKeyId>
      <Expiration>2099-01-01T00:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
  <ResponseMetadata><RequestId>example-request-id</RequestId></ResponseMetadata>
</AssumeRoleWithWebIdentityResponse>
"#
            ),
            "text/xml",
        )
    }
}

/// The IAM configuration the document tells the operator to create: the two
/// OIDC providers (client ID `sts.amazonaws.com`) and the two roles' trust
/// policies.
fn good_account() -> MockSts {
    MockSts {
        providers: vec![
            IamOidcProvider {
                host: GITHUB_HOST,
                client_ids: vec![STS_AUDIENCE],
            },
            IamOidcProvider {
                host: EKS_HOST,
                client_ids: vec![STS_AUDIENCE],
            },
        ],
        roles: vec![
            Trust {
                role_arn: DEPLOY_ROLE,
                host: GITHUB_HOST,
                aud: STS_AUDIENCE,
                sub: JOB_SUBJECT,
            },
            Trust {
                role_arn: READER_ROLE,
                host: EKS_HOST,
                aud: STS_AUDIENCE,
                sub: POD_SUBJECT,
            },
        ],
    }
}

/// A JWT the mock reads and does not verify, which is all STS-side checking
/// the tests need; real AWS fetches the provider's keys and verifies it.
fn unsigned_token(iss: &str, sub: &str, aud: &str) -> String {
    let enc = |v: serde_json::Value| URL_SAFE_NO_PAD.encode(v.to_string());
    format!(
        "{}.{}.sig",
        enc(serde_json::json!({"alg": "RS256", "typ": "JWT"})),
        enc(serde_json::json!({"iss": iss, "sub": sub, "aud": aud}))
    )
}

fn token_file(contents: &str) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "axess-aws-walkthrough-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, contents).expect("write projected token");
    path
}

async fn sts_server(account: MockSts) -> (MockServer, AwsStsClient) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(account)
        .mount(&server)
        .await;
    let client = AwsStsClient::new()
        .expect("client")
        .with_endpoint(Url::parse(&server.uri()).unwrap());
    (server, client)
}

fn github_id_token(sub: &str, aud: &str) -> String {
    unsigned_token("https://token.actions.githubusercontent.com", sub, aud)
}

fn eks_token(iss_host: &str, sub: &str, aud: &str) -> String {
    unsigned_token(&format!("https://{iss_host}"), sub, aud)
}

fn expect_sts(err: AwsStsError, status: u16, code: &str, message: &str) {
    match err {
        AwsStsError::StsError {
            http_status,
            code: got,
            message: text,
            fault_type,
            ..
        } => {
            assert_eq!(http_status, status);
            assert_eq!(got, code);
            assert!(text.contains(message), "message was: {text}");
            assert_eq!(fault_type.as_deref(), Some("Sender"));
        }
        other => panic!("expected StsError, got {other:?}"),
    }
}

// ── The walkthrough, end to end ─────────────────────────────────────────────

#[tokio::test]
async fn job_assumes_the_deploy_role() {
    let (_server, sts) = sts_server(good_account()).await;
    let token = github_id_token(JOB_SUBJECT, STS_AUDIENCE);
    let out = job_assumes_deploy_role(&sts, &token).await.unwrap();
    assert_eq!(
        out.assumed_role_arn,
        "arn:aws:sts::123456789012:assumed-role/ledger-ci-deploy/ci-deploy"
    );
    assert_eq!(out.subject_from_web_identity_token, JOB_SUBJECT);
    assert_eq!(&*out.credentials.access_key_id, "ASIAEXAMPLEKEY");
}

struct Fixture {
    app: Router,
    pipeline_token: String,
    _server: MockServer,
}

async fn fixture(account: MockSts, pod_token: &str, pipeline_audience: &str) -> Fixture {
    let (server, sts) = sts_server(account).await;
    let (der, jwks) = common::rsa_keypair("pipe-1");
    let (now, exp) = common::now_and_exp();
    let pipeline_token = common::sign(
        &serde_json::json!({
            "iss": CALLER_ISSUER,
            "sub": "project_path:gnomes/ledger:ref_type:branch:ref:main",
            "aud": pipeline_audience,
            "exp": exp,
            "iat": now,
            "namespace_id": "1204",
            "namespace_path": "gnomes",
            "project_id": "4711",
            "project_path": "gnomes/ledger",
            "ref": "main",
            "ref_type": "branch",
            "ref_protected": "true",
            "environment": "production",
        }),
        "pipe-1",
        &der,
    );
    let svc = Service {
        verifier: common::build_verifier(jwks, CALLER_ISSUER, CALLER_AUDIENCE),
        trust: TrustDomain::new("pipelines").unwrap(),
        tenant: TenantId::from_bytes([7u8; 16]),
        sts,
        role_arn: READER_ROLE.into(),
        web_identity_token_file: token_file(pod_token),
    };
    Fixture {
        app: router(svc),
        pipeline_token,
        _server: server,
    }
}

async fn call(f: &Fixture) -> (StatusCode, String) {
    let reply = f
        .app
        .clone()
        .oneshot(
            Request::get("/ready")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", f.pipeline_token),
                )
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = reply.status();
    let bytes = axum::body::to_bytes(reply.into_body(), 64 * 1024)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

#[tokio::test]
async fn pipeline_calls_service_which_assumes_its_reader_role() {
    let pod = eks_token(EKS_HOST, POD_SUBJECT, STS_AUDIENCE);
    let f = fixture(good_account(), &pod, CALLER_AUDIENCE).await;
    let (status, body) = call(&f).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        "arn:aws:sts::123456789012:assumed-role/ledger-secret-reader/ledger"
    );
}

#[tokio::test]
async fn pipeline_token_for_another_audience_never_reaches_aws() {
    let pod = eks_token(EKS_HOST, POD_SUBJECT, STS_AUDIENCE);
    let f = fixture(good_account(), &pod, "some-other-service").await;
    let (status, body) = call(&f).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, "caller not recognised");
}

// ── The misconfigurations the document names ────────────────────────────────

#[tokio::test]
async fn trust_policy_sub_not_matching_the_job_is_access_denied() {
    // A job on a feature branch asks for the role whose trust policy names
    // `main`. The token is valid and its audience is right; the condition on
    // `:sub` refuses it.
    let (_server, sts) = sts_server(good_account()).await;
    let token = github_id_token("repo:gnomes/axess:ref:refs/heads/feature-x", STS_AUDIENCE);
    let err = job_assumes_deploy_role(&sts, &token).await.unwrap_err();
    expect_sts(
        err,
        403,
        "AccessDenied",
        "Not authorized to perform sts:AssumeRoleWithWebIdentity",
    );
}

#[tokio::test]
async fn token_audience_missing_from_the_provider_client_ids_is_invalid_identity_token() {
    // The workflow asked GitHub for an ID token with a custom `aud`; the IAM
    // provider only lists `sts.amazonaws.com` as a client ID.
    let (_server, sts) = sts_server(good_account()).await;
    let token = github_id_token(JOB_SUBJECT, "axess-platform");
    let err = job_assumes_deploy_role(&sts, &token).await.unwrap_err();
    expect_sts(err, 400, "InvalidIdentityToken", "Incorrect token audience");
}

#[tokio::test]
async fn issuer_without_an_iam_oidc_provider_is_invalid_identity_token() {
    // The cluster's issuer was never registered as an IAM OIDC provider (a
    // second cluster, or the provider was created for the wrong URL). The
    // service reports a bad gateway and the log carries the AWS message.
    let account = MockSts {
        providers: vec![IamOidcProvider {
            host: GITHUB_HOST,
            client_ids: vec![STS_AUDIENCE],
        }],
        roles: vec![],
    };
    let pod = eks_token(EKS_HOST, POD_SUBJECT, STS_AUDIENCE);
    let f = fixture(account, &pod, CALLER_AUDIENCE).await;
    let (status, body) = call(&f).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(body, "upstream identity exchange failed");

    let (_server, sts) = sts_server(MockSts {
        providers: vec![],
        roles: vec![],
    })
    .await;
    let err = sts
        .assume_role_with_web_identity(&AssumeRoleWithWebIdentityRequest::new(
            READER_ROLE,
            "ledger",
            pod,
        ))
        .await
        .unwrap_err();
    expect_sts(
        err,
        400,
        "InvalidIdentityToken",
        &format!("No OpenIDConnect provider found in your account for https://{EKS_HOST}"),
    );
}

// ── Startup ─────────────────────────────────────────────────────────────────

#[test]
fn sts_client_reads_the_variables_the_webhook_injects() {
    let env: HashMap<&str, &str> = [
        ("AWS_ROLE_ARN", READER_ROLE),
        (
            "AWS_WEB_IDENTITY_TOKEN_FILE",
            "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
        ),
        ("AWS_REGION", "eu-central-1"),
    ]
    .into();
    let (sts, role, file) = Service::sts_from_env(|k| env.get(k).map(|v| v.to_string())).unwrap();
    assert_eq!(
        sts.endpoint().as_str(),
        "https://sts.eu-central-1.amazonaws.com/"
    );
    assert_eq!(role, READER_ROLE);
    assert_eq!(
        file,
        PathBuf::from("/var/run/secrets/eks.amazonaws.com/serviceaccount/token")
    );
    assert!(Service::sts_from_env(|_| None).is_none());
}
