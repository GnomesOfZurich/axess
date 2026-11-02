//! The Azure walkthrough (`docs/workload-identity/azure.md`), compiled.
//!
//! A pipeline job calls a Rust service protected by axess; the service, under
//! Azure workload identity federation, exchanges its own projected token
//! through `AzureFicClient` and reads a secret from Key Vault. Azure AD and
//! Key Vault are wiremock servers; the mock Azure AD holds the federated
//! identity credential the document tells the operator to create, and answers
//! the way Azure documents when a presented assertion does not match it, so
//! each misconfiguration the document names is reproduced here.
//!
//! The error codes and descriptions below are the ones Microsoft documents
//! (AADSTS70021, AADSTS700211, AADSTS700212, AADSTS70011). The mock was
//! written from that documentation, not recorded from a live tenant.

mod common;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axess::workload::outbound::cloud_sts::azure::{
    AzureFicClient, AzureFicError, AzureFicRequest, AzureFicResponse,
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
use wiremock::matchers::{header as header_is, method, path, query_param};
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

const TENANT: &str = "11111111-aaaa-bbbb-cccc-000000000001";
const CLIENT_ID: &str = "22222222-aaaa-bbbb-cccc-000000000002";
const AKS_ISSUER: &str = "https://westeurope.oic.prod-aks.azure.com/11111111-aaaa-bbbb-cccc-000000000001/aaaaaaaa-0000-0000-0000-000000000009/";
const POD_SUBJECT: &str = "system:serviceaccount:payments:ledger";
const EXCHANGE_AUDIENCE: &str = "api://AzureADTokenExchange";
const VAULT_SCOPE: &str = "https://vault.azure.net/.default";

// ANCHOR: service
/// What the service holds. Built once at startup.
#[derive(Clone)]
struct Service {
    verifier: Arc<JwtVerifier>,
    trust: TrustDomain,
    tenant: TenantId,
    fic: AzureFicClient,
    federated_token_file: PathBuf,
    vault: Url,
    http: reqwest::Client,
}

impl Service {
    /// The three variables the AKS workload identity webhook injects into a
    /// pod labelled `azure.workload.identity/use: "true"`.
    fn fic_from_env(env: impl Fn(&str) -> Option<String>) -> Option<(AzureFicClient, PathBuf)> {
        let tenant = env("AZURE_TENANT_ID")?;
        let client_id = env("AZURE_CLIENT_ID")?;
        let token_file = PathBuf::from(env("AZURE_FEDERATED_TOKEN_FILE")?);
        Some((
            AzureFicClient::new(tenant, client_id).expect("client"),
            token_file,
        ))
    }
}

/// `GET /secret`: authenticate the caller, then read the secret as the
/// service's own identity.
async fn read_secret(
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
    let token = vault_token(&svc).await.map_err(|e| {
        tracing::error!(error = %e, "Azure AD refused the federated exchange");
        (StatusCode::BAD_GATEWAY, "upstream identity exchange failed")
    })?;

    // 3. Read the secret with the Azure AD access token.
    let mut url = svc.vault.join("secrets/db-password").expect("secret URL");
    url.set_query(Some("api-version=7.4"));
    let reply = svc
        .http
        .get(url)
        .bearer_auth(&*token.access_token)
        .send()
        .await
        .map_err(|_| (StatusCode::BAD_GATEWAY, "key vault unreachable"))?;
    if !reply.status().is_success() {
        return Err((StatusCode::BAD_GATEWAY, "key vault refused the read"));
    }
    let body: serde_json::Value = reply
        .json()
        .await
        .map_err(|_| (StatusCode::BAD_GATEWAY, "key vault answer malformed"))?;
    body["value"]
        .as_str()
        .map(str::to_owned)
        .ok_or((StatusCode::BAD_GATEWAY, "key vault answer malformed"))
}

/// The exchange: the projected token in, a Key Vault access token out. The
/// file is read on every call because the kubelet rotates it.
async fn vault_token(svc: &Service) -> Result<AzureFicResponse, AzureFicError> {
    let assertion = tokio::fs::read_to_string(&svc.federated_token_file)
        .await
        .map_err(|e| AzureFicError::Transport(format!("federated token file: {e}")))?;
    svc.fic
        .acquire_token(&AzureFicRequest::new(assertion.trim()).with_scope(VAULT_SCOPE))
        .await
}

fn router(svc: Service) -> Router {
    Router::new()
        .route("/secret", get(read_secret))
        .with_state(svc)
}
// ANCHOR_END: service

// ── The mock Azure AD ───────────────────────────────────────────────────────

/// A federated identity credential as the portal or `az identity
/// federated-credential create` records it.
#[derive(Clone)]
struct FederatedCredential {
    issuer: String,
    subject: String,
    audience: String,
}

/// Azure AD's token endpoint with one federated credential on one app. It
/// reads the assertion's `iss`, `sub` and `aud` and compares them to the
/// credential, as Azure does after verifying the signature (which the mock
/// does not).
struct MockAzureAd {
    credential: FederatedCredential,
}

fn aad_error(status: u16, error: &str, code: u64, text: &str) -> ResponseTemplate {
    ResponseTemplate::new(status).set_body_json(serde_json::json!({
        "error": error,
        "error_description": format!("AADSTS{code}: {text}"),
        "error_codes": [code],
        "correlation_id": "6f1f9d0e-0000-4000-8000-0123456789ab",
    }))
}

impl Respond for MockAzureAd {
    fn respond(&self, req: &MockRequest) -> ResponseTemplate {
        let form: HashMap<String, String> = url::form_urlencoded::parse(&req.body)
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        let assertion = form.get("client_assertion").cloned().unwrap_or_default();
        let claims: serde_json::Value = assertion
            .split('.')
            .nth(1)
            .and_then(|p| URL_SAFE_NO_PAD.decode(p).ok())
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let iss = claims["iss"].as_str().unwrap_or_default();
        let sub = claims["sub"].as_str().unwrap_or_default();
        let aud = claims["aud"].as_str().unwrap_or_default();

        let scope = form.get("scope").map(String::as_str).unwrap_or_default();
        if !scope.ends_with("/.default") {
            return aad_error(
                400,
                "invalid_scope",
                70011,
                &format!(
                    "The provided request must include a 'scope' input parameter. The provided \
                     value for the input parameter 'scope' is not valid: '{scope}'. The scope \
                     must end in '/.default' for a client_credentials request."
                ),
            );
        }
        let c = &self.credential;
        if iss != c.issuer {
            return aad_error(
                401,
                "invalid_client",
                700211,
                &format!(
                    "No matching federated identity record found for presented assertion \
                     issuer '{iss}'. Please check the federated identity credential \
                     configuration."
                ),
            );
        }
        if aud != c.audience {
            return aad_error(
                401,
                "invalid_client",
                700212,
                &format!(
                    "No matching federated identity record found for presented assertion \
                     audience '{aud}'. Please check the federated identity credential \
                     configuration."
                ),
            );
        }
        if sub != c.subject {
            return aad_error(
                401,
                "invalid_client",
                70021,
                &format!(
                    "No matching federated identity record found for presented assertion. \
                     Assertion Issuer: '{iss}'. Assertion Subject: '{sub}'. Assertion \
                     Audience: '{aud}'."
                ),
            );
        }
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "aad-token-for-key-vault",
            "token_type": "Bearer",
            "expires_in": 3599,
        }))
    }
}

/// An unsigned-looking JWT: the mock reads the claims and does not verify
/// the signature, and the service never verifies its own projected token.
fn projected_token(iss: &str, sub: &str, aud: &str) -> String {
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
        "axess-azure-walkthrough-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, contents).expect("write projected token");
    path
}

/// The federated credential the document creates for the service's pod.
fn good_credential() -> FederatedCredential {
    FederatedCredential {
        issuer: AKS_ISSUER.into(),
        subject: POD_SUBJECT.into(),
        audience: EXCHANGE_AUDIENCE.into(),
    }
}

struct Fixture {
    app: Router,
    pipeline_token: String,
    // Held so the mocks outlive the test and verify their expectations.
    _ad: MockServer,
    _vault: MockServer,
}

/// Wire the mock Azure AD (with `credential` configured) and a mock Key
/// Vault. `vault_reads` is how many reads the vault must see.
async fn fixture(
    credential: FederatedCredential,
    pod_token: &str,
    vault_reads: u64,
    pipeline_audience: &str,
) -> Fixture {
    let ad = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/{TENANT}/oauth2/v2.0/token")))
        .respond_with(MockAzureAd { credential })
        .mount(&ad)
        .await;

    let vault = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/secrets/db-password"))
        .and(query_param("api-version", "7.4"))
        .and(header_is("authorization", "Bearer aad-token-for-key-vault"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": "correct-horse-battery",
            "id": "https://ledger-kv.vault.azure.net/secrets/db-password/0001",
        })))
        .expect(vault_reads)
        .mount(&vault)
        .await;

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

    let fic = AzureFicClient::new(TENANT, CLIENT_ID)
        .expect("client")
        .with_token_endpoint(
            Url::parse(&format!("{}/{TENANT}/oauth2/v2.0/token", ad.uri())).unwrap(),
        );
    let svc = Service {
        verifier: common::build_verifier(jwks, CALLER_ISSUER, CALLER_AUDIENCE),
        trust: TrustDomain::new("pipelines").unwrap(),
        tenant: TenantId::from_bytes([7u8; 16]),
        fic,
        federated_token_file: token_file(pod_token),
        vault: Url::parse(&format!("{}/", vault.uri())).unwrap(),
        http: reqwest::Client::new(),
    };
    Fixture {
        app: router(svc),
        pipeline_token,
        _ad: ad,
        _vault: vault,
    }
}

async fn call(f: &Fixture) -> (StatusCode, String) {
    let reply = f
        .app
        .clone()
        .oneshot(
            Request::get("/secret")
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

/// The exchange alone, against the same mock, to read the adapter's error.
async fn exchange_error(
    credential: FederatedCredential,
    pod_token: &str,
    scope: &str,
) -> AzureFicError {
    let ad = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/{TENANT}/oauth2/v2.0/token")))
        .respond_with(MockAzureAd { credential })
        .mount(&ad)
        .await;
    let fic = AzureFicClient::new(TENANT, CLIENT_ID)
        .expect("client")
        .with_token_endpoint(
            Url::parse(&format!("{}/{TENANT}/oauth2/v2.0/token", ad.uri())).unwrap(),
        );
    fic.acquire_token(&AzureFicRequest::new(pod_token).with_scope(scope))
        .await
        .expect_err("the misconfiguration must be refused")
}

fn expect_aad(err: AzureFicError, status: u16, error: &str, code: u64) {
    match err {
        AzureFicError::AzureError {
            http_status,
            error: got,
            error_description,
            error_codes,
            ..
        } => {
            assert_eq!(http_status, status);
            assert_eq!(got, error);
            assert_eq!(error_codes, vec![code]);
            assert!(
                error_description.starts_with(&format!("AADSTS{code}:")),
                "description was: {error_description}"
            );
        }
        other => panic!("expected AzureError, got {other:?}"),
    }
}

// ── The walkthrough, end to end ─────────────────────────────────────────────

#[tokio::test]
async fn pipeline_calls_service_which_reads_the_secret() {
    let pod = projected_token(AKS_ISSUER, POD_SUBJECT, EXCHANGE_AUDIENCE);
    let f = fixture(good_credential(), &pod, 1, CALLER_AUDIENCE).await;
    let (status, body) = call(&f).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "correct-horse-battery");
}

#[tokio::test]
async fn pipeline_token_for_another_audience_never_reaches_azure() {
    // The pipeline asked GitLab for an ID token with the wrong `aud`. The
    // service refuses it before the exchange; the vault sees no read.
    let pod = projected_token(AKS_ISSUER, POD_SUBJECT, EXCHANGE_AUDIENCE);
    let f = fixture(good_credential(), &pod, 0, "some-other-service").await;
    let (status, body) = call(&f).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, "caller not recognised");
}

// ── The misconfigurations the document names ────────────────────────────────

#[tokio::test]
async fn credential_subject_not_the_service_account_is_70021() {
    // The federated credential was created for another service account.
    let credential = FederatedCredential {
        subject: "system:serviceaccount:payments:billing".into(),
        ..good_credential()
    };
    let pod = projected_token(AKS_ISSUER, POD_SUBJECT, EXCHANGE_AUDIENCE);
    expect_aad(
        exchange_error(credential.clone(), &pod, VAULT_SCOPE).await,
        401,
        "invalid_client",
        70021,
    );
    // And the service reports a bad gateway, never the vault's secret.
    let f = fixture(credential, &pod, 0, CALLER_AUDIENCE).await;
    let (status, body) = call(&f).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(body, "upstream identity exchange failed");
}

#[tokio::test]
async fn credential_audience_not_the_exchange_audience_is_700212() {
    // The pod's token carries the audience the cluster was given, not the
    // one the credential was created with.
    let pod = projected_token(AKS_ISSUER, POD_SUBJECT, "sts.amazonaws.com");
    expect_aad(
        exchange_error(good_credential(), &pod, VAULT_SCOPE).await,
        401,
        "invalid_client",
        700212,
    );
}

#[tokio::test]
async fn credential_issuer_not_the_cluster_issuer_is_700211() {
    // The credential names the issuer URL of another cluster.
    let credential = FederatedCredential {
        issuer: "https://westeurope.oic.prod-aks.azure.com/other/other/".into(),
        ..good_credential()
    };
    let pod = projected_token(AKS_ISSUER, POD_SUBJECT, EXCHANGE_AUDIENCE);
    expect_aad(
        exchange_error(credential, &pod, VAULT_SCOPE).await,
        401,
        "invalid_client",
        700211,
    );
}

#[tokio::test]
async fn scope_without_default_suffix_is_70011() {
    let pod = projected_token(AKS_ISSUER, POD_SUBJECT, EXCHANGE_AUDIENCE);
    expect_aad(
        exchange_error(good_credential(), &pod, "https://vault.azure.net").await,
        400,
        "invalid_scope",
        70011,
    );
}

// ── Startup ─────────────────────────────────────────────────────────────────

#[test]
fn fic_client_reads_the_variables_the_webhook_injects() {
    let env: HashMap<&str, &str> = [
        ("AZURE_TENANT_ID", TENANT),
        ("AZURE_CLIENT_ID", CLIENT_ID),
        (
            "AZURE_FEDERATED_TOKEN_FILE",
            "/var/run/secrets/azure/tokens/azure-identity-token",
        ),
    ]
    .into();
    let (fic, file) = Service::fic_from_env(|k| env.get(k).map(|v| v.to_string())).unwrap();
    assert_eq!(fic.client_id(), CLIENT_ID);
    assert_eq!(
        fic.token_endpoint().as_str(),
        format!("https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token")
    );
    assert_eq!(
        file,
        PathBuf::from("/var/run/secrets/azure/tokens/azure-identity-token")
    );
    // A pod without the label has none of the variables: no client.
    assert!(Service::fic_from_env(|_| None).is_none());
}
