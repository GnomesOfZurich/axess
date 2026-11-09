//! # axess-example-fapi
//!
//! FAPI 2.0 (Financial-grade API) example for the Axess library.
//!
//! Demonstrates the FAPI 2.0 Baseline Security Profile:
//! - `private_key_jwt` client authentication; the client signs an assertion,
//!   no shared secret (FAPI 2.0 allows this or mTLS, never a secret)
//! - Pushed Authorization Requests (PAR); auth params sent server-to-server
//! - DPoP sender-constrained tokens; tokens bound to ephemeral key pair
//! - Form Post response mode; authorization code via POST, not URL query
//! - A DPoP-bound refresh with the login's key
//! - RP-Initiated Logout with id_token_hint
//! - Token revocation on logout
//!
//! ## Dual-mode operation
//!
//! **Mock mode (opt-in):** `FAPI_MOCK=1` runs an in-process mock OIDC server
//! that accepts any code and signs in as a seeded user. Zero setup, no
//! external dependencies, never for a deployment. Without `FAPI_ISSUER` and
//! without `FAPI_MOCK=1` the example refuses to start.
//!
//! ```sh
//! FAPI_MOCK=1 cargo run -p axess-example-fapi
//! ```
//!
//! **Live mode:** Set environment variables to connect to a real FAPI-compliant IdP.
//! See README.md for the Keycloak-in-podman setup (one command, pre-configured realm).
//!
//! ```sh
//! export FAPI_ISSUER=https://keycloak.local/realms/fapi
//! export FAPI_CLIENT_ID=axess-fapi-client
//! export FAPI_PRIVATE_KEY_FILE=/path/to/client-key.pem
//! cargo run -p axess-example-fapi
//! ```
//!
//! `FAPI_PRIVATE_KEY_FILE` names the PEM private key the client signs its
//! assertions with (`FAPI_PRIVATE_KEY_ALG`, default `ES256`;
//! `FAPI_PRIVATE_KEY_KID` sets the assertion's `kid`). Without it, and only
//! for an issuer on `localhost` or `127.0.0.1`, the example signs with the
//! development key in `keycloak/dev-client-key.pem`, which the bundled
//! Keycloak realm registers and nothing else accepts. Any other issuer
//! requires `FAPI_PRIVATE_KEY_FILE`.
//!
//! ## Endpoints
//!
//! - `GET  /`; home page with login link
//! - `GET  /auth/login`; initiates FAPI login (PAR → redirect to IdP)
//! - `POST /auth/callback`; handles IdP callback (form_post mode only; there
//!   is no query-mode `GET` callback)
//! - `GET  /profile`; the signed-in user and the key the tokens are bound to
//! - `POST /auth/refresh`; refreshes the tokens with a DPoP proof
//! - `POST /auth/logout`; RP-Initiated Logout (revoke tokens, redirect to IdP)

use axess::authn::{
    AuditContext, AuthnService, EntityState, IdentityAdmin, IdentityLookup, Tenant, TenantId, User,
    UserId,
};
use axess::federation::oauth::{
    ClientAssertionSigner, DpopKey, FapiConfig, OAuthClaims, OAuthLoginOptions,
    OAuthProviderConfig, ResponseMode, SenderConstraint,
};
use axess::testing::{MockFactorStore, MockIdentityStore};
use axess::{
    AuthSession, Clock, KeyExtractor, MemorySessionRegistry, MemorySessionStore, RateLimitConfig,
    RateLimitLayer, SecureRng, SessionLayer, SessionRegistryAdapter, SessionStore, SystemClock,
    SystemRng,
};
use axum::{
    Form, Router,
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
};
use jsonwebtoken::Algorithm;
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

/// Session limits tighter than the library's defaults (24 hours idle, 7 days
/// in all), as a bank would set them; the README says why.
const STRICT_IDLE_TTL: Duration = Duration::from_secs(15 * 60);
const STRICT_MAX_SESSION_AGE: Duration = Duration::from_secs(10 * 60 * 60);

type Service = AuthnService<MockIdentityStore, MockFactorStore>;

/// The address the example serves and the IdP sends the browser back to.
/// It is `localhost`, not `127.0.0.1`: the session cookie belongs to one host
/// name, and the redirect URI, the post-logout redirect and the address the
/// browser starts at must all name the same one, or the callback arrives
/// without the cookie and finds no login to finish. Keycloak runs on
/// `localhost` too, so its `form_post` is a same-site POST and the default
/// `SameSite=Lax` cookie goes with it.
const APP_ORIGIN: &str = "http://localhost:3000";

/// Session keys for what the login leaves behind for the refresh and the
/// logout: the ID token (the `id_token_hint` of RP-initiated logout), the
/// refresh token, the subject and nonce a refresh is checked against, and the
/// DPoP key the tokens are bound to. A production application keeps the
/// refresh token and the key sealed in its own store, not in the session;
/// the example's session store is memory and so are they.
const SESSION_ID_TOKEN_HINT: &str = "fapi.id_token_hint";
const SESSION_REFRESH_TOKEN: &str = "fapi.refresh_token";
const SESSION_SUBJECT: &str = "fapi.subject";
const SESSION_NONCE: &str = "fapi.nonce";
const SESSION_DPOP_KEY: &str = "fapi.dpop_key";

#[derive(Clone)]
struct AppState {
    authn: Arc<Service>,
    identity: MockIdentityStore,
    tenant: TenantId,
    /// The tenant policy: the e-mail domains whose identities may be created
    /// as local users. An identity outside them is refused, not provisioned.
    allowed_email_domains: Vec<String>,
    provider_name: String,
    post_logout_redirect: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(EnvFilter::new(std::env::var("RUST_LOG").unwrap_or_else(
            |_| "axess_example_fapi=debug,axess=debug".into(),
        )))
        .with(tracing_subscriber::fmt::layer())
        .try_init()?;

    let mode = run_mode(
        std::env::var("FAPI_ISSUER").ok().as_deref(),
        std::env::var("FAPI_MOCK").ok().as_deref(),
    )?;
    let is_live = matches!(mode, Mode::Live);

    // The tenant the IdP's users are created in. A real application reads it
    // from its tenant table; the in-memory store is seeded here.
    let tenant = TenantId::new(&SystemRng);
    let identity = MockIdentityStore::new().with_tenant(Tenant::new(
        tenant.to_string(),
        "fapi-example",
        "FAPI example tenant",
        EntityState::Active,
        UserId::system(),
        SystemClock.now(),
    )?);
    let registry = MemorySessionRegistry::new();
    let builder = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_registry(registry.clone());

    let (authn, provider_name) = if is_live {
        let (provider, name) = build_live_provider().await?;
        (builder.with_oauth_provider(provider).build(), name)
    } else {
        let (provider, name) = build_mock_provider();
        (builder.with_oauth_provider(provider).build(), name)
    };

    let session_store = MemorySessionStore::new();
    // Logins that were started and never finished, and sessions that ran out,
    // stay in the store until it is pruned. A persistent store is pruned the
    // same way.
    {
        let store = session_store.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                tick.tick().await;
                match store.prune_expired().await {
                    Ok(n) if n > 0 => info!(pruned = n, "expired sessions pruned"),
                    Ok(_) => {}
                    Err(e) => tracing::warn!(error = %e, "session prune failed"),
                }
            }
        });
    }
    // `axess::SystemRng` routes through the foundation crate's RNG
    // abstraction (same path the library uses internally), so the example
    // models the pattern adopters should copy instead of teaching `rand::*`.
    let mut signing_key = [0u8; 32];
    SystemRng.fill_bytes(&mut signing_key);
    // The `form_post` callback is a cross-site POST from the provider. Here the
    // provider is on localhost, which counts as the same site, so the default
    // `SameSite=Lax` cookie is sent. Against a provider on another site the
    // browser withholds a `Lax` cookie from that POST and the callback finds no
    // session: use `.with_same_site(SameSite::None)` there, which browsers
    // accept only together with `Secure` (so keep cookies `Secure`). That
    // switch also lets a cross-site page send the cookie with a forged `POST`;
    // refresh and logout stay safe only through `same_origin_only`, so keep it.
    // A session the registry no longer holds (a logout, a forced logout) is
    // refused on its next request.
    let session_layer = SessionLayer::new(
        session_store,
        signing_key,
        Arc::new(SessionRegistryAdapter(registry)),
    )
    .with_ttl(STRICT_IDLE_TTL)
    .with_max_session_age(Some(STRICT_MAX_SESSION_AGE))
    .with_secure(secure_cookies());

    let allowed_email_domains = if is_live {
        parse_domains(&std::env::var("FAPI_ALLOWED_EMAIL_DOMAINS").map_err(|_| {
            "FAPI_ALLOWED_EMAIL_DOMAINS is required: the e-mail domains \
                 (comma separated) whose identities may sign up"
        })?)
    } else {
        vec!["bank.example.com".to_string()]
    };
    let state = AppState {
        authn: Arc::new(authn),
        identity,
        tenant,
        allowed_email_domains,
        provider_name,
        post_logout_redirect: format!("{APP_ORIGIN}/"),
    };

    let app = routes().with_state(state).layer(session_layer);

    // Resolve the client address once, outside everything that reads one.
    // A FAPI deployment sits behind a TLS terminator, so name that
    // terminator's ranges with `TrustedProxies::from_cidrs` rather than
    // trusting loopback as this local example does.
    let app = axess::client_ip::layer(app, axess::client_ip::TrustedProxies::loopback_only());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    info!("Listening on 127.0.0.1:3000; open {APP_ORIGIN}");
    if !is_live {
        tracing::warn!(
            "Running in MOCK mode: the mock IdP accepts any code. Never run it \
             where others can reach it; set FAPI_ISSUER to use a real IdP"
        );
    }
    // `with_connect_info` is what puts the peer address where the
    // client-IP layer can read it.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;

    Ok(())
}

/// Logins one client address may start per window. `/auth/login` pushes an
/// authorization request to the IdP (server to server) and opens a session
/// with a pending login, so an unthrottled caller costs the IdP and the store.
const LOGIN_LIMIT: u32 = 10;
const LOGIN_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);

/// A per-client-address limit for `/auth/login`. It keys on the address
/// `axess::client_ip::layer` resolves (installed outside everything in
/// `main`); without that layer every request shares one bucket, which limits
/// harder, not less. A deployment behind several replicas needs a limit at
/// the edge as well, since this one counts per process.
fn login_limiter() -> RateLimitLayer {
    RateLimitLayer::new(
        RateLimitConfig::builder()
            .max_requests(LOGIN_LIMIT)
            .window(LOGIN_WINDOW)
            .key(KeyExtractor::ClientIp)
            .build(),
    )
}

/// The example's routes. The callback is `POST` only: the login asks for
/// `form_post`, so a code in a URL query is never expected and never accepted.
fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(home))
        .route("/auth/login", get(login).route_layer(login_limiter()))
        .route("/auth/callback", post(callback_post))
        .route("/profile", get(profile))
        .merge(
            // The callback is a cross-site POST by design and is protected by
            // `state`; refresh and logout are the application's own forms.
            Router::new()
                .route("/auth/refresh", post(refresh))
                .route("/auth/logout", post(logout))
                .route_layer(axum::middleware::from_fn(same_origin_only)),
        )
}

/// Whether the `Origin` (or, without one, `Sec-Fetch-Site`) names the app.
fn origin_allowed(headers: &axum::http::HeaderMap) -> bool {
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    match (header("origin"), header("sec-fetch-site")) {
        (Some(origin), _) => origin == APP_ORIGIN,
        (None, Some(site)) => site == "same-origin",
        (None, None) => false,
    }
}

/// Refuse a state-changing request that does not come from the application's
/// own origin. A browser sends `Origin` with every `POST`; `Sec-Fetch-Site`
/// is the fallback for one that omits it. A request with neither is not a
/// browser form and is refused too.
///
/// The session cookie is `SameSite=Lax`, which already keeps it off a
/// cross-site `POST`. Switching to `SameSite=None` (the comment at the
/// session layer says when a cross-site IdP needs it) takes that protection
/// away, and this check is what keeps refresh and logout from being forgeable
/// then.
async fn same_origin_only(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let ok = origin_allowed(req.headers());
    if !ok {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "cross-origin request refused",
        )
            .into_response();
    }
    next.run(req).await
}

// ── Mock mode ──────────────────────────────────────────────────────────────

/// Which identity provider the process talks to.
#[derive(Debug, PartialEq, Eq)]
enum Mode {
    Live,
    Mock,
}

/// Decide the mode from `FAPI_ISSUER` and `FAPI_MOCK`. The mock IdP accepts
/// any code, so it runs only when asked for with `FAPI_MOCK=1`: an unset or
/// misspelled `FAPI_ISSUER` is an error, not a silent mock.
fn run_mode(issuer: Option<&str>, mock: Option<&str>) -> Result<Mode, String> {
    let issuer = issuer.filter(|i| !i.is_empty());
    let mock = mock == Some("1");
    match (issuer, mock) {
        (Some(_), false) => Ok(Mode::Live),
        (None, true) => Ok(Mode::Mock),
        (Some(_), true) => Err("FAPI_ISSUER and FAPI_MOCK=1 are both set; choose one".to_string()),
        (None, false) => Err(
            "FAPI_ISSUER is not set. Set it to a FAPI-compliant issuer, or set \
             FAPI_MOCK=1 to run the mock IdP (which accepts any code; local use only)"
                .to_string(),
        ),
    }
}

fn build_mock_provider() -> (axess::testing::MockOAuthProvider, String) {
    use axess::testing::MockOAuthProvider;

    info!("Building mock FAPI service (no external IdP)");

    let mock = MockOAuthProvider::new("fapi-mock")
        .with_issuer("https://fapi-mock.example.com")
        .with_client_id("mock-fapi-client")
        .with_user(
            "user-001",
            "alice@bank.example.com",
            vec!["finance-team"],
            vec!["portfolio-viewer"],
        );

    // Note: MockOAuthProvider doesn't have a PAR endpoint, so FAPI enforcement
    // can't be applied. In mock mode we demonstrate the API surface without
    // the full PAR→redirect→callback round trip.
    info!("Mock mode: PAR and DPoP are shown in code but not exercised end-to-end");
    info!("Mock mode: Set FAPI_ISSUER instead of FAPI_MOCK to test against a real FAPI IdP");

    (mock, "fapi-mock".to_string())
}

// ── Live mode ──────────────────────────────────────────────────────────────

fn missing_live_creds() -> ! {
    tracing::error!(
        "missing FAPI_CLIENT_ID; this example runs a real FAPI RP flow against \
         an external OP. Quick start: (1) bring up the bundled Keycloak realm \
         from examples/fapi/keycloak, (2) export FAPI_ISSUER and \
         FAPI_CLIENT_ID=axess-fapi-client (the client signs with the bundled \
         development key unless FAPI_PRIVATE_KEY_FILE names another), (3) \
         re-run cargo run -p axess-example-fapi. See examples/fapi/README.md \
         for the full setup."
    );
    std::process::exit(2);
}

/// The development key the bundled Keycloak realm registers for
/// `axess-fapi-client` (its public half is the realm's `jwks.string`). It is
/// published with the source, so it authenticates to that local realm and
/// must never be registered anywhere else.
const DEV_CLIENT_KEY_PEM: &str = include_str!("../keycloak/dev-client-key.pem");

/// The `kid` the realm registers the development key under.
const DEV_CLIENT_KEY_ID: &str = "axess-fapi-dev";

/// The key the client signs its `private_key_jwt` assertions with.
struct ClientKey {
    pem: String,
    algorithm: Algorithm,
    key_id: Option<String>,
}

impl ClientKey {
    /// `FAPI_PRIVATE_KEY_FILE` (with `FAPI_PRIVATE_KEY_ALG`, default `ES256`,
    /// and `FAPI_PRIVATE_KEY_KID`), or the development key when it is unset
    /// and `issuer` is a local one. The development key is published with the
    /// source, so no other issuer may be given it.
    fn from_env(issuer: &str) -> Result<Self, String> {
        Self::load(issuer, std::env::var("FAPI_PRIVATE_KEY_FILE").ok())
    }

    fn load(issuer: &str, file: Option<String>) -> Result<Self, String> {
        let Some(path) = file else {
            if !is_local_issuer(issuer) {
                return Err("FAPI_PRIVATE_KEY_FILE is required for non-local issuers".to_string());
            }
            tracing::warn!(
                "FAPI_PRIVATE_KEY_FILE is not set: signing with the published \
                 development key, which only the bundled Keycloak realm accepts"
            );
            return Ok(Self::development());
        };
        let pem = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read FAPI_PRIVATE_KEY_FILE {path}: {e}"))?;
        let algorithm = std::env::var("FAPI_PRIVATE_KEY_ALG")
            .unwrap_or_else(|_| "ES256".to_string())
            .parse()
            .map_err(|e| format!("FAPI_PRIVATE_KEY_ALG: {e}"))?;
        Ok(Self {
            pem,
            algorithm,
            key_id: std::env::var("FAPI_PRIVATE_KEY_KID").ok(),
        })
    }

    fn development() -> Self {
        Self {
            pem: DEV_CLIENT_KEY_PEM.to_string(),
            algorithm: Algorithm::ES256,
            key_id: Some(DEV_CLIENT_KEY_ID.to_string()),
        }
    }

    /// The signer for `client_id`. FAPI 2.0 signs with `PS256`, `ES256` or
    /// `EdDSA`.
    fn signer(&self, client_id: &str) -> Result<ClientAssertionSigner, String> {
        let signer = ClientAssertionSigner::from_pem(client_id, &self.pem, self.algorithm)
            .map_err(|e| e.to_string())?;
        Ok(match &self.key_id {
            Some(kid) => signer.with_key_id(kid),
            None => signer,
        })
    }
}

/// Whether the issuer's host is `localhost` or `127.0.0.1`: the only issuers
/// the published development key may sign for. The issuer is parsed the way
/// an HTTP client parses it, so what is judged is the host that would be
/// connected to, not a guess at where the host ends.
fn is_local_issuer(issuer: &str) -> bool {
    let Ok(url) = url::Url::parse(issuer) else {
        return false;
    };
    matches!(url.scheme(), "http" | "https")
        && url
            .host_str()
            .is_some_and(|host| host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1")
}

async fn build_live_provider() -> Result<(OAuthProviderConfig, String), Box<dyn std::error::Error>>
{
    let issuer = std::env::var("FAPI_ISSUER")?;
    let client_id = std::env::var("FAPI_CLIENT_ID").unwrap_or_else(|_| missing_live_creds());
    let signer = ClientKey::from_env(&issuer)?.signer(&client_id)?;
    let provider_name = std::env::var("FAPI_PROVIDER_NAME").unwrap_or_else(|_| "fapi".to_string());

    info!("Discovering OIDC configuration from {issuer}...");
    // FAPI 2.0 authenticates the client by private_key_jwt or mTLS, never a
    // client secret, and `build` refuses a provider that would send one.
    // The assertion is signed for the issuer as audience.
    let provider = OAuthProviderConfig::discover_with_private_key_jwt(
        &provider_name,
        &issuer,
        signer,
        &format!("{APP_ORIGIN}/auth/callback"),
    )
    .await?
    // Without this list the logout redirect below is dropped: only an exact
    // match is forwarded to the IdP.
    .with_allowed_post_logout_redirect_uris([format!("{APP_ORIGIN}/")])
    // The token request carries a DPoP proof, and the key it is signed with
    // comes back in the claims. ID tokens must be signed with PS256, ES256
    // or EdDSA: widen `allowed_id_token_algs` only for an IdP that cannot.
    .with_fapi(FapiConfig {
        sender_constraint: SenderConstraint::DPoP,
        ..FapiConfig::default()
    })
    .build()?;
    info!("OIDC discovery complete; FAPI 2.0 profile enabled");

    Ok((provider, provider_name))
}

// ── Handlers ───────────────────────────────────────────────────────────────

async fn home() -> Html<&'static str> {
    Html(
        r#"<!doctype html>
<html><head><title>FAPI 2.0 Example</title></head><body>
<h1>Axess FAPI 2.0 Example</h1>
<p>Financial-grade API security profile: private_key_jwt + PAR + DPoP + form_post.</p>
<ul>
  <li><a href="/auth/login">Login (FAPI flow)</a></li>
  <li><a href="/profile">Profile</a> (requires login)</li>
</ul>
</body></html>"#,
    )
}

/// Initiate the FAPI login flow.
///
/// When FAPI is enabled on the provider, `begin_oauth_login` automatically:
/// 1. Pushes authorization parameters to the PAR endpoint (server-to-server)
/// 2. Gets back a `request_uri`
/// 3. Redirects the user to the IdP with only `client_id` + `request_uri`
///
/// We also request `response_mode=form_post` so the authorization code comes
/// back via POST body, not URL query params, and `offline_access` so the IdP
/// issues a refresh token.
async fn login(
    axum::extract::State(state): axum::extract::State<AppState>,
    session: AuthSession,
) -> impl IntoResponse {
    let options = OAuthLoginOptions::new()
        .response_mode(ResponseMode::FormPost)
        .extra_scope("offline_access");

    match state
        .authn
        .begin_oauth_login(&state.provider_name, &options, &session)
        .await
    {
        Ok((auth_url, _csrf)) => {
            info!("Redirecting to IdP (PAR-backed authorization URL)");
            Redirect::temporary(auth_url.as_str()).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "begin_oauth_login failed");
            Html(
                r#"<h1>Login Error</h1><p>Could not start the login.</p><p><a href="/">Back</a></p>"#,
            )
            .into_response()
        }
    }
}

/// Callback parameters, from the `form_post` body.
#[derive(Deserialize)]
struct CallbackParams {
    code: String,
    state: String,
    /// The issuer of the authorization response (RFC 9207), which the
    /// callback compares with the provider's; a FAPI server sends it.
    iss: Option<String>,
}

/// POST callback; form_post response mode (FAPI preferred).
///
/// The IdP returns the authorization code via an auto-submitting HTML form.
/// Code and state are in the POST body, not the URL; no leakage in browser
/// history, Referer headers, or server access logs.
async fn callback_post(
    axum::extract::State(state): axum::extract::State<AppState>,
    session: AuthSession,
    audit: AuditContext,
    Form(params): Form<CallbackParams>,
) -> impl IntoResponse {
    info!("Received callback via form_post (code not in URL)");
    handle_callback(&state, &params, &session, audit).await
}

/// Finish the login: exchange the code (the token request is authenticated by
/// `private_key_jwt` and carries a DPoP proof), verify the ID token, find or
/// create the local user, make the session authenticated, and keep what the
/// refresh and the logout need.
async fn handle_callback(
    state: &AppState,
    params: &CallbackParams,
    session: &AuthSession,
    audit: AuditContext,
) -> axum::response::Response {
    let authn = state.authn.with_audit_context(audit);
    let claims = match authn
        .finish_oauth_login_with_iss(&params.code, &params.state, params.iss.as_deref(), session)
        .await
    {
        Ok(claims) => claims,
        Err(e) => {
            tracing::error!(error = %e, "finish_oauth_login_with_iss failed");
            return failure_page(
                "Login Failed",
                "The provider's answer could not be accepted.",
            );
        }
    };

    let user = match local_user(state, &claims).await {
        Ok(user) => user,
        Err(e) => {
            tracing::error!(error = %e, "no local user for the identity");
            return failure_page(
                "Login Failed",
                "No local user could be found for this identity.",
            );
        }
    };
    if let Err(e) = authn.complete_oauth_login(&user, &claims, session).await {
        tracing::error!(error = %e, "complete_oauth_login failed");
        return failure_page("Login Failed", "The login could not be completed.");
    }
    info!(user_id = %user.id, "signed in through {}", claims.provider);
    keep_for_refresh_and_logout(session, &claims).await;

    // Demonstrate DPoP proof generation (would be used for API calls
    // to resource servers that require sender-constrained tokens).
    // The key is the one the token request was signed with and the
    // access token is bound to; keep it for the token's life and sign
    // every proof for the token with it.
    let dpop_demo = match claims.dpop_key.as_ref() {
        None => "<p><em>No DPoP key: this login was not sender-constrained.</em></p>".to_string(),
        Some(key) => dpop_demo(state, key, claims.access_token.as_deref()),
    };

    Html(format!(
        r#"<!doctype html>
<html><head><title>FAPI Login Success</title></head><body>
<h1>FAPI Login Successful</h1>
<h2>OIDC Claims</h2>
<ul>
  <li><strong>Provider:</strong> {provider}</li>
  <li><strong>Subject:</strong> {sub}</li>
  <li><strong>Email:</strong> {email}</li>
  <li><strong>Groups:</strong> {groups}</li>
  <li><strong>Roles:</strong> {roles}</li>
  <li><strong>ID Token Hint:</strong> {id_hint}</li>
  <li><strong>Refresh Token:</strong> {refresh}</li>
</ul>
{dpop_demo}
{actions}
</body></html>"#,
        provider = html_escape(&claims.provider),
        sub = html_escape(&claims.subject),
        email = html_escape(claims.email.as_deref().unwrap_or("(not provided)")),
        groups = html_escape(&claims.groups.join(", ")),
        roles = html_escape(&claims.roles.join(", ")),
        id_hint = present(claims.id_token_hint.is_some()),
        refresh = present(claims.refresh_token.is_some()),
        actions = ACTIONS,
    ))
    .into_response()
}

/// The e-mail domains of a comma-separated list, lower-cased.
fn parse_domains(list: &str) -> Vec<String> {
    list.split(',')
        .map(|d| d.trim().to_ascii_lowercase())
        .filter(|d| !d.is_empty())
        .collect()
}

/// The tenant policy for who may be created as a local user: the identity
/// must carry an e-mail address in one of the allowed domains.
fn domain_allowed(allowed: &[String], email: Option<&str>) -> bool {
    email
        .and_then(|e| e.rsplit_once('@'))
        .is_some_and(|(local, domain)| {
            !local.is_empty() && allowed.iter().any(|a| a.eq_ignore_ascii_case(domain))
        })
}

/// The local user an identity signs in as: the one created for its
/// `(issuer, subject)` on its first login, if the tenant policy lets it be
/// created. The example keeps the link in the user's login identifier; the
/// `oauth` example shows a link table.
async fn local_user(state: &AppState, claims: &OAuthClaims) -> Result<User, String> {
    let issuer = claims
        .additional_claims
        .get("iss")
        .and_then(|v| v.as_str())
        .ok_or("the ID token carries no issuer")?;
    let identifier = format!("{issuer}#{}", claims.subject);
    if let Some(user) = state
        .identity
        .find_user(&identifier, &state.tenant)
        .await
        .map_err(|e| e.to_string())?
    {
        return Ok(user);
    }
    // An address the IdP did not verify is whatever the account holder typed:
    // it says nothing about the domain, so it cannot create a user.
    if claims.email_verified != Some(true) {
        return Err("the identity's e-mail address is not verified".to_string());
    }
    if !domain_allowed(&state.allowed_email_domains, claims.email.as_deref()) {
        return Err("the identity's e-mail domain is not allowed to sign up".to_string());
    }
    let user = User::new(
        UserId::new(&SystemRng).to_string(),
        state.tenant.to_string(),
        identifier.clone(),
        claims.email.as_deref().unwrap_or(&claims.subject),
        EntityState::Active,
        UserId::system(),
        SystemClock.now(),
    )?;
    match state.identity.create_user(user.clone()).await {
        Ok(()) => Ok(user),
        // A concurrent first login for the same identity may have created it
        // first (the store answers "already exists", an error type of its
        // own): read again and sign in as that user. Only when nobody holds
        // the identifier is the failure the caller's.
        Err(create_error) => state
            .identity
            .find_user(&identifier, &state.tenant)
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| create_error.to_string()),
    }
}

/// Becoming authenticated cleared the session's custom data; store what the
/// refresh and the logout read.
async fn keep_for_refresh_and_logout(session: &AuthSession, claims: &OAuthClaims) {
    let text = |s: &str| serde_json::Value::String(s.to_string());
    if let Some(hint) = &claims.id_token_hint {
        session.set_custom(SESSION_ID_TOKEN_HINT, text(hint)).await;
    }
    if let Some(refresh) = &claims.refresh_token {
        session
            .set_custom(SESSION_REFRESH_TOKEN, text(refresh))
            .await;
        session
            .set_custom(SESSION_SUBJECT, text(&claims.subject))
            .await;
        if let Some(nonce) = &claims.nonce {
            session.set_custom(SESSION_NONCE, text(nonce)).await;
        }
    }
    if let Some(key) = &claims.dpop_key {
        session
            .set_custom(SESSION_DPOP_KEY, dpop_key_to_json(key))
            .await;
    }
}

/// The DPoP key's scalar as the session stores it.
fn dpop_key_to_json(key: &DpopKey) -> serde_json::Value {
    serde_json::Value::from(key.to_seed_bytes().to_vec())
}

/// The DPoP key back from the session.
fn dpop_key_from_json(value: serde_json::Value) -> Option<DpopKey> {
    serde_json::from_value::<[u8; 32]>(value)
        .ok()
        .map(DpopKey::from_seed)
}

/// A DPoP proof for a call to a resource server with `access_token`, signed
/// by `key`, the key the token is bound to.
fn dpop_demo(state: &AppState, key: &DpopKey, access_token: Option<&str>) -> String {
    match state.authn.generate_dpop_proof(
        &state.provider_name,
        key,
        "GET",
        "https://api.bank.example.com/accounts",
        access_token,
    ) {
        Ok(proof) => format!(
            "<h2>DPoP Proof (for API calls)</h2>\
             <p><strong>Thumbprint (jkt):</strong> <code>{}</code></p>\
             <p><strong>Proof JWT:</strong> <code style=\"word-break:break-all\">{}</code></p>",
            html_escape(&proof.thumbprint),
            html_escape(&proof.proof_jwt[..80.min(proof.proof_jwt.len())]),
        ),
        Err(e) => format!(
            "<p><em>DPoP not available: {}</em></p>",
            html_escape(&e.to_string())
        ),
    }
}

/// The buttons of a signed-in page.
const ACTIONS: &str = r#"<form method="POST" action="/auth/refresh">
  <button type="submit">Refresh tokens (DPoP-bound)</button>
</form>
<form method="POST" action="/auth/logout">
  <button type="submit">Logout (RP-Initiated + Token Revocation)</button>
</form>
<p><a href="/profile">Profile</a> | <a href="/">Home</a></p>"#;

fn present(yes: bool) -> &'static str {
    if yes { "present" } else { "none" }
}

fn failure_page(title: &str, message: &str) -> axum::response::Response {
    Html(format!(
        r#"<h1>{}</h1><p>{}</p><p><a href="/">Try again</a></p>"#,
        html_escape(title),
        html_escape(message)
    ))
    .into_response()
}

/// Protected profile page.
async fn profile(
    axum::extract::State(state): axum::extract::State<AppState>,
    session: AuthSession,
) -> impl IntoResponse {
    let Some((user_id, tenant_id)) = session.authenticated_ids().await else {
        return Redirect::temporary("/auth/login").into_response();
    };
    let identifier = match state.identity.get_user(&user_id).await {
        Ok(Some(user)) => user.identifier.to_string(),
        _ => return Redirect::temporary("/auth/login").into_response(),
    };
    let bound_to = session
        .get_custom(SESSION_DPOP_KEY)
        .await
        .and_then(dpop_key_from_json)
        .and_then(|key| key.thumbprint().ok())
        .unwrap_or_else(|| "(no DPoP key)".to_string());
    Html(format!(
        r#"<!doctype html>
<html><head><title>Profile</title></head><body>
<h1>Profile</h1>
<ul>
  <li><strong>User id:</strong> {user_id}</li>
  <li><strong>Tenant:</strong> {tenant_id}</li>
  <li><strong>Login identifier:</strong> {identifier}</li>
  <li><strong>Tokens bound to (jkt):</strong> {bound_to}</li>
</ul>
{ACTIONS}
</body></html>"#,
        identifier = html_escape(&identifier),
        bound_to = html_escape(&bound_to),
    ))
    .into_response()
}

/// Refresh on demand: exchange the stored refresh token at the IdP. The
/// request is authenticated by `private_key_jwt` and carries a DPoP proof
/// signed by the login's key, so the new access token is bound to the same
/// key; a refresh ID token is held to the same checks as the login's. Keep
/// the refresh token the IdP rotated to.
async fn refresh(
    axum::extract::State(state): axum::extract::State<AppState>,
    session: AuthSession,
    audit: AuditContext,
) -> axum::response::Response {
    if session.authenticated_ids().await.is_none() {
        return Redirect::to("/").into_response();
    }
    let text = |key: &'static str| {
        let session = session.clone();
        async move {
            session
                .get_custom(key)
                .await
                .and_then(|v| v.as_str().map(str::to_owned))
        }
    };
    let (Some(token), Some(subject)) = (
        text(SESSION_REFRESH_TOKEN).await,
        text(SESSION_SUBJECT).await,
    ) else {
        return failure_page(
            "No refresh token",
            "The provider issued no refresh token for this session.",
        );
    };
    let nonce = text(SESSION_NONCE).await;
    let key = session
        .get_custom(SESSION_DPOP_KEY)
        .await
        .and_then(dpop_key_from_json);
    let outcome = match state
        .authn
        .with_audit_context(audit)
        .refresh_oauth_token(
            &state.provider_name,
            &token,
            &subject,
            nonce.as_deref(),
            key.as_ref(),
        )
        .await
    {
        Ok(outcome) => outcome,
        Err(e) => {
            tracing::error!(error = %e, "refresh_oauth_token failed");
            return failure_page(
                "Refresh Failed",
                "The provider's answer could not be accepted.",
            );
        }
    };
    // The IdP may have spent the token that was sent; keep the one it returns,
    // and the newer ID token for the logout.
    session
        .set_custom(
            SESSION_REFRESH_TOKEN,
            serde_json::Value::String(outcome.refresh_token.to_string()),
        )
        .await;
    let id_token = outcome
        .id_token_claims
        .as_ref()
        .and_then(|c| c.id_token_hint.as_deref());
    if let Some(hint) = id_token {
        session
            .set_custom(
                SESSION_ID_TOKEN_HINT,
                serde_json::Value::String(hint.to_string()),
            )
            .await;
    }
    info!("tokens refreshed");
    let dpop = match key.as_ref() {
        Some(key) => dpop_demo(&state, key, Some(&outcome.access_token)),
        None => String::new(),
    };
    Html(format!(
        r#"<!doctype html>
<html><head><title>Tokens Refreshed</title></head><body>
<h1>Tokens Refreshed</h1>
<ul>
  <li><strong>New access token lifetime:</strong> {lifetime}</li>
  <li><strong>New ID token:</strong> {id_token}</li>
</ul>
{dpop}
{ACTIONS}
</body></html>"#,
        lifetime = outcome
            .expires_in
            .map_or_else(|| "(not stated)".to_string(), |s| format!("{s} s")),
        id_token = if id_token.is_some() {
            "verified"
        } else {
            "none"
        },
    ))
    .into_response()
}

/// RP-Initiated Logout; demonstrates the complete logout flow:
/// 1. Revoke the refresh token at the IdP (RFC 7009)
/// 2. Invalidate local session
/// 3. Redirect to IdP's end_session_endpoint with id_token_hint
///
/// The provider is the application's own, not a form field: a request
/// must not be able to point token revocation and the logout redirect at a
/// provider of its choosing.
async fn logout(
    axum::extract::State(state): axum::extract::State<AppState>,
    audit: AuditContext,
    session: AuthSession,
) -> axum::response::Response {
    let provider = state.provider_name.as_str();
    // Read what the logout needs before the session is cleared.
    let text = |v: Option<serde_json::Value>| v.and_then(|v| v.as_str().map(str::to_owned));
    let hint = text(session.get_custom(SESSION_ID_TOKEN_HINT).await);
    let refresh_token = text(session.get_custom(SESSION_REFRESH_TOKEN).await);

    // Step 1: Revoke the refresh token, which also ends the access tokens
    // issued from it at the IdP. A failure is logged and the logout goes on.
    if let Some(token) = refresh_token {
        match state
            .authn
            .revoke_oauth_token(provider, &token, Some("refresh_token"), None)
            .await
        {
            Ok(()) => info!("refresh token revoked"),
            Err(e) => tracing::warn!(error = %e, "token revocation failed"),
        }
    }

    // Step 2: End the local session. `logout` drops the registry entry,
    // records the logout, and clears the session and rotates its id whatever
    // the audit store does; a bare `session.clear()` would do the last two
    // only.
    if let Err(e) = state.authn.with_audit_context(audit).logout(&session).await {
        tracing::error!(error = %e, "logout could not be recorded; the session is cleared regardless");
    }
    info!("Local session invalidated");

    // Step 3: Redirect to IdP's end_session_endpoint (RP-Initiated Logout).
    // The IdP hands `state` back on the post-logout redirect; the landing
    // page is static and acts on nothing, so the example sends none.
    if let Some(end_session_url) = state.authn.build_end_session_url(
        provider,
        hint.as_deref(),
        Some(&state.post_logout_redirect),
        None,
    ) {
        info!("Redirecting to IdP end_session_endpoint");
        Redirect::to(end_session_url.as_str()).into_response()
    } else {
        // IdP doesn't support RP-Initiated Logout; redirect home.
        info!("IdP has no end_session_endpoint; redirecting home");
        Redirect::to("/").into_response()
    }
}

/// Escape text for interpolation into HTML. Claims and error text come
/// from the identity provider and are attacker-influenced.
fn html_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Cookies are `Secure` unless `AXESS_DEV_INSECURE_COOKIES=1` is set, for a
/// browser that refuses `Secure` cookies over plain HTTP. Local use only.
fn secure_cookies() -> bool {
    let insecure = std::env::var("AXESS_DEV_INSECURE_COOKIES").is_ok_and(|v| v == "1");
    if insecure {
        eprintln!("WARNING: AXESS_DEV_INSECURE_COOKIES=1, cookies are sent without Secure");
    }
    !insecure
}

#[cfg(test)]
mod tests;
