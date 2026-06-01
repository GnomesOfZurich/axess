//! # axess-example-fapi
//!
//! FAPI 2.0 (Financial-grade API) example for the Axess library.
//!
//! Demonstrates the FAPI 2.0 Baseline Security Profile:
//! - Pushed Authorization Requests (PAR); auth params sent server-to-server
//! - DPoP sender-constrained tokens; tokens bound to ephemeral key pair
//! - Form Post response mode; authorization code via POST, not URL query
//! - RP-Initiated Logout with id_token_hint
//! - Token revocation on logout
//!
//! ## Dual-mode operation
//!
//! **Mock mode (default):** Runs with an in-process mock OIDC server. Zero setup.
//! Shows the API wiring without external dependencies.
//!
//! ```sh
//! cargo run -p axess-example-fapi
//! ```
//!
//! **Live mode:** Set environment variables to connect to a real FAPI-compliant IdP.
//! See README.md for the Keycloak-in-podman setup (one command, pre-configured realm).
//!
//! ```sh
//! export FAPI_ISSUER=https://keycloak.local/realms/fapi
//! export FAPI_CLIENT_ID=axess-fapi-client
//! export FAPI_CLIENT_SECRET=your-secret
//! cargo run -p axess-example-fapi
//! ```
//!
//! ## Endpoints
//!
//! - `GET  /`; home page with login link
//! - `GET  /auth/login`; initiates FAPI login (PAR → redirect to IdP)
//! - `GET  /auth/callback`; handles IdP callback (query mode)
//! - `POST /auth/callback`; handles IdP callback (form_post mode)
//! - `GET  /profile`; shows authenticated user info + DPoP proof demo
//! - `POST /auth/logout`; RP-Initiated Logout (revoke tokens, redirect to IdP)

use axess::authn::AuthnService;
use axess::federation::oauth::{
    FapiConfig, OAuthLoginOptions, OAuthProviderConfig, ResponseMode, SenderConstraint,
};
use axess::testing::{MockFactorStore, MockIdentityStore};
use axess::{AuthSession, MemorySessionStore, SecureRng, SessionLayer};
use axum::{
    Form, Router,
    extract::Query,
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
};
use serde::Deserialize;
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

type Service = AuthnService<MockIdentityStore, MockFactorStore>;

#[derive(Clone)]
struct AppState {
    authn: Arc<Service>,
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

    let is_live = std::env::var("FAPI_ISSUER").is_ok();

    let (authn, provider_name) = if is_live {
        build_live_service().await?
    } else {
        build_mock_service()
    };

    let session_store = MemorySessionStore::new();
    // `axess::SystemRng` routes through the foundation crate's RNG
    // abstraction (same path the library uses internally), so the example
    // models the pattern adopters should copy instead of teaching `rand::*`.
    let mut signing_key = [0u8; 32];
    axess::SystemRng.fill_bytes(&mut signing_key);
    let session_layer = SessionLayer::new(session_store, signing_key).with_secure(false);

    let state = AppState {
        authn: Arc::new(authn),
        provider_name,
        post_logout_redirect: "http://127.0.0.1:3000/".to_string(),
    };

    let app = Router::new()
        .route("/", get(home))
        .route("/auth/login", get(login))
        .route("/auth/callback", get(callback_get).post(callback_post))
        .route("/profile", get(profile))
        .route("/auth/logout", post(logout))
        .with_state(state)
        .layer(session_layer);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    info!("Listening on http://127.0.0.1:3000");
    if !is_live {
        info!("Running in MOCK mode; set FAPI_ISSUER to connect to a real IdP");
    }
    axum::serve(listener, app.into_make_service()).await?;

    Ok(())
}

// ── Mock mode ──────────────────────────────────────────────────────────────

fn build_mock_service() -> (Service, String) {
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

    let identity = MockIdentityStore::new();
    let factors = MockFactorStore::new();
    let authn = AuthnService::new(identity, factors).with_oauth_provider(mock);

    // Note: MockOAuthProvider doesn't have a PAR endpoint, so FAPI enforcement
    // can't be applied. In mock mode we demonstrate the API surface without
    // the full PAR→redirect→callback round trip.
    info!("Mock mode: PAR and DPoP are shown in code but not exercised end-to-end");
    info!("Mock mode: Set FAPI_ISSUER to test against a real FAPI IdP");

    (authn, "fapi-mock".to_string())
}

// ── Live mode ──────────────────────────────────────────────────────────────

fn missing_live_creds() -> ! {
    tracing::error!(
        "missing FAPI_CLIENT_ID / FAPI_CLIENT_SECRET; this example runs a real \
         FAPI RP flow against an external OP. Quick start: (1) bring up the \
         bundled Keycloak realm from examples/fapi/keycloak, (2) export \
         FAPI_ISSUER, FAPI_CLIENT_ID=axess-fapi-client, and \
         FAPI_CLIENT_SECRET=axess-fapi-secret, (3) re-run cargo run -p \
         axess-example-fapi. See examples/fapi/README.md for the full setup."
    );
    std::process::exit(2);
}

async fn build_live_service() -> Result<(Service, String), Box<dyn std::error::Error>> {
    let issuer = std::env::var("FAPI_ISSUER")?;
    let client_id = std::env::var("FAPI_CLIENT_ID").unwrap_or_else(|_| missing_live_creds());
    let client_secret =
        std::env::var("FAPI_CLIENT_SECRET").unwrap_or_else(|_| missing_live_creds());
    let provider_name = std::env::var("FAPI_PROVIDER_NAME").unwrap_or_else(|_| "fapi".to_string());

    info!("Discovering OIDC configuration from {issuer}...");
    let provider = OAuthProviderConfig::discover(
        &provider_name,
        &issuer,
        &client_id,
        &client_secret,
        "http://localhost:3000/auth/callback",
    )
    .await?
    .with_fapi(FapiConfig {
        sender_constraint: SenderConstraint::DPoP,
        require_jarm: false,
        max_id_token_lifetime_secs: 300,
    })?;
    info!("OIDC discovery complete; FAPI 2.0 profile enabled");

    let identity = MockIdentityStore::new();
    let factors = MockFactorStore::new();
    let authn = AuthnService::new(identity, factors).with_oauth_provider(provider);

    Ok((authn, provider_name))
}

// ── Handlers ───────────────────────────────────────────────────────────────

async fn home() -> Html<&'static str> {
    Html(
        r#"<!doctype html>
<html><head><title>FAPI 2.0 Example</title></head><body>
<h1>Axess FAPI 2.0 Example</h1>
<p>Financial-grade API security profile: PAR + DPoP + form_post.</p>
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
/// back via POST body, not URL query params.
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
            Html(format!(
                "<h1>Login Error</h1><p>{e}</p><p><a href=\"/\">Back</a></p>"
            ))
            .into_response()
        }
    }
}

/// Callback parameters; works for both GET (query) and POST (form_post).
#[derive(Deserialize)]
struct CallbackParams {
    code: String,
    state: String,
}

/// GET callback; standard redirect mode.
async fn callback_get(
    axum::extract::State(state): axum::extract::State<AppState>,
    Query(params): Query<CallbackParams>,
    session: AuthSession,
) -> impl IntoResponse {
    handle_callback(&state, &params, &session).await
}

/// POST callback; form_post response mode (FAPI preferred).
///
/// The IdP returns the authorization code via an auto-submitting HTML form.
/// Code and state are in the POST body, not the URL; no leakage in browser
/// history, Referer headers, or server access logs.
async fn callback_post(
    axum::extract::State(state): axum::extract::State<AppState>,
    session: AuthSession,
    Form(params): Form<CallbackParams>,
) -> impl IntoResponse {
    info!("Received callback via form_post (code not in URL)");
    handle_callback(&state, &params, &session).await
}

async fn handle_callback(
    state: &AppState,
    params: &CallbackParams,
    session: &AuthSession,
) -> axum::response::Response {
    match state
        .authn
        .finish_oauth_login(&params.code, &params.state, session)
        .await
    {
        Ok(claims) => {
            // In a real app: look up or create a User from claims, then call
            // state.authn.complete_oauth_login(&user, &claims, &session).

            // Demonstrate DPoP proof generation (would be used for API calls
            // to resource servers that require sender-constrained tokens).
            let dpop_demo = match state.authn.generate_dpop_proof(
                &state.provider_name,
                "GET",
                "https://api.bank.example.com/accounts",
                claims.access_token.as_deref(),
            ) {
                Ok(proof) => format!(
                    "<h2>DPoP Proof (for API calls)</h2>\
                     <p><strong>Thumbprint (jkt):</strong> <code>{}</code></p>\
                     <p><strong>Proof JWT:</strong> <code style=\"word-break:break-all\">{}</code></p>",
                    proof.thumbprint,
                    &proof.proof_jwt[..80.min(proof.proof_jwt.len())],
                ),
                Err(e) => format!("<p><em>DPoP not available: {e}</em></p>"),
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
</ul>
{dpop_demo}
<form method="POST" action="/auth/logout">
  <input type="hidden" name="provider" value="{provider}" />
  <button type="submit">Logout (RP-Initiated + Token Revocation)</button>
</form>
<p><a href="/">Back to home</a></p>
</body></html>"#,
                provider = claims.provider,
                sub = claims.subject,
                email = claims.email.as_deref().unwrap_or("(not provided)"),
                groups = claims.groups.join(", "),
                roles = claims.roles.join(", "),
                id_hint = if claims.id_token_hint.is_some() {
                    "present"
                } else {
                    "none"
                },
                dpop_demo = dpop_demo,
            ))
            .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "finish_oauth_login failed");
            Html(format!(
                "<h1>Login Failed</h1><p>{e}</p><p><a href=\"/\">Try again</a></p>"
            ))
            .into_response()
        }
    }
}

/// Protected profile page.
async fn profile(session: AuthSession) -> impl IntoResponse {
    if session.is_authenticated().await {
        let user_id = session
            .user_id()
            .await
            .map(|id| id.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        Html(format!(
            r#"<!doctype html>
<html><head><title>Profile</title></head><body>
<h1>Profile</h1>
<p>Authenticated as: <strong>{user_id}</strong></p>
<form method="POST" action="/auth/logout">
  <button type="submit">Logout</button>
</form>
<p><a href="/">Home</a></p>
</body></html>"#
        ))
        .into_response()
    } else {
        Redirect::temporary("/auth/login").into_response()
    }
}

/// RP-Initiated Logout; demonstrates the complete logout flow:
/// 1. Revoke tokens at the IdP (RFC 7009)
/// 2. Invalidate local session
/// 3. Redirect to IdP's end_session_endpoint with id_token_hint
#[derive(Deserialize)]
struct LogoutParams {
    provider: Option<String>,
}

async fn logout(
    axum::extract::State(state): axum::extract::State<AppState>,
    session: AuthSession,
    Form(params): Form<LogoutParams>,
) -> axum::response::Response {
    let provider = params.provider.as_deref().unwrap_or(&state.provider_name);

    // Step 1: Revoke tokens if available (best-effort).
    // In a real app, you'd retrieve stored tokens from the session or database.
    if let Err(e) = state
        .authn
        .revoke_oauth_token(provider, "stored-refresh-token", Some("refresh_token"))
        .await
    {
        tracing::warn!(error = %e, "token revocation failed (expected in mock mode)");
    }

    // Step 2: Invalidate local session.
    session.clear().await;
    info!("Local session invalidated");

    // Step 3: Redirect to IdP's end_session_endpoint (RP-Initiated Logout).
    // In a real app, retrieve the stored id_token_hint from the session.
    if let Some(end_session_url) = state.authn.build_end_session_url(
        provider,
        None, // id_token_hint; would come from stored OAuthClaims
        Some(&state.post_logout_redirect),
        None, // state; optional CSRF for the redirect back
    ) {
        info!("Redirecting to IdP end_session_endpoint");
        Redirect::temporary(end_session_url.as_str()).into_response()
    } else {
        // IdP doesn't support RP-Initiated Logout; redirect home.
        info!("IdP has no end_session_endpoint; redirecting home");
        Redirect::temporary("/").into_response()
    }
}
