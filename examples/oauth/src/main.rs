//! # axess-example-oauth
//!
//! OAuth 2.0 / OpenID Connect login example using the Axess library.
//!
//! Demonstrates the full redirect-based login flow:
//! 1. User clicks "Login with Google" → redirected to IdP
//! 2. IdP authenticates → redirects back with authorization code
//! 3. Axess exchanges code for tokens, validates ID token, returns claims
//! 4. Application maps claims to a local user and establishes a session
//!
//! ## Running
//!
//! You need a real OIDC provider (Google, GitHub, Keycloak, or a test server).
//!
//! ### With Google:
//! 1. Create OAuth credentials at <https://console.cloud.google.com/apis/credentials>
//! 2. Set redirect URI to `http://localhost:3000/auth/callback/google`
//! 3. Run:
//!    ```sh
//!    OAUTH_CLIENT_ID=your-id OAUTH_CLIENT_SECRET=your-secret cargo run -p axess-example-oauth
//!    ```
//!
//! ### With oauth2-test-server (local, no external IdP):
//! See the integration tests in `axess-core/tests/` for a self-contained example.
//!
//! ## Endpoints
//!
//! - `GET /`; home page with login link
//! - `GET /auth/login/:provider`; initiates OAuth flow (redirects to IdP)
//! - `GET /auth/callback/:provider`; handles IdP callback
//! - `GET /profile`; shows authenticated user info (requires login)

use axess::authn::AuthnService;
use axess::federation::oauth::OAuthProviderConfig;
use axess::testing::{MockFactorStore, MockIdentityStore};
use axess::{AuthSession, MemorySessionStore, SecureRng, SessionLayer};
use axum::{
    Router,
    extract::{Path, Query, State},
    response::{Html, IntoResponse, Redirect},
    routing::get,
};
use serde::Deserialize;
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

type Service = AuthnService<MockIdentityStore, MockFactorStore>;

#[derive(Clone)]
struct AppState {
    authn: Arc<Service>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(EnvFilter::new(std::env::var("RUST_LOG").unwrap_or_else(
            |_| "axess_example_oauth=debug,axess=debug".into(),
        )))
        .with(tracing_subscriber::fmt::layer())
        .try_init()?;

    let client_id = std::env::var("OAUTH_CLIENT_ID").unwrap_or_else(|_| missing_creds());
    let client_secret = std::env::var("OAUTH_CLIENT_SECRET").unwrap_or_else(|_| missing_creds());
    let issuer =
        std::env::var("OAUTH_ISSUER").unwrap_or_else(|_| "https://accounts.google.com".to_string());
    let provider_name =
        std::env::var("OAUTH_PROVIDER_NAME").unwrap_or_else(|_| "google".to_string());

    info!("Discovering OIDC configuration from {issuer}...");
    let provider = OAuthProviderConfig::discover(
        &provider_name,
        &issuer,
        &client_id,
        &client_secret,
        "http://localhost:3000/auth/callback/google",
    )
    .await?;
    info!("OIDC discovery complete");

    let identity = MockIdentityStore::new();
    let factors = MockFactorStore::new();
    let authn = Arc::new(AuthnService::new(identity, factors).with_oauth_provider(provider));

    let session_store = MemorySessionStore::new();
    // Generate a fresh random key; sessions reset on restart (OK for dev).
    // In production, load a persistent key from a secret store. `axess::SystemRng`
    // routes through the foundation crate's RNG abstraction so the example
    // models the same pattern the library uses internally.
    let mut signing_key = [0u8; 32];
    axess::SystemRng.fill_bytes(&mut signing_key);
    let session_layer = SessionLayer::new(session_store, signing_key).with_secure(false); // HTTP for local dev

    let state = AppState { authn };

    let app = Router::new()
        .route("/", get(home))
        .route("/auth/login/{provider}", get(login))
        .route("/auth/callback/{provider}", get(callback))
        .route("/profile", get(profile))
        .with_state(state)
        .layer(session_layer);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    info!("Listening on http://127.0.0.1:3000");
    axum::serve(listener, app.into_make_service()).await?;

    Ok(())
}

/// Exit with a helpful message when OAuth credentials are missing.
/// The example talks to a real OIDC provider (Google by default) and
/// can't boot without them; the bare `expect` panic that used to fire
/// here gave no hint about README setup.
fn missing_creds() -> ! {
    tracing::error!(
        "missing OAUTH_CLIENT_ID / OAUTH_CLIENT_SECRET; this example performs a \
         real OAuth 2.0 Authorization Code + PKCE flow and needs credentials from an \
         OIDC provider. Quick start: (1) create credentials at \
         https://console.cloud.google.com/apis/credentials, (2) set redirect URI \
         http://localhost:3000/auth/callback/google, (3) re-run with \
         OAUTH_CLIENT_ID=your-id OAUTH_CLIENT_SECRET=your-secret cargo run -p \
         axess-example-oauth. See examples/oauth/README.md for non-Google providers \
         and for the no-credentials wiremock test path under axess-core/tests/."
    );
    std::process::exit(2);
}

async fn home() -> Html<&'static str> {
    Html(
        r#"<!doctype html>
<html><head><title>OAuth Example</title></head><body>
<h1>Axess OAuth Example</h1>
<p><a href="/auth/login/google">Login with Google</a></p>
<p><a href="/profile">View Profile</a> (requires login)</p>
</body></html>"#,
    )
}

/// Initiate the OAuth flow; redirects the user to the IdP.
async fn login(
    State(state): State<AppState>,
    Path(provider): Path<String>,
    session: AuthSession,
) -> impl IntoResponse {
    let options = axess::federation::oauth::OAuthLoginOptions::default();
    match state
        .authn
        .begin_oauth_login(&provider, &options, &session)
        .await
    {
        Ok((auth_url, _csrf)) => Redirect::temporary(auth_url.as_str()).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "begin_oauth_login failed");
            Html(format!("<h1>Error</h1><p>{e}</p><a href=\"/\">Back</a>")).into_response()
        }
    }
}

/// Handle the IdP callback; exchange code for tokens, show claims.
#[derive(Deserialize)]
struct CallbackParams {
    code: String,
    state: String,
}

async fn callback(
    State(state): State<AppState>,
    Path(_provider): Path<String>,
    Query(params): Query<CallbackParams>,
    session: AuthSession,
) -> impl IntoResponse {
    match state
        .authn
        .finish_oauth_login(&params.code, &params.state, &session)
        .await
    {
        Ok(claims) => {
            // In a real app, you'd look up or create a User from claims.subject,
            // then call state.authn.complete_oauth_login(&user, &claims, &session).
            // For this example, we just show the claims.
            Html(format!(
                r#"<!doctype html>
<html><head><title>Login Success</title></head><body>
<h1>Login Successful!</h1>
<h2>OIDC Claims</h2>
<ul>
  <li><strong>Provider:</strong> {}</li>
  <li><strong>Subject:</strong> {}</li>
  <li><strong>Email:</strong> {}</li>
  <li><strong>Email verified:</strong> {}</li>
  <li><strong>Name:</strong> {}</li>
</ul>
<p><a href="/">Back to home</a></p>
</body></html>"#,
                claims.provider,
                claims.subject,
                claims.email.as_deref().unwrap_or("(not provided)"),
                claims
                    .email_verified
                    .map_or("(not provided)".to_string(), |v| v.to_string()),
                claims.name.as_deref().unwrap_or("(not provided)"),
            ))
            .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "finish_oauth_login failed");
            Html(format!(
                "<h1>Login Failed</h1><p>{e}</p><a href=\"/\">Try again</a>"
            ))
            .into_response()
        }
    }
}

/// Protected page; shows session info (or redirects to login).
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
<p>Authenticated as: {user_id}</p>
<a href="/">Home</a>
</body></html>"#
        ))
        .into_response()
    } else {
        Redirect::temporary("/auth/login/google").into_response()
    }
}
