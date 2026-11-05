//! # axess-example-oauth
//!
//! OpenID Connect login that ends in an axess session. See the crate README
//! and `src/app.rs` for the flow.
//!
//! ## Running
//!
//! You need an OIDC provider (Google, Keycloak, Entra, or a test server).
//! With Google, create credentials at
//! <https://console.cloud.google.com/apis/credentials>, register
//! `http://localhost:3000/auth/callback/google` as a redirect URI, then:
//!
//! ```sh
//! OAUTH_CLIENT_ID=your-id OAUTH_CLIENT_SECRET=your-secret cargo run -p axess-example-oauth
//! ```
//!
//! `OAUTH_PRIVATE_KEY_FILE=/path/key.pem` authenticates with `private_key_jwt`
//! instead of `OAUTH_CLIENT_SECRET`.
//!
//! For a run with no external IdP, see `tests/federated_login.rs`: it drives
//! this application the way a browser does against an in-process provider.
//!
//! ## Endpoints
//!
//! - `GET /`; home page with a login link per provider
//! - `GET /auth/login/:provider`; starts the flow (redirects to the IdP)
//! - `GET /auth/callback/:provider`; the IdP's answer: signs in, creating the
//!   local user on first login when the tenant allows it
//! - `GET /profile`; the signed-in user, read from the axess session
//! - `POST /auth/refresh`; exchanges the IdP's refresh token for new tokens
//!   and asks the userinfo endpoint about the same subject
//! - `POST /auth/logout`; ends the session and sends the browser to the IdP's
//!   logout endpoint, when it has one
//! - `POST /auth/backchannel-logout`; the IdP ends a session (OIDC
//!   back-channel logout)

use axess_example_oauth::app::{self, ClientAuth, Config, ProviderSettings};
use axess_example_oauth::provisioning::Provisioning;
use tracing::info;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

const DEFAULT_BASE_URL: &str = "http://localhost:3000";
const DEFAULT_LISTEN: &str = "127.0.0.1:3000";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(EnvFilter::new(std::env::var("RUST_LOG").unwrap_or_else(
            |_| "axess_example_oauth=debug,axess=debug".into(),
        )))
        .with(tracing_subscriber::fmt::layer())
        .try_init()?;

    // `OAUTH_BASE_URL` is the origin the browser reaches this application on
    // (it is what the redirect URI registered at the IdP is built from), and
    // `OAUTH_LISTEN` the address it binds. Both default to the local setup
    // the Google walkthrough uses; the conformance runner moves them.
    let base_url = std::env::var("OAUTH_BASE_URL").unwrap_or_else(|_| DEFAULT_BASE_URL.to_string());
    let listen = std::env::var("OAUTH_LISTEN").unwrap_or_else(|_| DEFAULT_LISTEN.to_string());

    let provider = ProviderSettings {
        name: std::env::var("OAUTH_PROVIDER_NAME").unwrap_or_else(|_| "google".to_string()),
        issuer: std::env::var("OAUTH_ISSUER")
            .unwrap_or_else(|_| "https://accounts.google.com".to_string()),
        client_id: std::env::var("OAUTH_CLIENT_ID").unwrap_or_else(|_| missing_creds()),
        client_auth: client_auth(),
        post_logout_redirect: format!("{base_url}/"),
        base_url,
        id_token_algs: std::env::var("OAUTH_ID_TOKEN_ALGS")
            .map(|v| v.split(',').map(|a| a.trim().to_string()).collect())
            .unwrap_or_default(),
    };
    // `OAUTH_PROVISIONING=linked-only` turns just-in-time creation off: only
    // identities linked beforehand sign in.
    let provisioning = Provisioning::from_env(std::env::var("OAUTH_PROVISIONING"))?;

    info!("Discovering OIDC configuration from {}...", provider.issuer);
    let app = app::build(Config {
        providers: vec![provider],
        provisioning,
        require_verified_email: false,
        secure_cookies: secure_cookies(),
    })
    .await?;
    info!("OIDC discovery complete");

    // Resolve the client address once, outside everything that reads one.
    // Without it the audit rows carry no address and say so
    // (`ip_source = 'unknown'`). `loopback_only` suits a dev server bound
    // to 127.0.0.1; name the proxy's ranges in a real deployment.
    let router = axess::client_ip::layer(
        app.router,
        axess::client_ip::TrustedProxies::loopback_only(),
    );

    let listener = tokio::net::TcpListener::bind(&listen).await?;
    info!("Listening on http://{listen}");
    // `with_connect_info` is what puts the peer address where the
    // client-IP layer can read it.
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;

    Ok(())
}

/// The client authentication method. `OAUTH_PRIVATE_KEY_FILE` names a PEM
/// private key and selects `private_key_jwt` (the algorithm is
/// `OAUTH_PRIVATE_KEY_ALG`, default `RS256`, and `OAUTH_PRIVATE_KEY_KID` sets
/// the assertion's `kid`); otherwise `OAUTH_CLIENT_SECRET` is the secret.
fn client_auth() -> ClientAuth {
    let Ok(path) = std::env::var("OAUTH_PRIVATE_KEY_FILE") else {
        return ClientAuth::Secret(
            std::env::var("OAUTH_CLIENT_SECRET").unwrap_or_else(|_| missing_creds()),
        );
    };
    let pem = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        tracing::error!("cannot read OAUTH_PRIVATE_KEY_FILE {path}: {e}");
        std::process::exit(2);
    });
    let algorithm = std::env::var("OAUTH_PRIVATE_KEY_ALG")
        .unwrap_or_else(|_| "RS256".to_string())
        .parse()
        .unwrap_or_else(|e| {
            tracing::error!("OAUTH_PRIVATE_KEY_ALG: {e}");
            std::process::exit(2);
        });
    ClientAuth::PrivateKeyJwt {
        pem,
        algorithm,
        key_id: std::env::var("OAUTH_PRIVATE_KEY_KID").ok(),
    }
}

/// Exit with a helpful message when OAuth credentials are missing.
fn missing_creds() -> ! {
    tracing::error!(
        "missing OAUTH_CLIENT_ID / OAUTH_CLIENT_SECRET; this example performs a \
         real OAuth 2.0 Authorization Code + PKCE flow and needs credentials from an \
         OIDC provider. Quick start: (1) create credentials at \
         https://console.cloud.google.com/apis/credentials, (2) set redirect URI \
         http://localhost:3000/auth/callback/google, (3) re-run with \
         OAUTH_CLIENT_ID=your-id OAUTH_CLIENT_SECRET=your-secret cargo run -p \
         axess-example-oauth. See examples/oauth/README.md for non-Google providers; \
         the no-credentials path is the test in examples/oauth/tests/."
    );
    std::process::exit(2);
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
