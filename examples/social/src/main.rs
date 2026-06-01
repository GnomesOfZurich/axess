//! # axess-example-social
//!
//! Login with GitHub via [`axess::social::SocialProvider`].
//!
//! This example demonstrates the **plain-OAuth-2.0** user-login flow
//! for IdPs that do not support OIDC: GitHub user login, Twitter/X,
//! Discord, Reddit, Spotify, Strava. Identity comes from a userinfo
//! HTTPS GET, not from a signed ID token; see the
//! [`axess::social`](https://docs.rs/axess/latest/axess/social/)
//! module docs for the security delta vs OIDC and when to reach for
//! this vs `OAuthProviderConfig::discover()`.
//!
//! ## Running
//!
//! Create a GitHub OAuth app at <https://github.com/settings/developers>,
//! set the callback URL to `http://localhost:3000/auth/callback/github`,
//! then:
//!
//! ```sh
//! GITHUB_CLIENT_ID=your-id \
//! GITHUB_CLIENT_SECRET=your-secret \
//! cargo run -p axess-example-social
//! ```
//!
//! Open <http://localhost:3000/> and click "Login with GitHub".

pub mod providers;

use std::sync::Arc;

use axum::{
    Router,
    extract::{Query, State},
    response::{Html, IntoResponse, Redirect},
    routing::get,
};
use providers::Provider;
use serde::Deserialize;
use tower_cookies::{Cookie, CookieManagerLayer, Cookies};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Clone)]
struct AppState {
    github: Arc<Provider>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(EnvFilter::new(std::env::var("RUST_LOG").unwrap_or_else(
            |_| "axess_example_social=debug,axess=debug".into(),
        )))
        .with(tracing_subscriber::fmt::layer())
        .try_init()?;

    let client_id = std::env::var("GITHUB_CLIENT_ID").unwrap_or_else(|_| missing_creds());
    let client_secret = std::env::var("GITHUB_CLIENT_SECRET").unwrap_or_else(|_| missing_creds());

    // Reuse the recipe from `providers::github` instead of inlining
    // the URLs + claim mapper here. The recipes module is the
    // adopter-facing API; main.rs is the wire-up demo.
    let github = providers::github(
        client_id,
        client_secret,
        "http://localhost:3000/auth/callback/github",
    );

    let state = AppState {
        github: Arc::new(github),
    };

    let app = Router::new()
        .route("/", get(home))
        .route("/auth/login/github", get(login))
        .route("/auth/callback/github", get(callback))
        .layer(CookieManagerLayer::new())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    tracing::info!("Listening on http://127.0.0.1:3000");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn home() -> Html<&'static str> {
    Html(
        r#"<!doctype html>
<html><head><title>axess-example-social</title>
<style>body{font-family:system-ui,sans-serif;max-width:640px;margin:3em auto;padding:0 1em}</style>
</head><body>
<h1>axess social-login example</h1>
<p>Demonstrates the plain-OAuth-2.0 user-login flow for IdPs that do not support OIDC. This sample wires GitHub user login.</p>
<p><strong>Note:</strong> identity comes from GitHub's userinfo endpoint, not from a signed ID token. The security model is weaker than OIDC; see <code>axess::social</code> module docs for the delta and when to reach for OIDC instead.</p>
<p><a href="/auth/login/github">Login with GitHub →</a></p>
</body></html>"#,
    )
}

async fn login(State(state): State<AppState>, cookies: Cookies) -> impl IntoResponse {
    let csrf_state = state.github.mint_csrf_state();
    let auth = state.github.build_auth_url(&csrf_state);

    // Store CSRF state + PKCE verifier in short-lived cookies. A real
    // app would use the SessionLayer's pre-auth session instead; cookies
    // keep this example focused on the social flow.
    let mut state_cookie = Cookie::new("oauth_state", csrf_state);
    state_cookie.set_http_only(true);
    state_cookie.set_path("/");
    let mut pkce_cookie = Cookie::new("oauth_pkce", auth.pkce_verifier);
    pkce_cookie.set_http_only(true);
    pkce_cookie.set_path("/");
    cookies.add(state_cookie);
    cookies.add(pkce_cookie);

    Redirect::to(&auth.url)
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: String,
    state: String,
}

async fn callback(
    State(state): State<AppState>,
    Query(q): Query<CallbackQuery>,
    cookies: Cookies,
) -> impl IntoResponse {
    // Verify CSRF state matches what we issued at /auth/login/github.
    let stored_state = cookies
        .get("oauth_state")
        .map(|c| c.value().to_string())
        .unwrap_or_default();
    if stored_state.is_empty() || stored_state != q.state {
        return Html(
            r#"<h1>Auth failed</h1><p>CSRF state mismatch.</p><p><a href="/">Back</a></p>"#
                .to_string(),
        )
        .into_response();
    }

    let pkce_verifier = cookies
        .get("oauth_pkce")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    // Clear the pre-auth cookies; they have served their purpose.
    cookies.remove(Cookie::new("oauth_state", ""));
    cookies.remove(Cookie::new("oauth_pkce", ""));

    let access_token = match state.github.exchange_code(&q.code, &pkce_verifier).await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "token exchange failed");
            return Html(format!(
                "<h1>Auth failed</h1><p>Token exchange: {e}</p><p><a href=\"/\">Back</a></p>"
            ))
            .into_response();
        }
    };

    let claims = match state.github.fetch_userinfo(&access_token).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "userinfo fetch failed");
            return Html(format!(
                "<h1>Auth failed</h1><p>Userinfo: {e}</p><p><a href=\"/\">Back</a></p>"
            ))
            .into_response();
        }
    };

    let login = claims
        .raw
        .get("login")
        .and_then(|v| v.as_str())
        .unwrap_or("(no login)");
    let email = claims.email.as_deref().unwrap_or("(no email)");
    let name = claims.display_name.as_deref().unwrap_or("(no name)");

    Html(format!(
        r#"<!doctype html>
<html><head><title>Logged in</title>
<style>body{{font-family:system-ui,sans-serif;max-width:640px;margin:3em auto;padding:0 1em}}
pre{{background:#f4f4f4;padding:1em;overflow:auto}}</style>
</head><body>
<h1>Logged in via GitHub</h1>
<p>SocialProvider validated the OAuth code, fetched <code>GET /user</code>, and ran the adopter-supplied claim mapper.</p>
<table>
<tr><th align="left">subject (stable id)</th><td><code>{}</code></td></tr>
<tr><th align="left">login</th><td><code>{login}</code></td></tr>
<tr><th align="left">name</th><td>{name}</td></tr>
<tr><th align="left">email</th><td>{email}</td></tr>
</table>
<h2>Raw userinfo</h2>
<pre>{}</pre>
<p><strong>Reminder:</strong> these claims are TLS-trusted, not signed-and-verified.</p>
<p><a href="/">Back</a></p>
</body></html>"#,
        claims.subject,
        serde_json::to_string_pretty(&claims.raw).unwrap_or_default(),
    ))
    .into_response()
}

fn missing_creds() -> ! {
    tracing::error!(
        "missing GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET; create a GitHub OAuth app \
         at https://github.com/settings/developers with callback URL \
         http://localhost:3000/auth/callback/github, then re-run with \
         GITHUB_CLIENT_ID=your-id GITHUB_CLIENT_SECRET=your-secret \
         cargo run -p axess-example-social. See examples/social/README.md \
         for non-GitHub providers."
    );
    std::process::exit(2);
}
