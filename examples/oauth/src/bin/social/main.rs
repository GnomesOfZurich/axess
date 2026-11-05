//! # axess-example-oauth, `--bin social`
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
//! cargo run -p axess-example-oauth --bin social
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
    )?;

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
<html><head><title>axess-example-oauth: social login</title>
<style>body{font-family:system-ui,sans-serif;max-width:640px;margin:3em auto;padding:0 1em}</style>
</head><body>
<h1>axess social-login example</h1>
<p>Demonstrates the plain-OAuth-2.0 user-login flow for IdPs that do not support OIDC. This sample wires GitHub user login.</p>
<p><strong>Note:</strong> identity comes from GitHub's userinfo endpoint, not from a signed ID token. The security model is weaker than OIDC; see <code>axess::social</code> module docs for the delta and when to reach for OIDC instead.</p>
<p><a href="/auth/login/github">Login with GitHub →</a></p>
</body></html>"#,
    )
}

/// Whether the pre-auth cookies are `Secure`: yes unless
/// `AXESS_DEV_INSECURE_COOKIES=1` is set for plain HTTP in development.
fn secure_cookies() -> bool {
    std::env::var("AXESS_DEV_INSECURE_COOKIES").map_or(true, |v| v != "1")
}

/// The name of a pre-auth cookie. Under `Secure` it carries the `__Host-`
/// prefix (RFC 6265bis), which a browser honours only for a cookie set by
/// the host itself over HTTPS with `Path=/` and no `Domain`: a cookie of
/// that name planted by a sibling subdomain, an `http://` page or a
/// `Domain=` attribute is dropped, so the callback never reads a state or
/// verifier the attacker chose. Plain HTTP in development cannot carry the
/// prefix, so there the bare name is used.
fn pre_auth_cookie(base: &str, secure: bool) -> String {
    if secure {
        format!("__Host-{base}")
    } else {
        base.to_string()
    }
}

/// A pre-auth cookie as the login sets it: HTTP-only, `Lax`, `Path=/`, ten
/// minutes to live, and `Secure` when asked.
fn pre_auth_cookie_for(name: &str, value: String, secure: bool) -> Cookie<'static> {
    let mut cookie = Cookie::new(pre_auth_cookie(name, secure), value);
    cookie.set_http_only(true);
    cookie.set_same_site(tower_cookies::cookie::SameSite::Lax);
    cookie.set_path("/");
    cookie.set_secure(secure);
    cookie.set_max_age(tower_cookies::cookie::time::Duration::minutes(10));
    cookie
}

async fn login(State(state): State<AppState>, cookies: Cookies) -> impl IntoResponse {
    let csrf_state = state.github.mint_csrf_state();
    let auth = state.github.build_auth_url(&csrf_state);

    // Store CSRF state + PKCE verifier in short-lived cookies. A real
    // app would use the SessionLayer's pre-auth session instead; cookies
    // keep this example focused on the social flow.
    //
    // `Lax` still sends them on the top-level GET the provider redirects
    // back with, and withholds them from cross-site sub-requests. They are
    // `Secure` and `__Host-` prefixed unless `AXESS_DEV_INSECURE_COOKIES=1`
    // is set for plain HTTP; `Path=/` and no `Domain` are what the prefix
    // requires.
    let secure = secure_cookies();
    cookies.add(pre_auth_cookie_for("oauth_state", csrf_state, secure));
    cookies.add(pre_auth_cookie_for(
        "oauth_pkce",
        auth.pkce_verifier,
        secure,
    ));

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
    // Verify CSRF state matches what we issued at /auth/login/github. Only
    // the prefixed name is read under `Secure`: a planted bare `oauth_state`
    // cookie is not the one this app set and does not count.
    let secure = secure_cookies();
    let stored_state = cookies
        .get(&pre_auth_cookie("oauth_state", secure))
        .map(|c| c.value().to_string())
        .unwrap_or_default();
    // Constant-time comparison: the state is a secret the attacker must not
    // be able to guess byte by byte from response timing.
    let matches: bool =
        subtle::ConstantTimeEq::ct_eq(stored_state.as_bytes(), q.state.as_bytes()).into();
    if stored_state.is_empty() || !matches {
        return Html(
            r#"<h1>Auth failed</h1><p>CSRF state mismatch.</p><p><a href="/">Back</a></p>"#
                .to_string(),
        )
        .into_response();
    }

    let pkce_verifier = cookies
        .get(&pre_auth_cookie("oauth_pkce", secure))
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    // Clear the pre-auth cookies; they have served their purpose.
    // A removal only matches the cookie it replaces when the path agrees.
    for name in ["oauth_state", "oauth_pkce"] {
        let mut gone = Cookie::new(pre_auth_cookie(name, secure), "");
        gone.set_path("/");
        gone.set_secure(secure);
        cookies.remove(gone);
    }

    let access_token = match state.github.exchange_code(&q.code, &pkce_verifier).await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "token exchange failed");
            return Html(
                r#"<h1>Auth failed</h1><p>The token exchange was refused.</p><p><a href="/">Back</a></p>"#,
            )
            .into_response();
        }
    };

    let claims = match state.github.fetch_userinfo(&access_token).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "userinfo fetch failed");
            return Html(
                r#"<h1>Auth failed</h1><p>The profile could not be fetched.</p><p><a href="/">Back</a></p>"#,
            )
            .into_response();
        }
    };

    let login = html_escape(
        claims
            .raw
            .get("login")
            .and_then(|v| v.as_str())
            .unwrap_or("(no login)"),
    );
    let email = html_escape(claims.email.as_deref().unwrap_or("(no email)"));
    let name = html_escape(claims.display_name.as_deref().unwrap_or("(no name)"));

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
        html_escape(&claims.subject),
        html_escape(&serde_json::to_string_pretty(&claims.raw).unwrap_or_default()),
    ))
    .into_response()
}

fn missing_creds() -> ! {
    tracing::error!(
        "missing GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET; create a GitHub OAuth app \
         at https://github.com/settings/developers with callback URL \
         http://localhost:3000/auth/callback/github, then re-run with \
         GITHUB_CLIENT_ID=your-id GITHUB_CLIENT_SECRET=your-secret \
         cargo run -p axess-example-oauth --bin social. See examples/oauth/README.md \
         for non-GitHub providers."
    );
    std::process::exit(2);
}

/// Escape text for interpolation into HTML. Everything the IdP returns
/// (names, e-mail addresses, error descriptions) is attacker-influenced and
/// goes through this before it reaches a page.
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

#[cfg(test)]
mod tests {
    use super::{pre_auth_cookie, pre_auth_cookie_for};

    /// The state and verifier cookies expire on their own, so an abandoned
    /// login does not leave them in the browser indefinitely.
    #[test]
    fn pre_auth_cookies_expire_after_ten_minutes() {
        for name in ["oauth_state", "oauth_pkce"] {
            let cookie = pre_auth_cookie_for(name, "v".into(), true);
            assert_eq!(
                cookie.max_age(),
                Some(tower_cookies::cookie::time::Duration::minutes(10)),
                "{name}"
            );
        }
    }

    /// The default (Secure) deployment sets `__Host-` cookies, so a planted
    /// bare `oauth_state` is a different cookie and is never read; plain
    /// HTTP development keeps the bare names the browser can store.
    #[test]
    fn secure_pre_auth_cookies_carry_the_host_prefix() {
        assert_eq!(pre_auth_cookie("oauth_state", true), "__Host-oauth_state");
        assert_eq!(pre_auth_cookie("oauth_pkce", true), "__Host-oauth_pkce");
        assert_ne!(
            pre_auth_cookie("oauth_state", true),
            "oauth_state",
            "a planted bare cookie is not the one the callback reads"
        );
        assert_eq!(pre_auth_cookie("oauth_state", false), "oauth_state");
    }
}
