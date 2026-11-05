//! The application: provider setup, the router, and its handlers.
//!
//! Everything a request touches is built in [`build`]; `main.rs` only reads
//! the environment, binds a port and serves what comes back.

use crate::identities::MemoryFederatedIdentities;
use crate::provisioning::{Provisioner, Provisioning, Resolution, ResolveError, TenantPolicy};
use axess::authn::{
    AuditContext, AuthnService, EntityState, IdentityLookup, Tenant, TenantId, UserId,
};
use axess::federation::oauth::{
    BackChannelLogoutHandler, ClientAssertionSigner, DpopKey, OAuthError, OAuthLoginOptions,
    OAuthProvider, OAuthProviderConfig,
};
use axess::testing::{MockFactorStore, MockIdentityStore};
use axess::{
    AuthSession, Clock, MemorySessionRegistry, MemorySessionStore, SecureRng, SessionLayer,
    SessionRegistryAdapter, SystemClock, SystemRng,
};
use axum::{
    Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use jsonwebtoken::Algorithm;
use serde::Deserialize;
use std::sync::Arc;

/// The authentication service the example runs.
pub type Service = AuthnService<MockIdentityStore, MockFactorStore>;

/// Session key for the provider the signed-in user came from.
const SESSION_PROVIDER: &str = "example.provider";
/// Session key for the ID token, kept for RP-initiated logout.
const SESSION_ID_TOKEN_HINT: &str = "example.id_token_hint";
/// Session keys for what a refresh needs: the IdP's refresh token, the
/// subject the login recorded and the nonce of the login's ID token. A
/// production application keeps a refresh token sealed in its own store, not
/// in the session; the example's session store is memory and so is the token.
const SESSION_REFRESH_TOKEN: &str = "example.refresh_token";
const SESSION_SUBJECT: &str = "example.subject";
const SESSION_NONCE: &str = "example.nonce";
/// Session key for the seed of the DPoP key the tokens are bound to, when the
/// provider binds them (by default, wherever the IdP advertises DPoP). The
/// tokens work with this key and no other, so it is kept as carefully as the
/// refresh token beside it, and restored by whichever process refreshes.
const SESSION_DPOP_KEY: &str = "example.dpop_key";

/// The session spelling of a DPoP key: its seed, in hex.
fn dpop_key_to_text(key: &DpopKey) -> String {
    key.to_seed_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The key [`dpop_key_to_text`] spelled, or `None` for anything else.
fn dpop_key_from_text(text: &str) -> Option<DpopKey> {
    let bytes: Vec<u8> = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect::<Option<_>>()?;
    Some(DpopKey::from_seed(bytes.try_into().ok()?))
}

/// How the application authenticates to the IdP's token endpoint.
#[derive(Clone)]
pub enum ClientAuth {
    /// The client secret registered at the IdP (`client_secret_basic`).
    Secret(String),
    /// `private_key_jwt` (RFC 7523): an assertion signed with this key
    /// replaces the secret, and no request carries one.
    PrivateKeyJwt {
        /// The private key, PEM (PKCS#1 or PKCS#8).
        pem: String,
        /// The signing algorithm, as the IdP has the matching public key
        /// registered for it (`RS256`, `ES256`, ...).
        algorithm: Algorithm,
        /// The `kid` to put in the assertion's header, when the IdP's copy of
        /// the key has one.
        key_id: Option<String>,
    },
}

impl std::fmt::Debug for ClientAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Secret(_) => f.write_str("ClientAuth::Secret(<redacted>)"),
            Self::PrivateKeyJwt {
                algorithm, key_id, ..
            } => f
                .debug_struct("ClientAuth::PrivateKeyJwt")
                .field("algorithm", algorithm)
                .field("key_id", key_id)
                .field("pem", &"<redacted>")
                .finish(),
        }
    }
}

/// One identity-provider registration, in one place.
///
/// Both the authentication service and the back-channel logout handler need a
/// provider of their own (the service owns the one it is given), so each is
/// built by calling [`discover`](Self::discover) here. Changing how providers
/// are registered, or from where, is a change to this type and nowhere else.
#[derive(Clone, Debug)]
pub struct ProviderSettings {
    /// The registration name; it appears in the login and callback routes.
    pub name: String,
    /// The issuer URL whose `/.well-known/openid-configuration` is fetched.
    pub issuer: String,
    /// The OAuth client id registered at the IdP.
    pub client_id: String,
    /// How the client authenticates at the token endpoint.
    pub client_auth: ClientAuth,
    /// Where the IdP sends the browser after its own logout. It is forwarded
    /// only because it is on the provider's allowlist, and it must be
    /// registered at the IdP as well.
    pub post_logout_redirect: String,
    /// The origin the application is served from, e.g. `http://localhost:3000`.
    pub base_url: String,
    /// The signature algorithms the provider's tokens may use, as registered
    /// (`id_token_signed_response_alg`). Empty accepts what the provider
    /// advertises; name one (`RS256` is the OpenID Connect default) to refuse
    /// every other.
    pub id_token_algs: Vec<String>,
}

impl ProviderSettings {
    /// The callback URL registered at the IdP for this provider.
    pub fn redirect_uri(&self) -> String {
        format!("{}/auth/callback/{}", self.base_url, self.name)
    }

    /// Discover the provider's endpoints and keys and build its registration.
    pub async fn discover(
        &self,
    ) -> Result<OAuthProviderConfig, axess::federation::oauth::OAuthError> {
        let config = match &self.client_auth {
            ClientAuth::Secret(secret) => {
                OAuthProviderConfig::discover(
                    &self.name,
                    &self.issuer,
                    &self.client_id,
                    secret,
                    &self.redirect_uri(),
                )
                .await?
            }
            ClientAuth::PrivateKeyJwt {
                pem,
                algorithm,
                key_id,
            } => {
                let mut signer = ClientAssertionSigner::from_pem(&self.client_id, pem, *algorithm)?;
                if let Some(kid) = key_id {
                    signer = signer.with_key_id(kid);
                }
                OAuthProviderConfig::discover_with_private_key_jwt(
                    &self.name,
                    &self.issuer,
                    signer,
                    &self.redirect_uri(),
                )
                .await?
            }
        }
        // Without this list the redirect handed to the IdP's logout endpoint
        // is dropped: only an exact match is forwarded.
        .with_allowed_post_logout_redirect_uris([self.post_logout_redirect.as_str()]);
        if self.id_token_algs.is_empty() {
            config.build()
        } else {
            config
                .with_id_token_signing_algs(&self.id_token_algs)
                .build()
        }
    }
}

/// What [`build`] needs.
#[derive(Clone, Debug)]
pub struct Config {
    /// The identity providers a user can sign in with.
    pub providers: Vec<ProviderSettings>,
    /// Whether the tenant creates users on first login.
    pub provisioning: Provisioning,
    /// Refuse to create a user whose e-mail address the provider did not verify.
    pub require_verified_email: bool,
    /// Send the session cookie with `Secure`. Off only for a browser that
    /// refuses `Secure` cookies over plain HTTP on localhost.
    pub secure_cookies: bool,
}

/// The built application and the handles a caller may want to inspect.
pub struct App {
    /// The routes, with the session layer on. Serve it with
    /// `into_make_service_with_connect_info::<SocketAddr>()` behind
    /// [`axess::client_ip::layer`], as `main.rs` does.
    pub router: Router,
    /// The authentication service.
    pub authn: Arc<Service>,
    /// The identity store the users are created in.
    pub identity: MockIdentityStore,
    /// The federated-identity table.
    pub identities: Arc<MemoryFederatedIdentities>,
    /// The tenant the users live in.
    pub tenant: TenantId,
    /// Finds or creates the users; also how an administrator links an identity
    /// beforehand for a tenant that creates no one on first login.
    pub provisioner: Arc<Provisioner<MockIdentityStore, MemoryFederatedIdentities>>,
}

#[derive(Clone)]
struct AppState {
    authn: Arc<Service>,
    identity: MockIdentityStore,
    provisioner: Arc<Provisioner<MockIdentityStore, MemoryFederatedIdentities>>,
    tenant: TenantId,
    providers: Arc<Vec<ProviderSettings>>,
}

/// Why [`build`] failed.
#[derive(Debug)]
pub enum BuildError {
    /// A provider could not be discovered.
    Provider(String, axess::federation::oauth::OAuthError),
    /// The tenant record or the logout handler could not be set up.
    Setup(String),
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Provider(name, e) => write!(f, "provider {name}: {e}"),
            Self::Setup(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for BuildError {}

/// Build the application: providers, tenant, stores, session layer, routes.
pub async fn build(config: Config) -> Result<App, BuildError> {
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let rng: Arc<dyn SecureRng> = Arc::new(SystemRng);

    // The tenant the federated users belong to. A real application reads it
    // from its tenant table; the in-memory store is seeded here.
    let tenant_id = TenantId::new(&rng);
    let tenant = Tenant::new(
        tenant_id.to_string(),
        "example",
        "Example tenant",
        EntityState::Active,
        UserId::system(),
        clock.now(),
    )
    .map_err(BuildError::Setup)?;
    let identity = MockIdentityStore::new().with_tenant(tenant);
    let registry = MemorySessionRegistry::new();

    let mut builder = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_registry(registry.clone());
    let mut for_logout = Vec::new();
    for settings in &config.providers {
        let discover = |s: &ProviderSettings| {
            let s = s.clone();
            async move {
                s.discover()
                    .await
                    .map_err(|e| BuildError::Provider(s.name.clone(), e))
            }
        };
        builder = builder.with_oauth_provider(discover(settings).await?);
        let provider: Arc<dyn OAuthProvider> = Arc::new(discover(settings).await?);
        for_logout.push(provider);
    }
    let authn = Arc::new(builder.build());

    // IdP-initiated logout: the IdP POSTs a signed logout token here and the
    // sessions it names end. The handler shares the service's `sid` map, which
    // every login fills, and its registry, which the session layer consults.
    let backchannel = BackChannelLogoutHandler::new(
        &for_logout,
        Arc::new(SessionRegistryAdapter(registry.clone())),
        authn.sid_map(),
        clock.clone(),
    )
    .ok_or_else(|| BuildError::Setup("no provider advertises an issuer".into()))?
    .with_audit(authn.backchannel_logout_audit());

    let identities = Arc::new(MemoryFederatedIdentities::new());
    let provisioner = Arc::new(Provisioner::new(
        identity.clone(),
        identities.clone(),
        TenantPolicy {
            tenant: tenant_id,
            provisioning: config.provisioning,
            require_verified_email: config.require_verified_email,
        },
        clock,
        rng,
    ));

    // Generate a fresh random key; sessions reset on restart (OK for dev).
    // In production, load a persistent key from a secret store.
    let mut signing_key = [0u8; 32];
    SystemRng.fill_bytes(&mut signing_key);
    let session_layer = SessionLayer::new(MemorySessionStore::new(), signing_key)
        .with_secure(config.secure_cookies)
        // A session the registry no longer holds (back-channel logout, a
        // forced logout) is refused on its next request.
        .with_registry(Arc::new(SessionRegistryAdapter(registry)));

    let state = AppState {
        authn: authn.clone(),
        identity: identity.clone(),
        provisioner: provisioner.clone(),
        tenant: tenant_id,
        providers: Arc::new(config.providers),
    };

    let logout_routes = Router::new()
        .route(
            "/auth/backchannel-logout",
            post(BackChannelLogoutHandler::handle_backchannel_logout),
        )
        .with_state(backchannel);
    let router = Router::new()
        .route("/", get(home))
        .route("/auth/login/{provider}", get(login))
        .route("/auth/callback/{provider}", get(callback))
        .route("/profile", get(profile))
        .route("/auth/logout", post(logout))
        .route("/auth/refresh", post(refresh))
        .with_state(state)
        .merge(logout_routes)
        .layer(session_layer);

    Ok(App {
        router,
        authn,
        identity,
        identities,
        tenant: tenant_id,
        provisioner,
    })
}

async fn home(State(state): State<AppState>) -> Html<String> {
    let links: String = state
        .providers
        .iter()
        .map(|p| {
            format!(
                "<p><a href=\"/auth/login/{name}\">Sign in with {name}</a></p>",
                name = html_escape(&p.name)
            )
        })
        .collect();
    Html(format!(
        r#"<!doctype html>
<html><head><title>OAuth Example</title></head><body>
<h1>Axess OAuth Example</h1>
{links}
<p><a href="/profile">View Profile</a> (requires login)</p>
</body></html>"#
    ))
}

/// Start the login: the browser goes to the IdP. The login is begun for the
/// example's tenant, so completion refuses a user from any other.
async fn login(
    State(state): State<AppState>,
    Path(provider): Path<String>,
    session: AuthSession,
) -> Response {
    match state
        .authn
        .begin_oauth_login_in_tenant(
            &provider,
            &OAuthLoginOptions::default(),
            &state.tenant,
            &session,
        )
        .await
    {
        Ok((auth_url, _csrf)) => Redirect::temporary(auth_url.as_str()).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "begin_oauth_login failed");
            page(
                StatusCode::BAD_REQUEST,
                "Error",
                "Could not start the login.",
            )
        }
    }
}

/// The IdP's answer. `iss` is the RFC 9207 issuer parameter, compared with the
/// issuer the login began with.
#[derive(Deserialize)]
struct CallbackParams {
    code: String,
    state: String,
    iss: Option<String>,
}

/// Finish the login in three steps, each of which can refuse:
///
/// 1. `finish_oauth_login_with_iss` checks the callback and the ID token and
///    returns the claims, and binds them to this session (the claim lock).
///    The userinfo endpoint, if there is one, is asked for the same subject.
/// 2. [`Provisioner::resolve`] turns the claims into a local user: the one the
///    `(issuer, subject)` pair is linked to, or a new one if the tenant's
///    policy allows it.
/// 3. `complete_oauth_login` verifies the claim lock for that user and claims,
///    then makes the session authenticated. Claims that are not the ones step
///    1 returned for this session do not complete.
// ANCHOR: callback
async fn callback(
    State(state): State<AppState>,
    Path(_provider): Path<String>,
    Query(params): Query<CallbackParams>,
    session: AuthSession,
    audit: AuditContext,
) -> Response {
    let authn = state.authn.with_audit_context(audit);
    let claims = match authn
        .finish_oauth_login_with_iss(&params.code, &params.state, params.iss.as_deref(), &session)
        .await
    {
        Ok(claims) => claims,
        Err(e) => {
            tracing::error!(error = %e, "finish_oauth_login failed");
            return page(
                StatusCode::BAD_REQUEST,
                "Login failed",
                "The provider's answer could not be accepted.",
            );
        }
    };

    // The provider's userinfo endpoint, when it has one, must describe the
    // subject the ID token named (OIDC Core 5.3.2). A response about someone
    // else refuses the login; any other failure (no endpoint, a scope the
    // token lacks) leaves the ID token's claims, which the login rests on.
    // Tokens bound to a DPoP key travel with a proof signed by it.
    if let Some(access_token) = &claims.access_token {
        match authn
            .fetch_userinfo(
                &claims.provider,
                access_token,
                &claims.subject,
                claims.dpop_key.as_deref(),
            )
            .await
        {
            Ok(_) => {}
            Err(OAuthError::SubjectMismatch) => {
                tracing::error!("userinfo described another subject than the ID token");
                return page(
                    StatusCode::BAD_REQUEST,
                    "Login failed",
                    "The provider's answer could not be accepted.",
                );
            }
            Err(e) => tracing::debug!(error = %e, "userinfo not used"),
        }
    }

    let resolution = match state.provisioner.resolve(&claims).await {
        Ok(r) => r,
        Err(ResolveError::NotProvisioned | ResolveError::UnverifiedEmail) => {
            return page(
                StatusCode::FORBIDDEN,
                "No account",
                "This identity has no account here and the tenant does not create one.",
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "could not resolve a local user");
            return page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Login failed",
                "No local user could be found for this identity.",
            );
        }
    };
    let user = resolution.user();

    if let Err(e) = authn.complete_oauth_login(user, &claims, &session).await {
        tracing::error!(error = %e, "complete_oauth_login failed");
        return page(
            StatusCode::FORBIDDEN,
            "Login failed",
            "The login could not be completed.",
        );
    }
    tracing::info!(
        user_id = %user.id,
        created = resolution.created(),
        "signed in through {}",
        claims.provider
    );

    // Becoming authenticated cleared the session's custom data; keep what
    // logout needs. The ID token is the `id_token_hint` of RP-initiated logout.
    session
        .set_custom(
            SESSION_PROVIDER,
            serde_json::Value::String(claims.provider.to_string()),
        )
        .await;
    if let Some(hint) = &claims.id_token_hint {
        session
            .set_custom(
                SESSION_ID_TOKEN_HINT,
                serde_json::Value::String(String::from(&**hint)),
            )
            .await;
    }
    if let Some(refresh) = &claims.refresh_token {
        session
            .set_custom(
                SESSION_REFRESH_TOKEN,
                serde_json::Value::String(String::from(&**refresh)),
            )
            .await;
        session
            .set_custom(
                SESSION_SUBJECT,
                serde_json::Value::String(claims.subject.clone()),
            )
            .await;
        if let Some(nonce) = claims.additional_claims.get("nonce") {
            session.set_custom(SESSION_NONCE, nonce.clone()).await;
        }
        if let Some(key) = &claims.dpop_key {
            session
                .set_custom(
                    SESSION_DPOP_KEY,
                    serde_json::Value::String(dpop_key_to_text(key)),
                )
                .await;
        }
    }
    let landing = match resolution {
        Resolution::Created(_) => "/profile?welcome=1",
        Resolution::Found(_) => "/profile",
    };
    Redirect::to(landing).into_response()
}
// ANCHOR_END: callback

/// End the local session, then send the browser to the IdP's logout endpoint
/// so its session ends too (RP-initiated logout). The other direction, the IdP
/// telling us, is the back-channel route.
async fn logout(
    State(state): State<AppState>,
    session: AuthSession,
    audit: AuditContext,
) -> Response {
    let provider = session
        .get_custom(SESSION_PROVIDER)
        .await
        .and_then(|v| v.as_str().map(str::to_owned));
    let hint = session
        .get_custom(SESSION_ID_TOKEN_HINT)
        .await
        .and_then(|v| v.as_str().map(str::to_owned));
    if let Err(e) = state.authn.with_audit_context(audit).logout(&session).await {
        // The session is ended whatever the audit store did.
        tracing::error!(error = %e, "logout audit failed");
    }
    // The IdP hands `state` back on the post-logout redirect. The landing
    // page is static and has nothing to protect, so it is not checked; an
    // application whose landing page acts on the redirect should keep it
    // (the session is gone by then, so in a cookie) and compare.
    let mut random = [0u8; 16];
    SystemRng.fill_bytes(&mut random);
    let logout_state: String = random.iter().map(|b| format!("{b:02x}")).collect();
    let redirect = provider.as_deref().and_then(|name| {
        let settings = state.providers.iter().find(|p| p.name == name)?;
        state.authn.build_end_session_url(
            name,
            hint.as_deref(),
            Some(&settings.post_logout_redirect),
            Some(&logout_state),
        )
    });
    match redirect {
        Some(url) => Redirect::to(url.as_str()).into_response(),
        None => Redirect::to("/").into_response(),
    }
}

/// Refresh on demand: exchange the stored refresh token at the IdP for new
/// tokens, keep the token the IdP rotated to, and ask the userinfo endpoint,
/// with the new access token, about the same subject. Tokens bound to a DPoP
/// key are refreshed with the key the login returned, restored from the
/// session. A refresh response the library refuses (another issuer, another
/// subject, a nonce that does not match the login's) answers 502 and changes
/// nothing; a userinfo answer for another subject answers 502 and ends the
/// session.
// ANCHOR: refresh
async fn refresh(
    State(state): State<AppState>,
    session: AuthSession,
    audit: AuditContext,
) -> Response {
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
    let (Some(provider), Some(token), Some(subject)) = (
        text(SESSION_PROVIDER).await,
        text(SESSION_REFRESH_TOKEN).await,
        text(SESSION_SUBJECT).await,
    ) else {
        return page(
            StatusCode::CONFLICT,
            "No refresh token",
            "The provider issued no refresh token for this session.",
        );
    };
    let nonce = text(SESSION_NONCE).await;
    let dpop_key = text(SESSION_DPOP_KEY)
        .await
        .as_deref()
        .and_then(dpop_key_from_text);
    let authn = state.authn.with_audit_context(audit);
    let outcome = match authn
        .refresh_oauth_token(
            &provider,
            &token,
            &subject,
            nonce.as_deref(),
            dpop_key.as_ref(),
        )
        .await
    {
        Ok(outcome) => outcome,
        Err(e) => {
            tracing::error!(error = %e, "refresh_oauth_token failed");
            return page(
                StatusCode::BAD_GATEWAY,
                "Refresh failed",
                "The provider's answer could not be accepted.",
            );
        }
    };
    match authn
        .fetch_userinfo(
            &provider,
            &outcome.access_token,
            &subject,
            dpop_key.as_ref(),
        )
        .await
    {
        Ok(_) => {}
        Err(OAuthError::SubjectMismatch) => {
            // The IdP now vouches for another subject under this session's
            // tokens: nothing from this refresh is kept, and the session ends.
            tracing::error!("userinfo described another subject after the refresh");
            if let Err(e) = authn.logout(&session).await {
                tracing::error!(error = %e, "logout audit failed");
            }
            return page(
                StatusCode::BAD_GATEWAY,
                "Refresh failed",
                "The provider's answer could not be accepted.",
            );
        }
        Err(e) => tracing::debug!(error = %e, "userinfo not used"),
    }
    // The IdP may have spent the token that was sent; keep the one it returns.
    session
        .set_custom(
            SESSION_REFRESH_TOKEN,
            serde_json::Value::String(String::from(&*outcome.refresh_token)),
        )
        .await;
    page(StatusCode::OK, "Refreshed", "The tokens were refreshed.")
}
// ANCHOR_END: refresh

/// Protected page. It reads the axess session (who is signed in, in which
/// tenant) and loads the user from the identity store; the IdP's claims are
/// gone by now and the page does not need them.
// ANCHOR: profile
async fn profile(
    State(state): State<AppState>,
    Query(q): Query<std::collections::HashMap<String, String>>,
    session: AuthSession,
) -> Response {
    let Some((user_id, tenant_id)) = session.authenticated_ids().await else {
        return Redirect::to("/").into_response();
    };
    let user = match state.identity.get_user(&user_id).await {
        Ok(Some(user)) => user,
        _ => return Redirect::to("/").into_response(),
    };
    let welcome = if q.contains_key("welcome") {
        "<p>Welcome: your account was created by this login.</p>"
    } else {
        ""
    };
    Html(format!(
        r#"<!doctype html>
<html><head><title>Profile</title></head><body>
<h1>Profile</h1>
{welcome}
<ul>
  <li><strong>User id:</strong> {user_id}</li>
  <li><strong>Tenant:</strong> {tenant_id}</li>
  <li><strong>Login identifier:</strong> {identifier}</li>
  <li><strong>Name:</strong> {name}</li>
</ul>
<form method="POST" action="/auth/logout"><button type="submit">Log out</button></form>
<a href="/">Home</a>
</body></html>"#,
        identifier = html_escape(&user.identifier),
        name = html_escape(&user.display_name),
    ))
    .into_response()
}
// ANCHOR_END: profile

fn page(status: StatusCode, title: &str, message: &str) -> Response {
    (
        status,
        Html(format!(
            "<!doctype html><html><head><title>{title}</title></head><body>\
             <h1>{title}</h1><p>{message}</p><a href=\"/\">Back</a></body></html>"
        )),
    )
        .into_response()
}

/// Escape text for interpolation into HTML. Everything the IdP returns
/// (names, e-mail addresses, error descriptions) is attacker-influenced and
/// goes through this before it reaches a page.
pub fn html_escape(input: &str) -> String {
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
