//! The wiring the *Getting started* chapter walks through.
//!
//! The chapter includes the region between the ANCHOR comments, so the
//! code on that page is this code. Keep them in step by never editing
//! the chapter's block directly.

// ANCHOR: wiring
use axess::authn::{AuditContext, AuthnService, FactorCredential, FactorOutcome, LoginOutcome};
use axess::{AuthSession, InMemoryBackend, MemorySessionStore, SessionLayer};
use axum::Json;
use axum::extract::State;
use axum::{Router, http::StatusCode, response::IntoResponse, routing::get};
use serde::Deserialize;
use std::{sync::Arc, time::Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Backend -- one type implements both IdentityStore and FactorStore.
    let backend = InMemoryBackend::new().with_user_password("alice", "default", "Gnomes2+");

    // 2. Session store + 3. signing key.
    let session_store = MemorySessionStore::new();
    let signing_key: [u8; 32] = [0; 32]; // PLACEHOLDER, see "Signing keys" below.

    // 4. AuthnService -- type-erased over clock and RNG; production wires
    //    SystemClock + SystemRng.
    let service = Arc::new(AuthnService::new(backend.clone(), backend));

    // 5. SessionLayer threads the session through each request.
    let session_layer = SessionLayer::new(session_store, signing_key)
        .with_ttl(Duration::from_secs(86_400))
        .with_secure(false); // dev only -- see "Cookie security" below.

    let app = Router::new()
        .route("/", get(public_page))
        .route("/dashboard", get(protected_page))
        .route("/login", axum::routing::post(login))
        .with_state(service)
        .layer(session_layer);

    // 5. Resolve the client address once, outside everything that reads
    //    one. Without this the audit rows say `ip_source = 'unknown'` and
    //    a tenant IP policy cannot be satisfied. `loopback_only` is the
    //    right set for a dev server bound to 127.0.0.1; a deployment
    //    behind a proxy names that proxy's ranges instead.
    let app = axess::client_ip::layer(app, axess::client_ip::TrustedProxies::loopback_only());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    // `with_connect_info` is what puts the peer address where the
    // client-IP layer can read it. Serve without it and every request
    // arrives with no peer, so the layer has nothing to check a forwarded
    // chain against and resolves to nothing.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}

async fn public_page() -> &'static str {
    "everyone can see this"
}

async fn protected_page(session: AuthSession) -> impl IntoResponse {
    if session.is_authenticated().await {
        (StatusCode::OK, "welcome").into_response()
    } else {
        (StatusCode::UNAUTHORIZED, "log in first").into_response()
    }
}
// ANCHOR_END: wiring

// ANCHOR: login

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

async fn login(
    session: AuthSession,
    State(service): State<Arc<AuthnService<InMemoryBackend, InMemoryBackend>>>,
    // The audit context is an extractor: it reads the address the
    // client-IP layer resolved, plus the user agent and request id. It
    // cannot fail, so there is no rejection to handle.
    audit: AuditContext,
    Json(form): Json<LoginForm>,
) -> impl IntoResponse {
    // 0. Derive the request-scoped handle. Every call below goes through
    //    it, which is not a convention to remember: `begin_login` and
    //    `verify_factor` do not exist on the shared service.
    let service = service.with_audit_context(audit);

    // 1. Begin the login. Transitions Guest -> Authenticating.
    match service
        .begin_login(&form.username, "default", &session)
        .await
    {
        // The identifier resolved and the first factor is known. For a
        // password-only method that is `FactorKind::Password`.
        Ok(LoginOutcome::FactorRequired(_)) => {}
        Ok(LoginOutcome::InvalidCredentials) => {
            return (StatusCode::UNAUTHORIZED, "invalid credentials").into_response();
        }
        Ok(LoginOutcome::Locked { until }) => {
            return (StatusCode::FORBIDDEN, format!("locked until {until:?}")).into_response();
        }
        Ok(LoginOutcome::StepUpRequired { .. }) => {
            return (StatusCode::UNAUTHORIZED, "step-up required").into_response();
        }
        Err(e) => return (StatusCode::UNAUTHORIZED, format!("{e}")).into_response(),
    }

    // 2. Verify the password factor. Note the argument order:
    //    credential first, session second.
    match service
        .verify_factor(
            // `Password` holds a `ZeroizedString`, which wipes itself on
            // drop. `.into()` from a `String` is the conversion.
            &FactorCredential::Password(form.password.clone().into()),
            &session,
        )
        .await
    {
        Ok(FactorOutcome::Authenticated) => (StatusCode::OK, "logged in").into_response(),
        Ok(FactorOutcome::FactorRequired(next)) => {
            // Unreachable for a password-only method, but the branch matters
            // when chaining factors (password + TOTP, etc).
            (StatusCode::OK, format!("next factor: {next:?}")).into_response()
        }
        Ok(FactorOutcome::InvalidCredential) => {
            (StatusCode::UNAUTHORIZED, "invalid credentials").into_response()
        }
        Ok(FactorOutcome::Locked { until }) => {
            (StatusCode::FORBIDDEN, format!("locked until {until:?}")).into_response()
        }
        Err(e) => (StatusCode::UNAUTHORIZED, format!("{e}")).into_response(),
    }
}
// ANCHOR_END: login
