//! The wiring the *Getting started* chapter walks through.
//!
//! The chapter includes the region between the ANCHOR comments, so the
//! code on that page is this code. Keep them in step by never editing
//! the chapter's block directly.

// ANCHOR: wiring
use axess::authn::{
    AuditContext, AuthnService, FactorCredential, FactorOutcome, LoginOutcome, RequestAuthnService,
};
use axess::{
    AuthSession, InMemoryBackend, MemorySessionRegistry, MemorySessionStore, SecureRng,
    SessionLayer, SystemRng,
};
use axum::Json;
use axum::extract::State;
use axum::{Router, http::StatusCode, response::IntoResponse, routing::get};
use serde::Deserialize;
use std::{sync::Arc, time::Duration};

// Session limits tighter than the library's defaults (24 hours idle, 7 days
// in all); the README says why.
const STRICT_IDLE_TTL: Duration = Duration::from_secs(15 * 60);
const STRICT_MAX_SESSION_AGE: Duration = Duration::from_secs(10 * 60 * 60);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Backend -- one type implements both IdentityStore and FactorStore.
    let backend = InMemoryBackend::new()
        .with_default_tenant("default", "Default tenant")
        .with_user_password("alice", "default", "Sample2+");

    // 2. Session store + 3. signing key.
    // `MemorySessionStore` is unbounded and per process: it is for demos.
    // Production uses a persistent store (see the sqlite example).
    let session_store = MemorySessionStore::new();
    // A fresh random key per start: fine for a demo, where a restart only
    // signs everyone out. See "Signing keys" below for what production does.
    let mut signing_key = [0u8; 32];
    SystemRng.fill_bytes(&mut signing_key);

    // 4. AuthnService -- type-erased over clock and RNG; production wires
    //    SystemClock + SystemRng. The session registry records every login, so
    //    that a password reset or a forced logout ends the session; the
    //    session layer below reads the same one. The in-memory registry is
    //    per process: production uses the Valkey registry.
    let registry = MemorySessionRegistry::new();
    let service = Arc::new(
        AuthnService::builder_from_backend(backend)
            .with_registry(registry.clone())
            .build(),
    );

    // 5. SessionLayer threads the session through each request.
    // A short idle lifetime and a cap on the whole session, so abandoned
    // sessions do not pile up and a stolen cookie does not last.
    // The service's sink writes an audit row for each session the layer
    // ends by itself (one past the age cap, one the registry dropped).
    let session_layer = SessionLayer::new(
        session_store.clone(),
        signing_key,
        registry.handle(),
        service.session_end_audit(),
    )
    .with_ttl(STRICT_IDLE_TTL)
    .with_max_session_age(Some(STRICT_MAX_SESSION_AGE))
    .with_secure(secure_cookies()); // see "Cookie security" below.

    // Drop expired sessions every few minutes; nothing else removes them
    // from the in-memory store.
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(300));
        loop {
            tick.tick().await;
            session_store.purge_expired();
        }
    });

    let app = Router::new()
        .route("/", get(public_page))
        .route("/dashboard", get(protected_page))
        // No rate limiting here: production must put a limiter on /login
        // (see examples/sqlite for `RateLimitLayer`).
        .route("/login", axum::routing::post(login))
        .with_state(service)
        .layer(session_layer);

    // 6. Resolve the client address once, outside everything that reads
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

    let answer = attempt(&service, &form, &session).await;

    // 3. A refused attempt ends the login it began. A wrong password for a
    //    real account leaves that account's login open in the session,
    //    where an unknown username leaves the session untouched: the
    //    session, and the cookie set for a changed one, would say which
    //    usernames exist. Clearing on every refusal leaves the same fresh
    //    guest session either way. `login_with_password` does this too.
    if answer.status() != StatusCode::OK {
        session.clear().await;
    }
    answer
}

/// Steps 1 and 2 of a login: begin it, then verify the password.
async fn attempt(
    service: &RequestAuthnService<InMemoryBackend, InMemoryBackend>,
    form: &LoginForm,
    session: &AuthSession,
) -> axum::response::Response {
    // 1. Begin the login. Transitions Guest -> Authenticating.
    match service
        .begin_login(&form.username, "default", session)
        .await
    {
        // The identifier resolved and the first factor is known. For a
        // password-only method that is `FactorKind::Password`.
        Ok(LoginOutcome::FactorRequired(_)) => {}
        // Every answer that is not "send the password" still spends one
        // Argon2id check first. Without it an unknown, inactive or locked
        // username is answered in a millisecond and a real one in tens, and
        // the difference tells a guesser which usernames exist.
        // `login_with_password` does the same in one call.
        Ok(LoginOutcome::InvalidCredentials) => {
            service.burn_password_check(&form.password).await.ok();
            return (StatusCode::UNAUTHORIZED, "invalid credentials").into_response();
        }
        // Reached only when the service is built with
        // `with_lockout_revealed_on_begin`; by default a locked account
        // answers `InvalidCredentials` above, as an unknown username does,
        // so the lock is not observable before any proof.
        Ok(LoginOutcome::Locked { until }) => {
            service.burn_password_check(&form.password).await.ok();
            return locked_reply(until);
        }
        Ok(LoginOutcome::StepUpRequired { .. }) => {
            service.burn_password_check(&form.password).await.ok();
            return (StatusCode::UNAUTHORIZED, "step-up required").into_response();
        }
        Err(e) => {
            // The cause belongs in the log, not in the response.
            eprintln!("begin_login failed: {e}");
            service.burn_password_check(&form.password).await.ok();
            return (StatusCode::UNAUTHORIZED, "invalid credentials").into_response();
        }
    }

    // 2. Verify the password factor. Note the argument order:
    //    credential first, session second.
    match service
        .verify_factor(
            // `Password` holds a `ZeroizedString`, which wipes itself on
            // drop. `.into()` from a `String` is the conversion.
            &FactorCredential::Password(form.password.clone().into()),
            session,
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
        Ok(FactorOutcome::Locked { until }) => locked_reply(until),
        // Guesses from this address are slowed down. Only an account that
        // exists can be throttled, so a `429` with `Retry-After` would say
        // which usernames exist: the answer is the one a wrong password
        // gets, at the cost of the one password check the throttle skipped,
        // and the delay is logged on the server. `login_with_password` does
        // the same in one call.
        Ok(FactorOutcome::Throttled { retry_after }) => {
            eprintln!("login refused, guesses throttled for {retry_after:?}");
            service.burn_password_check(&form.password).await.ok();
            (StatusCode::UNAUTHORIZED, "invalid credentials").into_response()
        }
        Err(e) => {
            eprintln!("verify_factor failed: {e}");
            service.burn_password_check(&form.password).await.ok();
            (StatusCode::UNAUTHORIZED, "invalid credentials").into_response()
        }
    }
}

/// The answer for a locked account: the one a wrong password gets, so the
/// response does not tell a guesser that an account exists and is locked.
/// The lock is logged on the server.
fn locked_reply(until: impl std::fmt::Debug) -> axum::response::Response {
    eprintln!("login refused, account locked until {until:?}");
    (StatusCode::UNAUTHORIZED, "invalid credentials").into_response()
}
// ANCHOR_END: login

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
