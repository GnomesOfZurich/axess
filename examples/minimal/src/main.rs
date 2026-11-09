//! The wiring the *Getting started* chapter walks through.
//!
//! The chapter includes the region between the ANCHOR comments, so the
//! code on that page is this code. Keep them in step by never editing
//! the chapter's block directly.

// ANCHOR: wiring
use axess::authn::{AuditContext, AuthnService, FactorCredential, FactorOutcome, LoginOutcome};
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
        .with_user_password("alice", "default", "Gnomes2+");

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
    let session_layer = SessionLayer::new(session_store.clone(), signing_key, registry.handle())
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
        Ok(FactorOutcome::Locked { until }) => locked_reply(until),
        // Guesses from this address are slowed down: the same answer as a
        // wrong password, with `Retry-After` for a client that reads it.
        Ok(FactorOutcome::Throttled { retry_after }) => (
            StatusCode::TOO_MANY_REQUESTS,
            [(
                axum::http::header::RETRY_AFTER,
                retry_after.as_secs().max(1).to_string(),
            )],
            "invalid credentials",
        )
            .into_response(),
        Err(e) => {
            eprintln!("verify_factor failed: {e}");
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
mod tests {
    use super::*;

    /// The service, with a counted executor for its password checks.
    fn counted_service() -> (
        Arc<AuthnService<InMemoryBackend, InMemoryBackend>>,
        Arc<axess::blocking::KdfExecutor>,
    ) {
        let kdf = Arc::new(axess::blocking::KdfExecutor::inline());
        let backend = InMemoryBackend::new()
            .with_default_tenant("default", "Default tenant")
            .with_user_password("alice", "default", "Gnomes2+");
        let service = AuthnService::builder_from_backend(backend)
            .with_kdf_executor(kdf.clone())
            .build();
        (Arc::new(service), kdf)
    }

    /// Refuse a wrong password for `username` and return the status.
    async fn refuse(
        service: &Arc<AuthnService<InMemoryBackend, InMemoryBackend>>,
        username: &str,
    ) -> StatusCode {
        let form = LoginForm {
            username: username.to_string(),
            password: "not the password".to_string(),
        };
        login(
            axess_core::testing::test_session(),
            State(service.clone()),
            AuditContext::default(),
            Json(form),
        )
        .await
        .into_response()
        .status()
    }

    /// An unknown username costs exactly one password check, as a known one
    /// does, so the two cannot be told apart by how long the check takes.
    #[tokio::test]
    async fn an_unknown_user_costs_one_password_check_like_a_known_one() {
        let (service, kdf) = counted_service();

        let before = kdf.jobs_started();
        assert_eq!(refuse(&service, "alice").await, StatusCode::UNAUTHORIZED);
        let known = kdf.jobs_started() - before;

        let before = kdf.jobs_started();
        assert_eq!(refuse(&service, "mallory").await, StatusCode::UNAUTHORIZED);
        let unknown = kdf.jobs_started() - before;

        assert_eq!(known, 1, "a known user's refusal");
        assert_eq!(unknown, known, "an unknown user's refusal");
    }

    /// The same property as wall-clock time: the fastest unknown refusal is
    /// not far below the fastest known one. Timing depends on the machine,
    /// so this runs only on request (`cargo test -- --ignored`).
    #[tokio::test]
    #[ignore = "wall-clock comparison; the counting test is the gate"]
    async fn an_unknown_user_takes_about_as_long_as_a_known_one() {
        let (service, _) = counted_service();
        refuse(&service, "nobody").await;
        let fastest = |name: &'static str| {
            let service = service.clone();
            async move {
                let mut best = Duration::MAX;
                for _ in 0..3 {
                    let started = std::time::Instant::now();
                    refuse(&service, name).await;
                    best = best.min(started.elapsed());
                }
                best
            }
        };
        let known = fastest("alice").await;
        let unknown = fastest("mallory").await;
        assert!(unknown * 2 >= known, "unknown {unknown:?}, known {known:?}");
    }

    #[tokio::test]
    async fn a_locked_account_gets_the_wrong_password_answer() {
        let reply = locked_reply(Some("tomorrow"));
        assert_eq!(reply.status(), StatusCode::UNAUTHORIZED);
        let body = axum::body::to_bytes(reply.into_body(), 1024).await.unwrap();
        assert_eq!(&body[..], b"invalid credentials");
    }
}
