//! Claim-lock + session-registry mutation coverage on `complete_oauth_login`.

#![cfg(all(feature = "oauth", feature = "testing"))]

mod common;

use axess_core::{
    authn::service::AuthnService,
    testing::{
        mock_authn::{MockFactorStore, MockIdentityStore},
        test_session,
    },
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use common::test_tenant;

// These tests exercise `complete_oauth_login` directly, bypassing the HTTP
// ceremony, so they can drive `verify_oauth_claim_lock` and
// `register_oauth_session_or_clear` along every branch that cargo-mutants
// found uncovered.

/// Compute the claim-binding lock exactly as `compute_claim_lock` in
/// `login.rs` does: SHA-256(provider ":" subject ":" session_id_bytes)
/// URL-safe base64.
async fn test_claim_lock(
    provider: &str,
    subject: &str,
    session: &axess_core::AuthSession,
) -> String {
    use sha2::{Digest, Sha256};
    let sid = session.session_id().await;
    let mut hasher = Sha256::new();
    hasher.update(provider.as_bytes());
    hasher.update(b":");
    hasher.update(subject.as_bytes());
    hasher.update(b":");
    hasher.update(sid.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

/// Minimal `OAuthClaims` for claim-lock and registry tests.
fn test_claims(provider: &str, subject: &str) -> axess_factors::oauth::OAuthClaims {
    axess_factors::oauth::OAuthClaims {
        provider: std::sync::Arc::from(provider),
        subject: subject.to_string(),
        email: None,
        email_verified: None,
        name: None,
        groups: vec![],
        roles: vec![],
        access_token: None,
        refresh_token: None,
        oidc_sid: None,
        id_token_hint: None,
        additional_claims: serde_json::Value::Null,
    }
}

/// A `SessionRegistry` whose `register` always errors. Used to exercise
/// the register-failure branch in `register_oauth_session_or_clear`.
#[derive(Clone)]
struct FailingRegistry;

#[derive(Debug)]
struct FailRegisterError;

impl std::fmt::Display for FailRegisterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "injected register failure")
    }
}

impl std::error::Error for FailRegisterError {}

impl axess_core::SessionRegistry for FailingRegistry {
    type Error = FailRegisterError;

    async fn register(
        &self,
        user_id: &axess_core::UserId,
        session_id: &axess_core::SessionId,
    ) -> Result<(), FailRegisterError> {
        tracing::trace!(%user_id, %session_id, "FailingRegistry: register stub");
        Err(FailRegisterError)
    }

    async fn is_valid(
        &self,
        user_id: &axess_core::UserId,
        session_id: &axess_core::SessionId,
    ) -> Result<bool, FailRegisterError> {
        tracing::trace!(%user_id, %session_id, "FailingRegistry: is_valid stub");
        Ok(false)
    }

    async fn invalidate_user(&self, user_id: &axess_core::UserId) -> Result<(), FailRegisterError> {
        tracing::trace!(%user_id, "FailingRegistry: invalidate_user stub");
        Ok(())
    }

    async fn invalidate_session(
        &self,
        user_id: &axess_core::UserId,
        session_id: &axess_core::SessionId,
    ) -> Result<(), FailRegisterError> {
        tracing::trace!(%user_id, %session_id, "FailingRegistry: invalidate_session stub");
        Ok(())
    }

    async fn active_sessions(
        &self,
        user_id: &axess_core::UserId,
    ) -> Result<Vec<axess_core::SessionId>, FailRegisterError> {
        tracing::trace!(%user_id, "FailingRegistry: active_sessions stub returns empty");
        Ok(Vec::new())
    }
}

/// `complete_oauth_login` with no claim-lock stashed must
/// return `Err(AuthnError::NoFlow)`. Catches the mutation
/// `verify_oauth_claim_lock -> Ok(())` (line 438): the mutant succeeds even
/// though the session carries no lock; the real function refuses.
#[tokio::test]
async fn no_claim_lock_stashed_returns_no_flow() {
    use axess_core::authn::error::AuthnError;
    use axess_factors::oauth::MockOAuthProvider;

    let mock = MockOAuthProvider::new("idp").with_user("sub1", "u@e.com", vec![], vec![]);
    let user = common::test_user("u1", "user1");
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(user.clone());
    let authn = AuthnService::new(identity, MockFactorStore::new()).with_oauth_provider(mock);

    let session = test_session();
    // No claim lock stashed; session is clean.
    let claims = test_claims("idp", "sub1");
    let result = authn.complete_oauth_login(&user, &claims, &session).await;
    assert!(
        matches!(result, Err(AuthnError::NoFlow)),
        "missing claim lock must return NoFlow, got {result:?}"
    );
}

/// stashing a WRONG claim-lock must also return
/// `Err(AuthnError::NoFlow)`. Catches the mutation
/// `ct_eq -> true` (line 446): the mutant accepts any stashed string as
/// matching; the real function constant-time-compares and rejects a mismatch.
#[tokio::test]
async fn wrong_claim_lock_returns_no_flow() {
    use axess_core::authn::error::AuthnError;
    use axess_factors::oauth::MockOAuthProvider;

    let mock = MockOAuthProvider::new("idp2").with_user("sub2", "u@e.com", vec![], vec![]);
    let user = common::test_user("u1", "user1");
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(user.clone());
    let authn = AuthnService::new(identity, MockFactorStore::new()).with_oauth_provider(mock);

    let session = test_session();
    session
        .set_custom(
            "axess.oauth.claim_lock",
            serde_json::Value::String("totally-wrong-lock-value".to_string()),
        )
        .await;

    let claims = test_claims("idp2", "sub2");
    let result = authn.complete_oauth_login(&user, &claims, &session).await;
    assert!(
        matches!(result, Err(AuthnError::NoFlow)),
        "mismatched claim lock must return NoFlow, got {result:?}"
    );
}

/// when the session registry rejects `register`, the session
/// must be cleared and `Err(AuthnError::NoFlow)` returned. Catches the
/// mutation `register_oauth_session_or_clear -> Ok(())` (line 512): the
/// mutant succeeds silently; the real function propagates the registry error.
#[tokio::test]
async fn register_failure_returns_no_flow() {
    use axess_core::authn::error::AuthnError;
    use axess_factors::oauth::MockOAuthProvider;

    let mock = MockOAuthProvider::new("idp3").with_user("sub3", "u@e.com", vec![], vec![]);
    let user = common::test_user("u1", "user1");
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(user.clone());
    let authn = AuthnService::new(identity, MockFactorStore::new())
        .with_oauth_provider(mock)
        .with_registry(FailingRegistry);

    let session = test_session();
    let claims = test_claims("idp3", "sub3");
    let lock = test_claim_lock("idp3", "sub3", &session).await;
    session
        .set_custom("axess.oauth.claim_lock", serde_json::Value::String(lock))
        .await;

    let result = authn.complete_oauth_login(&user, &claims, &session).await;
    assert!(
        matches!(result, Err(AuthnError::NoFlow)),
        "registry register failure must return NoFlow, got {result:?}"
    );
}

/// with a working registry and an active user,
/// `complete_oauth_login` must return `Ok(())`. Catches two mutations:
/// `delete !` (line 516): the mutant enters the error block on a
///   *successful* register, returning `Err(NoFlow)`; the real code proceeds.
/// `!status.allows_login() -> true` (line 539): the mutant rejects active
///   users as locked; the real function passes them through.
#[tokio::test]
async fn active_user_with_working_registry_returns_ok() {
    use axess_core::MemorySessionRegistry;
    use axess_factors::oauth::MockOAuthProvider;

    let mock = MockOAuthProvider::new("idp4").with_user("sub4", "u@e.com", vec![], vec![]);
    let user = common::test_user("u1", "user1");
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(user.clone());
    let authn = AuthnService::new(identity, MockFactorStore::new())
        .with_oauth_provider(mock)
        .with_registry(MemorySessionRegistry::new());

    let session = test_session();
    let claims = test_claims("idp4", "sub4");
    let lock = test_claim_lock("idp4", "sub4", &session).await;
    session
        .set_custom("axess.oauth.claim_lock", serde_json::Value::String(lock))
        .await;

    let result = authn.complete_oauth_login(&user, &claims, &session).await;
    assert!(
        result.is_ok(),
        "active user + working registry must return Ok(()), got {result:?}"
    );
}

/// when the account is suspended after registry registration,
/// the session must be cleared and `Err(AuthnError::Locked)` returned.
/// Catches two mutations:
/// `register_oauth_session_or_clear -> Ok(())` (line 512): the mutant skips
///   the status check entirely.
/// `!status.allows_login() -> false` (line 539): the mutant never enters the
///   locked branch, silently authenticating a suspended account.
#[tokio::test]
async fn suspended_user_post_register_returns_locked() {
    use axess_core::MemorySessionRegistry;
    use axess_core::authn::error::AuthnError;
    use axess_core::authn::types::{EntityState, StatusDetail};
    use axess_factors::oauth::MockOAuthProvider;
    use chrono::Utc;

    let mock = MockOAuthProvider::new("idp5").with_user("sub5", "u@e.com", vec![], vec![]);
    let now = Utc::now();
    let suspended_user = axess_core::authn::types::User {
        status: EntityState::Suspended(StatusDetail {
            reason: std::sync::Arc::from("account under review"),
            since: now,
            until: None,
        }),
        ..common::test_user("u1", "user1")
    };
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(suspended_user.clone());
    let authn = AuthnService::new(identity, MockFactorStore::new())
        .with_oauth_provider(mock)
        .with_registry(MemorySessionRegistry::new());

    let session = test_session();
    let claims = test_claims("idp5", "sub5");
    let lock = test_claim_lock("idp5", "sub5", &session).await;
    session
        .set_custom("axess.oauth.claim_lock", serde_json::Value::String(lock))
        .await;

    let result = authn
        .complete_oauth_login(&suspended_user, &claims, &session)
        .await;
    assert!(
        matches!(result, Err(AuthnError::Locked { .. })),
        "suspended account must return Locked after post-register status check, got {result:?}"
    );
}

/// `verify_provider_issuer_matches` must refuse with `CsrfMismatch`
/// when the stored provider issuer differs from the current provider's issuer.
/// Catches the mutation `verify_provider_issuer_matches -> Ok(())` (line 796):
/// the mutant skips the check entirely, allowing a mismatched issuer to
/// proceed to token exchange.
///
/// Method: manually stash ceremony state with an attacker-controlled issuer,
/// then call `finish_oauth_login` with the correct CSRF state. Real code
/// returns `Err(CsrfMismatch)` at the issuer check; the mutant proceeds to
/// `exchange_code` and returns `Ok(claims)`.
#[tokio::test]
async fn verify_provider_issuer_mismatch_returns_csrf_mismatch() {
    use axess_factors::oauth::{MockOAuthProvider, OAuthError};

    // MockOAuthProvider::new("name") sets issuer = "https://name.example.com".
    let mock =
        MockOAuthProvider::new("idp-issuer-check").with_user("sub", "u@e.com", vec![], vec![]);
    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let authn = AuthnService::new(identity, MockFactorStore::new()).with_oauth_provider(mock);

    let session = test_session();
    // Stash a full ceremony manually; MockOAuthProvider doesn't implement
    // build_auth_url, so we can't use begin_oauth_login here.
    let csrf = "ax028-issuer-csrf-state-1234567890";
    let pkce_verifier = "a".repeat(43); // RFC 7636 §4.1 minimum, unreserved alphabet
    session
        .set_custom(
            "axess.oauth.csrf_state",
            serde_json::Value::String(csrf.into()),
        )
        .await;
    session
        .set_custom(
            "axess.oauth.nonce",
            serde_json::Value::String("test-nonce".into()),
        )
        .await;
    session
        .set_custom(
            "axess.oauth.pkce_verifier",
            serde_json::Value::String(pkce_verifier),
        )
        .await;
    session
        .set_custom(
            "axess.oauth.provider",
            serde_json::Value::String("idp-issuer-check".into()),
        )
        .await;
    session
        .set_custom(
            "axess.oauth.started",
            serde_json::Value::String(chrono::Utc::now().to_rfc3339()),
        )
        .await;
    // Attacker-controlled issuer; does NOT match provider's real issuer.
    session
        .set_custom(
            "axess.oauth.provider_issuer",
            serde_json::Value::String("https://attacker.example.com".into()),
        )
        .await;

    let result = authn.finish_oauth_login("any-code", csrf, &session).await;
    assert!(
        matches!(result, Err(OAuthError::CsrfMismatch)),
        "tampered provider_issuer must return CsrfMismatch, got {result:?}"
    );
}
