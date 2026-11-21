#![cfg(feature = "testing")]
//! The rails of a signup: the input `begin_signup` refuses before it reads
//! the store, a tenant that exists but is not active, a pending workflow of
//! another kind handed to `complete_signup`, and a completion stopped by a
//! registry that cannot register its session or a store that cannot activate
//! the account: nothing is done, and the same secret completes it later.

use axess_clock::testing::Shift;
use axess_core::session::SessionKey;
use axess_core::testing::fixtures as common;

use axess_core::authn::AuditContext;
use axess_core::authn::error::AuthnError;
use axess_core::authn::event::{AuthEventStatus, AuthEventType};
use axess_core::authn::service::{
    AuthnService, RequestAuthnService, SIGNUP_SESSION_NOT_REGISTERED_REASON, SignupOutcome,
};
use axess_core::authn::store::IdentityLookup;
use axess_core::authn::types::{EntityState, StatusDetail, Tenant, User};
use axess_core::session::data::{AuthState, WorkflowKind, WorkflowState};
use axess_core::session::extractor::AuthSession;
use axess_core::session::store::{MemorySessionRegistry, SessionRegistry};
use axess_core::testing::registry_double::{RegistryDouble, RegistryOp, Step};
use axess_core::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use common::{test_tenant, test_user, tid, uid};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// The longest identifier, display name or tenant identifier a signup takes.
const CAP: usize = axess_core::validation::MAX_IDENTIFIER_BYTES;
const _: () = assert!(axess_core::validation::MAX_DISPLAY_NAME_BYTES == CAP);

type Service = RequestAuthnService<MockIdentityStore, MockFactorStore>;

/// A service over a store holding `tenant`, and the store.
fn rig(tenant: Tenant) -> (Service, MockIdentityStore) {
    let clock = common::test_clock();
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(tenant);
    let service = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_clock(clock.clone())
        .build()
        .with_audit_context(AuditContext::default());
    (service, identity)
}

/// A person signing up as `identifier`, shown as `display_name`.
fn newcomer(identifier: &str, display_name: &str) -> User {
    let mut user = test_user("u1", identifier);
    user.display_name = display_name.into();
    user.status = EntityState::Candidate;
    user
}

/// The reason of every failed `SignupStarted` row, with the tenant it names.
fn refusals(
    identity: &MockIdentityStore,
) -> Vec<(String, Option<axess_core::authn::ids::TenantId>)> {
    identity
        .events()
        .iter()
        .filter(|e| {
            e.event_type == AuthEventType::SignupStarted
                && e.event_status == AuthEventStatus::Failure
        })
        .map(|e| {
            (
                e.error
                    .as_ref()
                    .map(|reason| reason.as_str().to_owned())
                    .unwrap_or_default(),
                e.tenant_id,
            )
        })
        .collect()
}

/// `begin_signup` refuses `user` in `tenant_identifier` as invalid input:
/// the error, one failed row naming the reason and no tenant, no stored
/// user and a session left as it was.
async fn assert_refused_as_invalid_input(user: User, tenant_identifier: &str) {
    let (service, identity) = rig(test_tenant());
    let session = test_session();
    let user_id = user.id;

    let result = service
        .begin_signup(user, tenant_identifier, &session)
        .await;

    assert!(
        matches!(result, Err(AuthnError::InvalidAssertion)),
        "{result:?}"
    );
    assert_eq!(
        refusals(&identity),
        vec![("invalid_input".to_owned(), None)]
    );
    assert!(identity.get_user(&user_id).await.unwrap().is_none());
    assert!(matches!(session.auth_state().await, AuthState::Guest));
}

/// `begin_signup` takes `user` into `tenant`: a verification secret comes
/// back and the user is stored.
async fn assert_started(user: User, tenant: Tenant) {
    let tenant_identifier = tenant.identifier.to_string();
    let (service, identity) = rig(tenant);
    let user_id = user.id;

    let outcome = service
        .begin_signup(user, &tenant_identifier, &test_session())
        .await
        .unwrap();

    assert!(
        matches!(outcome, SignupOutcome::Started(Some(_))),
        "{outcome:?}"
    );
    assert!(identity.get_user(&user_id).await.unwrap().is_some());
    assert!(refusals(&identity).is_empty());
}

// ── Input rails ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_empty_identifier_is_refused() {
    assert_refused_as_invalid_input(newcomer("", "Alice"), "default").await;
}

#[tokio::test]
async fn a_display_name_over_the_cap_is_refused() {
    assert_refused_as_invalid_input(
        newcomer("alice@example.com", &"a".repeat(CAP + 1)),
        "default",
    )
    .await;
}

#[tokio::test]
async fn an_empty_tenant_identifier_is_refused() {
    assert_refused_as_invalid_input(newcomer("alice@example.com", "Alice"), "").await;
}

#[tokio::test]
async fn a_tenant_identifier_over_the_cap_is_refused() {
    assert_refused_as_invalid_input(newcomer("alice@example.com", "Alice"), &"t".repeat(CAP + 1))
        .await;
}

#[tokio::test]
async fn a_control_character_in_the_identifier_is_refused() {
    assert_refused_as_invalid_input(newcomer("alice\u{0007}@example.com", "Alice"), "default")
        .await;
}

/// Printable and inside the cap, but not a form a new account may take:
/// surrounding whitespace reads as the same name without it.
#[tokio::test]
async fn an_identifier_with_surrounding_whitespace_is_refused() {
    assert_refused_as_invalid_input(newcomer(" alice@example.com", "Alice"), "default").await;
}

/// Each cap is the longest value taken, not the first one refused.
#[tokio::test]
async fn an_identifier_exactly_at_the_cap_is_taken() {
    assert_started(newcomer(&"a".repeat(CAP), "Alice"), test_tenant()).await;
}

#[tokio::test]
async fn a_display_name_exactly_at_the_cap_is_taken() {
    assert_started(
        newcomer("alice@example.com", &"a".repeat(CAP)),
        test_tenant(),
    )
    .await;
}

#[tokio::test]
async fn a_tenant_identifier_exactly_at_the_cap_is_taken() {
    let mut tenant = test_tenant();
    tenant.identifier = "t".repeat(CAP).into();
    assert_started(newcomer("alice@example.com", "Alice"), tenant).await;
}

// ── A tenant that exists but is not active ───────────────────────────────────

/// A suspended tenant takes no signup: the outcome is the one an unknown
/// tenant gets, the row names the tenant and its own reason, and no user is
/// stored.
#[tokio::test]
async fn a_suspended_tenant_takes_no_signup() {
    let mut tenant = test_tenant();
    tenant.status = EntityState::Suspended(StatusDetail::administrative("hold", common::start()));
    let (service, identity) = rig(tenant);
    let session = test_session();

    let outcome = service
        .begin_signup(newcomer("alice@example.com", "Alice"), "default", &session)
        .await
        .unwrap();

    assert!(
        matches!(outcome, SignupOutcome::TenantNotActive),
        "{outcome:?}"
    );
    assert_eq!(
        refusals(&identity),
        vec![("tenant_not_active".to_owned(), Some(tid("t1")))]
    );
    assert!(identity.get_user(&uid("u1")).await.unwrap().is_none());
    assert!(matches!(session.auth_state().await, AuthState::Guest));
}

// ── A pending workflow of another kind ───────────────────────────────────────

/// Lowercase hex SHA-256, the form a pending workflow keeps its secret in.
fn digest(secret: &str) -> String {
    use sha2::Digest as _;
    sha2::Sha256::digest(secret.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// A session pending a workflow of `kind` for `user`, completed by `secret`
/// for the next hour.
async fn pending(kind: WorkflowKind, user: &User, secret: &str) -> AuthSession {
    let session = test_session();
    session
        .set_pending_workflow(
            user.id,
            user.tenant_id,
            WorkflowState::new(kind, 1, common::start()).with_verification(
                digest(secret),
                axess_clock::Until::At(common::start().plus(axess_clock::SignedDuration::hours(1))),
            ),
        )
        .await;
    session
}

/// `complete_signup` completes a signup only. A session pending another
/// workflow for a user still awaiting activation, holding a secret that
/// matches and has not expired, activates nobody and stays as it was.
#[tokio::test]
async fn a_pending_workflow_of_another_kind_completes_no_signup() {
    let user = newcomer("alice@example.com", "Alice");
    for kind in [
        WorkflowKind::PasswordReset,
        WorkflowKind::EmailVerification,
        WorkflowKind::Custom("signup".into()),
    ] {
        let (service, identity) = rig(test_tenant());
        let identity = identity.with_user(user.clone());
        let session = pending(kind.clone(), &user, "the-secret").await;

        let result = service.complete_signup(&session, "the-secret").await;

        assert!(
            matches!(result, Err(AuthnError::NoFlow)),
            "{kind:?}: {result:?}"
        );
        let status = identity.account_status(&user.id).await.unwrap();
        assert!(matches!(status, EntityState::Candidate), "{kind:?}");
        assert!(
            matches!(
                session.auth_state().await,
                AuthState::PendingWorkflow { ref workflow, .. } if workflow.kind == kind
            ),
            "{kind:?}: the session is left pending what it was pending"
        );
        assert!(identity.events().is_empty(), "{kind:?}");
    }
}

/// The same session and secret under the signup kind do complete: the
/// refusal above is the kind's and nothing else's.
#[tokio::test]
async fn the_same_pending_state_as_a_signup_completes() {
    let user = newcomer("alice@example.com", "Alice");
    let (service, identity) = rig(test_tenant());
    let identity = identity.with_user(user.clone());
    let session = pending(WorkflowKind::Signup, &user, "the-secret").await;

    service
        .complete_signup(&session, "the-secret")
        .await
        .unwrap();

    assert!(identity.account_status(&user.id).await.unwrap().is_active());
    assert!(session.is_authenticated().await);
}

// ── A registry that cannot register, a store that cannot activate ────────────

/// A session registry that registers nothing while `refusing` is set, and is
/// an in-memory registry otherwise.
fn refusable(inner: MemorySessionRegistry, refusing: Arc<AtomicBool>) -> RegistryDouble {
    RegistryDouble::over(inner).before(move |call, _| {
        let refused = call.op() == RegistryOp::Register && refusing.load(Ordering::SeqCst);
        async move {
            if refused {
                Step::Fail("no room for the session")
            } else {
                Step::Forward
            }
        }
    })
}

/// A signup begun for Alice against a service whose registry is the
/// returned double: the service, the store, the registry, the session, the
/// verification secret and Alice's id.
struct SignupBegun {
    service: Service,
    identity: MockIdentityStore,
    registry: RegistryDouble,
    refusing: Arc<AtomicBool>,
    session: AuthSession,
    secret: String,
    user_id: axess_core::UserId,
}

impl SignupBegun {
    async fn new() -> Self {
        let clock = common::test_clock();
        let identity = MockIdentityStore::new()
            .with_clock(clock.clone())
            .with_tenant(test_tenant());
        let refusing = Arc::new(AtomicBool::new(false));
        let registry = refusable(
            MemorySessionRegistry::new().with_clock(Arc::new(clock.clone())),
            refusing.clone(),
        );
        let service = AuthnService::builder(identity.clone(), MockFactorStore::new())
            .with_clock(clock.clone())
            .with_registry(registry.clone())
            .build()
            .with_audit_context(AuditContext::default());
        let session = test_session();
        let user = newcomer("alice@example.com", "Alice");
        let user_id = user.id;
        let secret = match service
            .begin_signup(user, "default", &session)
            .await
            .unwrap()
        {
            SignupOutcome::Started(Some(verification)) => verification.secret().to_owned(),
            other => panic!("expected a verification secret, got {other:?}"),
        };
        Self {
            service,
            identity,
            registry,
            refusing,
            session,
            secret,
            user_id,
        }
    }

    /// The status and reason of every `SignupCompleted` row, in order, each
    /// checked to name Alice.
    fn completions(&self) -> Vec<(AuthEventStatus, Option<String>)> {
        self.identity
            .events()
            .iter()
            .filter(|e| e.event_type == AuthEventType::SignupCompleted)
            .map(|e| {
                assert_eq!(e.user_id, Some(self.user_id), "the row names the user");
                (
                    e.event_status.clone(),
                    e.error.as_ref().map(|reason| reason.as_str().to_owned()),
                )
            })
            .collect()
    }

    /// The sessions the registry holds for Alice.
    async fn registered(&self) -> Vec<SessionKey> {
        self.registry
            .inner()
            .active_sessions(&self.user_id)
            .await
            .unwrap()
    }

    /// Nothing was done: Alice is still a candidate, the session is still
    /// pending her signup and the registry holds no session of hers.
    async fn assert_nothing_done(&self) {
        let status = self.identity.account_status(&self.user_id).await.unwrap();
        assert!(matches!(status, EntityState::Candidate), "{status:?}");
        let state = self.session.auth_state().await;
        assert!(
            matches!(
                state,
                AuthState::PendingWorkflow { ref workflow, .. }
                    if workflow.kind == WorkflowKind::Signup
            ),
            "the signup is still pending: {state:?}"
        );
        assert!(self.registered().await.is_empty());
    }

    /// The same secret now completes the signup: Alice is active and the
    /// session authenticated and registered.
    async fn assert_completes(&self) {
        self.service
            .complete_signup(&self.session, &self.secret)
            .await
            .unwrap();
        let status = self.identity.account_status(&self.user_id).await.unwrap();
        assert!(status.is_active(), "{status:?}");
        assert!(self.session.is_authenticated().await);
        assert_eq!(
            self.registered().await,
            vec![self.session.session_key().await]
        );
    }
}

/// A signup whose session the registry cannot register activates nothing:
/// the account is still a candidate, the session still pending the signup,
/// and a failed completion row says why. The same secret completes the
/// signup once the registry answers.
#[tokio::test]
async fn a_signup_whose_session_cannot_be_registered_activates_nothing() {
    let w = SignupBegun::new().await;
    w.refusing.store(true, Ordering::SeqCst);

    let result = w.service.complete_signup(&w.session, &w.secret).await;

    assert!(
        matches!(result, Err(AuthnError::ExternalService(_))),
        "{result:?}"
    );
    w.assert_nothing_done().await;
    let refused = (
        AuthEventStatus::Failure,
        Some(SIGNUP_SESSION_NOT_REGISTERED_REASON.to_owned()),
    );
    assert_eq!(w.completions(), vec![refused.clone()]);

    w.refusing.store(false, Ordering::SeqCst);
    w.assert_completes().await;
    assert_eq!(
        w.completions(),
        vec![refused, (AuthEventStatus::Success, None)]
    );
}

/// A signup whose account the store cannot activate undoes the registration
/// it had made: the registry holds no session of the user, the account is
/// still a candidate, the signup still pending, and no completion is
/// recorded. The same secret completes it once the store answers.
#[tokio::test]
async fn a_signup_whose_account_cannot_be_activated_undoes_the_registration() {
    let w = SignupBegun::new().await;
    w.identity.arm_activate_user_failure();

    let result = w.service.complete_signup(&w.session, &w.secret).await;

    assert!(matches!(result, Err(AuthnError::Store(_))), "{result:?}");
    w.assert_nothing_done().await;
    assert!(w.completions().is_empty());

    w.identity.disarm_activate_user_failure();
    w.assert_completes().await;
    assert_eq!(w.completions(), vec![(AuthEventStatus::Success, None)]);
}
