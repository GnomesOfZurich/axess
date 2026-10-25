//! Every way `begin_login` can refuse before a user is known makes the same
//! store calls, in the same order, as a permitted request naming an identifier
//! that does not exist, runs no password hash, and leaves one audit row.
//!
//! The comparison is on the recorded sequence of calls into the identity and
//! factor stores (a [`CallLog`] shared by both), which is the thing a latency
//! observer is measuring.

use super::super::AuthnService;
use super::*;
use crate::authn::event::AuthFailureReason;
use crate::authn::ids::UserId;
use crate::authn::types::{EntityState, IpPolicy, Tenant, User};
use crate::authn::{AuditContext, RequestAuthnService};
use crate::blocking::KdfExecutor;
use crate::session::data::SessionData;
use crate::session::extractor::AuthSession;
use crate::session::layer::{SessionHandle, SessionInner};
use crate::testing::mock_authn::{CallLog, MockFactorStore, MockIdentityStore};
use axess_rng::SecureRng;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::RwLock;

/// What a refused-before-user request is expected to do, in order.
const PRE_USER_SEQUENCE: [&str; 6] = [
    "find_tenant",
    "ip_policy_for_tenant",
    "find_user",
    "account_status",
    "available_methods",
    "record_event",
];

fn session() -> AuthSession {
    let inner = SessionInner {
        id: crate::session::id::SessionId::new(&axess_rng::SystemRng),
        data: SessionData::default(),
        modified: false,
        needs_persist: false,
        regenerate: false,
        pre_cycle_id: None,
        rng: std::sync::Arc::new(axess_rng::SystemRng),
        pending_fingerprint: None,
        max_custom_bytes: 64 * 1024,
    };
    AuthSession(SessionHandle(Arc::new(RwLock::new(inner))))
}

fn tenant(identifier: &str, status: EntityState) -> Tenant {
    let now = chrono::Utc::now();
    Tenant {
        id: axess_identity::testing::tenant("t-eq"),
        identifier: identifier.into(),
        display_name: "acme".into(),
        status,
        created_by: UserId::system(),
        created_at: now,
        updated_by: UserId::system(),
        updated_at: now,
    }
}

fn user(display_name: &str) -> User {
    let now = chrono::Utc::now();
    User {
        id: axess_identity::testing::user("u-eq"),
        tenant_id: axess_identity::testing::tenant("t-eq"),
        identifier: "alice".into(),
        display_name: display_name.into(),
        status: EntityState::Active,
        webauthn_id: None,
        created_by: UserId::system(),
        created_at: now,
        updated_by: UserId::system(),
        updated_at: now,
    }
}

fn suspended() -> EntityState {
    EntityState::Suspended(crate::authn::types::StatusDetail {
        reason: "hold".into(),
        since: chrono::Utc::now() - chrono::Duration::days(1),
        until: None,
    })
}

struct Rig {
    svc: RequestAuthnService<MockIdentityStore, MockFactorStore>,
    log: CallLog,
    identity: MockIdentityStore,
    kdf: Arc<KdfExecutor>,
}

fn rig(
    tenant: Tenant,
    user: User,
    policy: Option<IpPolicy>,
    ctx: AuditContext,
    rng: Option<Arc<dyn SecureRng>>,
) -> Rig {
    let log = CallLog::new();
    let mut identity = MockIdentityStore::new()
        .with_call_log(&log)
        .with_tenant(tenant.clone())
        .with_user(user);
    if let Some(policy) = policy {
        identity = identity.with_ip_policy(&tenant.id, policy);
    }
    let kdf = Arc::new(KdfExecutor::inline());
    let mut builder =
        AuthnService::builder(identity.clone(), MockFactorStore::new().with_call_log(&log))
            .with_kdf_executor(kdf.clone());
    if let Some(rng) = rng {
        builder = builder.with_rng(rng);
    }
    Rig {
        svc: builder.build().with_audit_context(ctx),
        log,
        identity,
        kdf,
    }
}

fn from_ip(ip: &str) -> AuditContext {
    AuditContext {
        ip_address: Some(ip.parse().unwrap()),
        ..Default::default()
    }
}

fn allow_ten() -> IpPolicy {
    IpPolicy {
        allow: vec!["10.0.0.0/8".into()],
        deny: vec![],
    }
}

async fn run(rig: &Rig, identifier: &str, tenant_identifier: &str) -> Vec<&'static str> {
    let out = rig
        .svc
        .begin_login(identifier, tenant_identifier, &session())
        .await
        .expect("a refusal is an answer, not an error");
    assert!(matches!(out, LoginOutcome::InvalidCredentials), "{out:?}");
    assert_eq!(rig.kdf.jobs_started(), 0, "no password hash on this path");
    rig.log.calls()
}

fn last_reason(rig: &Rig) -> Option<AuthFailureReason> {
    rig.identity.events().last().and_then(|e| e.error.clone())
}

#[tokio::test]
async fn an_unknown_identifier_makes_the_baseline_sequence() {
    let r = rig(
        tenant("acme", EntityState::Active),
        user("alice"),
        None,
        AuditContext::default(),
        None,
    );
    assert_eq!(run(&r, "nobody", "acme").await, PRE_USER_SEQUENCE);
    assert_eq!(last_reason(&r), Some(AuthFailureReason::UnknownIdentifier));
}

#[tokio::test]
async fn an_ip_refusal_makes_the_baseline_sequence_and_an_audit_row() {
    let r = rig(
        tenant("acme", EntityState::Active),
        user("alice"),
        Some(allow_ten()),
        from_ip("203.0.113.9"),
        None,
    );
    assert_eq!(run(&r, "alice", "acme").await, PRE_USER_SEQUENCE);
    assert_eq!(last_reason(&r), Some(AuthFailureReason::IpPolicy));
    let event = r.identity.events().pop().unwrap();
    assert_eq!(
        event.tenant_id,
        Some(axess_identity::testing::tenant("t-eq"))
    );
    assert_eq!(event.user_id, None, "no user is named on a refusal");
}

#[tokio::test]
async fn a_restricting_policy_with_no_address_makes_the_baseline_sequence() {
    let r = rig(
        tenant("acme", EntityState::Active),
        user("alice"),
        Some(allow_ten()),
        AuditContext::default(),
        None,
    );
    assert_eq!(run(&r, "alice", "acme").await, PRE_USER_SEQUENCE);
    assert_eq!(last_reason(&r), Some(AuthFailureReason::IpPolicy));
}

#[tokio::test]
async fn an_unknown_tenant_makes_the_baseline_sequence() {
    let r = rig(
        tenant("acme", EntityState::Active),
        user("alice"),
        None,
        AuditContext::default(),
        None,
    );
    assert_eq!(run(&r, "alice", "no-such-tenant").await, PRE_USER_SEQUENCE);
    assert_eq!(last_reason(&r), Some(AuthFailureReason::UnknownTenant));
}

#[tokio::test]
async fn a_suspended_tenant_makes_the_baseline_sequence() {
    let r = rig(
        tenant("acme", suspended()),
        user("alice"),
        None,
        AuditContext::default(),
        None,
    );
    assert_eq!(run(&r, "alice", "acme").await, PRE_USER_SEQUENCE);
    assert_eq!(last_reason(&r), Some(AuthFailureReason::NotActive));
}

#[tokio::test]
async fn a_malformed_tenant_row_makes_the_baseline_sequence() {
    let r = rig(
        tenant("ac\u{1}me", EntityState::Active),
        user("alice"),
        None,
        AuditContext::default(),
        None,
    );
    assert_eq!(run(&r, "alice", "ac\u{1}me").await, PRE_USER_SEQUENCE);
    assert_eq!(last_reason(&r), Some(AuthFailureReason::InvalidTenantRow));
}

#[tokio::test]
async fn a_malformed_user_row_makes_the_baseline_sequence() {
    let r = rig(
        tenant("acme", EntityState::Active),
        user("al\0ice"),
        None,
        AuditContext::default(),
        None,
    );
    assert_eq!(run(&r, "alice", "acme").await, PRE_USER_SEQUENCE);
    assert_eq!(last_reason(&r), Some(AuthFailureReason::UnknownIdentifier));
}

#[tokio::test]
async fn a_real_user_with_no_methods_makes_the_same_sequence_too() {
    let r = rig(
        tenant("acme", EntityState::Active),
        user("alice"),
        None,
        AuditContext::default(),
        None,
    );
    assert_eq!(run(&r, "alice", "acme").await, PRE_USER_SEQUENCE);
    assert_eq!(
        last_reason(&r),
        Some(AuthFailureReason::NoFactorsConfigured)
    );
}

/// Counts the bytes the service asks its RNG for.
struct CountingRng(AtomicUsize);
impl SecureRng for CountingRng {
    fn fill_bytes(&self, dest: &mut [u8]) {
        self.0.fetch_add(dest.len(), Ordering::SeqCst);
        dest.fill(0x42);
    }
}

#[tokio::test]
async fn throwaway_ids_come_from_the_injected_rng() {
    let rng = Arc::new(CountingRng(AtomicUsize::new(0)));
    let r = rig(
        tenant("acme", EntityState::Active),
        user("alice"),
        None,
        AuditContext::default(),
        Some(rng.clone()),
    );
    run(&r, "alice", "no-such-tenant").await;
    assert_eq!(
        rng.0.load(Ordering::SeqCst),
        32,
        "one 16-byte tenant id and one 16-byte user id"
    );
}
