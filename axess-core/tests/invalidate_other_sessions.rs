#![cfg(feature = "testing")]
//! Ending a user's other sessions after a credential change: the session to
//! keep survives with its stored row, every other session of the user ends
//! in one step of the registry (one that registers or moves to a new id
//! while the call runs included), the user's refresh tokens are revoked
//! unless the caller keeps them by name, other users are left alone, and one
//! audit row records it. A registry or a refresh store that fails is
//! reported and audited beside whatever else happened, and a session to
//! keep that is not the user's ends nothing.

use axess_core::session::SessionKey;
use axess_core::testing::fixtures as common;

use axess_clock::Clock as _;
use axess_clock::testing::MockClock;
use axess_core::authn::AuditContext;
use axess_core::authn::error::AuthnError;
use axess_core::authn::event::{AuthEvent, AuthEventStatus, AuthEventType};
use axess_core::authn::ids::{DeviceId, TenantId, UserId};
use axess_core::authn::service::{
    Actor, AuthnService, OTHER_SESSIONS_NOT_ENDED_REASON, OtherSessionsError,
    REFRESH_TOKENS_NOT_REVOKED_REASON, RequestAuthnService,
};
use axess_core::session::data::SessionData;
use axess_core::session::refresh::{
    DeviceTokenRevocation, IssueRequest, Refresh, RefreshToken, RefreshTokenConfig, RefreshTokenId,
    RefreshTokenStore, RotationOutcome, TokenFamilyId, issue_refresh_token,
};
use axess_core::session::store::{
    MemorySessionRegistry, MemorySessionStore, MoveOutcome, SessionRegistry, SessionStore,
};
use axess_core::testing::AuthSessionTestExt;
use axess_core::testing::registry_double::{RegistryDouble, RegistryOp, Step};
use axess_core::testing::{
    MemoryRefreshTokenStore, MockRng,
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session_with_rng,
};
use common::{test_tenant, test_user, tid, uid};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// What the registry of a world is told to do with the one-step call: be
/// down for it, or let another request register sessions at two moments of
/// it, after the service has made it and before the registry's step runs,
/// and once the step has run.
#[derive(Clone, Default)]
struct Faults {
    ending_down: Arc<AtomicBool>,
    arrive_before_the_step: Arc<Mutex<Vec<SessionKey>>>,
    arrive_after_the_step: Arc<Mutex<Vec<SessionKey>>>,
}

/// A registry over the in-memory one that does what `faults` says to the
/// one-step call. It counts how often a user's sessions are listed.
fn faulty(inner: MemorySessionRegistry, faults: &Faults) -> RegistryDouble {
    let (before, after) = (faults.clone(), faults.clone());
    RegistryDouble::over(inner)
        .before(move |call, inner| {
            let down = before.ending_down.load(Ordering::SeqCst);
            let arriving = match call.op() {
                RegistryOp::InvalidateOtherSessions if !down => {
                    std::mem::take(&mut *before.arrive_before_the_step.lock().unwrap())
                }
                _ => Vec::new(),
            };
            async move {
                if call.op() != RegistryOp::InvalidateOtherSessions {
                    return Step::Forward;
                }
                if down {
                    return Step::Fail("registry down");
                }
                for id in arriving {
                    inner.register(call.user(), &id).await.unwrap();
                }
                Step::Forward
            }
        })
        .after(move |call, inner| {
            let arriving = match call.op() {
                RegistryOp::InvalidateOtherSessions => {
                    std::mem::take(&mut *after.arrive_after_the_step.lock().unwrap())
                }
                _ => Vec::new(),
            };
            async move {
                for id in arriving {
                    inner.register(call.user(), &id).await.unwrap();
                }
            }
        })
}

/// A refresh token store over the in-memory one whose revocation of a
/// user's tokens fails while `revoking_down` is set.
#[derive(Clone)]
struct FaultyTokens {
    inner: MemoryRefreshTokenStore,
    revoking_down: Arc<AtomicBool>,
}

impl RefreshTokenStore for FaultyTokens {
    type Error = std::io::Error;

    async fn store_token(&self, token: &RefreshToken) -> Result<(), Self::Error> {
        let Ok(()) = self.inner.store_token(token).await;
        Ok(())
    }

    async fn find_token(&self, hash: &str) -> Result<Option<RefreshToken>, Self::Error> {
        let Ok(found) = self.inner.find_token(hash).await;
        Ok(found)
    }

    async fn revoke_token(&self, id: &RefreshTokenId) -> Result<(), Self::Error> {
        let Ok(()) = self.inner.revoke_token(id).await;
        Ok(())
    }

    async fn revoke_user_tokens(&self, user: &UserId) -> Result<(), Self::Error> {
        if self.revoking_down.load(Ordering::SeqCst) {
            return Err(std::io::Error::other("token store down"));
        }
        let Ok(()) = self.inner.revoke_user_tokens(user).await;
        Ok(())
    }

    async fn revoke_device_tokens(
        &self,
        tenant: &TenantId,
        device: &DeviceId,
    ) -> Result<DeviceTokenRevocation, Self::Error> {
        let Ok(revoked) = self.inner.revoke_device_tokens(tenant, device).await;
        Ok(revoked)
    }

    async fn active_tokens(&self, user: &UserId) -> Result<Vec<RefreshToken>, Self::Error> {
        let Ok(active) = self.inner.active_tokens(user).await;
        Ok(active)
    }

    async fn revoke_family(
        &self,
        user: &UserId,
        family: &TokenFamilyId,
    ) -> Result<(), Self::Error> {
        let Ok(()) = self.inner.revoke_family(user, family).await;
        Ok(())
    }

    async fn issue_capped(&self, token: &RefreshToken, max: usize) -> Result<(), Self::Error> {
        let Ok(()) = self.inner.issue_capped(token, max).await;
        Ok(())
    }

    async fn rotate_token(
        &self,
        parent: &RefreshTokenId,
        token: &RefreshToken,
    ) -> Result<RotationOutcome, Self::Error> {
        let Ok(outcome) = self.inner.rotate_token(parent, token).await;
        Ok(outcome)
    }
}

struct World {
    svc: RequestAuthnService<MockIdentityStore, MockFactorStore>,
    identity: MockIdentityStore,
    registry: RegistryDouble,
    faults: Faults,
    store: MemorySessionStore,
    tokens: FaultyTokens,
    clock: MockClock,
    /// Alice's sessions: the first is the one she keeps.
    alice: Vec<SessionKey>,
    /// Bob's one session.
    bob: SessionKey,
    /// Alice's refresh tokens, one issued to each of two devices.
    alices_tokens: Vec<String>,
    /// Bob's refresh token.
    bobs_token: String,
}

/// A session whose ids are drawn from a generator seeded with `seed`.
fn session_from(seed: u64) -> axess_core::session::AuthSession {
    test_session_with_rng(MockRng::new(seed))
}

/// A session id of `who` with a stored row, not yet registered.
async fn stored_session(store: &MemorySessionStore, who: &str, seed: u64) -> SessionKey {
    let session = session_from(seed);
    session
        .set_authenticated(uid(who), tid("default"), common::start())
        .await;
    let id = session.session_key().await;
    store
        .save(&id, &SessionData::default(), Duration::from_secs(600))
        .await
        .unwrap();
    id
}

/// A registered session of `who` with a stored row.
async fn signed_in(
    registry: &RegistryDouble,
    store: &MemorySessionStore,
    who: &str,
    seed: u64,
) -> SessionKey {
    let id = stored_session(store, who, seed).await;
    registry.register(&uid(who), &id).await.unwrap();
    id
}

/// A refresh token of `who`, the plaintext the client holds.
async fn refresh_token(tokens: &FaultyTokens, clock: &MockClock, who: &str, seed: u64) -> String {
    let (plaintext, _) = issue_refresh_token(
        IssueRequest {
            user_id: &uid(who),
            tenant_id: &tid("t1"),
            device_info: None,
            family_id: None,
            device_id: None,
        },
        &RefreshTokenConfig::default(),
        tokens,
        &MockRng::new(seed),
        clock.now(),
    )
    .await
    .unwrap();
    plaintext
}

/// Alice signed in on four devices and holding two refresh tokens, Bob on
/// one device with one token. `attach_tokens` says whether the service was
/// given the refresh token store.
async fn world_with(attach_tokens: bool) -> World {
    let clock: MockClock = common::test_clock();
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(test_user("alice", "alice"))
        .with_user(test_user("bob", "bob"));
    let faults = Faults::default();
    let registry = faulty(
        MemorySessionRegistry::new().with_clock(Arc::new(clock.clone())),
        &faults,
    );
    let store = MemorySessionStore::new().with_clock(Arc::new(clock.clone()));
    let tokens = FaultyTokens {
        inner: MemoryRefreshTokenStore::new().with_clock(Arc::new(clock.clone())),
        revoking_down: Arc::default(),
    };
    let mut builder = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_clock(clock.clone())
        .with_registry(registry.clone())
        .with_session_store(store.clone());
    if attach_tokens {
        builder = builder.with_refresh_store(tokens.clone());
    }
    let svc = builder.build().with_audit_context(AuditContext::default());
    let mut alice = Vec::new();
    for seed in [101, 202, 303, 404] {
        alice.push(signed_in(&registry, &store, "alice", seed).await);
    }
    let bob = signed_in(&registry, &store, "bob", 505).await;
    let alices_tokens = vec![
        refresh_token(&tokens, &clock, "alice", 11).await,
        refresh_token(&tokens, &clock, "alice", 12).await,
    ];
    let bobs_token = refresh_token(&tokens, &clock, "bob", 13).await;
    World {
        svc,
        identity,
        registry,
        faults,
        store,
        tokens,
        clock,
        alice,
        bob,
        alices_tokens,
        bobs_token,
    }
}

async fn world() -> World {
    world_with(true).await
}

impl World {
    /// The sessions the registry holds for `who`, in a fixed order.
    async fn held(&self, who: &str) -> Vec<SessionKey> {
        let mut held = self
            .registry
            .inner()
            .active_sessions(&uid(who))
            .await
            .unwrap();
        held.sort_by_key(ToString::to_string);
        held
    }

    /// The sessions among `ids` that still have a stored row.
    async fn stored(&self, ids: &[SessionKey]) -> Vec<SessionKey> {
        let mut stored = Vec::new();
        for id in ids {
            if self.store.load(id).await.unwrap().is_some() {
                stored.push(*id);
            }
        }
        stored.sort_by_key(ToString::to_string);
        stored
    }

    /// Whether the refresh token `plaintext` still mints a session. Asked
    /// with rotation off, so the answer does not use the token up.
    async fn refreshes(&self, plaintext: &str) -> bool {
        let config = RefreshTokenConfig {
            rotation: false,
            ..RefreshTokenConfig::default()
        };
        Refresh::any_tenant(plaintext, |_| async { true })
            .without_device_check()
            .run(&self.tokens, &config, &MockRng::new(99), self.clock.now())
            .await
            .is_ok()
    }

    /// Which of Alice's two refresh tokens still mint a session.
    async fn alices_tokens_live(&self) -> Vec<bool> {
        let mut live = Vec::new();
        for token in &self.alices_tokens {
            live.push(self.refreshes(token).await);
        }
        live
    }

    fn invalidation_rows(&self) -> Vec<AuthEvent> {
        self.identity
            .events()
            .into_iter()
            .filter(|e| e.event_type == AuthEventType::SessionInvalidated)
            .collect()
    }

    /// Nothing ended, nothing was revoked and nothing was recorded.
    async fn assert_untouched(&self) {
        assert_eq!(self.held("alice").await, sorted(&self.alice));
        assert_eq!(self.stored(&self.alice).await, sorted(&self.alice));
        assert_eq!(self.held("bob").await, vec![self.bob]);
        assert_eq!(self.alices_tokens_live().await, [true, true]);
        assert!(self.invalidation_rows().is_empty(), "no row claims an end");
    }
}

fn sorted(ids: &[SessionKey]) -> Vec<SessionKey> {
    let mut ids = ids.to_vec();
    ids.sort_by_key(ToString::to_string);
    ids
}

// ── What is ended ────────────────────────────────────────────────────────────

/// The session that asked survives, with its row; every other session of
/// the user is gone from the registry and the store; another user's session
/// is untouched; one row records it, naming no session. The service lists
/// nothing itself: the registry ends the sessions in its own one step.
#[tokio::test]
async fn the_kept_session_survives_and_every_other_one_ends() {
    let w = world().await;
    let keep = w.alice[0];

    w.svc
        .invalidate_other_sessions(&uid("alice"), &keep, Actor::System)
        .await
        .unwrap();

    assert_eq!(w.held("alice").await, vec![keep]);
    assert_eq!(w.stored(&w.alice).await, vec![keep]);
    assert_eq!(w.held("bob").await, vec![w.bob]);
    assert_eq!(w.stored(&[w.bob]).await, vec![w.bob]);
    assert_eq!(
        w.registry.count(RegistryOp::ActiveSessions),
        0,
        "the service read no list of its own to end sessions from"
    );
    let rows = w.invalidation_rows();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].event_status, AuthEventStatus::Success);
    assert_eq!(rows[0].user_id, Some(uid("alice")));
    assert_eq!(
        rows[0].session_id, None,
        "the row stands for all that ended"
    );
    assert_eq!(rows[0].actor_id, None, "the user acted for themselves");
    assert_eq!(rows[0].error, None);
}

/// Whichever session is the one to keep, that one survives.
#[tokio::test]
async fn any_of_the_users_sessions_can_be_the_one_kept() {
    for kept in 0..4 {
        let w = world().await;
        let keep = w.alice[kept];
        w.svc
            .invalidate_other_sessions(&uid("alice"), &keep, Actor::System)
            .await
            .unwrap();
        assert_eq!(w.held("alice").await, vec![keep], "session {kept}");
    }
}

/// An administrator who ends a user's other sessions is named on the row.
#[tokio::test]
async fn an_administrator_who_acts_is_named_on_the_row() {
    let w = world().await;

    w.svc
        .invalidate_other_sessions(&uid("alice"), &w.alice[0], Actor::Admin(&uid("admin")))
        .await
        .unwrap();

    let rows = w.invalidation_rows();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].actor_id, Some(uid("admin")));
}

/// A user with no other session has nothing to end: the call succeeds and
/// still leaves its row.
#[tokio::test]
async fn a_user_with_one_session_keeps_it() {
    let w = world().await;

    w.svc
        .invalidate_other_sessions(&uid("bob"), &w.bob, Actor::System)
        .await
        .unwrap();

    assert_eq!(w.held("bob").await, vec![w.bob]);
    assert_eq!(w.held("alice").await, sorted(&w.alice));
    let rows = w.invalidation_rows();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].user_id, Some(uid("bob")));
}

// ── A sign-in or a rotation while the call runs ──────────────────────────────

/// A session that registers after the service has made its call and before
/// the registry's step runs is ended with the others: the cut-off is the
/// registry's step, not a list the service read earlier. Its stored row
/// goes too.
#[tokio::test]
async fn a_session_that_registers_while_the_call_runs_is_ended() {
    let w = world().await;
    let keep = w.alice[0];
    let late = stored_session(&w.store, "alice", 808).await;
    w.faults.arrive_before_the_step.lock().unwrap().push(late);

    w.svc
        .invalidate_other_sessions(&uid("alice"), &keep, Actor::System)
        .await
        .unwrap();

    assert_eq!(w.held("alice").await, vec![keep]);
    assert!(
        w.stored(&[late]).await.is_empty(),
        "the stored row of the session that arrived meanwhile is gone too"
    );
    let rows = w.invalidation_rows();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].event_status, AuthEventStatus::Success);
}

/// Another session that moves to a new id while the call runs is ended
/// under both: its new id is registered before the step and its old id is
/// dropped after it, as a rotation does, and neither survives.
#[tokio::test]
async fn a_session_that_rotates_while_the_call_runs_is_ended_under_both_ids() {
    let w = world().await;
    let (keep, rotating) = (w.alice[0], w.alice[2]);
    let rotated = stored_session(&w.store, "alice", 818).await;
    w.faults
        .arrive_before_the_step
        .lock()
        .unwrap()
        .push(rotated);

    w.svc
        .invalidate_other_sessions(&uid("alice"), &keep, Actor::System)
        .await
        .unwrap();
    // The rotation's last act: it drops the id it moved away from.
    w.registry
        .invalidate_session(&uid("alice"), &rotating)
        .await
        .unwrap();

    assert_eq!(w.held("alice").await, vec![keep]);
    assert!(w.stored(&[rotating, rotated]).await.is_empty());
}

/// A session to keep that another request carrying the same cookie moved
/// to a new key before the call cannot be told from a copy of that cookie:
/// every session of the user ends, the moved one included, with the rows
/// of every ended key, the refresh tokens are revoked, one success row is
/// written, and the call says that the caller was ended too.
#[tokio::test]
async fn a_session_to_keep_that_another_request_moved_ends_with_the_rest() {
    let w = world().await;
    let keep = w.alice[0];
    let moved_to = stored_session(&w.store, "alice", 919).await;
    assert_eq!(
        w.registry
            .move_session(&uid("alice"), &keep, &moved_to)
            .await
            .unwrap(),
        MoveOutcome::Moved
    );
    w.store.delete(&keep).await.unwrap();

    let result = w
        .svc
        .invalidate_other_sessions(&uid("alice"), &keep, Actor::System)
        .await;

    assert!(
        matches!(result, Err(OtherSessionsError::CallerEnded)),
        "{result:?}"
    );
    assert!(
        w.held("alice").await.is_empty(),
        "no session of the user is left"
    );
    let mut ended = w.alice.clone();
    ended.push(moved_to);
    assert!(
        w.stored(&ended).await.is_empty(),
        "the rows of every ended key are deleted, the moved session's among them"
    );
    assert_eq!(w.held("bob").await, vec![w.bob]);
    assert_eq!(w.alices_tokens_live().await, [false, false]);
    let rows = w.invalidation_rows();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].event_status, AuthEventStatus::Success);
    assert_eq!(rows[0].error, None);
    assert!(matches!(
        AuthnError::from(result.unwrap_err()),
        AuthnError::NoFlow
    ));
}

/// The caller is kept when its own request holds the key the session is
/// under now, whatever keys it held before.
#[tokio::test]
async fn a_session_kept_by_the_key_it_is_under_now_survives() {
    let w = world().await;
    let moved_to = stored_session(&w.store, "alice", 920).await;
    assert_eq!(
        w.registry
            .move_session(&uid("alice"), &w.alice[0], &moved_to)
            .await
            .unwrap(),
        MoveOutcome::Moved
    );

    w.svc
        .invalidate_other_sessions(&uid("alice"), &moved_to, Actor::System)
        .await
        .unwrap();

    assert_eq!(w.held("alice").await, vec![moved_to]);
    assert_eq!(w.stored(&[moved_to]).await, vec![moved_to]);
}

/// A session that registers once the registry's step has run is a sign-in
/// that came after the cut-off: it is not ended, and the call succeeds.
#[tokio::test]
async fn a_session_that_registers_after_the_step_is_a_later_sign_in() {
    let w = world().await;
    let keep = w.alice[0];
    let later = stored_session(&w.store, "alice", 828).await;
    w.faults.arrive_after_the_step.lock().unwrap().push(later);

    w.svc
        .invalidate_other_sessions(&uid("alice"), &keep, Actor::System)
        .await
        .unwrap();

    assert_eq!(w.held("alice").await, sorted(&[keep, later]));
    assert_eq!(w.stored(&[later]).await, vec![later]);
}

// ── Refresh tokens ───────────────────────────────────────────────────────────

/// The user's refresh tokens are revoked with the other sessions, on every
/// device: a token issued before the change no longer mints a session.
/// Another user's token is untouched.
#[tokio::test]
async fn the_users_refresh_tokens_are_revoked_with_the_other_sessions() {
    let w = world().await;
    assert_eq!(w.alices_tokens_live().await, [true, true]);

    w.svc
        .invalidate_other_sessions(&uid("alice"), &w.alice[0], Actor::System)
        .await
        .unwrap();

    assert_eq!(w.alices_tokens_live().await, [false, false]);
    assert!(w.refreshes(&w.bobs_token).await);
}

/// A caller that keeps the refresh tokens says so by the method's name: the
/// sessions end and the tokens still mint sessions.
#[tokio::test]
async fn the_refresh_tokens_are_kept_only_by_the_method_named_for_it() {
    let w = world().await;
    let keep = w.alice[0];

    w.svc
        .invalidate_other_sessions_keeping_refresh_tokens(&uid("alice"), &keep, Actor::System)
        .await
        .unwrap();

    assert_eq!(w.held("alice").await, vec![keep]);
    assert_eq!(w.alices_tokens_live().await, [true, true]);
    let rows = w.invalidation_rows();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].event_status, AuthEventStatus::Success);
}

/// A service that was not given the refresh token store cannot reach the
/// tokens: the sessions end, the call succeeds and the tokens stay.
#[tokio::test]
async fn without_the_refresh_store_the_tokens_are_out_of_reach() {
    let w = world_with(false).await;
    let keep = w.alice[0];

    w.svc
        .invalidate_other_sessions(&uid("alice"), &keep, Actor::System)
        .await
        .unwrap();

    assert_eq!(w.held("alice").await, vec![keep]);
    assert_eq!(w.alices_tokens_live().await, [true, true]);
}

/// A refresh token store that cannot revoke is reported after the sessions
/// were ended, with a failed row naming the tokens.
#[tokio::test]
async fn tokens_that_cannot_be_revoked_are_reported_and_audited() {
    let w = world().await;
    let keep = w.alice[0];
    w.tokens.revoking_down.store(true, Ordering::SeqCst);

    let result = w
        .svc
        .invalidate_other_sessions(&uid("alice"), &keep, Actor::Admin(&uid("admin")))
        .await;

    assert!(
        matches!(
            result,
            Err(OtherSessionsError::RefreshTokensNotRevoked {
                cause: AuthnError::ExternalService(_),
                audit: None,
            })
        ),
        "{result:?}"
    );
    assert_eq!(w.held("alice").await, vec![keep], "the sessions were ended");
    assert_eq!(w.alices_tokens_live().await, [true, true]);
    let rows = w.invalidation_rows();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].event_status, AuthEventStatus::Failure);
    assert_eq!(
        rows[0].error.as_ref().map(|reason| reason.as_str()),
        Some(REFRESH_TOKENS_NOT_REVOKED_REASON)
    );
    assert_eq!(rows[0].actor_id, Some(uid("admin")));
    assert_eq!(
        REFRESH_TOKENS_NOT_REVOKED_REASON,
        "refresh_tokens_not_revoked"
    );
}

// ── A registry that fails ────────────────────────────────────────────────────

/// A registry that does not carry out the step is reported: the sessions
/// are as they were, the refresh tokens are revoked all the same, and the
/// one row is a failure naming the sessions and the actor.
#[tokio::test]
async fn a_registry_that_fails_is_reported_and_audited() {
    let w = world().await;
    let keep = w.alice[0];
    w.faults.ending_down.store(true, Ordering::SeqCst);

    let result = w
        .svc
        .invalidate_other_sessions(&uid("alice"), &keep, Actor::Admin(&uid("admin")))
        .await;

    assert!(
        matches!(
            result,
            Err(OtherSessionsError::SessionsNotEnded {
                cause: AuthnError::ExternalService(_),
                refresh_tokens: None,
                audit: None,
            })
        ),
        "{result:?}"
    );
    assert_eq!(w.held("alice").await, sorted(&w.alice));
    assert_eq!(w.stored(&w.alice).await, sorted(&w.alice));
    assert_eq!(
        w.alices_tokens_live().await,
        [false, false],
        "a registry outage does not leave the tokens live as well"
    );
    let rows = w.invalidation_rows();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].event_status, AuthEventStatus::Failure);
    assert_eq!(
        rows[0].error.as_ref().map(|reason| reason.as_str()),
        Some(OTHER_SESSIONS_NOT_ENDED_REASON)
    );
    assert_eq!(rows[0].user_id, Some(uid("alice")));
    assert_eq!(rows[0].actor_id, Some(uid("admin")));
    assert_eq!(rows[0].session_id, None);
    assert_eq!(OTHER_SESSIONS_NOT_ENDED_REASON, "other_sessions_not_ended");
}

/// When neither the registry nor the refresh store answers, both failures
/// are reported, and the row names the sessions.
#[tokio::test]
async fn a_registry_and_a_token_store_that_both_fail_are_both_reported() {
    let w = world().await;
    w.faults.ending_down.store(true, Ordering::SeqCst);
    w.tokens.revoking_down.store(true, Ordering::SeqCst);

    let result = w
        .svc
        .invalidate_other_sessions(&uid("alice"), &w.alice[0], Actor::System)
        .await;

    let Err(OtherSessionsError::SessionsNotEnded {
        cause: AuthnError::ExternalService(_),
        refresh_tokens: Some(tokens),
        audit: None,
    }) = &result
    else {
        panic!("{result:?}");
    };
    assert!(
        matches!(**tokens, AuthnError::ExternalService(_)),
        "{tokens:?}"
    );
    let rows = w.invalidation_rows();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(
        rows[0].error.as_ref().map(|reason| reason.as_str()),
        Some(OTHER_SESSIONS_NOT_ENDED_REASON)
    );
}

/// An audit write that fails while the registry failed is reported beside
/// that failure, which it does not replace.
#[tokio::test]
async fn an_audit_failure_is_reported_beside_the_failure_it_was_recording() {
    let w = world().await;
    w.faults.ending_down.store(true, Ordering::SeqCst);
    w.identity.arm_record_event_failure();

    let result = w
        .svc
        .invalidate_other_sessions(&uid("alice"), &w.alice[0], Actor::System)
        .await;

    let Err(OtherSessionsError::SessionsNotEnded {
        cause: AuthnError::ExternalService(_),
        refresh_tokens: None,
        audit: Some(audit),
    }) = &result
    else {
        panic!("{result:?}");
    };
    assert!(matches!(**audit, AuthnError::Store(_)), "{audit:?}");
    assert!(w.invalidation_rows().is_empty());
}

/// The same for the tokens: an audit write that fails while the tokens
/// could not be revoked is carried beside that failure.
#[tokio::test]
async fn an_audit_failure_is_reported_beside_tokens_not_revoked() {
    let w = world().await;
    w.tokens.revoking_down.store(true, Ordering::SeqCst);
    w.identity.arm_record_event_failure();

    let result = w
        .svc
        .invalidate_other_sessions(&uid("alice"), &w.alice[0], Actor::System)
        .await;

    let Err(OtherSessionsError::RefreshTokensNotRevoked {
        cause: AuthnError::ExternalService(_),
        audit: Some(audit),
    }) = &result
    else {
        panic!("{result:?}");
    };
    assert!(matches!(**audit, AuthnError::Store(_)), "{audit:?}");
}

/// An audit write that fails after everything was ended is the one thing
/// reported: the sessions are ended, the tokens revoked, the row missing.
#[tokio::test]
async fn an_audit_failure_after_everything_ended_is_reported_as_unrecorded() {
    let w = world().await;
    let keep = w.alice[0];
    w.identity.arm_record_event_failure();

    let result = w
        .svc
        .invalidate_other_sessions(&uid("alice"), &keep, Actor::System)
        .await;

    assert!(
        matches!(
            result,
            Err(OtherSessionsError::Unrecorded(AuthnError::Store(_)))
        ),
        "{result:?}"
    );
    assert_eq!(w.held("alice").await, vec![keep]);
    assert_eq!(w.alices_tokens_live().await, [false, false]);
}

// ── Refusals ─────────────────────────────────────────────────────────────────

/// A session to keep that the registry does not hold for the user ends
/// nothing and revokes nothing: another user's session, or an id the
/// registry has never seen, would otherwise end the caller's own session
/// with the rest.
#[tokio::test]
async fn a_session_to_keep_that_is_not_the_users_ends_nothing() {
    let w = world().await;
    let never_registered = session_from(606).session_key().await;

    for keep in [w.bob, never_registered] {
        let result = w
            .svc
            .invalidate_other_sessions(&uid("alice"), &keep, Actor::System)
            .await;
        assert!(
            matches!(result, Err(OtherSessionsError::Refused(AuthnError::NoFlow))),
            "{result:?}"
        );
        w.assert_untouched().await;
    }
}

/// Without a registry there is nothing to end sessions in: an error, no
/// row, and no token revoked.
#[tokio::test]
async fn without_a_registry_nothing_is_ended_or_audited() {
    let clock = common::test_clock();
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(test_user("alice", "alice"));
    let tokens = FaultyTokens {
        inner: MemoryRefreshTokenStore::new().with_clock(Arc::new(clock.clone())),
        revoking_down: Arc::default(),
    };
    let token = refresh_token(&tokens, &clock, "alice", 21).await;
    let svc = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_clock(clock.clone())
        .with_refresh_store(tokens.clone())
        .build()
        .with_audit_context(AuditContext::default());
    let keep = session_from(707).session_key().await;

    let result = svc
        .invalidate_other_sessions(&uid("alice"), &keep, Actor::System)
        .await;

    assert!(
        matches!(
            result,
            Err(OtherSessionsError::Refused(AuthnError::Internal(_)))
        ),
        "{result:?}"
    );
    assert!(identity.events().is_empty());
    let still_live = Refresh::any_tenant(&token, |_| async { true })
        .without_device_check()
        .run(
            &tokens,
            &RefreshTokenConfig {
                rotation: false,
                ..RefreshTokenConfig::default()
            },
            &MockRng::new(98),
            clock.now(),
        )
        .await
        .is_ok();
    assert!(still_live, "a refused call revokes no token");
}

/// The error a handler answering with `AuthnError` gets: what each outcome
/// carries.
#[test]
fn each_outcome_converts_to_the_error_it_carries() {
    type Outcome = OtherSessionsError<std::io::Error>;
    let converted = |outcome: Outcome| -> AuthnError<std::io::Error> { outcome.into() };
    assert!(matches!(
        converted(Outcome::Refused(AuthnError::Internal("none".into()))),
        AuthnError::Internal(_)
    ));
    assert!(matches!(
        converted(Outcome::SessionsNotEnded {
            cause: AuthnError::ExternalService("down".into()),
            refresh_tokens: Some(Box::new(AuthnError::Internal("tokens".into()))),
            audit: Some(Box::new(AuthnError::Store(std::io::Error::other("audit")))),
        }),
        AuthnError::ExternalService(_)
    ));
    assert!(matches!(
        converted(Outcome::RefreshTokensNotRevoked {
            cause: AuthnError::ExternalService("down".into()),
            audit: None,
        }),
        AuthnError::ExternalService(_)
    ));
    assert!(matches!(
        converted(Outcome::Unrecorded(AuthnError::Store(
            std::io::Error::other("audit")
        ))),
        AuthnError::Store(_)
    ));
    assert!(matches!(
        converted(Outcome::CallerEnded),
        AuthnError::NoFlow
    ));
}
