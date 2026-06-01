#![cfg(feature = "testing")]
//! Concurrent session access: read/write interleaving under
//! `Arc<RwLock<SessionInner>>` and racing clear/authenticate paths.
//! Verifies no panics, no data corruption, no torn-read views.

mod common;

use axess_core::authn::factor::FactorKind;
use axess_core::session::data::AuthState;
use axess_core::testing::{AuthSessionTestExt, test_session};
use chrono::Utc;
use common::{tid, uid};
use std::sync::Arc;

/// Verify Arc<RwLock<SessionInner>> under concurrent reads and writes.
///
/// Spawns 20 tasks: 10 readers and 10 writers. Each runs for 200 iterations.
/// Writers alternate between modifying auth state and recording attempts.
/// Readers check auth state and custom data. The test asserts no panics,
/// no data corruption, and final state consistency.
#[tokio::test]
async fn concurrent_read_write_no_corruption() {
    let session = Arc::new(test_session());

    // Start in Authenticating state so both read and write paths are meaningful.
    session
        .begin_authenticating(
            uid("u1"),
            tid("t1"),
            "password+totp".into(),
            vec![FactorKind::Password, FactorKind::Totp],
        )
        .await;

    let iterations = 200;
    let mut handles = Vec::new();

    // Spawn 10 writer tasks.
    for i in 0..10 {
        let s = Arc::clone(&session);
        handles.push(tokio::spawn(async move {
            for j in 0..iterations {
                match (i + j) % 3 {
                    0 => {
                        // Record an attempt timestamp.
                        s.record_attempt_at(Utc::now()).await;
                    }
                    1 => {
                        // Write custom data.
                        s.set_custom(format!("writer-{i}"), serde_json::json!(j))
                            .await;
                    }
                    _ => {
                        // Re-set identifying state (exercises write lock).
                        s.set_identifying(uid("u1"), tid("t1")).await;
                        // Then move back to authenticating for other writers.
                        s.begin_authenticating(
                            uid("u1"),
                            tid("t1"),
                            "password+totp".into(),
                            vec![FactorKind::Password, FactorKind::Totp],
                        )
                        .await;
                    }
                }
            }
        }));
    }

    // Spawn 10 reader tasks. Each iteration cross-checks an
    // internal-consistency invariant on the reads so the values are
    // actually USED (not just discarded), giving the test a real
    // assertion if a future regression causes one read path to
    // diverge from another.
    for _ in 0..10 {
        let s = Arc::clone(&session);
        handles.push(tokio::spawn(async move {
            for _ in 0..iterations {
                let state = s.auth_state().await;
                let user = s.user_id().await;
                let tenant = s.tenant_id().await;
                let is_auth = s.is_authenticated().await;
                let data = s.data().await;
                let writer_0 = s.get_custom("writer-0").await;

                // Cross-read invariant: `is_authenticated()` MUST agree
                // with `auth_state()` being the `Authenticated` variant.
                // A concurrent reader observing inconsistent reads
                // (different lock-window views of the same underlying
                // state) would surface here as a panic.
                let state_says_auth = matches!(state, AuthState::Authenticated { .. });
                assert_eq!(
                    is_auth, state_says_auth,
                    "is_authenticated() disagrees with auth_state(): \
                     concurrent reads landed on inconsistent views: \
                     user={user:?} tenant={tenant:?} \
                     data_version={} writer_0={writer_0:?}",
                    data.version,
                );
            }
        }));
    }

    // Wait for all tasks: any panic inside a task causes an Err here.
    for handle in handles {
        handle
            .await
            .expect("task panicked during concurrent session access");
    }

    // Final state consistency: the session should be in a valid state.
    let final_state = session.auth_state().await;
    match &final_state {
        AuthState::Guest
        | AuthState::Identifying { .. }
        | AuthState::Authenticating { .. }
        | AuthState::Authenticated { .. }
        | AuthState::PendingWorkflow { .. } => {
            // Any valid state is acceptable: the point is no corruption.
        }
    }

    // user_id and tenant_id should be consistent with each other.
    let uid_now = session.user_id().await;
    let tid_now = session.tenant_id().await;
    match (&uid_now, &tid_now) {
        (Some(_), Some(_)) | (None, None) => {}
        _ => panic!(
            "inconsistent state: user_id={uid_now:?}, tenant_id={tid_now:?}: \
             both should be Some or both None"
        ),
    }
}

/// Verify that concurrent clear + write operations don't corrupt the session.
#[tokio::test]
async fn concurrent_clear_and_write() {
    let session = Arc::new(test_session());
    let iterations = 200;
    let mut handles = Vec::new();

    // Half the tasks clear the session.
    for _ in 0..10 {
        let s = Arc::clone(&session);
        handles.push(tokio::spawn(async move {
            for _ in 0..iterations {
                s.clear().await;
            }
        }));
    }

    // Half the tasks authenticate the session.
    for _ in 0..10 {
        let s = Arc::clone(&session);
        handles.push(tokio::spawn(async move {
            for _ in 0..iterations {
                s.set_authenticated(uid("u1"), tid("t1"), Utc::now()).await;
            }
        }));
    }

    for handle in handles {
        handle
            .await
            .expect("task panicked during concurrent clear/write");
    }

    // Final state must be either Guest or Authenticated: nothing in between.
    let final_state = session.auth_state().await;
    assert!(
        final_state.is_guest() || final_state.is_authenticated(),
        "unexpected final state after concurrent clear/authenticate: {final_state:?}"
    );
}
