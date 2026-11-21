#![cfg(feature = "testing")]
//! Password reset: a refused password keeps the link, an unknown user id
//! looks like a bad token, a bad ttl is refused for everyone alike, and an
//! unknown identifier costs the same store calls as a known one.

use axess_clock::testing::Shift;
use axess_core::testing::fixtures as common;

use axess_core::testing::AuthSessionTestExt;
use std::time::Duration;

use axess_core::authn::factor::PasswordRules;
use axess_core::authn::store::IdentityPasswordHistory;
use axess_core::authn::{AuditContext, RequestAuthnService};
use axess_core::authn::{error::AuthnError, service::AuthnService};
use axess_core::testing::mock_authn::{CallLog, MockFactorStore, MockIdentityStore};
use common::{test_tenant, test_user, uid};

type Svc = RequestAuthnService<MockIdentityStore, MockFactorStore>;

fn world(log: Option<&CallLog>) -> (Svc, MockIdentityStore) {
    let clock = common::test_clock();
    let user = test_user("u1", "alice");
    let mut identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(user.clone())
        .with_password_rules(
            &user.tenant_id,
            PasswordRules {
                history_count: 5,
                ..PasswordRules::default()
            },
        );
    if let Some(log) = log {
        identity = identity.with_call_log(log);
    }
    let handle = identity.clone();
    let svc = AuthnService::builder(identity, MockFactorStore::new())
        .with_clock(clock.clone())
        .build()
        .with_audit_context(AuditContext::default());
    (svc, handle)
}

#[tokio::test]
async fn a_password_refused_for_reuse_keeps_the_link() {
    let (svc, identity) = world(None);
    let user = uid("u1");
    let token = svc
        .begin_password_reset("alice", "default", Duration::from_secs(300))
        .await
        .unwrap()
        .expect("token");
    let reused = "Reused-password-1";
    identity
        .record_password_hash(&user, &axess_factors::generate_password_hash(reused))
        .await
        .unwrap();

    assert!(
        !svc.complete_password_reset(&user, &token, reused)
            .await
            .unwrap()
    );
    // The same link still works for a password that is not a reuse.
    assert!(
        svc.complete_password_reset(&user, &token, "Another-password-2")
            .await
            .unwrap(),
        "the refused attempt spent the single-use token"
    );
    // And it is single-use once it has been spent.
    assert!(
        !svc.complete_password_reset(&user, &token, "Third-password-3")
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn an_unknown_user_id_answers_like_a_bad_token() {
    let (svc, _) = world(None);
    let ghost = uid("nobody");
    let tenant = test_tenant().id;
    assert!(
        !svc.complete_password_reset(&ghost, "t", "New-password-123")
            .await
            .unwrap()
    );
    assert!(
        !svc.complete_password_reset_in_tenant(&ghost, &tenant, "t", "New-password-123")
            .await
            .unwrap()
    );
    // A known user with a bad token gets the same answer.
    assert!(
        !svc.complete_password_reset(&uid("u1"), "wrong", "New-password-123")
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn a_bad_ttl_is_refused_for_known_and_unknown_identifiers() {
    let (svc, _) = world(None);
    for ttl in [
        Duration::from_secs(u64::MAX),
        Duration::from_secs(1_000_000_000_000),
        Duration::from_secs(7 * 24 * 3600 + 1),
        Duration::ZERO,
    ] {
        for who in ["alice", "nobody"] {
            let outcome = svc.begin_password_reset(who, "default", ttl).await;
            assert!(
                matches!(outcome, Err(AuthnError::Internal(_))),
                "{who} with {ttl:?}: got {outcome:?}"
            );
        }
    }
}

#[tokio::test]
async fn an_unknown_identifier_makes_the_same_store_calls_as_a_known_one() {
    let counted = [
        "find_tenant",
        "find_user",
        "store_reset_token",
        "record_event",
    ];
    let mut per_identifier = Vec::new();
    for (who, tenant) in [
        ("alice", "default"),
        ("nobody", "default"),
        ("alice", "no-such-tenant"),
    ] {
        let log = CallLog::new();
        let (svc, _) = world(Some(&log));
        svc.begin_password_reset(who, tenant, Duration::from_secs(300))
            .await
            .unwrap();
        let calls = log.calls();
        per_identifier.push(
            counted
                .iter()
                .map(|name| calls.iter().filter(|c| *c == name).count())
                .collect::<Vec<_>>(),
        );
    }
    assert_eq!(per_identifier[0], vec![1, 1, 1, 1], "the known path");
    assert_eq!(per_identifier[1], per_identifier[0], "unknown user");
    assert_eq!(per_identifier[2], per_identifier[0], "unknown tenant");
}

#[tokio::test]
async fn the_dummy_token_of_an_unknown_identifier_cannot_be_redeemed() {
    let (svc, identity) = world(None);
    svc.begin_password_reset("nobody", "default", Duration::from_secs(300))
        .await
        .unwrap();
    let sentinel = axess_core::authn::ids::UserId::system();
    use axess_core::authn::store::IdentityPasswordReset;
    // Whatever hash was stored, it is already expired at the next instant.
    assert!(
        !identity
            .check_reset_token(
                &sentinel,
                "any",
                common::start().plus(axess_clock::SignedDuration::seconds(1))
            )
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn seven_days_is_the_longest_ttl() {
    let (svc, _) = world(None);
    let token = svc
        .begin_password_reset("alice", "default", Duration::from_secs(7 * 24 * 3600))
        .await
        .unwrap();
    assert!(token.is_some());
}

#[tokio::test]
async fn a_token_issued_before_the_tenant_was_suspended_resets_nothing_and_is_kept() {
    use axess_core::authn::types::{EntityState, StatusDetail};
    let (svc, identity) = world(None);
    let user = uid("u1");
    let token = svc
        .begin_password_reset("alice", "default", Duration::from_secs(300))
        .await
        .unwrap()
        .expect("token");

    let mut tenant = test_tenant();
    tenant.status = EntityState::Suspended(StatusDetail::administrative("test", common::start()));
    let active = test_tenant();
    let _ = identity.clone().with_tenant(tenant.clone());

    assert!(
        !svc.complete_password_reset(&user, &token, "New-password-123")
            .await
            .unwrap()
    );
    assert!(
        !svc.complete_password_reset_in_tenant(&user, &tenant.id, &token, "New-password-123")
            .await
            .unwrap()
    );

    // Reactivated, the same token still works: it was never spent.
    let _ = identity.clone().with_tenant(active);
    assert!(
        svc.complete_password_reset(&user, &token, "New-password-123")
            .await
            .unwrap()
    );
}

/// A tenant suspended while the new password is being hashed is honoured at
/// the commit: the reset is refused with its reason, the token is not spent
/// and no password is installed, so the same link works once the tenant is
/// active again.
#[tokio::test]
async fn a_tenant_suspended_during_the_hash_is_refused_at_the_commit() {
    let clock = common::test_clock();
    use axess_core::authn::event::{AuthEventStatus, AuthEventType};
    use axess_core::authn::factor::FactorKind;
    use axess_core::authn::store::FactorStore;
    use axess_core::authn::types::{AuthnScope, EntityState, StatusDetail};
    use std::sync::atomic::{AtomicBool, Ordering};

    let log = CallLog::new();
    let user = test_user("u1", "alice");
    let scope = AuthnScope::User {
        tenant_id: user.tenant_id,
        user_id: user.id,
    };
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(user.clone())
        .with_password_rules(
            &user.tenant_id,
            PasswordRules {
                history_count: 5,
                ..PasswordRules::default()
            },
        )
        .with_call_log(&log);
    let factors = MockFactorStore::new();
    let svc = AuthnService::builder(identity.clone(), factors.clone())
        .with_clock(clock.clone())
        .build()
        .with_audit_context(AuditContext::default());
    let token = svc
        .begin_password_reset("alice", "default", Duration::from_secs(300))
        .await
        .unwrap()
        .expect("token");

    // The first status check has passed by the time the history is read for
    // the hash; the tenant is suspended right there, once.
    let mut suspended = test_tenant();
    suspended.status =
        EntityState::Suspended(StatusDetail::administrative("test", common::start()));
    let flip = identity.clone();
    let once = AtomicBool::new(true);
    log.on("password_history", move || {
        if once.swap(false, Ordering::SeqCst) {
            let _ = flip.clone().with_tenant(suspended.clone());
        }
    });

    assert!(
        !svc.complete_password_reset(&user.id, &token, "New-password-123")
            .await
            .unwrap(),
        "the reset must be refused at the commit"
    );
    let refusal = identity
        .events()
        .into_iter()
        .rfind(|e| {
            e.event_type == AuthEventType::PasswordReset
                && e.event_status == AuthEventStatus::Failure
        })
        .expect("a failed PasswordReset row");
    assert_eq!(
        refusal.error.as_ref().map(ToString::to_string).as_deref(),
        Some("tenant_not_active")
    );
    assert!(
        factors
            .load_factor(&scope, FactorKind::Password)
            .await
            .unwrap()
            .is_none(),
        "no password was installed"
    );

    // Active again, the same token still works: it was never spent.
    let _ = identity.clone().with_tenant(test_tenant());
    assert!(
        svc.complete_password_reset(&user.id, &token, "New-password-123")
            .await
            .unwrap()
    );
}

mod cancelled_reset {
    //! The work after the token is spent is not the caller's to cancel.

    use super::*;
    use axess_core::session::store::{MemorySessionRegistry, SessionRegistry};
    use axess_core::testing::registry_double::{RegistryDouble, RegistryOp, Step};
    use axess_core::testing::test_session;
    use std::sync::Arc;

    /// A registry whose `invalidate_user` announces itself on `entered` and
    /// then takes a while, so a test can drop the caller in the middle of it.
    fn slow(inner: MemorySessionRegistry, entered: Arc<tokio::sync::Notify>) -> RegistryDouble {
        RegistryDouble::over(inner).before(move |call, _| {
            let entered = entered.clone();
            async move {
                if call.op() == RegistryOp::InvalidateUser {
                    entered.notify_one();
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Step::Forward
            }
        })
    }

    #[tokio::test]
    async fn a_reset_dropped_while_ending_sessions_still_ends_them() {
        let clock = common::test_clock();
        let entered = Arc::new(tokio::sync::Notify::new());
        let registry = slow(
            MemorySessionRegistry::new().with_clock(std::sync::Arc::new(clock.clone())),
            entered.clone(),
        );
        let user = test_user("u1", "alice");
        let identity = MockIdentityStore::new()
            .with_clock(clock.clone())
            .with_tenant(test_tenant())
            .with_user(user.clone());
        let svc = AuthnService::builder(identity.clone(), MockFactorStore::new())
            .with_clock(clock.clone())
            .with_registry(registry.clone())
            .build()
            .with_audit_context(AuditContext::default());
        let session = test_session();
        session
            .set_authenticated(user.id, user.tenant_id, common::start())
            .await;
        let sid = session.session_key().await;
        registry.register(&user.id, &sid).await.unwrap();
        assert!(registry.inner().is_valid(&user.id, &sid).await.unwrap());
        let token = svc
            .begin_password_reset("alice", "default", Duration::from_secs(300))
            .await
            .unwrap()
            .expect("token");

        // Drive the reset until the registry has been reached, then drop it
        // there (the block ends): the client went away in the middle of the
        // invalidation.
        {
            let entered = entered.notified();
            let reset = svc.complete_password_reset(&user.id, &token, "New-password-123");
            let mut reset = std::pin::pin!(reset);
            tokio::select! {
                r = &mut reset => panic!("the reset finished before the registry was reached: {r:?}"),
                _ = entered => {}
            }
        }
        tokio::time::sleep(Duration::from_millis(400)).await;

        assert!(
            !registry.inner().is_valid(&user.id, &sid).await.unwrap(),
            "the password changed, so the user's sessions must end even though the caller left"
        );
    }
}

mod masked_failures {
    //! The audit row's own failure must not hide what the reset could not
    //! do after the password was installed.

    use super::*;
    use axess_core::session::store::MemorySessionRegistry;
    use axess_core::testing::registry_double::{RegistryDouble, RegistryOp, Step};

    /// A registry whose `invalidate_user` fails: the sessions stay open.
    fn stuck(inner: MemorySessionRegistry) -> RegistryDouble {
        RegistryDouble::over(inner).before(|call, _| async move {
            match call.op() {
                RegistryOp::InvalidateUser => Step::Fail("registry unreachable"),
                _ => Step::Forward,
            }
        })
    }

    /// The registry could not end the sessions and the audit store could
    /// not take the row. The caller does not see the audit error alone: the
    /// sessions left open are the costlier failure and are reported first.
    #[tokio::test]
    async fn a_registry_failure_is_reported_even_when_the_audit_row_fails() {
        let clock = common::test_clock();
        let user = test_user("u1", "alice");
        let identity = MockIdentityStore::new()
            .with_clock(clock.clone())
            .with_tenant(test_tenant())
            .with_user(user.clone());
        let svc = AuthnService::builder(identity.clone(), MockFactorStore::new())
            .with_clock(clock.clone())
            .with_registry(stuck(
                MemorySessionRegistry::new().with_clock(std::sync::Arc::new(clock.clone())),
            ))
            .build()
            .with_audit_context(AuditContext::default());
        let token = svc
            .begin_password_reset("alice", "default", Duration::from_secs(300))
            .await
            .unwrap()
            .expect("token");
        identity.arm_record_event_failure();

        let err = svc
            .complete_password_reset(&user.id, &token, "New-password-123")
            .await
            .unwrap_err();

        assert!(
            matches!(err, AuthnError::ExternalService(_)),
            "the registry failure, not the audit failure, is the answer: {err:?}"
        );
    }
}

/// The dummy token an unknown identifier is given is stored under an id of
/// its own: the platform's system user may hold a real reset token, and the
/// dummy write must not replace it.
#[tokio::test]
async fn an_unknown_identifier_does_not_overwrite_the_system_users_token() {
    use axess_core::authn::store::IdentityPasswordReset;
    let (svc, identity) = world(None);
    let system = axess_core::authn::ids::UserId::SYSTEM;
    let now = common::start();
    identity
        .store_reset_token(
            &system,
            "real-token-hash",
            now.plus(axess_clock::SignedDuration::hours(1)),
            now,
            3,
        )
        .await
        .unwrap();

    let none = svc
        .begin_password_reset("nobody", "default", Duration::from_secs(300))
        .await
        .unwrap();
    assert!(none.is_none());

    assert!(
        identity
            .verify_reset_token(&system, "real-token-hash", now)
            .await
            .unwrap(),
        "the system user's token was overwritten by the dummy"
    );
}
