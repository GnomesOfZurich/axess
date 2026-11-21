//! Unit tests for [`super::SessionData`], [`super::AuthState`], and the
//! pure transition methods (`set_identifying`, `begin_authenticating`,
//! `set_authenticated`, `set_pending_workflow`, `advance_factor`,
//! `record_attempt_at`).
//!
//! Pulled sideways from the previous in-file `#[cfg(test)] mod` block so
//! the production-vs-tests ratio in `data.rs` becomes scannable. Tests
//! reach private items via `use super::*;`; file kept inside the
//! `session::data` module so visibility stays unchanged.

#![cfg(test)]

use super::*;
use axess_clock::testing::Shift;

/// A session row that omits the `version` field (as rows did before the
/// field existed) deserialises with `version == 1`, never with the current
/// `SESSION_DATA_VERSION`: such a row is below the current version, and the
/// session layer does not serve it.
#[test]
fn deserialised_session_without_version_field_defaults_to_one() {
    let json = serde_json::json!({
        "auth_state": { "kind": "Guest" },
        "fingerprint": null,
        "custom": {}
    });
    let parsed: SessionData = serde_json::from_value(json).expect("parse");
    assert_eq!(parsed.version, 1);
}

/// `pending_user_id()` returns `None` only for Guest and `Some`
/// for every other variant; `authenticated_user_id()` only for Authenticated.
#[test]
fn only_an_authenticated_state_has_an_authenticated_user_id() {
    let user = axess_identity::testing::user("u1");
    let tenant = axess_identity::testing::tenant("t1");
    assert!(AuthState::Guest.authenticated_user_id().is_none());
    assert!(
        AuthState::Identifying {
            user_id: user,
            tenant_id: tenant,
        }
        .authenticated_user_id()
        .is_none()
    );
    assert_eq!(
        AuthState::Authenticated {
            user_id: user,
            tenant_id: tenant,
            authn_time: axess_clock::testing::MockClock::reference_time(),
            signed_in_at: axess_clock::testing::MockClock::reference_time(),
            factors_completed: vec![],
            impersonator: None,
            ldap_groups: None,
            assurance: Vec::new(),
        }
        .authenticated_user_id(),
        Some(&user)
    );
}

/// `pending_user_id()` returns `None` only for Guest and `Some`
/// for every other variant. Kills `-> None` body replacement.
#[test]
fn pending_user_id_returns_none_only_for_guest() {
    let user = axess_identity::testing::user("u1");
    let tenant = axess_identity::testing::tenant("t1");

    assert!(AuthState::Guest.pending_user_id().is_none());
    assert_eq!(
        AuthState::Identifying {
            user_id: user,
            tenant_id: tenant,
        }
        .pending_user_id(),
        Some(&user)
    );
    assert_eq!(
        AuthState::Authenticated {
            user_id: user,
            tenant_id: tenant,
            authn_time: axess_clock::testing::MockClock::reference_time(),
            signed_in_at: axess_clock::testing::MockClock::reference_time(),
            factors_completed: vec![],
            impersonator: None,
            ldap_groups: None,
            assurance: Vec::new(),
        }
        .pending_user_id(),
        Some(&user)
    );
}

/// `tenant_id()` returns `None` only for Guest.
#[test]
fn tenant_id_returns_none_only_for_guest() {
    let user = axess_identity::testing::user("u1");
    let tenant = axess_identity::testing::tenant("t1");

    assert!(AuthState::Guest.tenant_id().is_none());
    assert_eq!(
        AuthState::Authenticated {
            user_id: user,
            tenant_id: tenant,
            authn_time: axess_clock::testing::MockClock::reference_time(),
            signed_in_at: axess_clock::testing::MockClock::reference_time(),
            factors_completed: vec![],
            impersonator: None,
            ldap_groups: None,
            assurance: Vec::new(),
        }
        .tenant_id(),
        Some(&tenant)
    );
}

/// `is_authenticated` returns true ONLY for Authenticated.
#[test]
fn is_authenticated_only_for_authenticated_variant() {
    let user = axess_identity::testing::user("u1");
    let tenant = axess_identity::testing::tenant("t1");

    assert!(!AuthState::Guest.is_authenticated());
    assert!(
        AuthState::Authenticated {
            user_id: user,
            tenant_id: tenant,
            authn_time: axess_clock::testing::MockClock::reference_time(),
            signed_in_at: axess_clock::testing::MockClock::reference_time(),
            factors_completed: vec![],
            impersonator: None,
            ldap_groups: None,
            assurance: Vec::new(),
        }
        .is_authenticated()
    );
}

/// `is_guest` returns true ONLY for Guest.
#[test]
fn is_guest_only_for_guest_variant() {
    let user = axess_identity::testing::user("u1");
    let tenant = axess_identity::testing::tenant("t1");

    assert!(AuthState::Guest.is_guest());
    assert!(
        !AuthState::Authenticated {
            user_id: user,
            tenant_id: tenant,
            authn_time: axess_clock::testing::MockClock::reference_time(),
            signed_in_at: axess_clock::testing::MockClock::reference_time(),
            factors_completed: vec![],
            impersonator: None,
            ldap_groups: None,
            assurance: Vec::new(),
        }
        .is_guest()
    );
}

/// WorkflowState::new initialises current_step=0.
#[test]
fn workflow_state_new_starts_at_step_zero() {
    let now = axess_clock::testing::MockClock::reference_time();
    let ws = WorkflowState::new(WorkflowKind::Signup, 3, now);
    assert_eq!(ws.current_step, 0);
    assert_eq!(ws.total_steps, 3);
    assert_eq!(ws.initiated_at, now);
    assert_eq!(ws.kind, WorkflowKind::Signup);
}

/// SessionData round-trips through JSON preserving all fields.
#[test]
fn session_data_json_round_trip() {
    let data = SessionData {
        version: SESSION_DATA_VERSION,
        auth_state: AuthState::Authenticated {
            user_id: axess_identity::testing::user("alice"),
            tenant_id: axess_identity::testing::tenant("acme"),
            authn_time: axess_clock::testing::MockClock::reference_time(),
            signed_in_at: axess_clock::testing::MockClock::reference_time(),
            factors_completed: vec![
                (
                    FactorKind::Password,
                    axess_clock::testing::MockClock::reference_time(),
                ),
                (
                    FactorKind::Totp,
                    axess_clock::testing::MockClock::reference_time(),
                ),
            ],
            impersonator: None,
            ldap_groups: None,
            assurance: Vec::new(),
        },
        fingerprint: Some("fp-abc".to_string()),
        device_id: Some(axess_identity::testing::device("dev-1")),
        device_proven: false,
        device_key: None,
        key_proven: false,
        key_binding: None,
        custom: serde_json::json!({"key": "value"}),
        revision: 7,
        touched_at: Some(axess_clock::testing::MockClock::reference_time()),
        ending: None,
    };
    let json = serde_json::to_value(&data).unwrap();
    let restored: SessionData = serde_json::from_value(json).unwrap();
    assert_eq!(restored.version, data.version);
    assert_eq!(restored.fingerprint, data.fingerprint);
    assert_eq!(restored.device_id, data.device_id);
    assert_eq!(restored.auth_state, data.auth_state);
}

/// `is_authenticating` returns true only for the
/// `Authenticating` variant. Pinning all five variants here
/// kills both the `-> true` / `-> false` body mutations.
#[test]
fn is_authenticating_only_true_for_authenticating_variant() {
    let user = axess_identity::testing::user("u");
    let tenant = axess_identity::testing::tenant("t");

    assert!(!AuthState::Guest.is_authenticating());
    assert!(
        !AuthState::Identifying {
            user_id: user,
            tenant_id: tenant,
        }
        .is_authenticating()
    );
    assert!(
        AuthState::Authenticating {
            user_id: user,
            tenant_id: tenant,
            method_name: Arc::from("password"),
            remaining: vec![],
            completed: vec![],
            attempt_count: 0,
            last_attempt: None,
            ldap_groups: None,
            assurance: Vec::new(),
            impersonator: None,
            flow: AuthFlow::Login,
        }
        .is_authenticating()
    );
    assert!(
        !AuthState::Authenticated {
            user_id: user,
            tenant_id: tenant,
            authn_time: axess_clock::testing::MockClock::reference_time(),
            signed_in_at: axess_clock::testing::MockClock::reference_time(),
            factors_completed: vec![],
            impersonator: None,
            ldap_groups: None,
            assurance: Vec::new(),
        }
        .is_authenticating()
    );
    assert!(
        !AuthState::PendingWorkflow {
            user_id: user,
            tenant_id: tenant,
            workflow: WorkflowState::new(
                WorkflowKind::Signup,
                1,
                axess_clock::testing::MockClock::reference_time()
            ),
        }
        .is_authenticating()
    );
}

// ── Transition method tests ────────────────────────────────────
//
// These are isolated tests of `AuthState`'s pure transition methods;
// no `AuthSession`, no `SessionData`, no async, no RwLock. Each test
// pins one transition's pre- and post-state.

fn now() -> Timestamp {
    axess_clock::testing::MockClock::reference_time()
}

#[test]
fn set_identifying_from_guest() {
    let user = axess_identity::testing::user("u1");
    let tenant = axess_identity::testing::tenant("t1");
    let mut state = AuthState::Guest;
    state.set_identifying(user, tenant);
    assert_eq!(
        state,
        AuthState::Identifying {
            user_id: user,
            tenant_id: tenant
        }
    );
}

#[test]
fn begin_authenticating_constructs_authenticating_with_factors_in_order() {
    let user = axess_identity::testing::user("u1");
    let tenant = axess_identity::testing::tenant("t1");
    let mut state = AuthState::Guest;
    state.begin_authenticating(
        user,
        tenant,
        Arc::from("password+totp"),
        required(vec![FactorKind::Password, FactorKind::Totp]),
    );
    match state {
        AuthState::Authenticating {
            user_id,
            tenant_id,
            method_name,
            remaining,
            completed,
            attempt_count,
            last_attempt,
            ldap_groups,
            impersonator,
            assurance,
            flow,
        } => {
            assert_eq!(flow, AuthFlow::Login, "a login is opened as a login");
            assert!(assurance.is_empty(), "a login begins with no proof");
            assert_eq!(user_id, user);
            assert_eq!(tenant_id, tenant);
            assert_eq!(&*method_name, "password+totp");
            assert_eq!(ldap_groups, None);
            assert_eq!(impersonator, None);
            assert_eq!(
                remaining,
                required(vec![FactorKind::Password, FactorKind::Totp])
            );
            assert!(completed.is_empty());
            assert_eq!(attempt_count, 0);
            assert!(last_attempt.is_none());
        }
        other => panic!("expected Authenticating, got {other:?}"),
    }
}

#[test]
fn set_authenticated_constructs_authenticated_with_empty_factors() {
    let user = axess_identity::testing::user("u1");
    let tenant = axess_identity::testing::tenant("t1");
    let t = now();
    let mut state = AuthState::Guest;
    state.set_authenticated(user, tenant, t);
    match state {
        AuthState::Authenticated {
            user_id,
            tenant_id,
            authn_time,
            signed_in_at,
            factors_completed,
            impersonator,
            ldap_groups,
            assurance,
        } => {
            assert!(assurance.is_empty(), "a direct transition proves nothing");
            assert_eq!(user_id, user);
            assert_eq!(tenant_id, tenant);
            assert_eq!(authn_time, t);
            assert_eq!(signed_in_at, t, "a direct transition is its own login");
            assert_eq!(impersonator, None, "a login is nobody's impersonation");
            assert_eq!(ldap_groups, None, "no LDAP bind in this login");
            assert!(
                factors_completed.is_empty(),
                "direct transition: no factor sequence"
            );
        }
        other => panic!("expected Authenticated, got {other:?}"),
    }
}

#[test]
fn advance_factor_still_authenticating_when_factors_remain() {
    let user = axess_identity::testing::user("u1");
    let tenant = axess_identity::testing::tenant("t1");
    let mut state = AuthState::Authenticating {
        user_id: user,
        tenant_id: tenant,
        method_name: Arc::from("password+totp"),
        remaining: required(vec![FactorKind::Password, FactorKind::Totp]),
        completed: vec![],
        attempt_count: 0,
        last_attempt: None,
        ldap_groups: None,
        assurance: Vec::new(),
        impersonator: None,
        flow: AuthFlow::Login,
    };
    let outcome = state.advance_factor(crate::authn::assurance::FactorAssurance::for_kind(
        FactorKind::Password,
        now(),
    ));
    assert_eq!(outcome, AdvanceOutcome::StillAuthenticating);
    match state {
        AuthState::Authenticating {
            remaining,
            completed,
            ..
        } => {
            assert_eq!(remaining, required(vec![FactorKind::Totp]));
            assert_eq!(kinds(&completed), vec![FactorKind::Password]);
        }
        other => panic!("expected still Authenticating, got {other:?}"),
    }
}

#[test]
fn advance_factor_completes_when_last_factor_verified() {
    let user = axess_identity::testing::user("u1");
    let tenant = axess_identity::testing::tenant("t1");
    let t = now();
    let mut state = AuthState::Authenticating {
        user_id: user,
        tenant_id: tenant,
        method_name: Arc::from("password"),
        remaining: required(vec![FactorKind::Password]),
        completed: vec![],
        attempt_count: 0,
        last_attempt: None,
        ldap_groups: None,
        assurance: Vec::new(),
        impersonator: None,
        flow: AuthFlow::Login,
    };
    let outcome = state.advance_factor(crate::authn::assurance::FactorAssurance::for_kind(
        FactorKind::Password,
        t,
    ));
    assert_eq!(outcome, AdvanceOutcome::Completed);
    match state {
        AuthState::Authenticated {
            user_id,
            tenant_id,
            authn_time,
            signed_in_at,
            factors_completed,
            impersonator,
            ldap_groups,
            assurance,
        } => {
            assert_eq!(
                signed_in_at, authn_time,
                "a login is signed in when it completes"
            );
            assert_eq!(
                assurance,
                vec![crate::authn::assurance::FactorAssurance::for_kind(
                    FactorKind::Password,
                    t
                )],
                "the factor's proof is carried into the authenticated state"
            );
            assert_eq!(user_id, user);
            assert_eq!(tenant_id, tenant);
            assert_eq!(authn_time, t);
            assert_eq!(impersonator, None, "a login is nobody's impersonation");
            assert_eq!(ldap_groups, None, "no LDAP bind in this login");
            assert_eq!(kinds(&factors_completed), vec![FactorKind::Password]);
        }
        other => panic!("expected Authenticated, got {other:?}"),
    }
}

/// MFA path with two factors: password then TOTP. Pins that the
/// `completed` list survives the transition to `Authenticated` as
/// `factors_completed` in completion order: relevant to audit
/// row "user logged in with password+totp" depends on this.
#[test]
fn advance_factor_carries_completed_factors_into_authenticated() {
    let user = axess_identity::testing::user("u1");
    let tenant = axess_identity::testing::tenant("t1");
    let t = now();
    let mut state = AuthState::Authenticating {
        user_id: user,
        tenant_id: tenant,
        method_name: Arc::from("password+totp"),
        remaining: required(vec![FactorKind::Password, FactorKind::Totp]),
        completed: vec![],
        attempt_count: 0,
        last_attempt: None,
        ldap_groups: None,
        assurance: Vec::new(),
        impersonator: None,
        flow: AuthFlow::Login,
    };
    assert_eq!(
        state.advance_factor(crate::authn::assurance::FactorAssurance::for_kind(
            FactorKind::Password,
            t
        )),
        AdvanceOutcome::StillAuthenticating
    );
    assert_eq!(
        state.advance_factor(crate::authn::assurance::FactorAssurance::for_kind(
            FactorKind::Totp,
            t
        )),
        AdvanceOutcome::Completed
    );
    match state {
        AuthState::Authenticated {
            factors_completed, ..
        } => {
            assert_eq!(
                kinds(&factors_completed),
                vec![FactorKind::Password, FactorKind::Totp],
                "completion order must be preserved"
            );
        }
        other => panic!("expected Authenticated, got {other:?}"),
    }
}

/// Calling `advance_factor` with a kind not in `remaining` is a
/// defensive no-op (state stays `Authenticating`, nothing moved).
/// Pins that the method does not panic or silently corrupt state.
#[test]
fn advance_factor_no_op_when_kind_not_in_remaining() {
    let user = axess_identity::testing::user("u1");
    let tenant = axess_identity::testing::tenant("t1");
    let mut state = AuthState::Authenticating {
        user_id: user,
        tenant_id: tenant,
        method_name: Arc::from("password"),
        remaining: required(vec![FactorKind::Password]),
        completed: vec![],
        attempt_count: 0,
        last_attempt: None,
        ldap_groups: None,
        assurance: Vec::new(),
        impersonator: None,
        flow: AuthFlow::Login,
    };
    let outcome = state.advance_factor(crate::authn::assurance::FactorAssurance::for_kind(
        FactorKind::Totp,
        now(),
    ));
    assert_eq!(outcome, AdvanceOutcome::StillAuthenticating);
    match state {
        AuthState::Authenticating {
            remaining,
            completed,
            ..
        } => {
            assert_eq!(remaining, required(vec![FactorKind::Password]));
            assert!(completed.is_empty());
        }
        other => panic!("expected Authenticating, got {other:?}"),
    }
}

/// Calling `advance_factor` on a non-`Authenticating` state is a
/// `NotApplicable` no-op. Required so partial-attribution audit
/// emits in ceremony code can fire even when the state has been
/// reset (e.g. concurrent logout) without panic.
#[test]
fn advance_factor_not_applicable_outside_authenticating() {
    let mut state = AuthState::Guest;
    assert_eq!(
        state.advance_factor(crate::authn::assurance::FactorAssurance::for_kind(
            FactorKind::Password,
            now()
        )),
        AdvanceOutcome::NotApplicable
    );
    assert_eq!(state, AuthState::Guest);
}

#[test]
fn record_attempt_at_increments_counter_and_captures_timestamp() {
    let user = axess_identity::testing::user("u1");
    let tenant = axess_identity::testing::tenant("t1");
    let t = now();
    let mut state = AuthState::Authenticating {
        user_id: user,
        tenant_id: tenant,
        method_name: Arc::from("password"),
        remaining: required(vec![FactorKind::Password]),
        completed: vec![],
        attempt_count: 0,
        last_attempt: None,
        ldap_groups: None,
        assurance: Vec::new(),
        impersonator: None,
        flow: AuthFlow::Login,
    };
    state.record_attempt_at(t);
    state.record_attempt_at(t);
    match state {
        AuthState::Authenticating {
            attempt_count,
            last_attempt,
            ..
        } => {
            assert_eq!(attempt_count, 2);
            assert_eq!(last_attempt, Some(t));
        }
        other => panic!("expected Authenticating, got {other:?}"),
    }
}

/// `record_attempt_at` on non-`Authenticating` is a silent no-op.
/// Pins behaviour that prevents a logout-mid-attempt race from
/// crashing.
#[test]
fn record_attempt_at_no_op_outside_authenticating() {
    let mut state = AuthState::Guest;
    state.record_attempt_at(now());
    assert_eq!(state, AuthState::Guest);
}

#[test]
fn set_pending_workflow_replaces_state() {
    let user = axess_identity::testing::user("u1");
    let tenant = axess_identity::testing::tenant("t1");
    let workflow = WorkflowState::new(WorkflowKind::Signup, 3, now());
    let mut state = AuthState::Guest;
    state.set_pending_workflow(user, tenant, workflow.clone());
    match state {
        AuthState::PendingWorkflow {
            user_id,
            tenant_id,
            workflow: w,
        } => {
            assert_eq!(user_id, user);
            assert_eq!(tenant_id, tenant);
            assert_eq!(w, workflow);
        }
        other => panic!("expected PendingWorkflow, got {other:?}"),
    }
}

/// The steps of a plain sequential method.
fn required(kinds: Vec<FactorKind>) -> Vec<crate::authn::factor::FactorStep> {
    kinds
        .into_iter()
        .map(crate::authn::factor::FactorStep::Required)
        .collect()
}

/// A recovery code completes a step that offers it beside TOTP, and the
/// factor recorded as completed is the one used, not the step's first choice.
#[test]
fn a_choice_step_is_completed_by_whichever_factor_it_offers() {
    use crate::authn::factor::FactorStep;
    let user = axess_identity::testing::user("u1");
    let tenant = axess_identity::testing::tenant("t1");
    let mut state = AuthState::Guest;
    state.begin_authenticating(
        user,
        tenant,
        Arc::from("password+totp"),
        vec![
            FactorStep::Required(FactorKind::Password),
            FactorStep::AnyOf(vec![FactorKind::Totp, FactorKind::RecoveryCode]),
        ],
    );
    let now = Timestamp::from_unix_seconds(1_700_000_000).unwrap();
    assert_eq!(
        state.advance_factor(crate::authn::assurance::FactorAssurance::for_kind(
            FactorKind::Password,
            now
        )),
        AdvanceOutcome::StillAuthenticating
    );
    assert_eq!(
        state.advance_factor(crate::authn::assurance::FactorAssurance::for_kind(
            FactorKind::RecoveryCode,
            now
        )),
        AdvanceOutcome::Completed
    );
    match state {
        AuthState::Authenticated {
            factors_completed, ..
        } => assert_eq!(
            kinds(&factors_completed),
            vec![FactorKind::Password, FactorKind::RecoveryCode]
        ),
        other => panic!("expected Authenticated, got {other:?}"),
    }
}

/// The impersonation is stored as an object with named fields, so a field
/// added later is a new key, not a new tuple arity.
#[test]
fn an_impersonation_is_stored_as_an_object() {
    let admin = axess_identity::testing::user("admin");
    let since = now();
    let mut state = AuthState::Guest;
    state.set_authenticated(
        axess_identity::testing::user("u1"),
        axess_identity::testing::tenant("t1"),
        since,
    );
    assert!(state.set_impersonator(admin, since));

    let json = serde_json::to_value(&state).unwrap();
    assert_eq!(json["impersonator"]["admin"], serde_json::json!(admin));
    assert_eq!(json["impersonator"]["since"], serde_json::json!(since));
    let back: AuthState = serde_json::from_value(json).unwrap();
    assert_eq!(back.impersonation(), Some(Impersonation { admin, since }));
}

/// The groups an LDAP bind step recorded ride the login into the
/// authenticated state, stay through a step-up, and end with a new login.
#[test]
fn ldap_groups_ride_the_login_into_the_authenticated_state() {
    let staff = vec!["staff".to_string()];
    let mut state = AuthState::Authenticating {
        user_id: axess_identity::testing::user("u1"),
        tenant_id: axess_identity::testing::tenant("t1"),
        method_name: Arc::from("ldap"),
        remaining: required(vec![FactorKind::LdapBind]),
        completed: vec![],
        attempt_count: 0,
        last_attempt: None,
        ldap_groups: Some(staff.clone()),
        impersonator: None,
        assurance: Vec::new(),
        flow: AuthFlow::Login,
    };
    assert_eq!(state.ldap_groups(), None, "not before the login completes");

    state.advance_factor(crate::authn::assurance::FactorAssurance::for_kind(
        FactorKind::LdapBind,
        now(),
    ));
    assert_eq!(state.ldap_groups(), Some(staff.as_slice()));

    assert!(state.begin_step_up(required(vec![FactorKind::Totp])));
    state.advance_factor(crate::authn::assurance::FactorAssurance::for_kind(
        FactorKind::Totp,
        now(),
    ));
    assert_eq!(
        state.ldap_groups(),
        Some(staff.as_slice()),
        "a step-up keeps the login's groups"
    );

    state.set_authenticated(
        axess_identity::testing::user("u1"),
        axess_identity::testing::tenant("t1"),
        now(),
    );
    assert_eq!(state.ldap_groups(), None, "a new login starts without them");
}

/// An impersonated session that steps up is still the administrator's
/// session in the user's name when the step-up completes.
#[test]
fn a_step_up_keeps_the_impersonation() {
    let admin = axess_identity::testing::user("admin");
    let since = now();
    let mut state = AuthState::Guest;
    state.set_authenticated(
        axess_identity::testing::user("u1"),
        axess_identity::testing::tenant("t1"),
        since,
    );
    assert!(state.set_impersonator(admin, since));

    assert!(state.begin_step_up(required(vec![FactorKind::Totp])));
    assert_eq!(
        state.advance_factor(crate::authn::assurance::FactorAssurance::for_kind(
            FactorKind::Totp,
            now()
        )),
        AdvanceOutcome::Completed
    );
    assert_eq!(
        state.impersonation(),
        Some(Impersonation { admin, since }),
        "the marker survives the step-up"
    );
}

fn kinds(factors: &[(FactorKind, axess_clock::Timestamp)]) -> Vec<FactorKind> {
    factors.iter().map(|(kind, _)| kind.clone()).collect()
}

fn user_and_tenant() -> (UserId, TenantId) {
    (
        axess_identity::testing::user("u1"),
        axess_identity::testing::tenant("t1"),
    )
}

/// A password login, then a step-up with TOTP: the password keeps the time of
/// the login, the TOTP gets the step-up's, and `authn_time` is the step-up's.
#[test]
fn a_step_up_keeps_the_time_of_the_factors_before_it() {
    let (user, tenant) = user_and_tenant();
    let login = now().minus(axess_clock::SignedDuration::hours(3));
    let step_up = now();
    let mut state = AuthState::Authenticating {
        user_id: user,
        tenant_id: tenant,
        method_name: "password".into(),
        remaining: required(vec![FactorKind::Password]),
        completed: vec![],
        attempt_count: 0,
        last_attempt: None,
        ldap_groups: None,
        assurance: Vec::new(),
        impersonator: None,
        flow: AuthFlow::Login,
    };
    assert_eq!(
        state.advance_factor(crate::authn::assurance::FactorAssurance::for_kind(
            FactorKind::Password,
            login
        )),
        AdvanceOutcome::Completed
    );
    assert!(state.begin_step_up(required(vec![FactorKind::Totp])));
    assert_eq!(
        state.advance_factor(crate::authn::assurance::FactorAssurance::for_kind(
            FactorKind::Totp,
            step_up
        )),
        AdvanceOutcome::Completed
    );

    assert_eq!(
        state.factor_completed_at(&FactorKind::Password),
        Some(login)
    );
    assert_eq!(state.factor_completed_at(&FactorKind::Totp), Some(step_up));
    assert_eq!(state.factor_completed_at(&FactorKind::Fido2), None);
    match state {
        AuthState::Authenticated { authn_time, .. } => assert_eq!(authn_time, step_up),
        other => panic!("expected Authenticated, got {other:?}"),
    }
}

/// Whether a request proved the session's device is that request's own
/// answer and no part of the stored session: it is not written, and a row
/// that carries it from an earlier release reads as unproven.
#[test]
fn whether_the_device_was_proven_is_never_stored() {
    let data = SessionData {
        device_id: Some(axess_identity::testing::device("dev-1")),
        device_proven: true,
        device_key: None,
        key_proven: false,
        key_binding: None,
        ..SessionData::default()
    };
    let stored = serde_json::to_value(&data).unwrap();
    assert!(stored.get("device_proven").is_none(), "{stored}");
    assert!(!stored["device_id"].is_null(), "{stored}");

    let mut earlier = stored;
    earlier["device_proven"] = serde_json::json!(true);
    let read: SessionData = serde_json::from_value(earlier).unwrap();
    assert!(!read.device_proven);
    assert_eq!(read.device_id, data.device_id);
}

/// A merge with what another request stored keeps this request's own answer
/// about the device, whatever the rows on either side say.
#[test]
fn a_merge_keeps_this_requests_own_answer_about_the_device() {
    let with = |proven: bool| SessionData {
        device_proven: proven,
        device_key: None,
        key_proven: false,
        key_binding: None,
        ..SessionData::default()
    };
    for (base, local, fresh) in [
        (false, true, false),
        (true, true, false),
        (true, false, true),
        (false, false, true),
    ] {
        let (base, mine, fresh) = (with(base), with(local), with(fresh));
        assert_eq!(merge_concurrent(&base, &mine, &fresh).device_proven, local);
        assert_eq!(merge_rotating(&base, &mine, &fresh).device_proven, local);
    }
}

/// The person at the browser, whose a session's device is: the user of the
/// user's own session, the administrator of an impersonation, and nobody
/// for a state that is not fully authenticated.
#[test]
fn the_person_at_the_browser_of_an_impersonation_is_the_administrator() {
    use axess_identity::testing::{tenant, user};
    let (alice, admin) = (user("alice"), user("admin"));
    assert_eq!(AuthState::Guest.person_at_browser(), None);

    let mut state = AuthState::Guest;
    state.set_authenticated(alice, tenant("t1"), now());
    assert_eq!(state.person_at_browser(), Some(alice));

    assert!(state.set_impersonator(admin, now()));
    assert_eq!(state.authenticated_user_id(), Some(&alice));
    assert_eq!(state.person_at_browser(), Some(admin));
}

/// The version of a stored row is read on its own, from a row of any shape:
/// a row with no `version` member reads as 1, and bytes that are not
/// MessagePack are an error.
#[cfg(any(
    feature = "sqlite",
    feature = "sqlite-unbundled",
    feature = "postgres",
    feature = "mysql",
    feature = "valkey"
))]
#[test]
fn the_version_of_a_stored_row_is_read_whatever_the_rest_holds() {
    let packed = |row: serde_json::Value| rmp_serde::to_vec_named(&row).unwrap();
    assert_eq!(
        stored_version(&packed(serde_json::json!({ "auth_state": "not a state" }))).unwrap(),
        1
    );
    for version in [1u8, 2, 3, 4] {
        let row = packed(serde_json::json!({ "version": version, "auth_state": 7 }));
        assert_eq!(stored_version(&row).unwrap(), version);
    }
    let current = rmp_serde::to_vec_named(&SessionData::default()).unwrap();
    assert_eq!(stored_version(&current).unwrap(), SESSION_DATA_VERSION);
    assert!(stored_version(b"{\"version\":3}").is_err());
}

/// What a store hands up for a row below the version holds that version and
/// nothing of the row.
#[test]
fn a_row_below_the_version_is_handed_up_as_its_version_alone() {
    let below = SessionData::below_version(2);
    assert_eq!(below.version, 2);
    assert!(below.auth_state.is_guest());
    assert_eq!(below.revision, 0);
    assert_eq!(below.custom, serde_json::Value::Null);
}

/// The anchor of a fixed impersonation is a fixed key: the SHA-256, whole,
/// of a tag of its own, the administrator, the target and the start time.
/// It is not the key of the 16-byte id an earlier release used as the anchor.
#[test]
fn an_impersonations_registry_anchor_is_a_fixed_key_of_its_own() {
    use crate::session::id::{SessionId, SessionKey};
    let admin = crate::authn::ids::UserId::try_new("00000000-0000-4000-8000-0000000000a1")
        .expect("a user id");
    let target = crate::authn::ids::UserId::try_new("00000000-0000-4000-8000-0000000000b2")
        .expect("a user id");
    let imp = Impersonation {
        admin,
        since: Timestamp::from_unix_seconds(1_800_000_000).expect("in range"),
    };
    let anchor = imp.registry_anchor(&target);
    assert_eq!(
        anchor.to_string(),
        "76f21623e24ceba36bd55cc09210183fbb9dce838d32788bc15abe93e7578e1a"
    );
    let mut earlier = [0u8; 16];
    earlier.copy_from_slice(&anchor.as_bytes()[..16]);
    let of_the_earlier_id = SessionKey::of(&SessionId::from_bytes(earlier));
    assert_eq!(
        of_the_earlier_id.to_string(),
        "4514ddd18c946ba80fc5bbb2e2085dd4eb6c603840e726dc894732342b17a7dd"
    );
    assert_ne!(anchor, of_the_earlier_id);
}
