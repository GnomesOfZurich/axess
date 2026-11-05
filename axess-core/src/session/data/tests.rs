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

/// A session row written by an older library that omitted
/// the `version` field (because it predated `SESSION_DATA_VERSION`)
/// must deserialise with `version == 1`. A
/// `default_version -> 0` mutation would silently mark every such
/// row as v0; `migrate()` would then think it needs an upgrade
/// every load, churning the store.
///
/// Invariant: a missing `version` field deserialises to the
/// pre-versioning legacy value `1` (NOT to the current
/// `SESSION_DATA_VERSION`); `migrate()` is responsible for
/// upgrading from there.
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

/// A session already at the current version must NOT be
/// re-migrated. Pins the `>=` guard against `<` and the
/// `-> true` / `-> false` body-replacement mutations: the only
/// behaviour consistent with all four mutation deltas is "false
/// when current; true when older; never the other way around".
#[test]
fn migrate_returns_false_when_version_already_current() {
    let mut data = SessionData::default();
    assert_eq!(data.version, SESSION_DATA_VERSION);
    let migrated = data.migrate();
    assert!(
        !migrated,
        "migrate must be a no-op when already at current version"
    );
    assert_eq!(data.version, SESSION_DATA_VERSION);
}

/// A stale (below-current) session is migrated and the function
/// returns `true`. Combined with the "current returns false" test
/// this discriminates `-> true` from `-> false` for `migrate`. Uses
/// `version: 1` (the real legacy pre-versioning value: see
/// `default_version`); `0` is not a state any deserialiser produces.
#[test]
fn migrate_returns_true_and_bumps_version_when_stale() {
    let mut data = SessionData {
        version: 1,
        ..Default::default()
    };
    let migrated = data.migrate();
    assert!(migrated, "migrate must return true on upgrade");
    assert_eq!(
        data.version, SESSION_DATA_VERSION,
        "migrate must bump version to current"
    );
}

/// A v1 session deserialised by a v2-aware library must
/// land with `device_id = None` via `serde(default)`. Pins the
/// wire-format compatibility: a `#[serde(default)]` removal would
/// fail this test because the `device_id` field would be missing
/// from the input JSON.
#[test]
fn deserialised_v1_session_gets_none_device_id() {
    let json = serde_json::json!({
        "version": 1,
        "auth_state": { "kind": "Guest" },
        "fingerprint": null,
        "custom": {}
    });
    let parsed: SessionData = serde_json::from_value(json).expect("parse v1");
    assert_eq!(parsed.device_id, None);
    assert_eq!(parsed.version, 1, "deserialisation must NOT auto-migrate");
}

/// Explicit migration from v1 bumps the version to v2 and
/// returns true. A v2 session loaded from disk does not need the
/// migration to do anything beyond the version bump because
/// `serde(default)` already filled the in-memory representation.
#[test]
fn migrate_v1_to_v2_bumps_version_and_signals_resave() {
    let mut data = SessionData {
        version: 1,
        ..Default::default()
    };
    let migrated = data.migrate();
    assert!(migrated, "v1 → v2 must signal a resave");
    assert_eq!(data.version, SESSION_DATA_VERSION);
    assert_eq!(data.device_id, None);
}

/// A future-version session (someone downgraded the
/// library) MUST NOT regress its version field. Pins the
/// `>=` direction: a `<` mutation would treat newer rows as
/// "needs upgrade" and clobber them down to `SESSION_DATA_VERSION`.
#[test]
fn migrate_does_not_regress_future_version() {
    let mut data = SessionData {
        version: SESSION_DATA_VERSION.saturating_add(1),
        ..Default::default()
    };
    let before = data.version;
    let migrated = data.migrate();
    assert!(!migrated, "migrate must be no-op for future-version data");
    assert_eq!(
        data.version, before,
        "migrate must NOT clobber future-version field"
    );
}

/// `user_id()` returns `None` only for Guest and `Some`
/// for every other variant. Kills `-> None` body replacement.
#[test]
fn user_id_returns_none_only_for_guest() {
    let user = axess_identity::testing::user("u1");
    let tenant = axess_identity::testing::tenant("t1");

    assert!(AuthState::Guest.user_id().is_none());
    assert_eq!(
        AuthState::Identifying {
            user_id: user,
            tenant_id: tenant,
        }
        .user_id(),
        Some(&user)
    );
    assert_eq!(
        AuthState::Authenticated {
            user_id: user,
            tenant_id: tenant,
            authn_time: chrono::Utc::now(),
            factors_completed: vec![],
            impersonator: None,
            ldap_groups: None,
        }
        .user_id(),
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
            authn_time: chrono::Utc::now(),
            factors_completed: vec![],
            impersonator: None,
            ldap_groups: None,
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
            authn_time: chrono::Utc::now(),
            factors_completed: vec![],
            impersonator: None,
            ldap_groups: None,
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
            authn_time: chrono::Utc::now(),
            factors_completed: vec![],
            impersonator: None,
            ldap_groups: None,
        }
        .is_guest()
    );
}

/// WorkflowState::new initialises current_step=0.
#[test]
fn workflow_state_new_starts_at_step_zero() {
    let now = chrono::Utc::now();
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
            authn_time: chrono::Utc::now(),
            factors_completed: vec![FactorKind::Password, FactorKind::Totp],
            impersonator: None,
            ldap_groups: None,
        },
        fingerprint: Some("fp-abc".to_string()),
        device_id: Some(axess_identity::testing::device("dev-1")),
        custom: serde_json::json!({"key": "value"}),
        revision: 7,
        touched_at: Some(chrono::Utc::now()),
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
            impersonator: None,
        }
        .is_authenticating()
    );
    assert!(
        !AuthState::Authenticated {
            user_id: user,
            tenant_id: tenant,
            authn_time: chrono::Utc::now(),
            factors_completed: vec![],
            impersonator: None,
            ldap_groups: None,
        }
        .is_authenticating()
    );
    assert!(
        !AuthState::PendingWorkflow {
            user_id: user,
            tenant_id: tenant,
            workflow: WorkflowState::new(WorkflowKind::Signup, 1, chrono::Utc::now()),
        }
        .is_authenticating()
    );
}

// ── Transition method tests ────────────────────────────────────
//
// These are isolated tests of `AuthState`'s pure transition methods;
// no `AuthSession`, no `SessionData`, no async, no RwLock. Each test
// pins one transition's pre- and post-state.

fn now() -> DateTime<Utc> {
    chrono::Utc::now()
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
        } => {
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
            factors_completed,
            impersonator,
            ldap_groups,
        } => {
            assert_eq!(user_id, user);
            assert_eq!(tenant_id, tenant);
            assert_eq!(authn_time, t);
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
        impersonator: None,
    };
    let outcome = state.advance_factor(&FactorKind::Password, now());
    assert_eq!(outcome, AdvanceOutcome::StillAuthenticating);
    match state {
        AuthState::Authenticating {
            remaining,
            completed,
            ..
        } => {
            assert_eq!(remaining, required(vec![FactorKind::Totp]));
            assert_eq!(completed, vec![FactorKind::Password]);
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
        impersonator: None,
    };
    let outcome = state.advance_factor(&FactorKind::Password, t);
    assert_eq!(outcome, AdvanceOutcome::Completed);
    match state {
        AuthState::Authenticated {
            user_id,
            tenant_id,
            authn_time,
            factors_completed,
            impersonator,
            ldap_groups,
        } => {
            assert_eq!(user_id, user);
            assert_eq!(tenant_id, tenant);
            assert_eq!(authn_time, t);
            assert_eq!(impersonator, None, "a login is nobody's impersonation");
            assert_eq!(ldap_groups, None, "no LDAP bind in this login");
            assert_eq!(factors_completed, vec![FactorKind::Password]);
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
        impersonator: None,
    };
    assert_eq!(
        state.advance_factor(&FactorKind::Password, t),
        AdvanceOutcome::StillAuthenticating
    );
    assert_eq!(
        state.advance_factor(&FactorKind::Totp, t),
        AdvanceOutcome::Completed
    );
    match state {
        AuthState::Authenticated {
            factors_completed, ..
        } => {
            assert_eq!(
                factors_completed,
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
        impersonator: None,
    };
    let outcome = state.advance_factor(&FactorKind::Totp, now());
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
        state.advance_factor(&FactorKind::Password, now()),
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
        impersonator: None,
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
    let now = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
    assert_eq!(
        state.advance_factor(&FactorKind::Password, now),
        AdvanceOutcome::StillAuthenticating
    );
    assert_eq!(
        state.advance_factor(&FactorKind::RecoveryCode, now),
        AdvanceOutcome::Completed
    );
    match state {
        AuthState::Authenticated {
            factors_completed, ..
        } => assert_eq!(
            factors_completed,
            vec![FactorKind::Password, FactorKind::RecoveryCode]
        ),
        other => panic!("expected Authenticated, got {other:?}"),
    }
}

/// A session written mid-login by a release that stored `remaining` as a
/// list of kinds still loads, its kinds read as required steps.
#[test]
fn a_mid_login_session_from_an_earlier_release_still_loads() {
    use crate::authn::factor::FactorStep;
    let legacy = serde_json::json!({
        "kind": "Authenticating",
        "user_id": axess_identity::testing::user("u1"),
        "tenant_id": axess_identity::testing::tenant("t1"),
        "method_name": "password+totp",
        "remaining": ["Totp"],
        "completed": ["Password"],
        "attempt_count": 0,
        "last_attempt": null,
    });
    let state: AuthState = serde_json::from_value(legacy.clone()).unwrap();
    match &state {
        AuthState::Authenticating { remaining, .. } => {
            assert_eq!(remaining, &vec![FactorStep::Required(FactorKind::Totp)]);
        }
        other => panic!("expected Authenticating, got {other:?}"),
    }
    // And through the session codec's own format.
    let packed = rmp_serde::to_vec_named(&legacy).unwrap();
    let from_msgpack: AuthState = rmp_serde::from_slice(&packed).unwrap();
    assert_eq!(from_msgpack, state);
    // The current shape round-trips.
    let again: AuthState =
        rmp_serde::from_slice(&rmp_serde::to_vec_named(&state).unwrap()).unwrap();
    assert_eq!(again, state);
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
    };
    assert_eq!(state.ldap_groups(), None, "not before the login completes");

    state.advance_factor(&FactorKind::LdapBind, now());
    assert_eq!(state.ldap_groups(), Some(staff.as_slice()));

    assert!(state.begin_step_up(required(vec![FactorKind::Totp])));
    state.advance_factor(&FactorKind::Totp, now());
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
        state.advance_factor(&FactorKind::Totp, now()),
        AdvanceOutcome::Completed
    );
    assert_eq!(
        state.impersonation(),
        Some(Impersonation { admin, since }),
        "the marker survives the step-up"
    );
}
