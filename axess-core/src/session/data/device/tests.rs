//! The judgement of a key binding over every kind of session state: a
//! guest, an identified user, a login in progress, a pending workflow, a
//! signed-in user, a step-up, and an impersonation within a tenant and
//! across tenants, each for a small set of people.

use super::*;
use crate::authn::factor::FactorKind;
use crate::authn::ids::{TenantId, UserId};
use crate::device_key::KeyThumbprint;
use crate::session::data::{AuthFlow, AuthState, Impersonation, WorkflowKind, WorkflowState};
use axess_clock::Timestamp;
use axess_identity::testing::{device, tenant, user};
use proptest::prelude::*;
use std::sync::Arc;

fn now() -> Timestamp {
    axess_clock::testing::MockClock::reference_time()
}

/// The people of the property: one of three users.
fn person(n: u8) -> UserId {
    user(&format!("person-{n}"))
}

/// One of two tenants.
fn tenant_of(n: u8) -> TenantId {
    tenant(&format!("tenant-{n}"))
}

/// The kinds of session state a binding is judged against.
#[derive(Debug, Clone, Copy)]
enum Kind {
    Guest,
    Identifying,
    LoggingIn,
    PendingWorkflow,
    SignedIn,
    SteppingUp,
}

/// A state of `kind` for `user` of `tenant`, impersonated by `admin` where
/// the kind carries one, and the person at its browser as the rule names
/// it: the administrator of an impersonation, else the signed-in user, and
/// nobody for a state that is not signed in.
fn state_of(
    kind: Kind,
    user: UserId,
    tenant: TenantId,
    admin: Option<UserId>,
) -> (AuthState, Option<UserId>) {
    let impersonator = admin.map(|admin| Impersonation {
        admin,
        since: now(),
    });
    let signed_in = Some(admin.unwrap_or(user));
    match kind {
        Kind::Guest => (AuthState::Guest, None),
        Kind::Identifying => (
            AuthState::Identifying {
                user_id: user,
                tenant_id: tenant,
            },
            None,
        ),
        Kind::LoggingIn => {
            let mut state = AuthState::Guest;
            state.begin_authenticating(
                user,
                tenant,
                Arc::from("password"),
                vec![crate::authn::factor::FactorStep::Required(
                    FactorKind::Password,
                )],
            );
            (state, None)
        }
        Kind::PendingWorkflow => (
            AuthState::PendingWorkflow {
                user_id: user,
                tenant_id: tenant,
                workflow: WorkflowState::new(WorkflowKind::Signup, 1, now()),
            },
            None,
        ),
        Kind::SignedIn => (
            AuthState::Authenticated {
                user_id: user,
                tenant_id: tenant,
                authn_time: now(),
                signed_in_at: now(),
                factors_completed: Vec::new(),
                impersonator,
                ldap_groups: None,
                assurance: Vec::new(),
            },
            signed_in,
        ),
        Kind::SteppingUp => (
            AuthState::Authenticating {
                user_id: user,
                tenant_id: tenant,
                method_name: Arc::from("step-up"),
                remaining: Vec::new(),
                completed: Vec::new(),
                attempt_count: 0,
                last_attempt: None,
                ldap_groups: None,
                impersonator,
                assurance: Vec::new(),
                flow: AuthFlow::StepUp {
                    signed_in_at: now(),
                },
            },
            signed_in,
        ),
    }
}

fn kind() -> impl Strategy<Value = Kind> {
    prop_oneof![
        Just(Kind::Guest),
        Just(Kind::Identifying),
        Just(Kind::LoggingIn),
        Just(Kind::PendingWorkflow),
        Just(Kind::SignedIn),
        Just(Kind::SteppingUp),
    ]
}

/// A binding made for `owner` on a device of `tenant`.
fn binding(owner: UserId, tenant: TenantId) -> SessionKeyBinding {
    SessionKeyBinding {
        owner,
        tenant_id: tenant,
        device_id: device("d"),
        thumbprint: KeyThumbprint::from_bytes([7; 32]),
        bound_at: now(),
    }
}

proptest! {
    /// A binding is in force exactly when the state is signed in and the
    /// person at its browser (the administrator of an impersonation, within
    /// a tenant or across tenants) is the one it was made for; the tenant
    /// the binding names is not compared.
    #[test]
    fn a_binding_is_in_force_exactly_for_the_signed_in_person_at_the_browser(
        kind in kind(),
        user in 0u8..3,
        admin in proptest::option::of(0u8..3),
        session_tenant in 0u8..2,
        owner in 0u8..3,
        device_tenant in 0u8..2,
    ) {
        let (state, at_browser) = state_of(
            kind,
            person(user),
            tenant_of(session_tenant),
            admin.map(person),
        );
        let made = binding(person(owner), tenant_of(device_tenant));
        let expected = at_browser == Some(person(owner));
        prop_assert_eq!(made.in_force_for(&state), expected, "{:?}", state);

        let mut row = SessionData {
            auth_state: state,
            key_binding: Some(made),
            ..SessionData::default()
        };
        prop_assert_eq!(row.key_binding_in_force().is_some(), expected);
        prop_assert_eq!(row.drop_binding_not_in_force(), !expected);
        prop_assert_eq!(row.key_binding.is_some(), expected);
        prop_assert!(!row.drop_binding_not_in_force(), "a second drop removes nothing");
    }
}

/// The cases the property draws from, named: the administrator's binding
/// holds through an impersonation of a user of another tenant, and through
/// a step-up of it, and the target's own binding does not.
#[test]
fn an_impersonation_across_tenants_keeps_the_administrators_binding() {
    let (admin, target) = (person(0), person(1));
    for kind in [Kind::SignedIn, Kind::SteppingUp] {
        let (state, _) = state_of(kind, target, tenant_of(1), Some(admin));
        assert!(
            binding(admin, tenant_of(0)).in_force_for(&state),
            "{kind:?}"
        );
        assert!(
            !binding(target, tenant_of(1)).in_force_for(&state),
            "{kind:?}"
        );
    }
}

proptest! {
    /// A device holds exactly when it was resolved for nobody, or the person
    /// it was resolved for is the person at the browser of the session as it
    /// stands (the administrator of an impersonation, within a tenant or
    /// across tenants) or, while nobody is signed in, the user a login in
    /// progress or another pending state names: never for a recorded person
    /// and a guest, nor for another person's login.
    #[test]
    fn a_device_holds_exactly_for_the_person_it_was_resolved_for(
        resolved_for in proptest::option::of(0u8..3),
        kind in kind(),
        user in 0u8..3,
        admin in proptest::option::of(0u8..3),
        session_tenant in 0u8..2,
        named in proptest::option::of(0u8..2),
    ) {
        let (state, at_browser) = state_of(
            kind,
            person(user),
            tenant_of(session_tenant),
            admin.map(person),
        );
        let pending = match kind {
            Kind::Identifying | Kind::LoggingIn | Kind::PendingWorkflow => Some(person(user)),
            Kind::Guest | Kind::SignedIn | Kind::SteppingUp => None,
        };
        let device_id = named.map(|n| device(&format!("device-{n}")));
        let resolved_for = resolved_for.map(person);
        let holds = resolved_for.is_none() || resolved_for == at_browser.or(pending);
        let mut row = SessionData {
            auth_state: state,
            device_id,
            ..SessionData::default()
        };
        let expected = device_id.filter(|_| holds);
        prop_assert_eq!(row.device_in_force(resolved_for.as_ref()), expected);
        prop_assert_eq!(
            row.drop_device_not_in_force(resolved_for.as_ref()),
            device_id.is_some() && !holds
        );
        prop_assert_eq!(row.device_id, expected);
    }
}

/// The cases the property draws from, named: a device resolved for the
/// administrator holds through an impersonation, within a tenant and across
/// tenants, and not for the user the session runs as; one resolved for
/// nobody holds for whoever signs in; one resolved for a person does not
/// hold for a guest or for another person's login in progress, and holds
/// for that person's own.
#[test]
fn a_device_resolved_for_the_administrator_holds_through_an_impersonation() {
    let (admin, target) = (person(0), person(1));
    let named = Some(device("d"));
    for tenant in [tenant_of(0), tenant_of(1)] {
        let (state, _) = state_of(Kind::SignedIn, target, tenant, Some(admin));
        let row = SessionData {
            auth_state: state,
            device_id: named,
            ..SessionData::default()
        };
        assert_eq!(row.device_in_force(Some(&admin)), named);
        assert_eq!(row.device_in_force(Some(&target)), None);
        assert_eq!(row.device_in_force(None), named);
    }
    let (guest, _) = state_of(Kind::Guest, admin, tenant_of(0), None);
    let (own_login, _) = state_of(Kind::LoggingIn, admin, tenant_of(0), None);
    let (other_login, _) = state_of(Kind::LoggingIn, target, tenant_of(0), None);
    for (state, holds) in [(guest, false), (own_login, true), (other_login, false)] {
        let row = SessionData {
            auth_state: state,
            device_id: named,
            ..SessionData::default()
        };
        assert_eq!(
            row.device_in_force(Some(&admin)),
            named.filter(|_| holds),
            "{:?}",
            row.auth_state
        );
    }
}
