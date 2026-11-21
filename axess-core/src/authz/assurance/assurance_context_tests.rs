//! The `assurance` attribute against a real policy set: the one-rule
//! requirement, the step-up a denial names, and the refusal's shape.

use super::*;
use crate::authn::factor::Fido2Ceremony;
use crate::authz::context::{BuildRequestContext, StandardRequestContext};
use crate::authz::provider::make_entity_uid;
use crate::authz::store::{AuthzDecision, PolicyEvaluator, PolicyStore};
use axess_clock::testing::Shift;
use cedar_policy::Entities;

/// The rule on the design page.
const RULE: &str = r#"
@step_up("passkey")
permit (
    principal,
    action == App::Action::"ApprovePayment",
    resource == App::Doc::"payment"
) when {
    context.assurance has fido2 &&
    context.assurance.fido2.user_verified &&
    context.assurance.fido2.credential == "device_bound" &&
    context.assurance.fido2.age_seconds <= 300
};
"#;

fn schema() -> String {
    let mut schema = serde_json::json!({
        "App": {
            "entityTypes": { "User": {}, "Doc": {} },
            "actions": {
                "ApprovePayment": {
                    "appliesTo": {
                        "principalTypes": ["User"],
                        "resourceTypes": ["Doc"],
                        "context": {
                            "type": "Record",
                            "attributes": { "assurance": { "type": "AxessAssurance" } }
                        }
                    }
                }
            }
        }
    });
    merge_assurance_schema(&mut schema, "App").expect("the fragment merges");
    schema.to_string()
}

fn store(policies: &str) -> PolicyStore {
    PolicyStore::from_text(policies, &schema()).expect("the policies validate against the fragment")
}

fn now() -> Timestamp {
    Timestamp::from_unix_seconds(1_700_000_000).unwrap()
}

fn ago(seconds: i64) -> Timestamp {
    now().minus(axess_clock::SignedDuration::seconds(seconds))
}

fn passkey(user_verified: bool, synced: bool, seconds_ago: i64) -> FactorAssurance {
    FactorAssurance::fido2(user_verified, synced, synced, None, ago(seconds_ago))
}

fn ask(
    store: &PolicyStore,
    record: &[FactorAssurance],
    resource: &str,
) -> (AuthzDecision, Option<StepUp>) {
    let context = AssuranceContext::from_session(record, now())
        .to_context()
        .unwrap();
    let principal = make_entity_uid("App", "User", "u").unwrap();
    let action = make_entity_uid("App", "Action", "ApprovePayment").unwrap();
    let resource = make_entity_uid("App", "Doc", resource).unwrap();
    let entities = Entities::empty();
    let decision = store.is_authorized(
        &entities,
        principal.clone(),
        action.clone(),
        resource.clone(),
        context.clone(),
    );
    // The step-up is the question a gate asks after a deny, and only then.
    let step_up = match decision {
        AuthzDecision::Allow => None,
        AuthzDecision::Deny => store.step_up_for(&entities, principal, action, resource, context),
    };
    (decision, step_up)
}

#[test]
fn a_fresh_device_bound_passkey_is_the_only_session_the_rule_permits() {
    let store = store(RULE);
    let passkey_step_up = Some(StepUp::Fido2(Fido2Ceremony::Passkey));
    let fresh = [passkey(true, false, 10)];
    assert_eq!(ask(&store, &fresh, "payment"), (AuthzDecision::Allow, None));

    let denied: [(&str, Vec<FactorAssurance>); 5] = [
        (
            "password only",
            vec![FactorAssurance::for_kind(FactorKind::Password, ago(10))],
        ),
        ("a passkey six minutes old", vec![passkey(true, false, 360)]),
        ("a synced passkey", vec![passkey(true, true, 10)]),
        (
            "a passkey without user verification",
            vec![passkey(false, false, 10)],
        ),
        ("a session from before the record existed", vec![]),
    ];
    for (case, record) in denied {
        assert_eq!(
            ask(&store, &record, "payment"),
            (AuthzDecision::Deny, passkey_step_up.clone()),
            "{case}: denied, and the step-up named"
        );
    }
}

#[test]
fn a_denial_no_step_up_would_cure_stays_a_plain_denial() {
    let store = store(RULE);
    let record = [FactorAssurance::for_kind(FactorKind::Password, ago(10))];
    assert_eq!(
        ask(&store, &record, "another-payment"),
        (AuthzDecision::Deny, None),
        "the rule never covers this resource, whatever the assurance"
    );
}

#[test]
fn a_context_without_the_attribute_names_no_step_up() {
    let store = store(RULE);
    let principal = make_entity_uid("App", "User", "u").unwrap();
    let action = make_entity_uid("App", "Action", "ApprovePayment").unwrap();
    let resource = make_entity_uid("App", "Doc", "payment").unwrap();
    assert_eq!(
        store.step_up_for(
            &Entities::empty(),
            principal,
            action,
            resource,
            Context::empty()
        ),
        None
    );
}

#[test]
fn the_weakest_step_up_that_satisfies_is_named() {
    let either = r#"
@step_up("passkey")
permit (principal, action == App::Action::"ApprovePayment", resource)
when { context.assurance has fido2 && context.assurance.fido2.age_seconds <= 300 };
@step_up("totp")
permit (principal, action == App::Action::"ApprovePayment", resource)
when { context.assurance has totp && context.assurance.totp.age_seconds <= 300 };
"#;
    assert_eq!(ask(&store(either), &[], "payment").1, Some(StepUp::Totp));
}

#[test]
fn an_annotation_that_cannot_satisfy_its_own_rule_prompts_nothing() {
    let mismatched = RULE.replace(
        "@step_up(\"passkey\")",
        "@step_up(\"security_key:discouraged\")",
    );
    assert_eq!(
        ask(&store(&mismatched), &[], "payment"),
        (AuthzDecision::Deny, None),
        "a ceremony that asks the authenticator not to verify cannot meet user_verified"
    );
}

#[test]
fn an_unknown_step_up_refuses_the_policy_set_by_name() {
    let misspelt = RULE.replace("@step_up(\"passkey\")", "@step_up(\"sms\")");
    let err = PolicyStore::from_text(&misspelt, &schema())
        .err()
        .expect("refused");
    let text = err.to_string();
    assert!(matches!(err, AuthzError::PolicyValidation(_)), "{text}");
    assert!(
        text.contains("\"sms\"") && text.contains("step_up"),
        "{text}"
    );
}

#[test]
fn the_attested_step_up_names_its_trust_anchor() {
    let attested = r#"
@step_up("attested_passkey:vendor-roots")
permit (principal, action == App::Action::"ApprovePayment", resource)
when {
    context.assurance has fido2 &&
    context.assurance.fido2 has trust_anchor &&
    context.assurance.fido2.trust_anchor == "vendor-roots"
};
"#;
    let store = store(attested);
    let proven = [FactorAssurance::fido2(
        true,
        false,
        false,
        Some(Arc::from("vendor-roots")),
        ago(5),
    )];
    assert_eq!(
        ask(&store, &proven, "payment"),
        (AuthzDecision::Allow, None)
    );
    assert_eq!(
        ask(&store, &[passkey(true, false, 5)], "payment").1,
        Some(StepUp::Fido2(Fido2Ceremony::AttestedPasskey {
            trust_anchor: "vendor-roots".into()
        }))
    );
}

#[test]
fn the_record_reads_back_from_the_context_it_built() {
    let record = [
        FactorAssurance::for_kind(FactorKind::Password, ago(120)),
        FactorAssurance::fido2(true, false, false, Some(Arc::from("vendor-roots")), ago(5)),
    ];
    let built = AssuranceContext::from_session(&record, now());
    let fido2 = built.factor("fido2").expect("fido2 present");
    assert_eq!(fido2.age_seconds, 5);
    assert_eq!(fido2.trust_anchor.as_deref(), Some("vendor-roots"));
    assert_eq!(built.factor("password").unwrap().age_seconds, 120);
    assert_eq!(
        AssuranceContext::from_context(&built.to_context().unwrap()),
        Some(built)
    );
}

#[test]
fn a_proof_dated_after_the_request_is_left_out() {
    let record = [FactorAssurance::for_kind(
        FactorKind::Password,
        now().plus(axess_clock::SignedDuration::seconds(1)),
    )];
    assert_eq!(
        AssuranceContext::from_session(&record, now()),
        AssuranceContext::default()
    );
}

#[test]
fn the_standard_context_carries_assurance_beside_its_own_attributes() {
    let assurance = AssuranceContext::from_session(&[passkey(true, false, 1)], now());
    let context = StandardRequestContext::new(true, None)
        .with_assurance(assurance.clone())
        .to_cedar_context()
        .unwrap();
    assert!(matches!(
        context.get("mfa_verified"),
        Some(EvalResult::Bool(true))
    ));
    assert_eq!(AssuranceContext::from_context(&context), Some(assurance));
}

/// `key_bound` is emitted only when the context is built with it, and then
/// as the boolean it was given.
#[test]
fn the_standard_context_carries_key_bound_only_when_asked() {
    let plain = StandardRequestContext::new(true, None)
        .to_cedar_context()
        .unwrap();
    assert!(plain.get("key_bound").is_none());
    for bound in [true, false] {
        let context = StandardRequestContext::new(true, None)
            .with_key_bound(bound)
            .to_cedar_context()
            .unwrap();
        assert!(
            matches!(context.get("key_bound"), Some(EvalResult::Bool(b)) if b == bound),
            "{bound}"
        );
    }
}

#[tokio::test]
async fn the_refusal_names_the_step_up_and_nothing_else() {
    use http_body_util::BodyExt;
    let response =
        AuthzRefusal::StepUpRequired(StepUp::Fido2(Fido2Ceremony::Passkey)).into_response();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        json,
        serde_json::json!({ "error": "step_up_required", "step_up": "passkey" })
    );
    let denied = AuthzRefusal::Denied.into_response();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    let body = denied.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json, serde_json::json!({ "error": "Access denied" }));
}

/// Two proofs under one attribute: the later proof holds it, whichever of
/// the two the session recorded first.
#[test]
fn of_two_proofs_under_one_attribute_the_later_one_holds_it() {
    let fresh = passkey(true, false, 5);
    let stale = passkey(false, true, 300);
    for record in [[fresh.clone(), stale.clone()], [stale, fresh]] {
        let built = AssuranceContext::from_session(&record, now());
        let held = built.factor("fido2").expect("fido2 present");
        assert_eq!(held.age_seconds, 5, "{record:?}");
        assert!(held.user_verified, "{record:?}");
        assert_eq!(held.credential, CredentialBinding::DeviceBound);
    }
}

/// An age is in whole seconds, so two proofs inside one second tie. The one
/// the session recorded last is the later proof and holds the attribute.
#[test]
fn of_two_proofs_of_one_age_the_one_recorded_last_holds_the_attribute() {
    let record = [passkey(false, true, 5), passkey(true, false, 5)];
    let built = AssuranceContext::from_session(&record, now());
    let held = built.factor("fido2").expect("fido2 present");
    assert!(held.user_verified);
    assert_eq!(held.credential, CredentialBinding::DeviceBound);
}

/// A schema that already carries the two types as the fragment defines them
/// merges again and is left as it was.
#[test]
fn merging_the_fragment_into_a_schema_that_has_it_changes_nothing() {
    let mut schema = serde_json::json!({ "App": { "entityTypes": {}, "actions": {} } });
    merge_assurance_schema(&mut schema, "App").expect("the fragment merges");
    let once = schema.clone();
    merge_assurance_schema(&mut schema, "App").expect("the same definitions merge again");
    assert_eq!(schema, once);
}

/// A schema that defines one of the two types differently is refused by the
/// type's name, and its own definition is not overwritten.
#[test]
fn a_schema_that_defines_an_assurance_type_differently_is_refused() {
    let own = serde_json::json!({ "type": "Record", "attributes": {} });
    let mut schema = serde_json::json!({
        "App": { "commonTypes": { "AxessAssurance": own.clone() } }
    });
    let refused = merge_assurance_schema(&mut schema, "App").unwrap_err();
    assert!(
        matches!(&refused, AuthzError::SchemaParse(text) if text.contains("AxessAssurance")),
        "{refused}"
    );
    assert_eq!(schema["App"]["commonTypes"]["AxessAssurance"], own);
}

/// A context whose `credential` is none of the three values the record
/// knows is not this record: it reads back as nothing, never as a proof with
/// a binding it did not state.
#[test]
fn a_credential_value_outside_the_three_reads_back_as_no_record() {
    let context_with = |credential: &str| {
        let factor = RestrictedExpression::new_record([
            (
                "user_verified".to_string(),
                RestrictedExpression::new_bool(true),
            ),
            (
                "credential".to_string(),
                RestrictedExpression::new_string(credential.to_string()),
            ),
            (
                "attested".to_string(),
                RestrictedExpression::new_bool(false),
            ),
            ("age_seconds".to_string(), RestrictedExpression::new_long(1)),
        ])
        .unwrap();
        let assurance = RestrictedExpression::new_record([("fido2".to_string(), factor)]).unwrap();
        Context::from_pairs([(ASSURANCE_ATTRIBUTE.to_string(), assurance)]).unwrap()
    };
    assert_eq!(
        AssuranceContext::from_context(&context_with("hardware")),
        None
    );
    for (stated, binding) in [
        ("device_bound", CredentialBinding::DeviceBound),
        ("synced", CredentialBinding::Synced),
        ("not_applicable", CredentialBinding::NotApplicable),
    ] {
        let read = AssuranceContext::from_context(&context_with(stated)).expect("a known value");
        assert_eq!(read.factor("fido2").unwrap().credential, binding);
    }
}
