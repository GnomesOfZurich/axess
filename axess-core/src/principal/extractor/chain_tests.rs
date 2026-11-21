//! The extractors over every chain an application can install: none, the
//! session alone, a workload resolver alone, both in either order, two
//! workload resolvers, and no step at all. A request presents a workload
//! credential in the `x-workload` header (and, for the second resolver, in
//! `x-workload-2`): `acme` is admitted, `beta` is another workload, `bad`
//! and `anon` are refused, `human` makes the resolver answer a human.

use std::sync::Arc;

use axum::http::{Request, StatusCode};
use tokio::sync::RwLock;

use super::*;
use crate::session::data::SessionData;
use crate::session::layer::{SessionHandle, SessionInner};
use crate::testing::MockResolver;
use crate::{AuthState, CliResolver, TenantId, TrustDomain, UserId};
use axess_rng::SystemRng;

const HEADER: &str = "x-workload";
const SECOND_HEADER: &str = "x-workload-2";

fn acme() -> TenantId {
    TenantId::from_bytes([7u8; 16])
}

fn workload_resolver(parts: &Parts) -> Option<MockResolver> {
    resolver_for(parts, HEADER)
}

fn second_resolver(parts: &Parts) -> Option<MockResolver> {
    resolver_for(parts, SECOND_HEADER)
}

/// The workload of tenant acme whose service is `service`.
fn acme_workload(service: &str) -> Principal {
    let cli = CliResolver::builder()
        .trust_domain(TrustDomain::new("example.org").expect("a trust domain"))
        .service_name(service)
        .tenant_id(acme())
        .tenant_slug("acme")
        .build()
        .expect("a workload");
    Principal::Workload(cli.workload().clone())
}

fn resolver_for(parts: &Parts, header: &str) -> Option<MockResolver> {
    let presented = parts.headers.get(header)?.to_str().ok()?;
    Some(match presented {
        "acme" => MockResolver::new(acme_workload("billing")),
        "beta" => MockResolver::new(acme_workload("reports")),
        "human" => MockResolver::new(Principal::Human(HumanPrincipal {
            user_id: UserId::from_bytes([1u8; 16]),
            tenant_id: acme(),
            session_id: None,
            impersonator: None,
            attributes: Default::default(),
        })),
        "bad" => MockResolver::invalid_component("not a workload of this domain"),
        _ => MockResolver::not_authenticated(),
    })
}

/// What a request carries: a chain, a session, a workload credential and
/// a second one.
#[derive(Default)]
struct Shape {
    chain: Option<PrincipalResolverChain>,
    session: Option<SessionData>,
    workload: Option<&'static str>,
    second: Option<&'static str>,
}

fn parts(shape: Shape) -> Parts {
    let mut request = Request::builder().uri("/");
    if let Some(value) = shape.workload {
        request = request.header(HEADER, value);
    }
    if let Some(value) = shape.second {
        request = request.header(SECOND_HEADER, value);
    }
    if let Some(data) = shape.session {
        let inner = SessionInner {
            data,
            ..SessionInner::detached(Arc::new(SystemRng))
        };
        request = request.extension(SessionHandle(Arc::new(RwLock::new(inner))));
    }
    if let Some(chain) = shape.chain {
        request = request.extension(chain);
    }
    request.body(()).expect("a request").into_parts().0
}

fn signed_in() -> SessionData {
    SessionData {
        auth_state: AuthState::Authenticated {
            user_id: UserId::new(&SystemRng),
            tenant_id: acme(),
            authn_time: axess_clock::testing::MockClock::reference_time(),
            signed_in_at: axess_clock::testing::MockClock::reference_time(),
            factors_completed: Vec::new(),
            impersonator: None,
            ldap_groups: None,
            assurance: Vec::new(),
        },
        ..SessionData::default()
    }
}

fn guest() -> SessionData {
    SessionData::default()
}

fn workload_only() -> PrincipalResolverChain {
    PrincipalResolverChain::new().workload(workload_resolver)
}

fn workload_then_session() -> PrincipalResolverChain {
    PrincipalResolverChain::new()
        .workload(workload_resolver)
        .session()
}

fn session_then_workload() -> PrincipalResolverChain {
    PrincipalResolverChain::new()
        .session()
        .workload(workload_resolver)
}

fn two_workloads() -> PrincipalResolverChain {
    PrincipalResolverChain::new()
        .workload(workload_resolver)
        .workload(second_resolver)
}

/// What each of the three extractors answers for one request: `"human"`,
/// `"workload"`, or the rejection's status.
async fn answers(shape: impl Fn() -> Shape) -> [String; 3] {
    fn rejected(rejection: PrincipalRejection) -> String {
        rejection.into_response().status().as_u16().to_string()
    }
    let any = match AuthPrincipal::from_request_parts(&mut parts(shape()), &()).await {
        Ok(p) => match p.into_inner() {
            Principal::Human(_) => "human".to_string(),
            Principal::Workload(w) => {
                assert_eq!(w.tenant_id, acme());
                "workload".to_string()
            }
        },
        Err(e) => rejected(e),
    };
    let human = match AuthHumanPrincipal::from_request_parts(&mut parts(shape()), &()).await {
        Ok(_) => "human".to_string(),
        Err(e) => rejected(e),
    };
    let workload = match AuthWorkloadPrincipal::from_request_parts(&mut parts(shape()), &()).await {
        Ok(w) => {
            assert_eq!(w.tenant_slug, "acme");
            "workload".to_string()
        }
        Err(e) => rejected(e),
    };
    [any, human, workload]
}

fn expect(any: &str, human: &str, workload: &str) -> [String; 3] {
    [any.to_string(), human.to_string(), workload.to_string()]
}

#[tokio::test]
async fn without_a_chain_the_session_alone_decides_and_a_workload_credential_is_not_read() {
    let shape = || Shape {
        chain: None,
        session: Some(signed_in()),
        workload: Some("acme"),
        ..Default::default()
    };
    assert_eq!(answers(shape).await, expect("human", "human", "403"));
}

#[tokio::test]
async fn a_session_chain_is_the_chain_a_request_without_one_gets() {
    for (session, want) in [
        (Some(signed_in()), expect("human", "human", "403")),
        (Some(guest()), expect("401", "401", "401")),
        (None, expect("500", "500", "500")),
    ] {
        let explicit = || Shape {
            chain: Some(PrincipalResolverChain::new().session()),
            session: session.clone(),
            workload: Some("acme"),
            ..Default::default()
        };
        let implicit = || Shape {
            chain: None,
            session: session.clone(),
            workload: Some("acme"),
            ..Default::default()
        };
        assert_eq!(answers(explicit).await, want);
        assert_eq!(answers(implicit).await, want);
    }
}

#[tokio::test]
async fn a_workload_chain_admits_a_workload_and_needs_no_session_layer() {
    let admitted = || Shape {
        chain: Some(workload_only()),
        session: None,
        workload: Some("acme"),
        ..Default::default()
    };
    assert_eq!(
        answers(admitted).await,
        expect("workload", "403", "workload")
    );

    let nothing_presented = || Shape {
        chain: Some(workload_only()),
        session: None,
        workload: None,
        ..Default::default()
    };
    assert_eq!(
        answers(nothing_presented).await,
        expect("401", "401", "401")
    );

    // A signed-in session is not read by a chain without a session step.
    let session_only = || Shape {
        chain: Some(workload_only()),
        session: Some(signed_in()),
        workload: None,
        ..Default::default()
    };
    assert_eq!(answers(session_only).await, expect("401", "401", "401"));
}

#[tokio::test]
async fn a_refused_workload_credential_refuses_the_request() {
    for presented in ["bad", "anon"] {
        let shape = || Shape {
            chain: Some(workload_only()),
            session: None,
            workload: Some(presented),
            ..Default::default()
        };
        assert_eq!(answers(shape).await, expect("401", "401", "401"));
    }
    let mut request = parts(Shape {
        chain: Some(workload_only()),
        session: None,
        workload: Some("bad"),
        ..Default::default()
    });
    let rejection = AuthWorkloadPrincipal::from_request_parts(&mut request, &())
        .await
        .expect_err("refused");
    assert!(
        matches!(
            rejection,
            PrincipalRejection::Identity(IdentityError::InvalidComponent(_))
        ),
        "{rejection:?}"
    );
}

#[tokio::test]
async fn workload_then_session_runs_both_steps() {
    // A workload credential and a signed-in session are two principals:
    // none of the three admits either.
    let both = || Shape {
        chain: Some(workload_then_session()),
        session: Some(signed_in()),
        workload: Some("acme"),
        ..Default::default()
    };
    assert_eq!(answers(both).await, expect("401", "401", "401"));

    let session_only = || Shape {
        chain: Some(workload_then_session()),
        session: Some(signed_in()),
        workload: None,
        ..Default::default()
    };
    assert_eq!(answers(session_only).await, expect("human", "human", "403"));

    // A bad credential is never passed on to the session behind it, by
    // any of the three.
    let bad_with_session = || Shape {
        chain: Some(workload_then_session()),
        session: Some(signed_in()),
        workload: Some("bad"),
        ..Default::default()
    };
    assert_eq!(answers(bad_with_session).await, expect("401", "401", "401"));

    let no_layer = || Shape {
        chain: Some(workload_then_session()),
        session: None,
        workload: None,
        ..Default::default()
    };
    assert_eq!(answers(no_layer).await, expect("500", "500", "500"));
}

#[tokio::test]
async fn session_then_workload_runs_both_steps() {
    let both = || Shape {
        chain: Some(session_then_workload()),
        session: Some(signed_in()),
        workload: Some("acme"),
        ..Default::default()
    };
    assert_eq!(answers(both).await, expect("401", "401", "401"));

    let guest_with_credential = || Shape {
        chain: Some(session_then_workload()),
        session: Some(guest()),
        workload: Some("acme"),
        ..Default::default()
    };
    assert_eq!(
        answers(guest_with_credential).await,
        expect("workload", "403", "workload")
    );

    let guest_alone = || Shape {
        chain: Some(session_then_workload()),
        session: Some(guest()),
        workload: None,
        ..Default::default()
    };
    assert_eq!(answers(guest_alone).await, expect("401", "401", "401"));

    // The credential behind a signed-in session is read, and its refusal
    // refuses the request in all three.
    let bad_behind_session = || Shape {
        chain: Some(session_then_workload()),
        session: Some(signed_in()),
        workload: Some("bad"),
        ..Default::default()
    };
    assert_eq!(
        answers(bad_behind_session).await,
        expect("401", "401", "401")
    );
}

#[tokio::test]
async fn a_chain_with_no_step_resolves_no_one() {
    let shape = || Shape {
        chain: Some(PrincipalResolverChain::new()),
        session: Some(signed_in()),
        workload: Some("acme"),
        ..Default::default()
    };
    assert_eq!(answers(shape).await, expect("401", "401", "401"));
}

#[tokio::test]
async fn a_workload_step_that_answers_a_human_is_refused() {
    let shape = || Shape {
        chain: Some(workload_then_session()),
        session: Some(guest()),
        workload: Some("human"),
        ..Default::default()
    };
    assert_eq!(answers(shape).await, expect("403", "403", "403"));
}

/// Every shape in which a step refuses the credential the request
/// presents, before or after a step that resolves someone.
fn refused_shapes() -> Vec<Shape> {
    let mut shapes = Vec::new();
    for presented in ["bad", "anon", "human"] {
        shapes.push(Shape {
            chain: Some(workload_only()),
            session: None,
            workload: Some(presented),
            ..Default::default()
        });
        for session in [signed_in(), guest()] {
            for chain in [workload_then_session(), session_then_workload()] {
                shapes.push(Shape {
                    chain: Some(chain),
                    session: Some(session.clone()),
                    workload: Some(presented),
                    ..Default::default()
                });
            }
        }
        // A second workload step that resolves acme does not outweigh a
        // first one that refuses, nor the other way round.
        shapes.push(Shape {
            chain: Some(two_workloads()),
            workload: Some(presented),
            second: Some("acme"),
            ..Default::default()
        });
        shapes.push(Shape {
            chain: Some(two_workloads()),
            workload: Some("acme"),
            second: Some(presented),
            ..Default::default()
        });
    }
    shapes
}

/// The rejection a refused shape gets, by what the step was shown.
fn refusal_status(shape: &Shape) -> StatusCode {
    if shape.workload == Some("human") || shape.second == Some("human") {
        StatusCode::FORBIDDEN
    } else {
        StatusCode::UNAUTHORIZED
    }
}

#[tokio::test]
async fn auth_principal_refuses_a_request_whose_credential_a_step_refuses() {
    for shape in refused_shapes() {
        let want = refusal_status(&shape);
        let rejection = AuthPrincipal::from_request_parts(&mut parts(shape), &())
            .await
            .expect_err("a refused credential refuses the request");
        assert_eq!(rejection.into_response().status(), want);
    }
}

#[tokio::test]
async fn auth_human_principal_refuses_a_request_whose_credential_a_step_refuses() {
    for shape in refused_shapes() {
        let want = refusal_status(&shape);
        let signed_in = shape
            .session
            .as_ref()
            .is_some_and(|data| matches!(data.auth_state, AuthState::Authenticated { .. }));
        let rejection = AuthHumanPrincipal::from_request_parts(&mut parts(shape), &())
            .await
            .expect_err("a signed-in session behind a refused credential is not admitted");
        assert_eq!(
            rejection.into_response().status(),
            want,
            "signed in: {signed_in}"
        );
    }
}

#[tokio::test]
async fn auth_workload_principal_refuses_a_request_whose_credential_a_step_refuses() {
    for shape in refused_shapes() {
        let want = refusal_status(&shape);
        let rejection = AuthWorkloadPrincipal::from_request_parts(&mut parts(shape), &())
            .await
            .expect_err("a refused credential refuses the request");
        assert_eq!(rejection.into_response().status(), want);
    }
}

#[test]
fn a_chain_lists_its_steps_in_order() {
    assert_eq!(
        format!("{:?}", workload_then_session()),
        r#"["workload", "session"]"#
    );
    assert_eq!(format!("{:?}", PrincipalResolverChain::new()), "[]");
}

#[test]
fn every_rejection_keeps_its_status() {
    assert_eq!(
        PrincipalRejection::Identity(IdentityError::NotAuthenticated)
            .into_response()
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

/// Every shape in which two steps resolve different principals: a
/// signed-in session beside a workload credential in either order, and two
/// workload credentials of different workloads.
fn conflicting_shapes() -> Vec<Shape> {
    vec![
        Shape {
            chain: Some(workload_then_session()),
            session: Some(signed_in()),
            workload: Some("acme"),
            ..Default::default()
        },
        Shape {
            chain: Some(session_then_workload()),
            session: Some(signed_in()),
            workload: Some("acme"),
            ..Default::default()
        },
        Shape {
            chain: Some(two_workloads()),
            workload: Some("acme"),
            second: Some("beta"),
            ..Default::default()
        },
    ]
}

fn is_conflicting(rejection: &PrincipalRejection) -> bool {
    matches!(rejection, PrincipalRejection::ConflictingCredentials)
}

#[tokio::test]
async fn auth_principal_refuses_two_credentials_of_different_principals() {
    for shape in conflicting_shapes() {
        let rejection = AuthPrincipal::from_request_parts(&mut parts(shape), &())
            .await
            .expect_err("two principals");
        assert!(is_conflicting(&rejection), "{rejection:?}");
    }
}

#[tokio::test]
async fn auth_human_principal_refuses_two_credentials_of_different_principals() {
    for shape in conflicting_shapes() {
        let rejection = AuthHumanPrincipal::from_request_parts(&mut parts(shape), &())
            .await
            .expect_err("two principals");
        assert!(is_conflicting(&rejection), "{rejection:?}");
    }
}

#[tokio::test]
async fn auth_workload_principal_refuses_two_credentials_of_different_principals() {
    for shape in conflicting_shapes() {
        let rejection = AuthWorkloadPrincipal::from_request_parts(&mut parts(shape), &())
            .await
            .expect_err("two principals");
        assert!(is_conflicting(&rejection), "{rejection:?}");
    }
}

#[tokio::test]
async fn two_credentials_of_one_workload_admit_it() {
    let shape = || Shape {
        chain: Some(two_workloads()),
        workload: Some("acme"),
        second: Some("acme"),
        ..Default::default()
    };
    assert_eq!(answers(shape).await, expect("workload", "403", "workload"));
}

#[test]
fn conflicting_credentials_answer_401() {
    assert_eq!(
        PrincipalRejection::ConflictingCredentials
            .into_response()
            .status(),
        StatusCode::UNAUTHORIZED
    );
}
