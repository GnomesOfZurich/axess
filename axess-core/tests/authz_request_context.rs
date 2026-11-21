#![cfg(feature = "authz")]
//! What each request context hands Cedar: `NoContext` nothing,
//! `StandardRequestContext` its MFA flag always and the client address and
//! the timestamp only when it was given them, and a context behind an `Arc`
//! what the context itself does. A schema lists the attributes a request
//! may carry, so an attribute emitted unasked is a refused request.

use axess_clock::Timestamp;
use axess_core::authz::context::{BuildRequestContext, NoContext, StandardRequestContext};
use cedar_policy::{Context, EvalResult};
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::Arc;

/// The Cedar context `context` builds.
fn built<C: BuildRequestContext>(context: &C) -> Context {
    context.to_cedar_context().expect("a context")
}

/// The names of the attributes `context` carries.
fn attributes(context: &Context) -> BTreeSet<String> {
    context.clone().into_iter().map(|(name, _)| name).collect()
}

fn names<const N: usize>(names: [&str; N]) -> BTreeSet<String> {
    names.into_iter().map(str::to_owned).collect()
}

fn string(context: &Context, name: &str) -> Option<String> {
    match context.get(name) {
        Some(EvalResult::String(value)) => Some(value),
        _ => None,
    }
}

fn an_instant() -> Timestamp {
    Timestamp::from_utc(2031, 3, 1, 12, 30, 5).unwrap()
}

#[test]
fn no_context_is_the_empty_context() {
    let context = built(&NoContext);
    assert_eq!(context, Context::empty());
    assert_eq!(attributes(&context), names([]));
}

#[test]
fn the_standard_context_alone_carries_only_the_mfa_flag() {
    for flag in [true, false] {
        let context = built(&StandardRequestContext::new(flag, None));
        assert_eq!(attributes(&context), names(["mfa_verified"]));
        assert!(
            matches!(context.get("mfa_verified"), Some(EvalResult::Bool(got)) if got == flag),
            "mfa_verified is {flag}"
        );
    }
}

#[test]
fn a_client_address_is_carried_when_given() {
    for address in ["192.0.2.7", "2001:db8::7"] {
        let ip: IpAddr = address.parse().unwrap();
        let context = built(&StandardRequestContext::new(true, Some(ip)));
        assert_eq!(attributes(&context), names(["ip_address", "mfa_verified"]));
        assert_eq!(string(&context, "ip_address").as_deref(), Some(address));
    }
}

#[test]
fn the_explicit_timestamp_form_carries_it_as_rfc_3339() {
    let context = built(&StandardRequestContext::at(false, None, an_instant()));
    assert_eq!(attributes(&context), names(["mfa_verified", "timestamp"]));
    assert_eq!(
        string(&context, "timestamp").as_deref(),
        Some("2031-03-01T12:30:05+00:00")
    );
    assert!(matches!(
        context.get("mfa_verified"),
        Some(EvalResult::Bool(false))
    ));
}

#[test]
fn an_address_and_a_timestamp_are_carried_together() {
    let ip: IpAddr = "192.0.2.7".parse().unwrap();
    let context = built(&StandardRequestContext::at(true, Some(ip), an_instant()));
    assert_eq!(
        attributes(&context),
        names(["ip_address", "mfa_verified", "timestamp"])
    );
    assert_eq!(string(&context, "ip_address").as_deref(), Some("192.0.2.7"));
    assert_eq!(
        string(&context, "timestamp").as_deref(),
        Some("2031-03-01T12:30:05+00:00")
    );
}

#[test]
fn a_context_behind_an_arc_builds_what_the_context_builds() {
    let ip: IpAddr = "192.0.2.7".parse().unwrap();
    let shared = Arc::new(StandardRequestContext::at(true, Some(ip), an_instant()));
    assert_eq!(built(&shared), built(shared.as_ref()));
    assert_eq!(
        attributes(&built(&shared)),
        names(["ip_address", "mfa_verified", "timestamp"])
    );
    assert_eq!(built(&Arc::new(NoContext)), Context::empty());
}
