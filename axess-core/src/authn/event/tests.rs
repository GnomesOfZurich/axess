//! Unit tests for [`super::AuditContext`], [`super::AuthEventType`],
//! [`super::AuthEventStatus`], [`super::AuthEvent`], and
//! [`super::AuthEventBuilder`].
//!
//! Pulled sideways from the previous in-file `#[cfg(test)] mod` block
//! so the production-vs-tests ratio in `event.rs` becomes scannable.

#![cfg(test)]

use super::*;
use axum::extract::FromRequestParts;
use axum::http::HeaderMap;
use std::net::IpAddr;

/// Request parts carrying `headers`, and the address the client-IP layer
/// resolved if there was one.
fn parts(headers: HeaderMap, resolved: Option<&str>) -> axum::http::request::Parts {
    let mut req = axum::http::Request::builder().body(()).unwrap();
    *req.headers_mut() = headers;
    if let Some(ip) = resolved {
        req.extensions_mut()
            .insert(crate::client_ip::ClientIp::for_test(Some(
                ip.parse().unwrap(),
            )));
    }
    req.into_parts().0
}

#[tokio::test]
async fn audit_context_from_headers_with_all_fields() {
    let mut headers = HeaderMap::new();
    headers.insert("user-agent", "Mozilla/5.0 TestBrowser".parse().unwrap());

    let mut p = parts(headers, Some("203.0.113.42"));
    p.extensions
        .insert(crate::middleware::request_id::RequestId(
            "req-abc-123".to_owned(),
        ));
    let ctx = AuditContext::from_request_parts(&mut p, &()).await.unwrap();

    assert_eq!(
        ctx.ip_address,
        Some("203.0.113.42".parse::<IpAddr>().unwrap())
    );
    assert_eq!(ctx.user_agent.as_deref(), Some("Mozilla/5.0 TestBrowser"));
    assert_eq!(ctx.request_id.as_deref(), Some("req-abc-123"));
    assert!(
        ctx.geo_country.is_none(),
        "geo_country requires external lookup"
    );
    assert!(
        ctx.session_id.is_none(),
        "no session on the request means no session id"
    );
}

#[tokio::test]
async fn audit_context_missing_headers_produce_none() {
    let mut p = parts(HeaderMap::new(), None);
    let ctx = AuditContext::from_request_parts(&mut p, &()).await.unwrap();

    assert!(ctx.ip_address.is_none());
    assert!(ctx.user_agent.is_none());
    assert!(ctx.request_id.is_none());
    assert!(ctx.geo_country.is_none());
    assert!(ctx.session_id.is_none());
}

#[test]
fn event_carries_ip_and_user_agent_from_audit_context() {
    let ctx = AuditContext {
        ip_source: crate::client_ip::Source::Forwarded,
        trace_id: None,
        ip_address: Some("203.0.113.42".parse().unwrap()),
        user_agent: Some("TestAgent/1.0".to_string()),
        request_id: Some("req-xyz".to_string()),
        geo_country: Some("CH".to_string()),
        session_id: None,
    };

    let event = AuthEventBuilder::attributed(
        axess_identity::testing::user("user-1"),
        axess_identity::testing::tenant("tenant-1"),
        AuthEventType::LoginAttempt,
        AuthEventStatus::Success,
    )
    .with_audit_context(&ctx)
    .build();

    assert_eq!(event.ip_address, Some("203.0.113.42".parse().unwrap()));
    assert_eq!(event.user_agent.as_deref(), Some("TestAgent/1.0"));
    assert_eq!(event.request_id.as_deref(), Some("req-xyz"));
    assert_eq!(event.geo_country.as_deref(), Some("CH"));
}

#[test]
fn with_audit_context_does_not_overwrite_explicit_session() {
    let sid = crate::session::id::SessionId::from_bytes(*uuid::Uuid::new_v4().as_bytes());
    let ctx = AuditContext {
        session_id: Some(uuid::Uuid::new_v4().to_string()),
        ..Default::default()
    };

    let event = AuthEventBuilder::attributed(
        axess_identity::testing::user("u"),
        axess_identity::testing::tenant("t"),
        AuthEventType::Authenticated,
        AuthEventStatus::Success,
    )
    .with_session(sid)
    .with_audit_context(&ctx)
    .build();

    // The explicit session_id should be preserved, not overwritten.
    assert_eq!(event.session_id, Some(sid));
}

#[test]
fn empty_audit_context_leaves_event_fields_none() {
    let ctx = AuditContext::default();
    let event = AuthEventBuilder::attributed(
        axess_identity::testing::user("u"),
        axess_identity::testing::tenant("t"),
        AuthEventType::LogoutAttempt,
        AuthEventStatus::Success,
    )
    .with_audit_context(&ctx)
    .build();

    assert!(event.ip_address.is_none());
    assert!(event.user_agent.is_none());
    assert!(event.request_id.is_none());
    assert!(event.geo_country.is_none());
}

/// Pin every wire string for `AuthEventType::as_str` so a
/// `""`/`"xyzzy"` mutation flips an observable comparison. SOC
/// dashboards, alerting rules, and DB schemas are keyed off these
/// exact strings; silently changing them breaks the audit trail.
#[test]
fn auth_event_type_as_str_pins_wire_strings() {
    for (variant, expected) in [
        (AuthEventType::Authenticated, "authenticated"),
        (AuthEventType::LoginAttempt, "login_attempt"),
        (AuthEventType::LogoutAttempt, "logout_attempt"),
        (AuthEventType::FactorVerified, "factor_verified"),
        (AuthEventType::FactorSetup, "factor_setup"),
        (AuthEventType::FactorEnabled, "factor_enabled"),
        (AuthEventType::FactorDisabled, "factor_disabled"),
        (AuthEventType::MethodEnabled, "method_enabled"),
        (AuthEventType::MethodDisabled, "method_disabled"),
        (
            AuthEventType::PasswordResetRequested,
            "password_reset_requested",
        ),
        (AuthEventType::PasswordReset, "password_reset"),
        (AuthEventType::SessionExpired, "session_expired"),
        (AuthEventType::SessionInvalidated, "session_invalidated"),
        (AuthEventType::SignupStarted, "signup_started"),
        (AuthEventType::SignupCompleted, "signup_completed"),
        (AuthEventType::AccountSuspended, "account_suspended"),
        (AuthEventType::AccountActivated, "account_activated"),
        (AuthEventType::Impersonation, "impersonation"),
        // Device-event variants. Wire strings ARE the
        // contract with `docs/production/audit-events.md`; changing them
        // breaks SOC dashboards built against the documented
        // names.
        (AuthEventType::DeviceFirstSeen, "device_first_seen"),
        (AuthEventType::DeviceTrustGranted, "device_trust_granted"),
        (AuthEventType::DeviceRevoked, "device_revoked"),
        (AuthEventType::DevicePurged, "device_purged"),
        (AuthEventType::DeviceBindingAdded, "device_binding_added"),
        (
            AuthEventType::DeviceFingerprintMismatch,
            "device_fingerprint_mismatch",
        ),
    ] {
        assert_eq!(variant.as_str(), expected);
        // FromStr round-trip: pins the as_str <-> from_str symmetry.
        let parsed: AuthEventType = expected.parse().expect("round-trip parse");
        assert_eq!(parsed, variant);
    }
}

/// `with_device` populates `AuthEvent::device_id`, the new
/// audit-table column. Round-trips through `build_at` (used by every
/// emit site that captures a deterministic timestamp) AND through
/// `serde_json` (the wire format `record_event` impls typically
/// serialize to). The skip-if-None serde shape keeps
/// audit rows backwards-compatible: events without a device omit
/// the field entirely rather than serialising `null`.
#[test]
fn with_device_populates_device_id_and_round_trips() {
    let device = axess_identity::testing::device("dev-abc-123");
    let event = AuthEventBuilder::success(AuthEventType::DeviceFirstSeen)
        .attributed_to(
            &axess_identity::testing::user("u"),
            &axess_identity::testing::tenant("t"),
        )
        .with_device(device)
        .build_at(chrono::Utc::now());

    assert_eq!(event.device_id.as_ref(), Some(&device));

    // serde round-trip: the JSON form is what production audit
    // backends persist (and what this crate's tests assert
    // against). `device_id` must survive the round-trip.
    let json = serde_json::to_value(&event).expect("serialize");
    assert_eq!(
        json["device_id"],
        serde_json::to_value(device).expect("serialize device id"),
    );

    let back: AuthEvent = serde_json::from_value(json).expect("deserialize");
    assert_eq!(back.device_id, event.device_id);
}

/// Events emitted without `with_device` omit the field
/// from the JSON shape entirely (skip_serializing_if).
/// Audit-row consumers that `select * from auth_events` and
/// expected the field to be absent for legacy rows continue to
/// see the same shape for events whose call site doesn't have a
/// `device_id` to attach.
#[test]
fn event_without_device_omits_field_in_json() {
    let event = AuthEventBuilder::success(AuthEventType::LoginAttempt)
        .attributed_to(
            &axess_identity::testing::user("u"),
            &axess_identity::testing::tenant("t"),
        )
        .build();

    assert!(event.device_id.is_none());
    let json = serde_json::to_value(&event).unwrap();
    assert!(
        json.get("device_id").is_none(),
        "device_id must be skipped from JSON when None"
    );
}

/// `Display` for `AuthEventType` must produce the same wire
/// string as `as_str`. Mutation `Ok(Default::default())` would emit
/// an empty string from `format!("{e}")`, breaking every
/// `tracing::warn!(event = %e)` log line.
#[test]
fn auth_event_type_display_matches_as_str() {
    for variant in [
        AuthEventType::Authenticated,
        AuthEventType::LoginAttempt,
        AuthEventType::Impersonation,
    ] {
        let displayed = format!("{}", variant);
        assert_eq!(displayed, variant.as_str());
        assert!(!displayed.is_empty());
    }
}

/// Pin every wire string for `AuthEventStatus::as_str`.
#[test]
fn auth_event_status_as_str_pins_wire_strings() {
    for (variant, expected) in [
        (AuthEventStatus::Success, "success"),
        (AuthEventStatus::Failure, "failure"),
        (AuthEventStatus::Locked, "locked"),
        (AuthEventStatus::Expired, "expired"),
        (AuthEventStatus::Suspicious, "suspicious"),
    ] {
        assert_eq!(variant.as_str(), expected);
        let parsed: AuthEventStatus = expected.parse().expect("round-trip parse");
        assert_eq!(parsed, variant);
    }
}

/// `Display` for `AuthEventStatus` matches `as_str`.
#[test]
fn auth_event_status_display_matches_as_str() {
    for variant in [
        AuthEventStatus::Success,
        AuthEventStatus::Failure,
        AuthEventStatus::Suspicious,
    ] {
        let displayed = format!("{}", variant);
        assert_eq!(displayed, variant.as_str());
        assert!(!displayed.is_empty());
    }
}

/// The extractor must propagate the session id from the session on the
/// request. A `Default::default()` mutation would silently lose the
/// correlation between an event and the session that produced it.
#[tokio::test]
async fn audit_context_carries_session_id() {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("user-agent", "AuditUA/1".parse().unwrap());

    let session = crate::testing::test_session();
    let expected_sid = session.session_id().await.to_string();

    let mut p = parts(headers, Some("10.1.2.3"));
    // `AuthSession` extracts the `SessionHandle` the session layer put in
    // the extensions, so that is what a request has to carry.
    p.extensions.insert(session.0.clone());
    let ctx = AuditContext::from_request_parts(&mut p, &()).await.unwrap();
    assert_eq!(
        ctx.session_id.as_deref(),
        Some(expected_sid.as_str()),
        "the extractor must populate session_id from the session"
    );
    assert_eq!(
        ctx.ip_address.map(|ip| ip.to_string()).as_deref(),
        Some("10.1.2.3")
    );
    assert_eq!(ctx.user_agent.as_deref(), Some("AuditUA/1"));
}

#[tokio::test]
async fn audit_context_takes_the_resolved_ip_and_ignores_the_header() {
    // A client-supplied `X-Real-IP` must not reach the audit row. There
    // is no longer an argument through which it could: the extractor
    // reads the resolved value and never the header.
    let mut headers = HeaderMap::new();
    headers.insert("x-real-ip", "192.0.2.5".parse().unwrap());
    headers.insert("user-agent", "Mozilla/5.0 TestBrowser".parse().unwrap());

    let resolved: IpAddr = "203.0.113.42".parse().unwrap();
    let mut p = parts(headers, Some("203.0.113.42"));
    let ctx = AuditContext::from_request_parts(&mut p, &()).await.unwrap();

    assert_eq!(
        ctx.ip_address,
        Some(resolved),
        "the resolved address wins over the header"
    );
    assert_eq!(ctx.user_agent.as_deref(), Some("Mozilla/5.0 TestBrowser"));
}

#[tokio::test]
async fn audit_context_records_no_ip_rather_than_a_forged_one() {
    let mut headers = HeaderMap::new();
    headers.insert("x-real-ip", "192.0.2.5".parse().unwrap());

    // No client-IP layer, so nothing resolved an address.
    let mut p = parts(headers, None);
    let ctx = AuditContext::from_request_parts(&mut p, &()).await.unwrap();

    assert!(
        ctx.ip_address.is_none(),
        "an unresolved address must stay empty, not fall back to the header"
    );
}

#[test]
fn failure_reason_round_trips_through_its_wire_string() {
    // Every variant must survive as_str -> from_str, or a reason written
    // by one version reads back as something else in the next.
    let all = [
        AuthFailureReason::NotActive,
        AuthFailureReason::UnknownTenant,
        AuthFailureReason::InvalidTenantRow,
        AuthFailureReason::UnknownIdentifier,
        AuthFailureReason::CrossTenantImpersonation,
        AuthFailureReason::TokenRefresh,
        AuthFailureReason::TokenRefreshNoToken,
        AuthFailureReason::TokenRefreshUnknownProvider,
        AuthFailureReason::TokenRefreshProviderRejected,
        AuthFailureReason::CeremonyExpired,
        AuthFailureReason::CsrfMismatch,
        AuthFailureReason::MissingIssuer,
        AuthFailureReason::PkceVerifierInvalid,
        AuthFailureReason::TokenExchange,
        AuthFailureReason::ProviderMismatch,
        AuthFailureReason::Other("anything else".to_owned()),
    ];
    for reason in all {
        let wire = reason.as_str().to_owned();
        assert_eq!(
            AuthFailureReason::from(wire.as_str()),
            reason,
            "`{wire}` did not round-trip"
        );
    }
}

#[test]
fn failure_reason_tags_are_distinct() {
    // Two variants sharing a tag would silently merge on read-back.
    let tags = [
        AuthFailureReason::NotActive,
        AuthFailureReason::UnknownTenant,
        AuthFailureReason::InvalidTenantRow,
        AuthFailureReason::UnknownIdentifier,
        AuthFailureReason::CrossTenantImpersonation,
        AuthFailureReason::TokenRefresh,
        AuthFailureReason::TokenRefreshNoToken,
        AuthFailureReason::TokenRefreshUnknownProvider,
        AuthFailureReason::TokenRefreshProviderRejected,
        AuthFailureReason::CeremonyExpired,
        AuthFailureReason::CsrfMismatch,
        AuthFailureReason::MissingIssuer,
        AuthFailureReason::PkceVerifierInvalid,
        AuthFailureReason::TokenExchange,
        AuthFailureReason::ProviderMismatch,
    ]
    .map(|r| r.as_str().to_owned());
    let unique: std::collections::BTreeSet<_> = tags.iter().collect();
    assert_eq!(
        unique.len(),
        tags.len(),
        "duplicate wire tag among variants"
    );
}

#[test]
fn unknown_reason_becomes_other_rather_than_failing() {
    // An audit row must never be lost because this version does not know
    // the tag: a newer axess, or an adopter's own reason, still reads.
    let parsed = AuthFailureReason::from("some_reason_from_a_newer_version");
    assert_eq!(
        parsed,
        AuthFailureReason::Other("some_reason_from_a_newer_version".to_owned())
    );
    assert_eq!(parsed.as_str(), "some_reason_from_a_newer_version");
    assert!("anything".parse::<AuthFailureReason>().is_ok());
}

#[test]
fn failure_reason_serialises_as_a_plain_string() {
    // The JSON an adopter already stores must not change shape just
    // because the Rust type became an enum.
    let json = serde_json::to_string(&AuthFailureReason::UnknownTenant).unwrap();
    assert_eq!(json, r#""unknown_tenant""#);

    let back: AuthFailureReason = serde_json::from_str(r#""unknown_tenant""#).unwrap();
    assert_eq!(back, AuthFailureReason::UnknownTenant);

    // And a free-form one is still a bare string, not a tagged enum.
    let other = serde_json::to_string(&AuthFailureReason::Other("boom".into())).unwrap();
    assert_eq!(other, r#""boom""#);
}

/// The trace id is what joins an audit row to the trace that crosses
/// services, so it has to survive the context reaching the event.
#[tokio::test]
async fn trace_id_reaches_the_event_through_the_context() {
    let ctx = AuditContext {
        trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_owned()),
        ..Default::default()
    };
    let event = AuthEventBuilder::new(
        None,
        None,
        AuthEventType::LoginAttempt,
        AuthEventStatus::Failure,
    )
    .with_audit_context(&ctx)
    .build_at(chrono::Utc::now());
    assert_eq!(
        event.trace_id.as_deref(),
        Some("4bf92f3577b34da6a3ce929d0e0e4736")
    );
}

/// Without the `trace-id` feature there is nothing typed to read, and a
/// `traceparent` header is not a trace id until it is parsed. `None` is
/// the honest answer rather than a malformed value in a join column.
#[tokio::test]
async fn no_trace_context_means_no_trace_id() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "traceparent",
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
            .parse()
            .unwrap(),
    );
    let mut p = parts(headers, None);
    let ctx = AuditContext::from_request_parts(&mut p, &()).await.unwrap();
    assert!(ctx.trace_id.is_none());
}

/// `X-Request-Id` is an ordinary request header, so a caller can set it to
/// anything of any length, and this value lands in an audit row. Only the
/// value the layer validated and put in the extensions is read; honouring
/// an upstream id is what `accept-client-id` is for.
#[tokio::test]
async fn a_client_supplied_request_id_header_is_not_believed() {
    let mut headers = HeaderMap::new();
    headers.insert("x-request-id", "forged-by-the-caller".parse().unwrap());

    let mut p = parts(headers, None);
    let ctx = AuditContext::from_request_parts(&mut p, &()).await.unwrap();

    assert!(
        ctx.request_id.is_none(),
        "a header the caller writes must not reach the audit row"
    );
}
