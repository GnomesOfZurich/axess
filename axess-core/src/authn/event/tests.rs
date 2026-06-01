//! Unit tests for [`super::AuditContext`], [`super::AuthEventType`],
//! [`super::AuthEventStatus`], [`super::AuthEvent`], and
//! [`super::AuthEventBuilder`].
//!
//! Pulled sideways from the previous in-file `#[cfg(test)] mod` block
//! so the production-vs-tests ratio in `event.rs` becomes scannable.

#![cfg(test)]

use super::*;
use axum::http::HeaderMap;
use std::net::IpAddr;

#[test]
fn audit_context_from_headers_with_all_fields() {
    let mut headers = HeaderMap::new();
    headers.insert("x-real-ip", "203.0.113.42".parse().unwrap());
    headers.insert("user-agent", "Mozilla/5.0 TestBrowser".parse().unwrap());
    headers.insert("x-request-id", "req-abc-123".parse().unwrap());

    let ctx = extract_audit_context(&headers, None);

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
        "sync extractor cannot read session ID"
    );
}

#[test]
fn audit_context_missing_headers_produce_none() {
    let headers = HeaderMap::new();
    let ctx = extract_audit_context(&headers, None);

    assert!(ctx.ip_address.is_none());
    assert!(ctx.user_agent.is_none());
    assert!(ctx.request_id.is_none());
    assert!(ctx.geo_country.is_none());
    assert!(ctx.session_id.is_none());
}

#[test]
fn ip_from_x_forwarded_for_takes_first() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-forwarded-for",
        "198.51.100.1, 203.0.113.50".parse().unwrap(),
    );

    let ip = ip_from_headers(&headers);
    assert_eq!(ip, Some("198.51.100.1".parse::<IpAddr>().unwrap()));
}

#[test]
fn ip_from_x_real_ip_preferred_over_forwarded() {
    let mut headers = HeaderMap::new();
    headers.insert("x-real-ip", "10.0.0.1".parse().unwrap());
    headers.insert("x-forwarded-for", "192.168.1.1".parse().unwrap());

    let ip = ip_from_headers(&headers);
    assert_eq!(ip, Some("10.0.0.1".parse::<IpAddr>().unwrap()));
}

#[test]
fn event_carries_ip_and_user_agent_from_audit_context() {
    let ctx = AuditContext {
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

    assert_eq!(event.ip_address.as_deref(), Some("203.0.113.42"));
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

/// `extract_audit_context_async` must propagate the
/// session ID from a real `AuthSession`. A `Default::default()`
/// mutation would silently lose the session correlation.
#[tokio::test]
async fn extract_audit_context_async_carries_session_id() {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("x-real-ip", "10.1.2.3".parse().unwrap());
    headers.insert("user-agent", "AuditUA/1".parse().unwrap());

    let session = crate::testing::test_session();
    let expected_sid = session.session_id().await.to_string();

    let ctx = extract_audit_context_async(&headers, Some(&session)).await;
    assert_eq!(
        ctx.session_id.as_deref(),
        Some(expected_sid.as_str()),
        "async extractor must populate session_id from the session"
    );
    assert_eq!(
        ctx.ip_address.map(|ip| ip.to_string()).as_deref(),
        Some("10.1.2.3")
    );
    assert_eq!(ctx.user_agent.as_deref(), Some("AuditUA/1"));
}
