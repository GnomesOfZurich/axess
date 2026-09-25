//! Error type for authentication service operations.

use crate::authn::types::EntityState;

/// Errors that can occur during authentication flows.
///
/// Parameterised over the backend error type `E` so that storage errors are
/// propagated with their original type rather than being erased.
///
/// # Suggested HTTP status code mapping
///
/// | Variant | HTTP Status | Rationale |
/// |---|---|---|
/// | `Store` | `500 Internal Server Error` | Backend / database failure; not the client's fault. |
/// | `NoFlow` | `409 Conflict` | No active authentication flow in the session; client must start one first. |
/// | `NotActive` | `403 Forbidden` | Account exists but is disabled, suspended, or otherwise ineligible. |
/// | `Locked` | `423 Locked` | Account locked due to too many failed attempts; retry after cooldown. |
/// | `InvalidAssertion` | `401 Unauthorized` | FIDO2 cryptographic validation failed; credential rejected. |
/// | `ExternalService` | `502 Bad Gateway` | Upstream provider (LDAP, OAuth IdP) returned an error or timed out. |
///
/// These are suggestions for handler authors. The library does not convert
/// errors to HTTP responses automatically; that mapping belongs in your
/// application's error-handling layer.
#[derive(Debug, thiserror::Error)]
pub enum AuthnError<E: std::error::Error + Send + Sync + 'static> {
    /// An error from the underlying identity or factor store.
    #[error("store error: {0}")]
    Store(#[source] E),

    /// No active authentication flow found in the session.
    ///
    /// Returned by `verify_factor` when the session is not in `Authenticating` state.
    #[error("no active authentication flow")]
    NoFlow,

    /// The account exists but is not in a state that permits login.
    #[error("account not active: {0:?}")]
    NotActive(EntityState),

    /// The account is locked (suspension or accumulated failed attempts).
    ///
    /// Returned by:
    /// - `prepare_factor` when [`account_status`](crate::authn::IdentityLookup::account_status)
    ///   reports `Suspended`.
    /// - FIDO2 `finish_discoverable_login` when the lockout threshold is
    ///   reached during a discoverable assertion's failure path.
    ///
    /// `until` is the suspension expiry when known (for `Suspended`
    /// accounts whose `StatusDetail.until` is set), `None` for
    /// indefinite locks or for the failed-attempt lockout (which has
    /// no inherent expiry: an admin must reset). Use
    /// [`lockout_expiry`](Self::lockout_expiry) for one-call access
    /// that also handles the legacy
    /// `NotActive(EntityState::Suspended(_))` case.
    ///
    /// Callers should display a generic "account locked" message
    /// (rendering `until` if present and non-trivial) rather than
    /// distinguishing failed-attempt vs admin-suspension reasons;
    /// that distinction is operator-visible via the audit log,
    /// never a property of the error response.
    #[error("account locked")]
    Locked {
        /// Wall-clock expiry of the lock, when known.
        until: Option<chrono::DateTime<chrono::Utc>>,
    },

    /// A FIDO2/WebAuthn assertion or registration failed validation.
    ///
    /// Distinct from [`NoFlow`](Self::NoFlow) (no ceremony in progress): this means a
    /// ceremony was in progress but the cryptographic validation failed.
    #[error("invalid FIDO2 assertion")]
    InvalidAssertion,

    /// An external service (LDAP, OAuth IdP, etc.) failed with a
    /// non-credential error (connection timeout, network issue, etc.).
    ///
    /// Callers should treat this as a transient failure and may retry or
    /// show a "service unavailable" message, not "invalid credentials".
    #[error("external service error: {0}")]
    ExternalService(String),

    /// A tenant-scoped operation was invoked against a target whose
    /// `tenant_id` does not match the caller-supplied expected tenant.
    ///
    /// Returned by the `_in_tenant` family of methods on `AuthnService`
    /// (e.g. `suspend_user_in_tenant`, `activate_user_in_tenant`,
    /// `begin_impersonation_in_tenant`) when the structural rail
    /// fires. Suggested HTTP status: `403 Forbidden` (the caller is
    /// authenticated but operating outside their authorised scope).
    ///
    /// Treat audit logging of this variant as security-relevant;
    /// it almost always indicates either a buggy admin UI or an
    /// attempted cross-tenant pivot.
    #[error("cross-tenant operation refused")]
    CrossTenant,
}

impl<E: std::error::Error + Send + Sync + 'static> AuthnError<E> {
    /// Return the lockout expiry timestamp when this error represents
    /// a locked account, regardless of whether the lock surfaces as
    /// [`AuthnError::Locked`] or as `AuthnError::NotActive(EntityState::Suspended(_))`.
    ///
    /// Returns `None` for indefinite locks, for failed-attempt
    /// lockouts (which have no inherent expiry), and for any
    /// non-lock error variant. Use this from UI code that wants to
    /// render "try again at X" without distinguishing the two error
    /// shapes: both a `prepare_factor` Suspended-account rejection
    /// and a FIDO2 discoverable-login lockout collapse to a single
    /// `Option<DateTime<Utc>>` lookup.
    ///
    /// Saves callers from deep-pattern-matching
    /// `EntityState::Suspended(StatusDetail { until, .. })` and
    /// handling the `AuthnError::Locked { until }` shape separately;
    /// both legs collapse to one call.
    pub fn lockout_expiry(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        match self {
            AuthnError::Locked { until } => *until,
            AuthnError::NotActive(EntityState::Suspended(detail)) => detail.until,
            _ => None,
        }
    }
}

/// Compute the `Retry-After` delta-seconds from a lockout expiry
/// timestamp relative to a reference time.
///
/// Returns `Some(secs)` ONLY when `until` is strictly in the future
/// (`until > now`); `Some(0)` is never emitted because the RFC 9110
/// `Retry-After: 0` reading is "retry immediately," which subverts the
/// lockout semantic. `until == now` and `until < now` both collapse to
/// `None`.
///
/// Extracted from [`AuthnError::into_response`] so the strict-greater
/// boundary is unit-testable without depending on wall-clock progress
/// between constructing the input and reading the response.
#[cfg(feature = "default-error-response")]
fn retry_secs_from(
    until: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<u64> {
    let secs = (until - now).num_seconds();
    if secs > 0 { Some(secs as u64) } else { None }
}

/// Default `IntoResponse` mapping for [`AuthnError`].
///
/// Gated behind the `default-error-response` feature because mapping a
/// library error to an HTTP response is policy that belongs to the
/// application: status code, body shape, locale, correlation IDs, and
/// problem+json formatting are all things callers may want to override.
/// The doc table on [`AuthnError`] documents the recommended mapping for
/// applications that ship their own impl.
///
/// Enable with `axess-core = { features = ["default-error-response"] }`
/// to get the conservative default below.
#[cfg(feature = "default-error-response")]
impl<E: std::error::Error + Send + Sync + 'static> AuthnError<E> {
    /// `IntoResponse`-shaped conversion taking the reference time
    /// explicitly. Test code with [`MockClock`](crate::testing::MockClock)
    /// uses this to pin the `Retry-After` header against a controllable
    /// clock; the trait impl below delegates here with `Utc::now()`
    /// for production callers, which produces wall-clock behaviour
    /// that's correct but non-deterministic across runs.
    ///
    /// Adopters who don't enable the `default-error-response` feature
    /// can still construct their own `IntoResponse` impl on top of
    /// this helper without forking the body/status logic.
    pub fn into_response_at(self, now: chrono::DateTime<chrono::Utc>) -> axum::response::Response {
        use axum::http::{HeaderValue, StatusCode, header};
        use axum::response::IntoResponse as _;

        // Surface lockout expiry to the client. Computed BEFORE
        // the move-into-match so the `lockout_expiry()` accessor (which
        // already handles both `Locked { until }` and the legacy
        // `NotActive(Suspended(_))` shape) can read `&self`.
        let until = self.lockout_expiry();

        let (status, message) = match &self {
            AuthnError::Store(_) => {
                tracing::error!(error = %self, "authentication store error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            AuthnError::NoFlow => (StatusCode::CONFLICT, "no active authentication flow"),
            AuthnError::NotActive(_) => (StatusCode::FORBIDDEN, "account not active"),
            AuthnError::Locked { .. } => (StatusCode::LOCKED, "account locked"),
            AuthnError::InvalidAssertion => (StatusCode::UNAUTHORIZED, "invalid assertion"),
            AuthnError::ExternalService(_) => {
                tracing::error!(error = %self, "external service error");
                (StatusCode::BAD_GATEWAY, "external service unavailable")
            }
            AuthnError::CrossTenant => (StatusCode::FORBIDDEN, "cross-tenant operation refused"),
        };

        // Include `until_iso` in the body so JSON-only clients
        // (mobile apps, SPAs) can render expiry without parsing
        // `Retry-After`. Conservative: emit only when known + in the
        // future. Past or `None` collapses to a plain `{"error": …}`
        // body for backwards compat with existing clients.
        let until_secs = until.and_then(|t| retry_secs_from(t, now));
        let body = match (until, until_secs) {
            (Some(t), Some(_)) => {
                serde_json::json!({ "error": message, "until_iso": t.to_rfc3339() })
            }
            _ => serde_json::json!({ "error": message }),
        };

        let mut response = (status, axum::Json(body)).into_response();

        // Emit RFC 9110 §10.2.3 `Retry-After` header (delta-seconds)
        // for any lockout-shaped error whose expiry is in the future.
        // Browsers and well-behaved HTTP clients honour this for
        // automatic backoff; rendering "locked until X" UI is a
        // body-side concern. Pulls `until` from both `Locked { until }`
        // and the deep-nested `NotActive(Suspended(StatusDetail{until,..}))`.
        if let Some(secs) = until_secs {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(secs));
        }

        response
    }
}

#[cfg(feature = "default-error-response")]
impl<E: std::error::Error + Send + Sync + 'static> axum::response::IntoResponse for AuthnError<E> {
    /// Delegates to [`AuthnError::into_response_at`] with `chrono::Utc::now()`
    /// as the reference time. Production-correct but non-deterministic;
    /// tests asserting on `Retry-After` should call `into_response_at`
    /// directly with a `MockClock`-derived timestamp.
    fn into_response(self) -> axum::response::Response {
        self.into_response_at(chrono::Utc::now())
    }
}

#[cfg(all(test, feature = "default-error-response"))]
mod into_response_tests {
    use super::*;
    use axum::response::IntoResponse;

    /// Concrete error type so the generic impl is monomorphised.
    #[derive(Debug, thiserror::Error)]
    #[error("test")]
    struct TestStoreError;

    /// Every variant maps to its documented HTTP status and a
    /// JSON `{"error": "..."}` body. Pins the whole `into_response`
    /// against the `Default::default()` body-replacement mutation,
    /// which would emit an empty 200 OK and silently break the
    /// recommended mapping for every variant.
    #[tokio::test]
    async fn into_response_emits_documented_status_per_variant() {
        let cases: Vec<(AuthnError<TestStoreError>, axum::http::StatusCode)> = vec![
            (
                AuthnError::Store(TestStoreError),
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (AuthnError::NoFlow, axum::http::StatusCode::CONFLICT),
            (
                AuthnError::NotActive(EntityState::Active),
                axum::http::StatusCode::FORBIDDEN,
            ),
            (
                AuthnError::Locked { until: None },
                axum::http::StatusCode::LOCKED,
            ),
            (
                AuthnError::InvalidAssertion,
                axum::http::StatusCode::UNAUTHORIZED,
            ),
            (
                AuthnError::ExternalService("upstream timeout".into()),
                axum::http::StatusCode::BAD_GATEWAY,
            ),
            (AuthnError::CrossTenant, axum::http::StatusCode::FORBIDDEN),
        ];

        for (err, expected_status) in cases {
            let label = format!("{err:?}");
            let response = err.into_response();
            assert_eq!(
                response.status(),
                expected_status,
                "{label} must map to {expected_status:?}"
            );
            // Body must be a non-empty JSON object; distinguishes the
            // real impl from a `Default::default()` empty 200.
            let body = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .expect("collect body");
            assert!(!body.is_empty(), "{label} response body must be non-empty");
            let parsed: serde_json::Value =
                serde_json::from_slice(&body).expect("body must be JSON");
            assert!(
                parsed.get("error").and_then(|v| v.as_str()).is_some(),
                "{label} body must contain a string `error` field, got {parsed}"
            );
        }
    }

    /// `Locked { until: Some(future) }` emits a `Retry-After` header
    /// carrying delta-seconds AND surfaces `until_iso` in the JSON
    /// body so clients have a standard way to learn the lockout window.
    #[tokio::test]
    async fn locked_with_future_until_emits_retry_after_and_until_iso() {
        use axum::http::header;

        let until = chrono::Utc::now() + chrono::Duration::seconds(900);
        let err: AuthnError<TestStoreError> = AuthnError::Locked { until: Some(until) };
        let response = err.into_response();

        assert_eq!(response.status(), axum::http::StatusCode::LOCKED);

        let retry_after = response
            .headers()
            .get(header::RETRY_AFTER)
            .expect("Retry-After header must be present when until is in the future")
            .to_str()
            .unwrap()
            .parse::<u64>()
            .expect("Retry-After must be a numeric delta-seconds value");
        assert!(
            retry_after > 0 && retry_after <= 900,
            "Retry-After should be in (0, 900] seconds, got {retry_after}"
        );

        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .expect("collect body");
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["error"], "account locked");
        let until_iso = parsed["until_iso"]
            .as_str()
            .expect("until_iso must be present in the body");
        assert!(
            until_iso.contains('T'),
            "until_iso must be RFC 3339 (got {until_iso:?})"
        );
    }

    /// `Locked { until: None }` is the indefinite-lock /
    /// failed-attempt-counter case. No `Retry-After` (the client has
    /// nothing to wait *for*; an admin reset is required) and no
    /// `until_iso` in the body: back-compat with the previous body
    /// shape for clients that didn't inspect the new field.
    #[tokio::test]
    async fn locked_with_no_until_omits_retry_after_and_until_iso() {
        use axum::http::header;

        let err: AuthnError<TestStoreError> = AuthnError::Locked { until: None };
        let response = err.into_response();

        assert_eq!(response.status(), axum::http::StatusCode::LOCKED);
        assert!(
            response.headers().get(header::RETRY_AFTER).is_none(),
            "Retry-After must be absent when until is None"
        );

        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .expect("collect body");
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(parsed.get("until_iso").is_none());
    }

    /// `NotActive(Suspended(_))` carries `until` deep-nested in
    /// `StatusDetail`. The `lockout_expiry()` accessor reaches
    /// it; the IntoResponse impl must too, so a Suspended user gets
    /// the same Retry-After signal as a `Locked { until }` user.
    #[tokio::test]
    async fn not_active_suspended_with_future_until_emits_retry_after() {
        use crate::authn::types::StatusDetail;
        use axum::http::header;

        let until = chrono::Utc::now() + chrono::Duration::seconds(60);
        let detail = StatusDetail {
            reason: "test suspend".into(),
            since: chrono::Utc::now(),
            until: Some(until),
        };
        let err: AuthnError<TestStoreError> = AuthnError::NotActive(EntityState::Suspended(detail));
        let response = err.into_response();

        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
        assert!(
            response.headers().get(header::RETRY_AFTER).is_some(),
            "Suspended-with-until must also emit Retry-After (parity with Locked)"
        );
    }

    /// A Suspended `until` already in the past collapses to no
    /// `Retry-After` and no `until_iso`: there's nothing to wait for.
    /// Avoids emitting `Retry-After: 0` which clients interpret as
    /// "retry immediately."
    #[tokio::test]
    async fn locked_with_past_until_omits_retry_after() {
        use axum::http::header;

        let past = chrono::Utc::now() - chrono::Duration::seconds(60);
        let err: AuthnError<TestStoreError> = AuthnError::Locked { until: Some(past) };
        let response = err.into_response();

        assert!(
            response.headers().get(header::RETRY_AFTER).is_none(),
            "a `until` in the past must not emit Retry-After"
        );
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .expect("collect body");
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            parsed.get("until_iso").is_none(),
            "a `until` in the past must not emit until_iso"
        );
    }

    /// Pin the strict-greater boundary `secs > 0` inside `retry_secs_from`.
    /// Discriminates `> 0` against `>= 0`, `> 1`, `delete >`:
    /// - `until == now` (delta = 0): original returns None; `>= 0` would
    ///   return `Some(0)`, which clients read as "retry immediately"
    ///   and breaks the lockout semantic.
    /// - `until = now + 1s`: original returns `Some(1)`; pins `> 1`
    ///   which would collapse 1-second locks to None.
    /// - `until = now - 1s`: original returns None; pins the past path
    ///   for completeness.
    #[test]
    fn retry_secs_from_pins_strict_greater_boundary() {
        let now = chrono::Utc::now();

        // until == now: delta = 0. Must return None; kills `>= 0` mutation
        // (which would emit `Some(0)` and produce a `Retry-After: 0`
        // header that clients interpret as immediate retry).
        assert_eq!(
            retry_secs_from(now, now),
            None,
            "until == now must return None (kills `> → >=` boundary mutation)"
        );

        // until = now + 1s: delta = 1. Must return Some(1).
        assert_eq!(
            retry_secs_from(now + chrono::Duration::seconds(1), now),
            Some(1)
        );

        // until = now + 60s: delta = 60. Must return Some(60).
        assert_eq!(
            retry_secs_from(now + chrono::Duration::seconds(60), now),
            Some(60)
        );

        // until = now - 1s: delta = -1. Must return None.
        assert_eq!(
            retry_secs_from(now - chrono::Duration::seconds(1), now),
            None
        );
    }

    /// `into_response_at` lets test code pin the `Retry-After` header
    /// deterministically by supplying its own reference time, instead
    /// of being subject to the wall clock `into_response` uses by
    /// default.
    #[tokio::test]
    async fn into_response_at_uses_caller_supplied_reference_time() {
        use axum::http::header;

        // Anchor "now" in the past so the lockout window we compute is
        // independent of test-execution wall clock. With `now = 2026-01-01T00:00:00Z`
        // and `until = now + 300s`, the Retry-After must be exactly 300
        // regardless of when the test runs.
        let now = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let until = now + chrono::Duration::seconds(300);

        let err: AuthnError<TestStoreError> = AuthnError::Locked { until: Some(until) };
        let response = err.into_response_at(now);

        let retry_after = response
            .headers()
            .get(header::RETRY_AFTER)
            .expect("Retry-After present")
            .to_str()
            .unwrap()
            .parse::<u64>()
            .expect("delta-seconds value");
        assert_eq!(
            retry_after, 300,
            "Retry-After must equal until-now exactly when caller pins the reference time"
        );
    }

    /// `lockout_expiry` returns the inner `Option<DateTime<Utc>>`
    /// from `Locked { until }` and from
    /// `NotActive(EntityState::Suspended(StatusDetail { until, .. }))`,
    /// and `None` for any other variant. Pins the body against the
    /// `-> None` body-replacement mutation, which would lose the
    /// `Locked`/`Suspended` payloads and collapse every lockout to
    /// "no expiry".
    #[test]
    fn lockout_expiry_extracts_from_locked_and_suspended_variants() {
        use crate::authn::types::{EntityState, StatusDetail};

        let t = chrono::DateTime::parse_from_rfc3339("2026-06-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        // Locked { until: Some(t) } → Some(t)
        let locked: AuthnError<TestStoreError> = AuthnError::Locked { until: Some(t) };
        assert_eq!(
            locked.lockout_expiry(),
            Some(t),
            "Locked must surface its `until` (kills `-> None`)"
        );

        // Locked { until: None } → None (indefinite lock, not the same
        // as a missing variant).
        let locked_indefinite: AuthnError<TestStoreError> = AuthnError::Locked { until: None };
        assert_eq!(locked_indefinite.lockout_expiry(), None);

        // NotActive(Suspended(StatusDetail { until: Some(t), .. })) → Some(t)
        let suspended: AuthnError<TestStoreError> =
            AuthnError::NotActive(EntityState::Suspended(StatusDetail {
                reason: std::sync::Arc::from("test-suspended"),
                since: t - chrono::Duration::seconds(60),
                until: Some(t),
            }));
        assert_eq!(
            suspended.lockout_expiry(),
            Some(t),
            "Suspended StatusDetail.until must surface (kills `-> None`)"
        );

        // Other variants → None
        let cross: AuthnError<TestStoreError> = AuthnError::CrossTenant;
        assert_eq!(cross.lockout_expiry(), None);
    }

    /// The trait impl delegates to `into_response_at` with `Utc::now()`,
    /// so wall-clock callers still get correct behaviour. Pinning a
    /// 60-minute lockout window means the header must land somewhere
    /// in (0, 3600] regardless of execution timing; the boundary
    /// protects against the trait impl accidentally ignoring `until`
    /// or emitting a negative/zero value.
    #[tokio::test]
    async fn into_response_trait_impl_still_emits_retry_after() {
        use axum::http::header;

        let until = chrono::Utc::now() + chrono::Duration::seconds(3600);
        let err: AuthnError<TestStoreError> = AuthnError::Locked { until: Some(until) };
        let response = err.into_response();

        let retry_after = response
            .headers()
            .get(header::RETRY_AFTER)
            .expect("Retry-After present via trait impl")
            .to_str()
            .unwrap()
            .parse::<u64>()
            .expect("delta-seconds value");
        assert!(
            (1..=3600).contains(&retry_after),
            "Retry-After via trait impl must land in (0, 3600], got {retry_after}"
        );
    }
}
