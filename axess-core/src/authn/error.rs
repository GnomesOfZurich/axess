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
/// | `Impersonated` | `403 Forbidden` | An impersonated session asked for a credential change (or another impersonation) the deployment does not allow. |
/// | `NotActive` | `403 Forbidden` | Account exists and its `EntityState` does not admit a login: pending, terminated, archived, or a `Suspended` reached on a path that does not answer `Locked`. An administrative suspension ends only when an operator ends it. |
/// | `Locked` | `423 Locked` | The failure counter's lockout (ends by itself after the policy's `duration`, or when an operator resets the counter), or a `Suspended` account on the login path. One status for both: a client retries after `Retry-After`; it learns nothing about which it was. |
/// | `Throttled` | `429 Too Many Requests` | Consecutive wrong guesses under this key have earned a delay that has not run; `Retry-After` carries it. |
/// | `InvalidAssertion` | `401 Unauthorized` | FIDO2 cryptographic validation failed; credential rejected. |
/// | `ExternalService` | `502 Bad Gateway` | Upstream provider (LDAP, OAuth IdP) returned an error or timed out. |
/// | `Internal` | `500 Internal Server Error` | The library failed in a way that is not the client's fault and not a store error (a hashing task panicked or the blocking pool shut down). |
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

    /// The session is an impersonation, and the deployment does not let an
    /// impersonated session do this: issue a refresh token, enrol or delete
    /// a factor, or impersonate again (see
    /// [`with_impersonated_credential_changes_allowed`](crate::authn::service::AuthnServiceBuilder::with_impersonated_credential_changes_allowed)).
    /// Suggested HTTP status `403 Forbidden`. The refusal is audited with
    /// [`AuthFailureReason::Impersonated`](crate::authn::event::AuthFailureReason::Impersonated)
    /// and the administrator as actor.
    #[error("refused for an impersonated session")]
    Impersonated,

    /// The account exists and its [`EntityState`] does not admit a login.
    ///
    /// Carries the state the store answered: `Pending`, `Terminated`,
    /// `Archived`, `Candidate`, or a `Suspended` on a path that does not
    /// answer [`Locked`](Self::Locked). A
    /// `Suspended` whose detail's cause is
    /// [`Administrative`](crate::authn::types::StatusCause::Administrative)
    /// is an operator's act and ends only when an operator ends it (or at
    /// the `until` the operator set); the detail's
    /// [`cause`](crate::authn::types::StatusDetail::cause) says which, and
    /// [`EntityState::is_administratively_disabled`] reads it.
    #[error("account not active: {0:?}")]
    NotActive(EntityState),

    /// The login was refused because the account is locked.
    ///
    /// Two sources answer this one variant, and the variant is an
    /// error-level union of them, not a statement about [`EntityState`]:
    ///
    /// - The failure counter. The library derives its lockout from
    ///   `failed_attempts` under the tenant's `LockoutPolicy` at every gate
    ///   before a verifier runs; it is never an `EntityState`. It ends by
    ///   itself after the policy's `duration`, or when an operator resets
    ///   the counter (a password reset does too) when `duration` is `None`.
    ///   `until` is the lockout's end when the policy has one.
    /// - A `Suspended` account on the login path (`prepare_factor`,
    ///   `verify_factor`, the passkey and OAuth completions), whatever the
    ///   detail's cause. An administrative suspension comes from an operator
    ///   and ends only by an operator; `until` is the detail's `until`.
    ///
    /// Returned by `prepare_factor` when
    /// [`account_status`](crate::authn::IdentityLookup::account_status)
    /// reports `Suspended` or the counter is at the limit, and by the FIDO2
    /// `finish_discoverable_login` when the lockout threshold is reached on
    /// a discoverable assertion's failure path.
    /// [`lockout_expiry`](Self::lockout_expiry) reads `until` from this
    /// variant and from `NotActive(Suspended(_))` in one call.
    ///
    /// A login screen shows one "account locked" message (with `until` when
    /// present) and does not say which source it was; that distinction is
    /// for the operator in the audit log. A decision that must tell them
    /// apart (a self-service recovery admits a locked-out account and never
    /// a disabled one) does not read this error: it reads the account's
    /// `EntityState` and asks [`EntityState::can_self_recover`].
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

    /// The tenant an operation names does not load: it is not stored, or a
    /// store that holds users does not hold their tenant. Refused (fail
    /// closed) where the operation needs the tenant's status; no tenant
    /// state can be named, and nothing crossed a tenant boundary. Suggested
    /// HTTP status: `403 Forbidden`.
    #[error("tenant not found")]
    UnknownTenant,

    /// The password-hashing executor is saturated: its waiting queue is at
    /// its limit or the job waited past the acquire timeout. A capacity
    /// condition, not a fault: nothing was checked, the client may try
    /// again. Suggested HTTP status `503 Service Unavailable` with a
    /// `Retry-After` of `retry_after`;
    /// [`into_response_at`](Self::into_response_at) sends both. See
    /// [`KdfExecutor::with_max_queue`](crate::blocking::KdfExecutor::with_max_queue).
    #[error("authentication service busy")]
    Busy {
        /// How long the client should wait before retrying.
        retry_after: std::time::Duration,
    },

    /// Consecutive wrong guesses under this key (the account and the client
    /// address, by the tenant's
    /// [`LockoutPolicy::throttle`](crate::authn::types::LockoutPolicy::throttle))
    /// have earned a delay that has not run. Returned by `prepare_factor`;
    /// `verify_factor` answers the same refusal as
    /// [`FactorOutcome::Throttled`](crate::authn::service::FactorOutcome::Throttled).
    /// No credential was checked and nothing was counted. Suggested HTTP
    /// status `429 Too Many Requests` with `Retry-After` of `retry_after`;
    /// [`into_response_at`](Self::into_response_at) sends both.
    #[error("too many attempts")]
    Throttled {
        /// How long until a guess under this key runs again.
        retry_after: std::time::Duration,
    },

    /// The library itself failed: a blocking task (password hashing) panicked
    /// or the blocking pool was shut down. Not the client's fault and not a
    /// store error; suggested HTTP status `500`. The message is for logs and
    /// is never put in a response body.
    #[error("internal error: {0}")]
    Internal(String),
}

/// The `Retry-After` a saturated hashing executor answers with: one second,
/// the order of a short burst of logins draining through the pool. The
/// executor knows no better figure, and a `503` without one invites an
/// immediate retry.
pub(crate) const KDF_BUSY_RETRY_AFTER: std::time::Duration = std::time::Duration::from_secs(1);

impl<E: std::error::Error + Send + Sync + 'static> From<crate::blocking::KdfError>
    for AuthnError<E>
{
    /// [`Busy`](crate::blocking::KdfError::Busy) is [`AuthnError::Busy`] with
    /// a `retry_after` of one second; a panicked or shut-down executor is
    /// [`AuthnError::Internal`].
    fn from(e: crate::blocking::KdfError) -> Self {
        match e {
            crate::blocking::KdfError::Busy => AuthnError::Busy {
                retry_after: KDF_BUSY_RETRY_AFTER,
            },
            crate::blocking::KdfError::Join(_) | crate::blocking::KdfError::Closed => {
                AuthnError::Internal(e.to_string())
            }
        }
    }
}

impl<E: std::error::Error + Send + Sync + 'static> AuthnError<E> {
    /// Return the lockout expiry timestamp when this error represents
    /// a locked account, regardless of whether the lock surfaces as
    /// [`AuthnError::Locked`] or as `AuthnError::NotActive(EntityState::Suspended(_))`.
    ///
    /// Returns `None` for an indefinite suspension, for a failed-attempt
    /// lockout whose policy has no `duration`, and for any non-lock error
    /// variant. Use this from UI code that wants to render "try again at X"
    /// without distinguishing the two error shapes: both a `prepare_factor`
    /// Suspended-account rejection and a FIDO2 discoverable-login lockout
    /// collapse to a single `Option<DateTime<Utc>>` lookup.
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
    // Round up: a lock with 400 ms left is a second away, not "retry now".
    let millis = (until - now).num_milliseconds();
    if millis > 0 {
        Some(((millis + 999) / 1000) as u64)
    } else {
        None
    }
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
    /// clock. The `IntoResponse` impl below delegates here with `Utc::now()`
    /// because that trait method cannot take a clock (a declared exception
    /// to the injected-clock rule); handlers that hold a clock call this
    /// method directly.
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
            AuthnError::Impersonated => {
                (StatusCode::FORBIDDEN, "refused for an impersonated session")
            }
            AuthnError::NotActive(_) => (StatusCode::FORBIDDEN, "account not active"),
            AuthnError::Locked { .. } => (StatusCode::LOCKED, "account locked"),
            AuthnError::InvalidAssertion => (StatusCode::UNAUTHORIZED, "invalid assertion"),
            AuthnError::ExternalService(_) => {
                tracing::error!(error = %self, "external service error");
                (StatusCode::BAD_GATEWAY, "external service unavailable")
            }
            AuthnError::CrossTenant => (StatusCode::FORBIDDEN, "cross-tenant operation refused"),
            AuthnError::UnknownTenant => (StatusCode::FORBIDDEN, "tenant not found"),
            AuthnError::Busy { .. } => {
                tracing::warn!("authentication service busy; answering 503");
                (StatusCode::SERVICE_UNAVAILABLE, "service busy, retry later")
            }
            AuthnError::Throttled { .. } => (
                StatusCode::TOO_MANY_REQUESTS,
                "too many attempts, retry later",
            ),
            AuthnError::Internal(_) => {
                tracing::error!(error = %self, "internal authentication error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };

        // Include `until_iso` in the body so JSON-only clients
        // (mobile apps, SPAs) can render expiry without parsing
        // `Retry-After`. Conservative: emit only when known + in the
        // future. Past or `None` collapses to a plain `{"error": …}`
        // body for backwards compat with existing clients.
        // A busy executor's or a throttle's delay is a duration, not an
        // instant; it joins the lockout expiry as the one `Retry-After` the
        // response carries, rounded up so a fraction of a second is never
        // "retry now".
        let busy_secs = match &self {
            AuthnError::Busy { retry_after } | AuthnError::Throttled { retry_after } => Some(
                u64::try_from(retry_after.as_millis().div_ceil(1000).max(1)).unwrap_or(u64::MAX),
            ),
            _ => None,
        };
        let until_secs = until.and_then(|t| retry_secs_from(t, now)).or(busy_secs);
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
    /// as the reference time.
    ///
    /// This is a declared exception to the injected-clock rule: axum's
    /// `IntoResponse::into_response` takes no arguments, so the trait method
    /// cannot be handed a clock. Code that has one (a handler holding the
    /// service's clock, and every test) calls
    /// `into_response_at(clock.now())` instead and the exception never
    /// applies.
    fn into_response(self) -> axum::response::Response {
        self.into_response_at(chrono::Utc::now())
    }
}

#[cfg(all(test, feature = "default-error-response"))]
mod into_response_tests {
    use super::*;
    use axum::response::IntoResponse;

    /// The reference time the tests pass to `into_response_at`.
    fn fixed_now() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

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
            (AuthnError::Impersonated, axum::http::StatusCode::FORBIDDEN),
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
            (AuthnError::UnknownTenant, axum::http::StatusCode::FORBIDDEN),
            (
                AuthnError::Busy {
                    retry_after: std::time::Duration::from_secs(1),
                },
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                AuthnError::Throttled {
                    retry_after: std::time::Duration::from_secs(2),
                },
                axum::http::StatusCode::TOO_MANY_REQUESTS,
            ),
            (
                AuthnError::Internal("hash task panicked".into()),
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ];

        for (err, expected_status) in cases {
            let label = format!("{err:?}");
            let response = err.into_response_at(fixed_now());
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

    /// `Throttled { retry_after }` answers 429 with the delay as
    /// `Retry-After`, rounded up so a fraction of a second is never
    /// `Retry-After: 0`, and no `until_iso`: the delay is a duration, not an
    /// instant.
    #[tokio::test]
    async fn throttled_emits_429_with_the_delay_rounded_up_as_retry_after() {
        use axum::http::header;
        for (delay_ms, expected) in [(2_000u64, "2"), (1_400, "2"), (300, "1")] {
            let err: AuthnError<TestStoreError> = AuthnError::Throttled {
                retry_after: std::time::Duration::from_millis(delay_ms),
            };
            let response = err.into_response_at(fixed_now());
            assert_eq!(response.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(
                response
                    .headers()
                    .get(header::RETRY_AFTER)
                    .expect("Retry-After present")
                    .to_str()
                    .unwrap(),
                expected,
                "a delay of {delay_ms} ms"
            );
            let body = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["error"], "too many attempts, retry later");
            assert!(json.get("until_iso").is_none());
        }
    }

    /// `Locked { until: Some(future) }` emits a `Retry-After` header
    /// carrying delta-seconds AND surfaces `until_iso` in the JSON
    /// body so clients have a standard way to learn the lockout window.
    #[tokio::test]
    async fn locked_with_future_until_emits_retry_after_and_until_iso() {
        use axum::http::header;

        let until = fixed_now() + chrono::Duration::seconds(900);
        let err: AuthnError<TestStoreError> = AuthnError::Locked { until: Some(until) };
        let response = err.into_response_at(fixed_now());

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
        let response = err.into_response_at(fixed_now());

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

        let until = fixed_now() + chrono::Duration::seconds(60);
        let detail =
            StatusDetail::administrative("test suspend", fixed_now()).with_until(Some(until));
        let err: AuthnError<TestStoreError> = AuthnError::NotActive(EntityState::Suspended(detail));
        let response = err.into_response_at(fixed_now());

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

        let past = fixed_now() - chrono::Duration::seconds(60);
        let err: AuthnError<TestStoreError> = AuthnError::Locked { until: Some(past) };
        let response = err.into_response_at(fixed_now());

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

    /// A lock with a fractional second left reports the next whole second.
    #[test]
    fn retry_secs_from_rounds_a_partial_second_up() {
        let now = fixed_now();
        assert_eq!(
            retry_secs_from(now + chrono::Duration::milliseconds(500), now),
            Some(1),
            "a half-second lock must not read as retry-now"
        );
        assert_eq!(
            retry_secs_from(now + chrono::Duration::milliseconds(1500), now),
            Some(2)
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
        let now = fixed_now();

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
        let suspended: AuthnError<TestStoreError> = AuthnError::NotActive(EntityState::Suspended(
            StatusDetail::administrative(
                std::sync::Arc::from("test-suspended"),
                t - chrono::Duration::seconds(60),
            )
            .with_until(Some(t)),
        ));
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

#[cfg(test)]
mod kdf_error_mapping_tests {
    //! A saturated hashing executor is a capacity condition, not a library
    //! fault: the caller must see a retryable answer, where a panicked or
    //! shut-down executor is an internal error.

    use super::*;
    use crate::blocking::KdfError;

    #[derive(Debug, thiserror::Error)]
    #[error("test")]
    struct TestStoreError;

    #[test]
    fn a_busy_executor_is_not_an_internal_error() {
        let mapped: AuthnError<TestStoreError> = KdfError::Busy.into();
        assert!(
            !matches!(mapped, AuthnError::Internal(_)),
            "Busy must be answered as retryable, not as a 500: {mapped:?}"
        );
    }

    #[cfg(feature = "default-error-response")]
    #[tokio::test]
    async fn busy_answers_503_with_retry_after() {
        use axum::http::header;
        let err: AuthnError<TestStoreError> = AuthnError::Busy {
            retry_after: std::time::Duration::from_secs(3),
        };
        let response = err.into_response_at(chrono::Utc::now());
        assert_eq!(
            response.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            response
                .headers()
                .get(header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
            Some("3")
        );
        // Under a second still says one, never zero.
        let short: AuthnError<TestStoreError> = AuthnError::Busy {
            retry_after: std::time::Duration::from_millis(200),
        };
        let response = short.into_response_at(chrono::Utc::now());
        assert_eq!(
            response
                .headers()
                .get(header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
            Some("1")
        );
    }

    #[test]
    fn a_failed_or_closed_executor_stays_internal() {
        let joined: AuthnError<TestStoreError> = KdfError::Join("panicked".into()).into();
        let closed: AuthnError<TestStoreError> = KdfError::Closed.into();
        assert!(matches!(joined, AuthnError::Internal(_)));
        assert!(matches!(closed, AuthnError::Internal(_)));
    }
}
