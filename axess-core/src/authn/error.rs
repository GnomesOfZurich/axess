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
/// | `Locked` | `423 Locked` | The failure counter's lockout (ends by itself after the policy's `duration`, or when an operator resets the counter), or a `Suspended` account on the login path. One status for both: a client retries after `Retry-After`, which a lock that never ends does not carry; it learns nothing about which it was. |
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
    ///   `verify_factor`, the passkey ceremonies and the OAuth completion),
    ///   whatever the detail's cause. `until` is the detail's `until` only
    ///   when the cause is `StatusCause::Lockout`; an administrative hold, a
    ///   pending verification or a closure answers `until: None`, as an
    ///   indefinite lockout does, so the answer does not say that an
    ///   operator holds the account or until when.
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
        /// When the lock ends, when known: at a reading of the clock, or
        /// never ([`Until::Forever`](axess_clock::Until::Forever)) for a
        /// lockout duration that runs past the range of a reading.
        until: Option<axess_clock::Until>,
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
    /// a locked account, whether the lock surfaces as
    /// [`AuthnError::Locked`] or as `AuthnError::NotActive(EntityState::Suspended(_))`
    /// with [`StatusCause::Lockout`](crate::authn::types::StatusCause::Lockout).
    ///
    /// Returns `None` for an indefinite lockout, for a failed-attempt
    /// lockout whose policy has no `duration`, for a suspension of any other
    /// cause (an administrative hold, a pending verification, a closure),
    /// whatever end the store keeps for it, and for any non-lock error
    /// variant. The end of an operator's hold is not the caller's to learn,
    /// and the default response would send it as `Retry-After`.
    ///
    /// Use this from UI code that wants to render "try again at X"
    /// without distinguishing the two error shapes: both a `prepare_factor`
    /// lockout and a FIDO2 discoverable-login lockout collapse to a single
    /// `Option<Until>` lookup. An end that never comes is
    /// [`Until::Forever`](axess_clock::Until::Forever);
    /// [`Until::at`](axess_clock::Until::at) gives the reading of one that
    /// does.
    pub fn lockout_expiry(&self) -> Option<axess_clock::Until> {
        match self {
            AuthnError::Locked { until } => *until,
            AuthnError::NotActive(EntityState::Suspended(detail))
                if detail.cause == crate::authn::types::StatusCause::Lockout =>
            {
                detail.until
            }
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
/// Separate from [`AuthnError::into_response`] so the strict-greater
/// boundary is unit-testable without depending on wall-clock progress
/// between constructing the input and reading the response.
#[cfg(feature = "default-error-response")]
fn retry_secs_from(until: axess_clock::Timestamp, now: axess_clock::Timestamp) -> Option<u64> {
    // Round up: a lock with 400 ms left is a second away, not "retry now".
    let millis = until.since(now).whole_milliseconds();
    if millis > 0 {
        u64::try_from((millis + 999) / 1000).ok()
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
    /// clock. The `IntoResponse` impl below delegates here with the system clock
    /// because that trait method cannot take a clock (a declared exception
    /// to the injected-clock rule); handlers that hold a clock call this
    /// method directly.
    ///
    /// Adopters who don't enable the `default-error-response` feature
    /// can still construct their own `IntoResponse` impl on top of
    /// this helper without forking the body/status logic.
    pub fn into_response_at(self, now: axess_clock::Timestamp) -> axum::response::Response {
        use axum::http::{HeaderValue, StatusCode, header};
        use axum::response::IntoResponse as _;

        // Surface lockout expiry to the client. Computed BEFORE
        // the move-into-match so the `lockout_expiry()` accessor (which
        // already handles both `Locked { until }` and the legacy
        // `NotActive(Suspended(_))` shape) can read `&self`.
        let end = self.lockout_expiry();

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
        // `Retry-After` can only state a time, so a lock that never ends
        // carries none. The body states the end of a lock still to come, and
        // one that never ends as the reading it is stored as, the latest
        // reading, which earlier releases sent for it.
        let (until, lock_secs) = match end {
            Some(axess_clock::Until::At(t)) => match retry_secs_from(t, now) {
                Some(secs) => (Some(t), Some(secs)),
                None => (None, None),
            },
            Some(axess_clock::Until::Forever) => (Some(axess_clock::Until::LEGACY_FOREVER), None),
            None => (None, None),
        };
        let until_secs = lock_secs.or(busy_secs);
        let body = match until {
            Some(t) => {
                serde_json::json!({ "error": message, "until_iso": t.to_rfc3339_numeric_offset() })
            }
            None => serde_json::json!({ "error": message }),
        };

        let mut response = (status, axum::Json(body)).into_response();

        // Emit RFC 9110 §10.2.3 `Retry-After` header (delta-seconds)
        // for any lockout-shaped error whose expiry is a reading in the
        // future. Browsers and well-behaved HTTP clients honour this for
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
    /// Delegates to [`AuthnError::into_response_at`] with the system
    /// clock's reading as the reference time.
    ///
    /// This is a declared exception to the injected-clock rule: axum's
    /// `IntoResponse::into_response` takes no arguments, so the trait method
    /// cannot be handed a clock. Code that has one (a handler holding the
    /// service's clock, and every test) calls
    /// `into_response_at(clock.now())` instead and the exception never
    /// applies.
    fn into_response(self) -> axum::response::Response {
        // A host clock outside the range of a reading reads as the nearer
        // end of the range.
        let now = axess_clock::Timestamp::from_system_time(std::time::SystemTime::now());
        self.into_response_at(now)
    }
}

#[cfg(all(test, feature = "default-error-response"))]
mod into_response_tests;

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
        let response = err.into_response_at(axess_clock::testing::MockClock::reference_time());
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
        let response = short.into_response_at(axess_clock::testing::MockClock::reference_time());
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
