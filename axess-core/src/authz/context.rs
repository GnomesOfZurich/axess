//! Request context for Cedar ABAC policies.
//!
//! Cedar's `Context` field carries request-level facts that policies can
//! inspect: IP address, MFA verification status, session age, time of day.
//! Without this, Cedar can only reason about principals and resources, so ABAC
//! conditions are impossible.
//!
//! # Usage
//!
//! Use [`StandardRequestContext`] for most applications:
//!
//! ```rust,ignore
//! use axess_core::authz::context::StandardRequestContext;
//!
//! // Default: emits `mfa_verified` (+ `ip_address` if Some) only.
//! // `mfa_complete` is the application's own fact, derived from what it
//! // recorded when the user finished the factors its policy demands.
//! let ctx = StandardRequestContext::new(
//!     mfa_complete,
//!     Some("192.168.1.1".parse().unwrap()),
//! );
//!
//! // Opt-in timestamp from an injectable Clock (DST-friendly). Only
//! // emitted when explicitly provided; Cedar schema must then declare
//! // `timestamp` as well.
//! let ctx = StandardRequestContext::at(
//!     mfa_complete,
//!     client_ip.get(),
//!     clock.now(),
//! );
//!
//! let authz = state.authz.for_user_id_with_context(&user_id, ctx)?;
//! authz.require("PostJournalEntry", &ledger_id).await?;
//! ```
//!
//! For applications that do not need ABAC context, use [`NoContext`]; it
//! produces an empty Cedar `Context` with zero overhead.
//!
//! # Cedar schema requirements
//!
//! Whatever attributes `StandardRequestContext` actually emits for a
//! given request must appear in the matching Cedar action's context
//! declaration; Cedar's schema validation rejects requests carrying
//! attributes the schema does not list. Minimum (always-emitted):
//!
//! ```json
//! "context": {
//!     "type": "Record",
//!     "attributes": {
//!         "mfa_verified": { "type": "Boolean" }
//!     }
//! }
//! ```
//!
//! Add `"ip_address": { "type": "String", "required": false }` if you
//! ever pass `Some(ip)` to `new` / `at`; add `"timestamp": { "type":
//! "String", "required": false }` if you call `at(..)` with an explicit
//! timestamp.

use cedar_policy::{Context, RestrictedExpression};
use chrono::{DateTime, Utc};

use super::error::AuthzError;

// ── BuildRequestContext ───────────────────────────────────────────────────────

/// Converts request-level data into a Cedar [`Context`] for ABAC evaluation.
///
/// Implement this trait to provide custom context attributes beyond what
/// [`StandardRequestContext`] offers (e.g. geographic region, subscription
/// tier, feature flags).
pub trait BuildRequestContext: Send + Sync {
    /// Produce the Cedar [`Context`] for this request.
    ///
    /// Any error causes the authorization check to fail closed.
    fn to_cedar_context(&self) -> Result<Context, AuthzError>;
}

// ── RequestContextProvider ────────────────────────────────────────────────────

/// Builds the Cedar [`Context`] for one request of a `require_authz!` gate.
///
/// The macro looks for an `Arc<dyn RequestContextProvider>` in the request
/// extensions and calls [`context_for`](Self::context_for) with the session
/// and the request head. Install it with an `Extension` layer beside the
/// policy store and the entity provider; the extension must be stored under
/// exactly this type (an `Arc<MyProvider>` is a different type to the
/// extension map).
///
/// Derive facts such as MFA status from the session or from state the
/// application's own layers wrote into the request extensions, never from a
/// header, a query parameter or any other value the caller writes.
///
/// # Without a provider
///
/// When no provider is installed the gate evaluates with an empty context.
/// That is safe for a policy set that never mentions `context`. For one that
/// does it fails closed in two ways: a context attribute the action's schema
/// declares required makes the request invalid, which `PolicyStore` denies,
/// and `PolicyStore` also denies any request in which a policy errors during
/// evaluation. The schema validator refuses a policy that reads an optional
/// attribute without a `context has ..` guard, so the one case an empty
/// context can permit is a policy that guards its access and treats absence
/// as allowed. Declare the attributes policies rely on as required, and
/// install a provider wherever policies reason about the context.
///
/// # Errors
///
/// An `Err` is treated as a denial: the gate answers 403 and logs the error.
pub trait RequestContextProvider: Send + Sync {
    /// Produce the Cedar context for this request.
    fn context_for<'a>(
        &'a self,
        session: &'a crate::session::AuthSession,
        request: &'a axum::http::request::Parts,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Context, AuthzError>> + Send + 'a>>;
}

// ── NoContext ─────────────────────────────────────────────────────────────────

/// Zero-overhead context for applications that do not use ABAC in Cedar policies.
///
/// Produces an empty [`Context`]. Use this when all Cedar policy decisions are
/// based purely on principal attributes (RBAC) or resource relationships (ReBAC).
pub struct NoContext;

impl BuildRequestContext for NoContext {
    fn to_cedar_context(&self) -> Result<Context, AuthzError> {
        Ok(Context::empty())
    }
}

// ── StandardRequestContext ────────────────────────────────────────────────────

/// Request context covering the most common ABAC attributes for web applications.
///
/// Attributes exposed to Cedar policies (only emitted ones must appear
/// in the schema; see module docs):
///
/// | Cedar attribute    | Type    | Always present |
/// |--------------------|---------|----------------|
/// | `mfa_verified`     | Boolean | yes            |
/// | `ip_address`       | String  | only if `Some` |
/// | `timestamp`        | String (ISO 8601) | only if built via [`StandardRequestContext::at`] |
///
/// Cedar policy example: require recent MFA for financial operations:
///
/// ```cedar
/// permit (
///     principal in App::Role::"finance-member",
///     action == App::Action::"PostJournalEntry",
///     resource is App::Ledger
/// ) when {
///     context.mfa_verified == true
/// };
/// ```
pub struct StandardRequestContext {
    /// Whether the current session has completed all required MFA factors.
    pub mfa_verified: bool,

    /// Source IP address, if available. Passed as a string; use Cedar's
    /// `ip()` extension function in policies if you need range checks.
    pub ip_address: Option<std::net::IpAddr>,

    /// Optional request timestamp. `None` (the default from [`new`])
    /// means *no* `timestamp` attribute is emitted into the Cedar
    /// context, so the schema doesn't need to declare one. Set via
    /// [`at`] with a `clock.now()` value if your policies inspect time.
    ///
    /// [`new`]: Self::new
    /// [`at`]: Self::at
    pub timestamp: Option<DateTime<Utc>>,
}

impl StandardRequestContext {
    /// Create a context without a timestamp.
    ///
    /// The Cedar request will carry `mfa_verified` (and `ip_address` if
    /// `Some`). No wall-clock call is made; DST-safe by construction.
    /// Use [`at`](Self::at) when a policy needs the time-of-request.
    pub fn new(mfa_verified: bool, ip_address: Option<std::net::IpAddr>) -> Self {
        Self {
            mfa_verified,
            ip_address,
            timestamp: None,
        }
    }

    /// Create a context with an explicit timestamp from an injectable
    /// clock. Pass `clock.now()` so DST tests can pin time.
    ///
    /// Emits `timestamp: String` (RFC 3339) into the Cedar context, so
    /// the corresponding action's schema must declare `timestamp`.
    pub fn at(
        mfa_verified: bool,
        ip_address: Option<std::net::IpAddr>,
        timestamp: DateTime<Utc>,
    ) -> Self {
        Self {
            mfa_verified,
            ip_address,
            timestamp: Some(timestamp),
        }
    }
}

impl BuildRequestContext for StandardRequestContext {
    fn to_cedar_context(&self) -> Result<Context, AuthzError> {
        let mut pairs: Vec<(String, RestrictedExpression)> = vec![(
            "mfa_verified".to_string(),
            RestrictedExpression::new_bool(self.mfa_verified),
        )];

        if let Some(ip) = &self.ip_address {
            pairs.push((
                "ip_address".to_string(),
                RestrictedExpression::new_string(ip.to_string()),
            ));
        }

        if let Some(ts) = &self.timestamp {
            pairs.push((
                "timestamp".to_string(),
                RestrictedExpression::new_string(ts.to_rfc3339()),
            ));
        }

        Context::from_pairs(pairs).map_err(|e| AuthzError::Context(format!("{e:?}")))
    }
}

// ── Blanket impl for Arc<T> ───────────────────────────────────────────────────

impl<T: BuildRequestContext> BuildRequestContext for std::sync::Arc<T> {
    fn to_cedar_context(&self) -> Result<Context, AuthzError> {
        self.as_ref().to_cedar_context()
    }
}
