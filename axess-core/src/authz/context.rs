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

use axess_clock::Timestamp;
use cedar_policy::{Context, RestrictedExpression};

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

    /// Whether this value stands for the facts of a request. `true` for
    /// every context but [`NoContext`], which stands for "none".
    ///
    /// An [`AuthzStore`](super::session::AuthzStore) refuses to begin a
    /// session for a value that answers `false` while the policies in force
    /// read `context`, whichever of its builders is handed the value: naming
    /// `NoContext` to a builder that takes a context supplies none.
    fn supplies_context(&self) -> bool {
        true
    }
}

// ── RequestContextProvider ────────────────────────────────────────────────────

/// Builds the Cedar [`Context`] for one request of a `require_authz!` gate.
///
/// The gate takes the provider from its
/// [`AuthzInstallation`](super::installation::AuthzInstallation) and calls
/// [`context_for`](Self::context_for) with the session and the request head.
/// Hand it to
/// [`AuthzInstallation::new`](super::installation::AuthzInstallation::new)
/// together with the policy store and the entity provider; there is no
/// other way to give a gate a context provider.
///
/// Derive facts such as MFA status from the session or from state the
/// application's own layers wrote into the request extensions, never from a
/// header, a query parameter or any other value the caller writes.
///
/// # Without a provider
///
/// When a policy or template of the store reads the `context` variable
/// ([`PolicyStore::mentions_context`](super::store::PolicyStore::mentions_context)),
/// the installation cannot be built without a provider:
/// `AuthzInstallation::new` answers
/// [`AuthzError::ContextProviderRequired`], because an empty context would
/// let a `forbid` that guards an optional attribute with `context has ..`
/// stop applying while the `permit` beside it allows. When none reads it the
/// installation takes `None` and its gates evaluate with an empty context.
/// The store answers from the parsed policies, so the word in a comment or a
/// string is not a read.
///
/// A policy reload can bring a read in after the installation was built
/// with `None`. The gate then refuses each request with a 500 and an error
/// log until a set that does not read `context` is in force again, so an
/// application that reloads policies passes a provider from the start.
/// Declare the attributes policies rely on as required.
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
///
/// It supplies no context, and says so
/// ([`supplies_context`](BuildRequestContext::supplies_context) is `false`):
/// an [`AuthzStore`](super::session::AuthzStore) whose policies read
/// `context` refuses a session begun with it, with
/// [`AuthzError::ContextRequired`].
pub struct NoContext;

impl BuildRequestContext for NoContext {
    fn to_cedar_context(&self) -> Result<Context, AuthzError> {
        Ok(Context::empty())
    }

    fn supplies_context(&self) -> bool {
        false
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
/// | `assurance`        | `AxessAssurance` | only if built with [`StandardRequestContext::with_assurance`] |
/// | `key_bound`        | Boolean | only if built with [`StandardRequestContext::with_key_bound`] |
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
    pub timestamp: Option<Timestamp>,

    /// The session's assurance record, emitted as `assurance` when `Some`
    /// (see [`with_assurance`](Self::with_assurance)); the action's schema
    /// must then declare `assurance` (`AxessAssurance`).
    pub assurance: Option<super::assurance::AssuranceContext>,

    /// Whether this request ran as a session bound to a device key and
    /// proved that key, emitted as `key_bound` when `Some` (see
    /// [`with_key_bound`](Self::with_key_bound)); the action's schema must
    /// then declare `key_bound: Bool`.
    pub key_bound: Option<bool>,
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
            assurance: None,
            key_bound: None,
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
        timestamp: Timestamp,
    ) -> Self {
        Self {
            mfa_verified,
            ip_address,
            timestamp: Some(timestamp),
            assurance: None,
            key_bound: None,
        }
    }

    /// Emit `assurance` as well: the session's record, built with
    /// [`AssuranceContext::from_session`](super::assurance::AssuranceContext::from_session)
    /// from [`AuthSession::assurance`](crate::session::extractor::AuthSession::assurance)
    /// and the clock reading of this request.
    #[must_use]
    pub fn with_assurance(mut self, assurance: super::assurance::AssuranceContext) -> Self {
        self.assurance = Some(assurance);
        self
    }

    /// Emit `key_bound` as well: whether the request ran as a session bound
    /// to a device key and proved that key, as
    /// [`AuthSession::key_bound`](crate::session::extractor::AuthSession::key_bound)
    /// answers. A deployment that prefers device keys without requiring them
    /// can then demand one for the actions that warrant it:
    ///
    /// ```cedar
    /// forbid (principal, action == App::Action::"Transfer", resource)
    /// unless { context.key_bound };
    /// ```
    #[must_use]
    pub fn with_key_bound(mut self, key_bound: bool) -> Self {
        self.key_bound = Some(key_bound);
        self
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
                RestrictedExpression::new_string(ts.to_rfc3339_numeric_offset()),
            ));
        }

        if let Some(assurance) = &self.assurance {
            pairs.push((
                super::assurance::ASSURANCE_ATTRIBUTE.to_string(),
                assurance.to_expression()?,
            ));
        }

        if let Some(key_bound) = self.key_bound {
            pairs.push((
                "key_bound".to_string(),
                RestrictedExpression::new_bool(key_bound),
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

    fn supplies_context(&self) -> bool {
        self.as_ref().supplies_context()
    }
}
