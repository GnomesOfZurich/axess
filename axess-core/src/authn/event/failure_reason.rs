//! [`AuthFailureReason`]: why a failed [`AuthEvent`](super::AuthEvent) failed.

use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

/// Why a failed [`AuthEvent`](super::AuthEvent) failed.
///
/// This is the field a SOC dashboard groups by, so it is an enum rather
/// than free text. It used to be a `String`, which is the same defect
/// [`AuthEventBuilder::locked`](crate::authn::event::AuthEventBuilder::locked)
/// was introduced to fix for the *outcome*: querying meant matching a
/// string, and a string nothing enforced. One call site wrote
/// `"cross-tenant impersonation refused"`, with spaces, so it did not
/// even sort alongside the snake_case tags it sat beside.
///
/// [`Other`](Self::Other) carries anything axess has no tag for,
/// including an adopter's own detail. Parsing never fails: an
/// unrecognised string becomes `Other`, so rows written by an older
/// version, or by an adopter, read back without loss.
///
/// The wire form is the string from [`as_str`](Self::as_str), in both
/// serde and database columns, so this is a Rust-level type change only.
///
/// Two reasons are equal when their tags are: `Other("unknown_tenant")` is
/// equal to [`UnknownTenant`](Self::UnknownTenant), since the string form
/// cannot tell them apart and reads either back as `UnknownTenant`. A round
/// trip through the string is therefore the identity under `==`; `match`
/// still tells the variants apart.
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub enum AuthFailureReason {
    /// The account or factor exists but is not in an active state.
    NotActive,
    /// The identity is valid and active but has no usable authentication
    /// method configured, so there is nothing to challenge.
    NoFactorsConfigured,
    /// No tenant matched the identifier supplied at login.
    UnknownTenant,
    /// The tenant row was present but could not be interpreted.
    InvalidTenantRow,
    /// The tenant's IP policy refused the request: the client address is not
    /// allowed, or the policy restricts and no address was resolved.
    IpPolicy,
    /// No identity matched the identifier supplied at login.
    UnknownIdentifier,
    /// An administrator tried to impersonate across a tenant boundary.
    CrossTenantImpersonation,
    /// An OAuth refresh-token exchange failed.
    TokenRefresh,
    /// A refresh was attempted with no refresh token stored.
    TokenRefreshNoToken,
    /// A refresh named a provider that is not registered.
    TokenRefreshUnknownProvider,
    /// The identity provider rejected the refresh token.
    TokenRefreshProviderRejected,
    /// A refresh for a provider that binds tokens to a DPoP key was asked
    /// without the key, and refused before anything was sent: a caller
    /// fault, not an identity provider's verdict on the token.
    TokenRefreshDpopKeyMissing,
    /// The OAuth ceremony outlived its timeout before the callback.
    CeremonyExpired,
    /// The `state` returned by the identity provider did not match.
    CsrfMismatch,
    /// The stored ceremony carried no issuer to compare against, or the
    /// callback was finished without the `iss` parameter a provider that
    /// advertises it sends.
    MissingIssuer,
    /// The stored PKCE verifier was absent or unusable.
    PkceVerifierInvalid,
    /// The authorization-code exchange was rejected.
    TokenExchange,
    /// The callback's provider did not match the one the flow began with.
    ProviderMismatch,
    /// An impersonated session asked to change the user's credentials (issue a
    /// refresh token, enrol or delete a factor), or to impersonate again, and
    /// the deployment does not allow it.
    Impersonated,
    /// A credential of one tenant was presented in another (a discoverable
    /// passkey whose user belongs to another tenant).
    CrossTenant,
    /// An impersonated session tried to begin another impersonation.
    NestedImpersonation,
    /// The session asking to impersonate is not authenticated.
    AdminNotAuthenticated,
    /// The session asking to impersonate belongs to another user than the
    /// administrator named.
    SessionIsNotAdmin,
    /// The administrator named for an impersonation does not exist.
    UnknownAdmin,
    /// The administrator asking to impersonate is not active.
    AdminNotActive,
    /// The user to impersonate does not exist.
    UnknownTarget,
    /// The user to impersonate could not be read from the store.
    TargetLookupFailed,
    /// The impersonating session could not be registered with the session
    /// registry, so it could not be ended with the user's other sessions.
    SessionNotRegistered,
    /// A credential change came from a session that is neither authenticated
    /// as the user nor the user's own signup.
    EnrolmentContext,
    /// A credential change came from a session whose authentication is older
    /// than the deployment allows; the user must authenticate again.
    AuthnTooOld,
    /// The provider a ceremony began with could not be resolved at the
    /// callback: removed since, its tenant's store unreachable, or its
    /// discovery failed.
    ProviderUnavailable,
    /// The ceremony's DPoP key is unusable: the stashed key does not decode,
    /// or the provider binds tokens and the ceremony stashed none.
    DpopKeyInvalid,
    /// A guess was refused by the throttle: consecutive wrong guesses under
    /// the key had earned a delay that had not run, so no credential was
    /// checked.
    Throttled,
    /// Anything axess has no tag for, including adopter-supplied detail.
    ///
    /// Prefer a variant where one fits: `Other` is not queryable as a
    /// class, which is the problem this type exists to solve.
    Other(String),
}

impl PartialEq for AuthFailureReason {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for AuthFailureReason {}

impl AuthFailureReason {
    /// Stable string representation for database storage.
    ///
    /// Not `&'static str`, unlike
    /// [`AuthEventStatus::as_str`](super::AuthEventStatus::as_str), because
    /// [`Other`](Self::Other) borrows its own payload.
    pub fn as_str(&self) -> &str {
        match self {
            Self::NotActive => "not_active",
            Self::NoFactorsConfigured => "no_factors_configured",
            Self::UnknownTenant => "unknown_tenant",
            Self::InvalidTenantRow => "invalid_tenant_row",
            Self::IpPolicy => "ip_policy",
            Self::UnknownIdentifier => "unknown_identifier",
            Self::CrossTenantImpersonation => "cross_tenant_impersonation",
            Self::TokenRefresh => "token_refresh",
            Self::TokenRefreshNoToken => "token_refresh_no_token",
            Self::TokenRefreshUnknownProvider => "token_refresh_unknown_provider",
            Self::TokenRefreshProviderRejected => "token_refresh_provider_rejected",
            Self::TokenRefreshDpopKeyMissing => "token_refresh_dpop_key_missing",
            Self::CeremonyExpired => "ceremony_expired",
            Self::CsrfMismatch => "csrf_mismatch",
            Self::MissingIssuer => "missing_issuer",
            Self::PkceVerifierInvalid => "pkce_verifier_invalid",
            Self::TokenExchange => "token_exchange",
            Self::ProviderMismatch => "provider_mismatch",
            Self::Impersonated => "impersonated",
            Self::CrossTenant => "cross_tenant",
            Self::NestedImpersonation => "nested_impersonation",
            Self::AdminNotAuthenticated => "admin_not_authenticated",
            Self::SessionIsNotAdmin => "session_is_not_admin",
            Self::UnknownAdmin => "unknown_admin",
            Self::AdminNotActive => "admin_not_active",
            Self::UnknownTarget => "unknown_target",
            Self::TargetLookupFailed => "target_lookup_failed",
            Self::SessionNotRegistered => "session_not_registered",
            Self::EnrolmentContext => "enrolment_context",
            Self::AuthnTooOld => "authn_too_old",
            Self::ProviderUnavailable => "provider_unavailable",
            Self::DpopKeyInvalid => "dpop_key_invalid",
            Self::Throttled => "throttled",
            Self::Other(s) => s,
        }
    }
}

impl From<&str> for AuthFailureReason {
    fn from(s: &str) -> Self {
        match s {
            "not_active" => Self::NotActive,
            "no_factors_configured" => Self::NoFactorsConfigured,
            "unknown_tenant" => Self::UnknownTenant,
            "invalid_tenant_row" => Self::InvalidTenantRow,
            "ip_policy" => Self::IpPolicy,
            "unknown_identifier" => Self::UnknownIdentifier,
            "cross_tenant_impersonation" => Self::CrossTenantImpersonation,
            "token_refresh" => Self::TokenRefresh,
            "token_refresh_no_token" => Self::TokenRefreshNoToken,
            "token_refresh_unknown_provider" => Self::TokenRefreshUnknownProvider,
            "token_refresh_provider_rejected" => Self::TokenRefreshProviderRejected,
            "token_refresh_dpop_key_missing" => Self::TokenRefreshDpopKeyMissing,
            "ceremony_expired" => Self::CeremonyExpired,
            "csrf_mismatch" => Self::CsrfMismatch,
            "missing_issuer" => Self::MissingIssuer,
            "pkce_verifier_invalid" => Self::PkceVerifierInvalid,
            "token_exchange" => Self::TokenExchange,
            "provider_mismatch" => Self::ProviderMismatch,
            "impersonated" => Self::Impersonated,
            "cross_tenant" => Self::CrossTenant,
            "nested_impersonation" => Self::NestedImpersonation,
            "admin_not_authenticated" => Self::AdminNotAuthenticated,
            "session_is_not_admin" => Self::SessionIsNotAdmin,
            "unknown_admin" => Self::UnknownAdmin,
            "admin_not_active" => Self::AdminNotActive,
            "unknown_target" => Self::UnknownTarget,
            "target_lookup_failed" => Self::TargetLookupFailed,
            "session_not_registered" => Self::SessionNotRegistered,
            "enrolment_context" => Self::EnrolmentContext,
            "authn_too_old" => Self::AuthnTooOld,
            "provider_unavailable" => Self::ProviderUnavailable,
            "dpop_key_invalid" => Self::DpopKeyInvalid,
            "throttled" => Self::Throttled,
            other => Self::Other(other.to_owned()),
        }
    }
}

impl From<String> for AuthFailureReason {
    fn from(s: String) -> Self {
        // Route through the borrowed form so the tag table lives once,
        // then avoid re-allocating when nothing matched.
        match Self::from(s.as_str()) {
            Self::Other(_) => Self::Other(s),
            known => known,
        }
    }
}

impl FromStr for AuthFailureReason {
    /// Parsing cannot fail: an unrecognised tag becomes
    /// [`Other`](Self::Other) rather than an error, so an audit row is
    /// never dropped for carrying a reason this version does not know.
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from(s))
    }
}

impl fmt::Display for AuthFailureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// Serialized as the plain tag string rather than as a Rust enum, so the
// JSON an adopter already stores is unchanged by this type existing.
impl Serialize for AuthFailureReason {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AuthFailureReason {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self::from(String::deserialize(deserializer)?))
    }
}
