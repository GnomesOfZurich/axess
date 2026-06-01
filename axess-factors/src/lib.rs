#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Factor implementations for axess: password (Argon2id), TOTP (RFC 6238),
//! HOTP (RFC 4226).
//!
//! All comparisons against secret material use [`subtle::ConstantTimeEq`];
//! all in-memory secrets are wrapped in [`zeroize::Zeroizing`] so the buffer
//! is wiped on drop. Verification functions clamp digit length and TOTP
//! drift windows to defensive bounds.
//!
//! # Module layout
//!
//! - `password`: Argon2id hashing/verification re-exports from
//!   `password_auth` (`password` feature).
//! - `hotp`: HOTP per RFC 4226 with SHA-1 / SHA-256 / SHA-512
//!   variants (`hotp` feature).
//! - `totp`: TOTP per RFC 6238, secret generation, and `otpauth://`
//!   URI builder (`totp` feature).
//!
//! Each module is feature-gated; `lib.rs` re-exports everything at the
//! crate root so downstream code can import via either path.

/// Server-issued [`EmailOtpConfig`](email_otp::EmailOtpConfig): the typed
/// challenge state for the out-of-band email factor (`email_otp` feature).
#[cfg(feature = "email_otp")]
pub mod email_otp;
/// FIDO2/WebAuthn factor data: [`Fido2Config`](fido2::Fido2Config) +
/// [`Fido2Credential`](fido2::Fido2Credential) +
/// [`Fido2Options`](fido2::Fido2Options) +
/// re-exports of `webauthn-rs` primitives (`fido2` feature).
#[cfg(feature = "fido2")]
pub mod fido2;
/// Always-on stub when the `fido2` feature is off; provides the typed
/// [`Fido2Config`](fido2_stub::Fido2Config) so adopters' admin tooling
/// can round-trip factor rows that include FIDO2 data without pulling
/// `webauthn-rs`. Re-exported below as `fido2` so the public path stays
/// the same across feature configurations.
#[cfg(not(feature = "fido2"))]
#[path = "fido2.rs"]
pub mod fido2_stub;
#[cfg(not(feature = "fido2"))]
pub use fido2_stub as fido2;
/// Bearer JWT workload-auth middleware. Verifies inbound
/// `Authorization: Bearer <jwt>` headers against configured issuers and
/// JWKS, inserts a [`WorkloadIdentity`](bearer::WorkloadIdentity) into
/// axum request extensions (`bearer` feature).
#[cfg(feature = "bearer")]
pub mod bearer;
/// Workload-identity federation. The generic
/// [`federation::workload::WorkloadResolver`] verifies any JWT-bearer
/// workload token (GitHub Actions OIDC, Kubernetes SA, GitLab CI OIDC,
/// Okta, Azure AD, Auth0, axess `LocalIdP`, …) via a caller-supplied
/// claim parser + mapping closure. Gated on the `jwt` feature.
#[cfg(feature = "jwt")]
pub mod federation;
#[cfg(feature = "hotp")]
pub mod hotp;
/// JWT validation + `JwtVerifier` builder + SPIFFE JWT-SVID resolver
/// (`jwt` / `jwt-svid` features). Adopters performing JWT verification
/// (workload identity, federated OIDC checks, custom logout flows) share
/// the same hardened parse-and-verify paths internally used by OAuth +
/// back-channel logout.
#[cfg(feature = "jwt")]
pub mod jwt;
/// LDAP simple-bind verifier: [`LdapProvider`](ldap::LdapProvider)
/// trait + [`LdapProviderConfig`](ldap::LdapProviderConfig) production
/// impl (`ldap3`-backed) + [`MockLdapProvider`](ldap::MockLdapProvider)
/// (`ldap` feature). HealthCheck integration lives in axess-core as
/// an extension impl.
#[cfg(feature = "ldap")]
pub mod ldap;
/// mTLS SPIFFE X509-SVID resolver. Extracts a
/// [`Principal::Workload`](axess_identity::Principal::Workload) from
/// the leaf client certificate in a rustls peer-cert chain (`mtls`
/// feature).
#[cfg(feature = "mtls")]
pub mod mtls;
/// OAuth 2.0 / OIDC ceremony surface: `OAuthProvider` trait,
/// `DefaultOAuthProvider` (openidconnect-backed), builder, device-flow,
/// FAPI 2.0 DPoP (`oauth` / `fapi` features).
#[cfg(feature = "oauth")]
pub mod oauth;
/// OIDC discovery + JWKS retrieval / rotation primitives (`oidc`
/// feature). Shared between the full OAuth ceremony surface and adopters
/// that verify JWTs without taking it.
#[cfg(feature = "oidc")]
pub mod oidc;
/// [`OtpAlgorithm`](otp_algorithm::OtpAlgorithm): the storage-shape HMAC
/// algorithm tag shared by [`TotpConfig`](totp::TotpConfig) and
/// [`HotpConfig`](hotp::HotpConfig). Gated on `totp` OR `hotp` because
/// it has no consumer outside the two OTP configs.
#[cfg(any(feature = "totp", feature = "hotp"))]
pub mod otp_algorithm;
/// Outbound OAuth client: `client_credentials` grant with optional
/// `private_key_jwt` client assertion (RFC 7523) (`outbound-oauth`
/// feature).
#[cfg(feature = "outbound-oauth")]
pub mod outbound_oauth_client;
#[cfg(feature = "password")]
pub mod password;
/// PKCE (RFC 7636) `code_verifier` predicate. Always-on (no feature
/// gate) because it's a pure-spec character-class check with no
/// protocol deps.
pub mod pkce;
/// [`ZeroizedString`](secret::ZeroizedString): secret-string primitive
/// shared across factor configs and other credential-bearing types.
/// Always on (no feature gate) because the orchestrator's OAuth token
/// storage and delegated-credential storage hold it without the
/// `password`/`totp`/`hotp` features.
pub mod secret;
/// Plain-OAuth-2.0 user login ("social login") for IdPs that don't
/// support OIDC (GitHub user login, Twitter/X, Discord, Reddit,
/// Spotify, …). Off by default. **Weaker security model** than the
/// OIDC path under [`oauth`]: claims come from a TLS-trusted userinfo
/// endpoint, not from a signed assertion. See module docs for the
/// full delta and when to reach for this.
#[cfg(feature = "social")]
pub mod social;
#[cfg(feature = "totp")]
pub mod totp;

#[cfg(feature = "password")]
pub use password::{PasswordConfig, PasswordRules, generate_password_hash, verify_password};

#[cfg(feature = "hotp")]
pub use hotp::{HOTP_LENGTH, HotpAlgorithm, HotpConfig, verify_hotp};

#[cfg(feature = "totp")]
pub use totp::{
    TOTP, TOTP_LENGTH, TOTP_PERIOD, TotpAlgorithm, TotpConfig, TotpVerifyParams, build_totp_uri,
    generate_totp_secret, verify_totp,
};

#[cfg(feature = "email_otp")]
pub use email_otp::EmailOtpConfig;

pub use fido2::Fido2Config;
#[cfg(feature = "fido2")]
pub use fido2::{
    AuthenticationResult, AuthenticatorAttachment, CredentialID, DefaultFido2Provider,
    Fido2Credential, Fido2Options, Fido2Provider, MockFido2Provider,
};

#[cfg(feature = "ldap")]
pub use ldap::{
    LdapBindResult, LdapError, LdapGroupSearch, LdapProvider, LdapProviderConfig, MockLdapProvider,
};

#[cfg(feature = "mtls")]
pub use mtls::{MtlsError, MtlsResolver, PeerCertChain, SpiffeIdComponents, peek_spiffe};

#[cfg(feature = "oidc")]
pub use oidc::{Discovery, DiscoveryDocument, JwksCache, MIN_JWKS_REFRESH_INTERVAL, OidcError};

#[cfg(feature = "bearer")]
pub use bearer::{
    BearerConfig, BearerError, BearerIssuerConfig, BearerTokenLayer, BearerTokenService,
    JwtVerificationError, WorkloadIdentity, validate_bearer_token,
};

#[cfg(feature = "outbound-oauth")]
pub use outbound_oauth_client::{ClientAuthMethod, OAuthClientError, OutboundOAuthClient};

#[cfg(any(feature = "totp", feature = "hotp"))]
pub use otp_algorithm::OtpAlgorithm;

pub use secret::ZeroizedString;

// ── Shared constants ────────────────────────────────────────────────────────

/// Maximum HOTP digit length accepted by verification.
///
/// Axess's custom HOTP impl computes truncation modulo `10^digits` in `u64`,
/// so the full 10-digit range is usable without overflow. Standard codes are
/// 6–8 digits per RFC 4226; the upper bound exists to cap CPU/memory cost
/// from a corrupted or malicious factor config.
#[cfg(feature = "hotp")]
pub(crate) const MAX_HOTP_DIGITS: usize = 10;

/// Maximum TOTP digit length accepted by verification.
///
/// Lower than [`MAX_HOTP_DIGITS`] because the underlying `totp-rs` crate
/// enforces RFC 6238 §1.2's 6..=8 digit range in `TOTP::new`; values above
/// 8 are rejected by the upstream library before our own guard runs.
/// Tracking the real limit here keeps the guard meaningful and prevents
/// silent rejection from a future caller that assumes the constant is
/// authoritative.
#[cfg(feature = "totp")]
pub(crate) const MAX_TOTP_DIGITS: usize = 8;

/// Minimum acceptable shared-secret length **after** decoding, in bytes.
///
/// RFC 4226 §4 R6: "The length of the shared secret MUST be at least 128
/// bits. This document RECOMMENDs a shared secret length of 160 bits."
/// Verification refuses any secret shorter than this; a buggy enrollment
/// path that persisted a 32-bit secret destroys brute-force resistance and
/// must not be honoured silently. The library's secret generator already
/// produces 20 bytes (160 bits), so this only fires on user error or a
/// migrated legacy config.
#[cfg(any(feature = "hotp", feature = "totp"))]
pub(crate) const MIN_OTP_SECRET_BYTES: usize = 16;
