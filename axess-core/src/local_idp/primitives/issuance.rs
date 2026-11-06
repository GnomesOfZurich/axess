//! The issuance audit hook a mint reports to, and the lifetime cap a mint is
//! checked against before it is signed.

use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::Algorithm;

use super::MintClaims;

// ── Issuance audit hook ──────────────────────────────────────────────────────

/// A single mint event observed by an [`IssuanceListener`]. Borrowed
/// fields mirror what the fixture knew at signing time; the listener
/// can copy whichever pieces it needs into its own log type. The
/// signed JWT is **not** included: listeners that need to record
/// per-token state should use [`MintClaims::with_jwt_id`] and key off
/// `claims.jwt_id`.
///
/// `IssuanceEvent` is non-`Clone` and borrows from the fixture's
/// internal state, so listeners must extract owned data inside
/// [`IssuanceListener::on_mint`] rather than retaining the event
/// itself.
#[derive(Debug)]
pub struct IssuanceEvent<'a> {
    /// `iss` claim: the fixture's configured issuer.
    pub issuer: &'a str,
    /// JWT header `kid`: the signing key's id.
    pub key_id: &'a str,
    /// JWT header `alg`: the signing algorithm in effect.
    pub algorithm: Algorithm,
    /// Caller-supplied claim set (sub, aud, exp, nbf, iat, jti, custom).
    pub claims: &'a MintClaims,
}

/// Adopter-supplied callback fired after every successful mint.
/// Models the production-side audit log boundary: adopters writing
/// integration tests against axess can assert on issuance behaviour
/// (count, subject, audience, lifetime) without parsing the resulting
/// JWT.
///
/// The listener fires **after** the token is signed but **before**
/// [`LocalIdpFixture::mint`](crate::testing::local_idp::LocalIdpFixture::mint)
/// returns. Mints that violate the fixture's
/// [`with_max_ttl`](crate::testing::local_idp::LocalIdpFixture::with_max_ttl)
/// cap panic before reaching the listener, so the listener only sees mints
/// the fixture actually issued.
///
/// Implement this trait directly for custom recording shapes, or use
/// the included [`MockIssuanceListener`](crate::testing::local_idp::MockIssuanceListener)
/// for the common "capture everything, assert later" pattern.
pub trait IssuanceListener: Send + Sync {
    /// Invoked once per successful mint. Implementations should be
    /// fast and panic-free; the fixture is on the caller's hot path.
    fn on_mint(&self, event: &IssuanceEvent<'_>);
}

/// Why [`enforce_max_ttl_fallible`] refused a claim set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TtlRefusal {
    /// The lifetime `exp - now` is over the cap.
    Exceeds {
        /// The computed lifetime.
        observed: Duration,
        /// The configured cap.
        max: Duration,
    },
    /// The cap or the claim set cannot produce a usable token.
    Invalid(crate::local_idp::LifetimeFault),
}

/// Panics if the claim set is refused by [`enforce_max_ttl_fallible`]: its
/// lifetime `exp - now` exceeds `max_ttl`, `max_ttl` is not positive, the
/// token has already expired, or `nbf` is after `exp`.
/// Called from
/// [`LocalIdpFixture::mint_with_header_at`](crate::testing::local_idp::LocalIdpFixture::mint_with_header_at)
/// when the fixture has a TTL policy configured. The lifetime is measured
/// from the supplied `now`, never from a caller-supplied `iat`, so a
/// future-dated `iat` cannot shrink it.
#[cfg(any(test, feature = "testing"))]
pub(crate) fn enforce_max_ttl(claims: &MintClaims, max_ttl: Duration, now: DateTime<Utc>) {
    match enforce_max_ttl_fallible(claims, max_ttl, now) {
        Ok(()) => {}
        Err(TtlRefusal::Exceeds { observed, max }) => panic!(
            "LocalIdpFixture::mint refusing token with lifetime {observed} \
             exceeding the fixture's max_ttl of {max}. \
             Set MintClaims.expires_at within the cap or relax the policy \
             via `with_max_ttl`.",
        ),
        Err(TtlRefusal::Invalid(fault)) => {
            panic!("LocalIdpFixture::mint refusing an invalid lifetime: {fault}")
        }
    }
}

/// Returns the refusal if the claim set's lifetime exceeds `max_ttl`
/// ([`TtlRefusal::Exceeds`]), or the cap is zero or negative, the token has
/// already expired (`exp <= now`), or `nbf` is after `exp`
/// ([`TtlRefusal::Invalid`]).
/// Production-side counterpart to [`enforce_max_ttl`];
/// `LocalIdp::mint` surfaces these as `IssuanceError::LifetimeExceedsCap`
/// and `IssuanceError::InvalidLifetime` rather than panicking. Reference time
/// is the supplied `now`
/// (typically `Clock::now()`); the fixture's variant takes the same
/// `now` through its `_at` mint methods.
pub(crate) fn enforce_max_ttl_fallible(
    claims: &MintClaims,
    max_ttl: Duration,
    now: DateTime<Utc>,
) -> Result<(), TtlRefusal> {
    use crate::local_idp::LifetimeFault;
    // Measured from NOW, not from a caller-supplied `issued_at`: a future-dated
    // `iat` would otherwise shrink the apparent lifetime under the cap while
    // the token stays valid for the whole span.
    let lifetime = claims.expires_at - now;
    // A cap that is not positive admits nothing; a token that is already
    // expired, or whose `nbf` is after its `exp`, is never valid. Each is a
    // refusal, not a mint that only looks within the cap.
    if max_ttl <= Duration::zero() {
        return Err(TtlRefusal::Invalid(LifetimeFault::NonPositiveCap));
    }
    if lifetime <= Duration::zero() {
        return Err(TtlRefusal::Invalid(LifetimeFault::AlreadyExpired));
    }
    if claims.not_before.is_some_and(|nbf| nbf > claims.expires_at) {
        return Err(TtlRefusal::Invalid(LifetimeFault::NotBeforeAfterExpiry));
    }
    if lifetime <= max_ttl {
        Ok(())
    } else {
        Err(TtlRefusal::Exceeds {
            observed: lifetime,
            max: max_ttl,
        })
    }
}
