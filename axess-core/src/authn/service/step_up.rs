//! Step-up authentication helper.
//!
//! Decides whether the device on which an authentication attempt is
//! happening warrants a fresh strong-customer-authentication ceremony
//! ahead of the standard factor flow (PSD2 RTS Art 4 / NIST SP
//! 800-63B-4 §5.2.6).
//!
//! # Why a free function and not a trait
//!
//! The decision is pure data: given a [`Device`] and a [`StepUpPolicy`],
//! produce an `Option<Vec<FactorKind>>`. There's no IO, no async, and
//! no state that would benefit from polymorphism. Apps that need
//! richer logic (geo, time-of-day, resource-sensitivity tiers) layer
//! it on top of this primitive rather than replacing the primitive.
//!
//! # Wiring pattern
//!
//! ```text
//! let outcome = service.begin_login(identifier, tenant, &session).await?;
//! let outcome = match (outcome, resolved_device) {
//!     (outcome @ LoginOutcome::FactorRequired(_), Some(device)) => {
//!         match decide_step_up_for_user(&device, &user_id, &policy) {
//!             Some(allowed_factors) => LoginOutcome::StepUpRequired {
//!                 device_id: device.id.clone(),
//!                 allowed_factors,
//!             },
//!             None => outcome,
//!         }
//!     }
//!     (other, _) => other,
//! };
//! ```
//!
//! `user_id` is the id the login is for, which the application holds from
//! its own identifier lookup; `begin_login` does not return it.
//!
//! The relabelled outcome enforces nothing by itself: the remaining steps
//! are still the original method's. To make the session actually prove one
//! of `allowed_factors`, call
//! [`begin_step_up`](crate::authn::service::RequestAuthnService::begin_step_up)
//! once the session is authenticated, then drive `prepare_factor` and
//! `verify_factor` as for any login.
//!
//! axess does **not** reach into the device subsystem from
//! `begin_login`. `Device` resolution is a middleware concern
//! ([`SessionLayer::with_device_resolver`](crate::session::SessionLayer::with_device_resolver))
//! and the application owns the substitution above.
//!
//! [`Device`]: crate::device::types::Device

use crate::authn::factor::FactorKind;
use crate::authn::ids::UserId;
use crate::device::types::{Device, DeviceTrustLevel};

/// Application-level step-up policy.
///
/// Maps a device's [`DeviceTrustLevel`] to the factor kinds the
/// application accepts as proof of fresh SCA on that device. Empty
/// vectors mean "no step-up required for this trust level"; absent
/// entries are treated the same. The default returned by
/// [`StepUpPolicy::default`] reflects the step-up baseline:
///
/// | Trust level | Step-up factors required |
/// |-------------|--------------------------|
/// | `Unknown` | `[Totp]` (a possession factor) |
/// | `Seen` | `[Totp]` |
/// | `Trusted` | `[Totp]` |
/// | `Revoked` | `[Totp]`, and never less than the `Unknown` list |
///
/// The default lists TOTP only, so it does not change with compile-time
/// features. Override via [`StepUpPolicy::builder`] to add
/// `FactorKind::Fido2`, or when your tenant's policy otherwise differs (e.g.
/// tighter for high-value users, looser for known internal-network ranges, …).
///
/// # A device is recognised by a hint, not proven
///
/// A device is matched by a fingerprint of request headers and the client
/// address, all of which the client chooses. Someone who has a user's
/// password can send the same headers from the same network range and be
/// matched to that user's `Trusted` device. That is why the default asks
/// for a factor on a `Trusted` device too: skipping step-up there trusts
/// the fingerprint to be unforgeable. Set `trusted` to an empty list
/// ([`StepUpPolicyBuilder::trusted`]) only where a second signal that the
/// client cannot copy, such as a device certificate or an app-held key,
/// backs the match.
///
/// # A `Revoked` device never steps up less than an `Unknown` one
///
/// An empty `revoked` list does not mean "no step-up": a revoked device is
/// judged with the `Unknown` list, so a policy that sets `revoked` to
/// nothing cannot let a revoked device through more easily than a stranger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepUpPolicy {
    /// Factor kinds accepted for an `Unknown` device. Empty = no
    /// step-up required.
    pub unknown: Vec<FactorKind>,
    /// Factor kinds accepted for a `Seen` device. Empty = no
    /// step-up required.
    pub seen: Vec<FactorKind>,
    /// Factor kinds accepted for a `Trusted` device. Empty = no step-up
    /// on a trusted device, which is only as safe as the device match is
    /// unforgeable (see the type docs); the default is non-empty.
    pub trusted: Vec<FactorKind>,
    /// Factor kinds accepted for a `Revoked` device. Empty means the
    /// `unknown` list applies, never "no step-up": a revoked device is
    /// not trusted, and login on one should be rejected before this helper
    /// runs.
    pub revoked: Vec<FactorKind>,
}

impl Default for StepUpPolicy {
    fn default() -> Self {
        Self {
            unknown: default_step_up_factors(),
            seen: default_step_up_factors(),
            trusted: default_step_up_factors(),
            revoked: default_step_up_factors(),
        }
    }
}

impl StepUpPolicy {
    /// Construct via the builder.
    ///
    /// Thin wrapper over [`StepUpPolicyBuilder::default`]: exists so
    /// callers don't have to import the builder type directly.
    /// `cargo-mutants` will flag the `builder -> Default::default()`
    /// mutant as behaviour-preserving; that's by design (the function
    /// has no observable behaviour beyond constructing the builder).
    /// Skip from sweeps via `.cargo-mutants.toml` if it becomes noisy.
    pub fn builder() -> StepUpPolicyBuilder {
        StepUpPolicyBuilder::default()
    }

    /// Borrow the factor list for a given trust level. Used by
    /// [`decide_step_up_for_user`]. An empty `revoked` list answers with the
    /// `unknown` list: a revoked device never steps up less than a stranger.
    pub fn for_level(&self, level: DeviceTrustLevel) -> &[FactorKind] {
        match level {
            DeviceTrustLevel::Unknown => &self.unknown,
            DeviceTrustLevel::Seen => &self.seen,
            DeviceTrustLevel::Trusted => &self.trusted,
            DeviceTrustLevel::Revoked if self.revoked.is_empty() => &self.unknown,
            DeviceTrustLevel::Revoked => &self.revoked,
        }
    }
}

fn default_step_up_factors() -> Vec<FactorKind> {
    // Possession factors per PSD2 RTS Art 4. We list TOTP only so
    // the default compiles without feature flags. Apps using FIDO2
    // should override via `StepUpPolicyBuilder::unknown`
    // / `::seen` to include `FactorKind::Fido2`; including it
    // conditionally here would split the default across feature
    // flags, making the StepUpPolicy shape depend on compile-time
    // configuration.
    vec![FactorKind::Totp]
}

/// Builder for [`StepUpPolicy`].
#[derive(Debug, Default, Clone)]
pub struct StepUpPolicyBuilder {
    unknown: Option<Vec<FactorKind>>,
    seen: Option<Vec<FactorKind>>,
    trusted: Option<Vec<FactorKind>>,
    revoked: Option<Vec<FactorKind>>,
}

impl StepUpPolicyBuilder {
    /// Override the factor list for `Unknown` devices.
    pub fn unknown(mut self, factors: Vec<FactorKind>) -> Self {
        self.unknown = Some(factors);
        self
    }
    /// Override the factor list for `Seen` devices.
    pub fn seen(mut self, factors: Vec<FactorKind>) -> Self {
        self.seen = Some(factors);
        self
    }
    /// Override the factor list for `Trusted` devices. The default asks for
    /// a factor; an empty list lets a trusted device skip step-up, which
    /// trusts the device match (a hint that the client controls) to be
    /// unforgeable. Do that only with a second signal the client cannot
    /// copy.
    pub fn trusted(mut self, factors: Vec<FactorKind>) -> Self {
        self.trusted = Some(factors);
        self
    }
    /// Override the factor list for `Revoked` devices. An empty list means
    /// the `unknown` list applies; login on a revoked device should be
    /// rejected before step-up policy evaluates.
    pub fn revoked(mut self, factors: Vec<FactorKind>) -> Self {
        self.revoked = Some(factors);
        self
    }
    /// Finalise the [`StepUpPolicy`]. Unset slots fall back to the
    /// default for that trust level.
    pub fn build(self) -> StepUpPolicy {
        let d = StepUpPolicy::default();
        StepUpPolicy {
            unknown: self.unknown.unwrap_or(d.unknown),
            seen: self.seen.unwrap_or(d.seen),
            trusted: self.trusted.unwrap_or(d.trusted),
            revoked: self.revoked.unwrap_or(d.revoked),
        }
    }
}

/// Pure decision: given a resolved [`Device`], the user who is logging in
/// and a [`StepUpPolicy`], return the list of step-up factor options the
/// application should present, or `None` when no step-up is required.
///
/// Wraps [`StepUpPolicy::for_level`] with the empty-vec → `None`
/// translation so callers don't have to write the conditional twice.
///
/// A device owned by a different user counts as [`DeviceTrustLevel::Unknown`]:
/// its trust was earned by someone else and does not carry over. An
/// unowned device, or one the user owns, is judged by its own level.
pub fn decide_step_up_for_user(
    device: &Device,
    user: &UserId,
    policy: &StepUpPolicy,
) -> Option<Vec<FactorKind>> {
    let owned_by_someone_else = device.user_id.as_ref().is_some_and(|owner| owner != user);
    let level = if owned_by_someone_else {
        DeviceTrustLevel::Unknown
    } else {
        device.trust_level
    };
    factors_or_none(policy.for_level(level))
}

/// [`decide_step_up_for_user`] for a request that may have no device at all.
///
/// A request the device layer could not fingerprint (it sent no
/// `User-Agent`, or the device store was unavailable) resolves to no device.
/// That is not a reason to skip step-up: a client chooses whether to send
/// the header, so "no device" is judged as an `Unknown` one, with the
/// policy's `unknown` factors.
pub fn decide_step_up_for_optional(
    device: Option<&Device>,
    user: &UserId,
    policy: &StepUpPolicy,
) -> Option<Vec<FactorKind>> {
    match device {
        Some(device) => decide_step_up_for_user(device, user, policy),
        None => factors_or_none(policy.for_level(DeviceTrustLevel::Unknown)),
    }
}

/// `Some(factors)` for a non-empty list, `None` for "no step-up".
fn factors_or_none(factors: &[FactorKind]) -> Option<Vec<FactorKind>> {
    if factors.is_empty() {
        None
    } else {
        Some(factors.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::types::FingerprintHash;
    use chrono::{TimeZone, Utc};

    fn build_device(level: DeviceTrustLevel) -> Device {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        Device {
            id: crate::authn::ids::testing::device("d"),
            tenant_id: crate::authn::ids::testing::tenant("t"),
            user_id: Some(crate::authn::ids::testing::user("u")),
            trust_level: level,
            fingerprint_hash: FingerprintHash::from_bytes([0u8; 32]),
            first_seen_at: now,
            last_seen_at: now,
            revoked_at: None,
            demoted_at: None,
            bindings: Vec::new(),
        }
    }

    fn owner() -> UserId {
        crate::authn::ids::testing::user("u")
    }

    /// Pin: the default policy demands a factor at every trust level. A
    /// `Trusted` device is matched by a fingerprint the client controls, so
    /// copying the headers must not skip step-up; a `Revoked` device never
    /// steps up less than a stranger.
    #[test]
    fn default_policy_step_up_matrix() {
        let p = StepUpPolicy::default();
        for level in [
            DeviceTrustLevel::Unknown,
            DeviceTrustLevel::Seen,
            DeviceTrustLevel::Trusted,
            DeviceTrustLevel::Revoked,
        ] {
            assert_eq!(
                decide_step_up_for_user(&build_device(level), &owner(), &p),
                Some(vec![FactorKind::Totp]),
                "{level:?}"
            );
        }
    }

    /// Skipping step-up on a trusted device is an explicit choice.
    #[test]
    fn an_empty_trusted_list_skips_step_up_only_when_asked_for() {
        let p = StepUpPolicy::builder().trusted(Vec::new()).build();
        assert!(
            decide_step_up_for_user(&build_device(DeviceTrustLevel::Trusted), &owner(), &p)
                .is_none()
        );
        assert!(
            decide_step_up_for_user(&build_device(DeviceTrustLevel::Unknown), &owner(), &p)
                .is_some()
        );
    }

    /// An empty `revoked` list does not wave a revoked device through: it
    /// is judged with the `unknown` list.
    #[test]
    fn an_empty_revoked_list_falls_back_to_the_unknown_list() {
        let p = StepUpPolicy::builder()
            .unknown(vec![FactorKind::EmailOtp])
            .revoked(Vec::new())
            .build();
        assert_eq!(
            decide_step_up_for_user(&build_device(DeviceTrustLevel::Revoked), &owner(), &p),
            Some(vec![FactorKind::EmailOtp])
        );
        // With nothing required of strangers either, nothing is required.
        let open = StepUpPolicy::builder()
            .unknown(Vec::new())
            .revoked(Vec::new())
            .build();
        assert!(
            decide_step_up_for_user(&build_device(DeviceTrustLevel::Revoked), &owner(), &open)
                .is_none()
        );
    }

    /// A request with no resolved device is judged as an unknown one.
    #[test]
    fn no_device_is_judged_as_unknown() {
        let p = StepUpPolicy::default();
        assert_eq!(
            decide_step_up_for_optional(None, &owner(), &p),
            Some(vec![FactorKind::Totp])
        );
        let device = build_device(DeviceTrustLevel::Trusted);
        let relaxed = StepUpPolicy::builder().trusted(Vec::new()).build();
        assert!(decide_step_up_for_optional(Some(&device), &owner(), &relaxed).is_none());
        assert!(decide_step_up_for_optional(None, &owner(), &relaxed).is_some());
    }

    /// Pin: builder overrides. A tenant tightening policy on Trusted
    /// devices gets the override applied.
    #[test]
    fn builder_overrides_trusted_to_require_step_up() {
        let p = StepUpPolicy::builder()
            .trusted(vec![FactorKind::EmailOtp])
            .build();
        let factors =
            decide_step_up_for_user(&build_device(DeviceTrustLevel::Trusted), &owner(), &p);
        assert_eq!(factors, Some(vec![FactorKind::EmailOtp]));
    }

    /// Pin: empty factor lists translate to `None` even if explicitly
    /// configured. "No step-up needed" must mean the wrapper returns
    /// `None` so the caller can pass through to `FactorRequired`.
    #[test]
    fn empty_factor_list_produces_none() {
        let p = StepUpPolicy::builder().unknown(Vec::new()).build();
        assert!(
            decide_step_up_for_user(&build_device(DeviceTrustLevel::Unknown), &owner(), &p)
                .is_none()
        );
    }

    /// Pin: `for_level` returns the configured slice for each trust
    /// level; used by the docs example and by callers that want to
    /// inspect the policy without invoking the wrapper.
    #[test]
    fn for_level_returns_configured_slice() {
        let p = StepUpPolicy::builder()
            .seen(vec![FactorKind::EmailOtp])
            .build();
        assert_eq!(p.for_level(DeviceTrustLevel::Seen), &[FactorKind::EmailOtp]);
    }

    /// Pin: builder Default is the identity: building an unmodified
    /// builder produces the same `StepUpPolicy::default()`.
    #[test]
    fn unmodified_builder_equals_default() {
        let built = StepUpPolicy::builder().build();
        assert_eq!(built, StepUpPolicy::default());
    }

    /// mutant kill: `StepUpPolicyBuilder::revoked` was missed by
    /// the original test set because every example used `Trusted` or
    /// `Unknown` as the override target. Exercise the `revoked` setter
    /// explicitly so a no-op replacement of its body cannot survive.
    #[test]
    fn revoked_builder_setter_threads_through_to_build() {
        let p = StepUpPolicy::builder()
            .revoked(vec![FactorKind::Totp])
            .build();
        assert_eq!(p.revoked, vec![FactorKind::Totp]);
        // And confirm the rest of the policy stayed at defaults; a
        // mutated `revoked` setter that smashed sibling fields would
        // change those too.
        assert_eq!(p.unknown, default_step_up_factors());
        assert_eq!(p.seen, default_step_up_factors());
        assert_eq!(p.trusted, default_step_up_factors());
    }

    /// A device owned by someone else is Unknown to the user logging in,
    /// whatever trust it earned for its owner.
    #[test]
    fn foreign_trusted_device_is_treated_as_unknown() {
        let device = build_device(DeviceTrustLevel::Trusted);
        let owner = crate::authn::ids::testing::user("u");
        let other = crate::authn::ids::testing::user("someone-else");
        // Under a policy that lets a trusted device skip step-up, the owner
        // skips it and the other user does not.
        let p = StepUpPolicy::builder().trusted(Vec::new()).build();
        assert!(decide_step_up_for_user(&device, &owner, &p).is_none());
        assert_eq!(
            decide_step_up_for_user(&device, &other, &p),
            Some(p.for_level(DeviceTrustLevel::Unknown).to_vec())
        );
        let mut unowned = build_device(DeviceTrustLevel::Trusted);
        unowned.user_id = None;
        assert!(decide_step_up_for_user(&unowned, &other, &p).is_none());
    }
}
