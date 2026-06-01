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
//! let outcome = service.begin_login(identifier, tenant, &session, ip).await?;
//! let outcome = match outcome {
//!     LoginOutcome::FactorRequired(_) if let Some(device) = resolved_device => {
//!         match decide_step_up(&device, &policy) {
//!             Some(allowed_factors) => LoginOutcome::StepUpRequired {
//!                 device_id: device.id.clone(),
//!                 allowed_factors,
//!             },
//!             None => outcome,
//!         }
//!     }
//!     other => other,
//! };
//! ```
//!
//! axess does **not** reach into the device subsystem from
//! `begin_login`. `Device` resolution is a middleware concern
//! ([`SessionLayer::with_device_resolver`](crate::session::SessionLayer::with_device_resolver))
//! and the application owns the substitution above.
//!
//! [`Device`]: crate::device::types::Device

use crate::authn::factor::FactorKind;
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
/// | `Unknown` | `[Fido2, Totp]` (any one, possession factor) |
/// | `Seen` | `[Fido2, Totp]` |
/// | `Trusted` | _none_; Trusted devices skip step-up |
/// | `Revoked` | _none_; login should already be rejected upstream |
///
/// Override via [`StepUpPolicy::builder`] when your tenant's policy
/// differs (e.g. tighter for high-value users, looser for known
/// internal-network ranges, …).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepUpPolicy {
    /// Factor kinds accepted for an `Unknown` device. Empty = no
    /// step-up required.
    pub unknown: Vec<FactorKind>,
    /// Factor kinds accepted for a `Seen` device. Empty = no
    /// step-up required.
    pub seen: Vec<FactorKind>,
    /// Factor kinds accepted for a `Trusted` device. Almost always
    /// empty; the whole point of `Trusted` is "we don't need to
    /// step up." Non-empty is a tighter-than-baseline override.
    pub trusted: Vec<FactorKind>,
    /// Factor kinds accepted for a `Revoked` device. Almost always
    /// empty; login on a Revoked device should already be rejected
    /// before this helper runs.
    pub revoked: Vec<FactorKind>,
}

impl Default for StepUpPolicy {
    fn default() -> Self {
        Self {
            unknown: default_step_up_factors(),
            seen: default_step_up_factors(),
            trusted: Vec::new(),
            revoked: Vec::new(),
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
    /// [`decide_step_up`].
    pub fn for_level(&self, level: DeviceTrustLevel) -> &[FactorKind] {
        match level {
            DeviceTrustLevel::Unknown => &self.unknown,
            DeviceTrustLevel::Seen => &self.seen,
            DeviceTrustLevel::Trusted => &self.trusted,
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
    /// Override the factor list for `Trusted` devices. Almost always
    /// empty; set this only when your tenant runs tighter-than-
    /// baseline policy that requires step-up even on trusted
    /// hardware.
    pub fn trusted(mut self, factors: Vec<FactorKind>) -> Self {
        self.trusted = Some(factors);
        self
    }
    /// Override the factor list for `Revoked` devices. Almost always
    /// empty; login on a revoked device should be rejected before
    /// step-up policy evaluates.
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

/// Pure decision: given a resolved [`Device`] and a [`StepUpPolicy`],
/// return the list of step-up factor options the application should
/// present, or `None` when no step-up is required.
///
/// Wraps [`StepUpPolicy::for_level`] with the empty-vec → `None`
/// translation so callers don't have to write the conditional twice.
pub fn decide_step_up(device: &Device, policy: &StepUpPolicy) -> Option<Vec<FactorKind>> {
    let factors = policy.for_level(device.trust_level);
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
            bindings: Vec::new(),
        }
    }

    /// Pin: default policy demands step-up on `Unknown` and `Seen`,
    /// passes through silently on `Trusted` and `Revoked`.
    #[test]
    fn default_policy_step_up_matrix() {
        let p = StepUpPolicy::default();
        assert!(decide_step_up(&build_device(DeviceTrustLevel::Unknown), &p).is_some());
        assert!(decide_step_up(&build_device(DeviceTrustLevel::Seen), &p).is_some());
        assert!(decide_step_up(&build_device(DeviceTrustLevel::Trusted), &p).is_none());
        assert!(decide_step_up(&build_device(DeviceTrustLevel::Revoked), &p).is_none());
    }

    /// Pin: builder overrides. A tenant tightening policy on Trusted
    /// devices gets the override applied.
    #[test]
    fn builder_overrides_trusted_to_require_step_up() {
        let p = StepUpPolicy::builder()
            .trusted(vec![FactorKind::Totp])
            .build();
        let factors = decide_step_up(&build_device(DeviceTrustLevel::Trusted), &p);
        assert_eq!(factors, Some(vec![FactorKind::Totp]));
    }

    /// Pin: empty factor lists translate to `None` even if explicitly
    /// configured. "No step-up needed" must mean the wrapper returns
    /// `None` so the caller can pass through to `FactorRequired`.
    #[test]
    fn empty_factor_list_produces_none() {
        let p = StepUpPolicy::builder().unknown(Vec::new()).build();
        assert!(decide_step_up(&build_device(DeviceTrustLevel::Unknown), &p).is_none());
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
        assert!(p.trusted.is_empty());
    }
}
