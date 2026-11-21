//! The security profile a service runs under: recorded on the builder when
//! a profile is applied, and held when the service is built.
//!
//! [`ProfileValues::authn_service_builder`](crate::profile::ProfileValues::authn_service_builder)
//! tightens the builder and records the profile it came from. From then on
//! the profile is a property of the service, not of that one call:
//! [`AuthnServiceBuilder::try_build`] refuses a setting looser than the
//! profile's value, whichever setter wrote it and whenever, unless the
//! caller named that setting with
//! [`waive_profile_floor`](AuthnServiceBuilder::waive_profile_floor). A
//! waived setting that is below its floor is a deviation: it is logged once
//! when the service is built and read back from it with
//! [`AuthnService::profile_deviations`](crate::authn::service::AuthnService::profile_deviations).

use std::time::Duration;

use super::AuthnServiceBuilder;
use crate::authn::store::{FactorStore, IdentityStore};
use crate::profile::SecurityProfile;

/// A setting of the authentication service that a security profile governs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProfileSetting {
    /// The Argon2id cost of new password hashes (`with_argon2_cost`): at
    /// least the profile's memory and passes.
    Argon2Cost,
    /// The longest lifetime a password reset token may be given
    /// (`with_max_password_reset_ttl`): at most the profile's.
    MaxPasswordResetTtl,
    /// The default lifetime of a password reset token
    /// (`with_password_reset_ttl`): at most the profile's, when both name
    /// one.
    PasswordResetTtl,
    /// How recently an administrator must have authenticated to impersonate
    /// (`with_impersonation_max_authn_age`): a limit, at most the profile's.
    ImpersonationMaxAuthnAge,
    /// How recently a session must have authenticated to change a passkey
    /// (`Fido2Options::max_authn_age`): a limit, at most the profile's.
    Fido2MaxAuthnAge,
}

impl ProfileSetting {
    /// Every setting the service holds for a profile, in the order
    /// [`AuthnServiceBuilder::validate`] checks them.
    pub const ALL: [Self; 5] = [
        Self::Argon2Cost,
        Self::MaxPasswordResetTtl,
        Self::PasswordResetTtl,
        Self::ImpersonationMaxAuthnAge,
        Self::Fido2MaxAuthnAge,
    ];

    /// The name of the `ProfileValues` field that holds the profile's value.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Argon2Cost => "argon2_cost",
            Self::MaxPasswordResetTtl => "max_password_reset_ttl",
            Self::PasswordResetTtl => "password_reset_ttl",
            Self::ImpersonationMaxAuthnAge => "impersonation_max_authn_age",
            Self::Fido2MaxAuthnAge => "fido2_max_authn_age",
        }
    }
}

impl std::fmt::Display for ProfileSetting {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Why [`AuthnServiceBuilder::try_build`] refused to build a service.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthnBuildError {
    /// The default password reset lifetime is above the cap on reset
    /// lifetimes: every reset under the default lifetime would be refused
    /// when requested. Shorten the lifetime or raise the cap.
    #[error(
        "the default password reset lifetime (with_password_reset_ttl, {ttl:?}) is above the \
         cap on reset lifetimes (with_max_password_reset_ttl, {cap:?}): every reset under the \
         default lifetime would be refused"
    )]
    PasswordResetTtlAboveCap {
        /// The default lifetime.
        ttl: Duration,
        /// The cap.
        cap: Duration,
    },
    /// A setting is looser than the security profile the builder was put
    /// under, and the caller did not waive it. Tighten the setting, or name
    /// the exception with
    /// [`waive_profile_floor`](AuthnServiceBuilder::waive_profile_floor).
    #[error(
        "{setting} is looser than SecurityProfile::{profile:?} allows: it is {found}, and the \
         profile's is {floor}; tighten it, or name the exception with \
         waive_profile_floor(ProfileSetting::{setting:?})"
    )]
    BelowProfileFloor {
        /// The profile the builder was put under.
        profile: SecurityProfile,
        /// The setting that is looser than the profile's.
        setting: ProfileSetting,
        /// The value the builder holds, as text.
        found: String,
        /// The profile's value, as text.
        floor: String,
    },
}

/// What a builder knows of the profile it was put under.
#[derive(Debug, Clone, Default)]
pub(crate) struct ProfileRecord {
    /// The profile applied, the stricter one when several were.
    applied: Option<SecurityProfile>,
    /// The settings the caller waived by name.
    waived: Vec<ProfileSetting>,
    /// The waived settings that are below their floor, settled at build.
    deviations: Vec<ProfileSetting>,
}

/// A limit as an error message carries it.
fn limit_text(limit: Option<Duration>) -> String {
    limit.map_or_else(|| "no limit".to_owned(), |limit| format!("{limit:?}"))
}

/// Whether `value` is a limit at most `floor`; a value with no limit is not.
fn within_limit(value: Option<Duration>, floor: Duration) -> bool {
    value.is_some_and(|value| value <= floor)
}

impl<I, F> AuthnServiceBuilder<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Put the builder under `profile`: every setting the profile governs
    /// must hold the profile's value or a tighter one when the service is
    /// built. A builder already under a profile keeps the stricter of the
    /// two.
    pub(crate) fn under_profile(mut self, profile: SecurityProfile) -> Self {
        let stricter = match (self.profile.applied, profile) {
            (Some(SecurityProfile::Strict), _) | (_, SecurityProfile::Strict) => {
                SecurityProfile::Strict
            }
            (_, SecurityProfile::Standard) => SecurityProfile::Standard,
        };
        self.profile.applied = Some(stricter);
        self
    }

    /// The security profile this builder was put under by
    /// [`ProfileValues::authn_service_builder`](crate::profile::ProfileValues::authn_service_builder),
    /// if any: the stricter one when several were applied.
    #[must_use]
    pub fn security_profile(&self) -> Option<SecurityProfile> {
        self.profile.applied
    }

    /// Let `setting` be looser than the security profile's value: the one
    /// way below a profile's floor, written out by name.
    ///
    /// Without it, [`try_build`](Self::try_build) refuses a setting looser
    /// than the profile the builder is under. With it, the setting may hold
    /// any value; when that value is below the floor the service is built,
    /// says so once at `warn`, and lists the setting in
    /// [`AuthnService::profile_deviations`](crate::authn::service::AuthnService::profile_deviations).
    /// A waiver for a setting that holds its floor changes nothing, and so
    /// does one on a builder under no profile. It can be written before or
    /// after the profile is applied.
    #[must_use]
    pub fn waive_profile_floor(mut self, setting: ProfileSetting) -> Self {
        if !self.profile.waived.contains(&setting) {
            self.profile.waived.push(setting);
        }
        self
    }

    /// The settings the built service holds below its security profile's
    /// floor: each was waived by name. Empty before the service is built.
    pub(crate) fn profile_deviations(&self) -> &[ProfileSetting] {
        &self.profile.deviations
    }

    /// What [`try_build`](Self::try_build) would refuse, without building:
    /// a default reset lifetime above the cap, then the first setting (in
    /// the order of [`ProfileSetting::ALL`]) that is looser than the
    /// security profile the builder is under and was not waived.
    ///
    /// # Errors
    ///
    /// The refusal.
    pub fn validate(&self) -> Result<(), AuthnBuildError> {
        if let Some(ttl) = self.hardening.password_reset_ttl
            && ttl > self.hardening.max_password_reset_ttl
        {
            return Err(AuthnBuildError::PasswordResetTtlAboveCap {
                ttl,
                cap: self.hardening.max_password_reset_ttl,
            });
        }
        match self
            .below_floor()
            .into_iter()
            .find(|below| !self.profile.waived.contains(&below.setting))
        {
            Some(below) => Err(below.into_error()),
            None => Ok(()),
        }
    }

    /// Settle the profile record for the built service: refuse what
    /// [`validate`](Self::validate) refuses, record the waived settings that
    /// are below their floor, and say once what the service runs under.
    pub(super) fn settle_profile(&mut self) -> Result<(), AuthnBuildError> {
        self.validate()?;
        let Some(profile) = self.profile.applied else {
            return Ok(());
        };
        let below = self.below_floor();
        for below in &below {
            tracing::warn!(
                profile = ?profile,
                setting = %below.setting,
                value = %below.found,
                profile_value = %below.floor,
                "AuthnService holds a setting below its security profile, by a named waiver"
            );
        }
        self.profile.deviations = below.iter().map(|below| below.setting).collect();
        tracing::info!(
            profile = ?profile,
            deviations = self.profile.deviations.len(),
            "AuthnService built under a security profile"
        );
        Ok(())
    }

    /// Every governed setting that is looser than the applied profile's
    /// value, waived or not, in the order of [`ProfileSetting::ALL`]. Empty
    /// under no profile.
    fn below_floor(&self) -> Vec<BelowFloor> {
        let Some(profile) = self.profile.applied else {
            return Vec::new();
        };
        let floor = profile.values();
        let hardening = &self.hardening;
        let mut below = Vec::new();
        let mut note = |setting, found: String, most: String| {
            below.push(BelowFloor {
                profile,
                setting,
                found,
                floor: most,
            });
        };
        if !hardening.argon2_cost.is_at_least(floor.argon2_cost) {
            note(
                ProfileSetting::Argon2Cost,
                format!("{:?}", hardening.argon2_cost),
                format!("{:?}", floor.argon2_cost),
            );
        }
        if hardening.max_password_reset_ttl > floor.max_password_reset_ttl {
            note(
                ProfileSetting::MaxPasswordResetTtl,
                format!("{:?}", hardening.max_password_reset_ttl),
                format!("{:?}", floor.max_password_reset_ttl),
            );
        }
        // A builder with no default lifetime issues none: only a default
        // longer than the profile's is looser.
        if let (Some(own), Some(most)) = (hardening.password_reset_ttl, floor.password_reset_ttl)
            && own > most
        {
            note(
                ProfileSetting::PasswordResetTtl,
                format!("{own:?}"),
                format!("{most:?}"),
            );
        }
        if let Some(most) = floor.impersonation_max_authn_age
            && !within_limit(hardening.impersonation_max_authn_age, most)
        {
            note(
                ProfileSetting::ImpersonationMaxAuthnAge,
                limit_text(hardening.impersonation_max_authn_age),
                format!("{most:?}"),
            );
        }
        #[cfg(feature = "fido2")]
        if let Some(most) = floor.fido2_max_authn_age
            && !within_limit(self.fido2_options.max_authn_age, most)
        {
            note(
                ProfileSetting::Fido2MaxAuthnAge,
                limit_text(self.fido2_options.max_authn_age),
                format!("{most:?}"),
            );
        }
        below
    }
}

/// One governed setting found looser than the profile's value.
struct BelowFloor {
    profile: SecurityProfile,
    setting: ProfileSetting,
    found: String,
    floor: String,
}

impl BelowFloor {
    fn into_error(self) -> AuthnBuildError {
        AuthnBuildError::BelowProfileFloor {
            profile: self.profile,
            setting: self.setting,
            found: self.found,
            floor: self.floor,
        }
    }
}
