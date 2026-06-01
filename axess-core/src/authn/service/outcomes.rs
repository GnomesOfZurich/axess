//! Outcome types returned by [`AuthnService`](super::AuthnService) methods.

use crate::authn::factor::FactorKind;
use crate::authn::ids::DeviceId;
use std::sync::Arc;

/// Result of beginning a login attempt.
#[derive(Debug)]
pub enum LoginOutcome {
    /// The first factor is required: session is now `Authenticating`.
    /// Call `prepare_factor` then present the factor UI.
    FactorRequired(FactorKind),
    /// The account is locked out.
    Locked {
        /// Wall-clock instant at which the lockout expires, or `None` for an indefinite lockout.
        until: Option<chrono::DateTime<chrono::Utc>>,
    },
    /// Bad credentials. Deliberately vague: do NOT distinguish user-not-found
    /// from wrong-password to prevent user enumeration.
    InvalidCredentials,
    /// Step-up authentication is required before the factor UI is
    /// presented. The application's `Device` resolver classified the
    /// requesting device as needing a fresh strong-customer-
    /// authentication ceremony (PSD2 RTS Art 4 / NIST SP 800-63B-4
    /// §5.2.6) and the configured
    /// [`StepUpPolicy`](crate::authn::service::step_up::StepUpPolicy)
    /// returned a non-empty factor set.
    ///
    /// axess does not emit this variant from
    /// [`AuthnService::begin_login`](super::AuthnService::begin_login)
    /// directly; `Device` resolution is a middleware concern
    /// ([`SessionLayer::with_device_resolver`](crate::session::SessionLayer::with_device_resolver))
    /// and the application substitutes the outcome per the wiring
    /// pattern documented on
    /// [`decide_step_up`](crate::authn::service::step_up::decide_step_up).
    ///
    /// `allowed_factors` is the set the application may accept as
    /// proof of step-up (typical: `[Fido2, Totp]`, a possession
    /// factor). The application chooses one and drives it through
    /// the normal `prepare_factor` / `verify_factor` flow.
    StepUpRequired {
        /// The device the step-up applies to. Stable id from
        /// [`Device::id`](crate::device::types::Device::id) so
        /// the application can audit the decision and the eventual
        /// `DeviceTrustGranted` transition together.
        device_id: DeviceId,
        /// Factor kinds the application accepts as proof of fresh
        /// SCA on this device. Non-empty by construction (an empty
        /// set means "no step-up required" and would be folded into
        /// `FactorRequired` by the caller).
        allowed_factors: Vec<FactorKind>,
    },
}

/// Result of preparing a factor challenge.
///
/// Returned by [`AuthnService::prepare_factor`](super::AuthnService::prepare_factor). Challenge-based factors
/// (EmailOtp, Fido2) return data the application must act on, e.g. sending
/// an email or forwarding a WebAuthn challenge to the browser. Simple factors
/// (Password, TOTP, HOTP) are always [`Ready`](PrepareOutcome::Ready).
pub enum PrepareOutcome {
    /// No preparation needed: the UI can present the input form immediately.
    Ready,
    /// An OTP code was generated and stored. The application must deliver it
    /// to the user via the indicated channel (email address).
    ///
    /// The `code` is plaintext; the hashed version is already persisted in the
    /// factor store. After delivery, the application calls `verify_factor` with
    /// the code the user enters.
    SendOtp {
        /// The plaintext OTP code to deliver. Zeroized on drop to minimize
        /// the window during which the code is recoverable from memory.
        code: crate::authn::factor::ZeroizedString,
        /// Where to send it (email address for EmailOtp).
        destination: Arc<str>,
    },
    /// A challenge was already sent and hasn't expired yet (cooldown active).
    /// The application should show a "code already sent" message rather than
    /// sending a new one.
    AlreadySent {
        /// Where the code was sent (email address for EmailOtp).
        destination: Arc<str>,
    },
    /// A FIDO2/WebAuthn challenge was generated (placeholder for future use).
    Fido2Challenge {
        /// Opaque challenge data to forward to the browser's WebAuthn API.
        challenge: serde_json::Value,
    },
}

impl std::fmt::Debug for PrepareOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ready => write!(f, "Ready"),
            Self::SendOtp { destination, .. } => f
                .debug_struct("SendOtp")
                .field("code", &"***")
                .field("destination", destination)
                .finish(),
            Self::AlreadySent { destination } => f
                .debug_struct("AlreadySent")
                .field("destination", destination)
                .finish(),
            Self::Fido2Challenge { .. } => f.debug_struct("Fido2Challenge").finish_non_exhaustive(),
        }
    }
}

#[cfg(test)]
mod outcomes_tests {
    use super::*;

    /// `LoginOutcome::StepUpRequired` carries the resolved
    /// `device_id` and a non-empty `allowed_factors` set. Pin that
    /// the variant constructs, pattern-matches by field name, and
    /// surfaces the typed payload to callers.
    #[test]
    fn login_outcome_step_up_required_carries_device_id_and_factors() {
        use crate::authn::ids::testing as id_fixtures;
        let device_id = id_fixtures::device("d-step-up");
        let outcome = LoginOutcome::StepUpRequired {
            device_id,
            allowed_factors: vec![FactorKind::Totp],
        };
        match outcome {
            LoginOutcome::StepUpRequired {
                device_id: got_id,
                allowed_factors,
            } => {
                assert_eq!(got_id, device_id);
                assert_eq!(allowed_factors, vec![FactorKind::Totp]);
            }
            other => panic!("expected StepUpRequired, got {other:?}"),
        }
    }

    /// Pins `<impl Debug for PrepareOutcome>::fmt` body
    /// against `Ok(Default::default())` (effectively `Ok(())` writing
    /// nothing). The redaction-aware Debug surface MUST emit the
    /// variant name and the destination field; a no-op formatter
    /// would return an empty string, masking debug output for
    /// post-mortems.
    #[test]
    fn prepare_outcome_debug_redacts_code_and_includes_variant_and_destination() {
        let ready = format!("{:?}", PrepareOutcome::Ready);
        assert_eq!(ready, "Ready", "Ready variant must format as the bare name");

        let send_otp = format!(
            "{:?}",
            PrepareOutcome::SendOtp {
                code: crate::authn::factor::ZeroizedString::new("12345678"),
                destination: Arc::from("user@example.com"),
            }
        );
        assert!(
            send_otp.contains("SendOtp"),
            "SendOtp variant name must appear"
        );
        assert!(
            send_otp.contains("user@example.com"),
            "destination must appear (got {send_otp:?})"
        );
        assert!(
            !send_otp.contains("12345678"),
            "plaintext code must NOT appear in Debug output (got {send_otp:?})"
        );
        assert!(
            send_otp.contains("***"),
            "redacted placeholder must appear (got {send_otp:?})"
        );

        let already_sent = format!(
            "{:?}",
            PrepareOutcome::AlreadySent {
                destination: Arc::from("alt@example.com"),
            }
        );
        assert!(already_sent.contains("AlreadySent"));
        assert!(already_sent.contains("alt@example.com"));

        let fido2 = format!(
            "{:?}",
            PrepareOutcome::Fido2Challenge {
                challenge: serde_json::json!({"opaque": true}),
            }
        );
        assert!(fido2.contains("Fido2Challenge"));
        assert!(
            !fido2.contains("opaque"),
            "Debug surface must use finish_non_exhaustive to avoid leaking challenge contents (got {fido2:?})"
        );
    }
}

/// Result of verifying a factor step.
#[derive(Debug)]
pub enum FactorOutcome {
    /// This was the last factor; session is now `Authenticated`.
    Authenticated,
    /// More factors remain: present the next factor UI.
    FactorRequired(FactorKind),
    /// The credential was wrong.
    InvalidCredential,
    /// Too many failed attempts: the account is now locked.
    Locked {
        /// Wall-clock instant at which the lockout expires, or `None` for an indefinite lockout.
        until: Option<chrono::DateTime<chrono::Utc>>,
    },
}

/// Result of beginning a signup flow.
#[derive(Debug)]
pub enum SignupOutcome {
    /// User account created, session moved to `PendingWorkflow(Signup)`.
    /// The application should now send a verification email or similar.
    Started,
    /// A user with this identifier already exists in the tenant.
    AlreadyExists,
    /// The target tenant does not exist or is not active.
    TenantNotActive,
}
