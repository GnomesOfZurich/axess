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
    ///
    /// Answered by `begin_login` only when the service was built with
    /// [`with_lockout_revealed_on_begin`](crate::authn::AuthnServiceBuilder::with_lockout_revealed_on_begin);
    /// by default a locked account gets [`InvalidCredentials`](Self::InvalidCredentials),
    /// as an unknown identifier does, so the lock is not observable before
    /// any proof. The audit row says `Locked` either way.
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
    /// The variant is a label for the caller's UI and enforces nothing:
    /// the session is only held to a step-up once the application has called
    /// [`RequestAuthnService::begin_step_up`](super::RequestAuthnService::begin_step_up)
    /// on the authenticated session. Call it first, then show the prompt.
    ///
    /// axess does not emit this variant from
    /// [`RequestAuthnService::begin_login`](super::RequestAuthnService::begin_login)
    /// directly; `Device` resolution is a middleware concern
    /// ([`SessionLayer::with_device_resolver`](crate::session::SessionLayer::with_device_resolver))
    /// and the application substitutes the outcome per the wiring
    /// pattern documented on
    /// [`decide_step_up_for_user`](crate::authn::service::step_up::decide_step_up_for_user).
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
/// Returned by [`RequestAuthnService::prepare_factor`](super::RequestAuthnService::prepare_factor). Challenge-based factors
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
        /// The address the code went to, MASKED (`a***@example.com`), because
        /// this answer reaches a caller who has only typed a username and
        /// must not learn the address behind it.
        destination: Arc<str>,
    },
    /// A FIDO2/WebAuthn challenge was generated (placeholder for future use).
    Fido2Challenge {
        /// Opaque challenge data to forward to the browser's WebAuthn API.
        challenge: serde_json::Value,
    },
}

impl PrepareOutcome {
    /// The destination for display to the person logging in, masked
    /// (`a***@example.com`), or `None` for an outcome that has none.
    ///
    /// Show this and never `destination` itself: `SendOtp` carries the full
    /// address because the application needs it to deliver the code, but a
    /// login page is shown to someone who has only typed a username.
    pub fn masked_destination(&self) -> Option<Arc<str>> {
        match self {
            Self::SendOtp { destination, .. } => Some(mask_email(destination)),
            Self::AlreadySent { destination } => Some(mask_email(destination)),
            _ => None,
        }
    }
}

/// Mask an email address for display: the first character of the local part,
/// three asterisks, and the whole domain. Anything that is not shaped like
/// an address is masked entirely. Masking an already masked address leaves
/// it as it is.
pub(crate) fn mask_email(address: &str) -> Arc<str> {
    match address.split_once('@') {
        Some((local, domain)) if !local.is_empty() && !domain.is_empty() => {
            let first: String = local.chars().take(1).collect();
            Arc::from(format!("{first}***@{domain}"))
        }
        _ => Arc::from("***"),
    }
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
    /// Consecutive wrong guesses under this key (the account and the
    /// client address, by the tenant's
    /// [`LockoutPolicy::throttle`](crate::authn::types::LockoutPolicy::throttle))
    /// have earned a delay that has not run: the credential was not checked
    /// and nothing was counted. Answer it as a wrong credential to the
    /// person, with `retry_after` as `Retry-After` where the client reads
    /// headers; it says nothing a wrong guess did not already say.
    Throttled {
        /// How long until a guess under this key runs again.
        retry_after: std::time::Duration,
    },
}

/// The single-use secret that completes a signup, and when it stops working.
///
/// The session keeps only a digest of it. Hand it to the person through a
/// channel they alone read (a mailed link, a code); it is shown here once and
/// cannot be recovered from the session. `Debug` does not print it.
#[derive(Clone)]
pub struct SignupVerification {
    pub(crate) secret: zeroize::Zeroizing<String>,
    pub(crate) expires_at: chrono::DateTime<chrono::Utc>,
}

impl SignupVerification {
    /// The secret, URL-safe text of 43 characters (256 bits).
    pub fn secret(&self) -> &str {
        &self.secret
    }

    /// When `complete_signup` stops accepting the secret.
    pub fn expires_at(&self) -> chrono::DateTime<chrono::Utc> {
        self.expires_at
    }
}

impl std::fmt::Debug for SignupVerification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignupVerification")
            .field("secret", &"[redacted]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Result of beginning a signup flow.
#[derive(Debug)]
pub enum SignupOutcome {
    /// User account created, session moved to `PendingWorkflow(Signup)`.
    /// The application should now send a verification email or similar.
    ///
    /// With the default hidden conflicts this is also the answer for an
    /// identifier that was already taken: nothing was created and the session
    /// stays anonymous. So `Started` alone does not mean an account was made.
    /// Read [`AuthSession::pending_user_id`](crate::session::AuthSession::pending_user_id):
    /// `None` means the identifier was taken, and the handler must not send a
    /// verification mail or say anything the caller could tell apart from a
    /// success (the same page, the same timing as far as it can).
    ///
    /// The payload is the verification secret of the signup now in flight:
    /// `Some` when an account is pending (a new one, or this session's own
    /// signup submitted again, which replaces the earlier secret), `None`
    /// when the identifier was taken. Mail the secret to the address the
    /// person gave and pass it to
    /// [`complete_signup`](crate::authn::service::RequestAuthnService::complete_signup)
    /// when they return with it.
    Started(Option<SignupVerification>),
    /// A user with this identifier already exists in the tenant.
    AlreadyExists,
    /// The target tenant does not exist or is not active.
    TenantNotActive,
}
