//! The errors of the Workload API client.
//!
//! Text that came from the agent (a gRPC status message, a SPIFFE ID, a
//! parser's complaint about a certificate) is escaped and cut by
//! [`log_safe`] before it is put into an error, so an error can be logged
//! as it is.

use std::time::Duration;

use axess_factors::log_text::log_safe;
use axess_identity::TrustDomain;

use super::proto::ProtoError;
use super::wire::WireError;
use crate::metrics::WorkloadCredentialKind;

/// The most bytes of the agent's text one error keeps.
pub(crate) const REMOTE_TEXT_BYTES: usize = 256;

/// Text the agent wrote, made safe for an error message.
pub(crate) fn remote_text(text: &str) -> String {
    log_safe(text, REMOTE_TEXT_BYTES)
}

/// A gRPC status code, as the agent reports the outcome of a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GrpcCode {
    /// 1: the call was cancelled.
    Cancelled,
    /// 2: an error the agent did not classify, and any code this client
    /// does not know.
    Unknown,
    /// 3: the request was refused as written. The Workload API answers
    /// this to a call without the `workload.spiffe.io` metadata.
    InvalidArgument,
    /// 4: the agent gave up waiting.
    DeadlineExceeded,
    /// 5: what was asked for does not exist.
    NotFound,
    /// 6: what was to be created exists already.
    AlreadyExists,
    /// 7: the agent has no identity for this workload: no registration
    /// entry matches it, or none has reached the agent yet.
    PermissionDenied,
    /// 8: a quota or a limit was reached.
    ResourceExhausted,
    /// 9: the agent is not in a state to answer.
    FailedPrecondition,
    /// 10: the call was aborted.
    Aborted,
    /// 11: a value was out of range.
    OutOfRange,
    /// 12: the agent does not implement the method.
    Unimplemented,
    /// 13: an internal error of the agent.
    Internal,
    /// 14: the agent is not available, which a retry may cure.
    Unavailable,
    /// 15: data was lost.
    DataLoss,
    /// 16: the caller is not authenticated.
    Unauthenticated,
}

impl GrpcCode {
    /// The code for a non-zero `grpc-status` value; a value outside the
    /// defined range reads as [`GrpcCode::Unknown`].
    pub fn from_status(status: u32) -> Self {
        match status {
            1 => Self::Cancelled,
            3 => Self::InvalidArgument,
            4 => Self::DeadlineExceeded,
            5 => Self::NotFound,
            6 => Self::AlreadyExists,
            7 => Self::PermissionDenied,
            8 => Self::ResourceExhausted,
            9 => Self::FailedPrecondition,
            10 => Self::Aborted,
            11 => Self::OutOfRange,
            12 => Self::Unimplemented,
            13 => Self::Internal,
            14 => Self::Unavailable,
            15 => Self::DataLoss,
            16 => Self::Unauthenticated,
            _ => Self::Unknown,
        }
    }

    /// The code's name as gRPC writes it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cancelled => "CANCELLED",
            Self::Unknown => "UNKNOWN",
            Self::InvalidArgument => "INVALID_ARGUMENT",
            Self::DeadlineExceeded => "DEADLINE_EXCEEDED",
            Self::NotFound => "NOT_FOUND",
            Self::AlreadyExists => "ALREADY_EXISTS",
            Self::PermissionDenied => "PERMISSION_DENIED",
            Self::ResourceExhausted => "RESOURCE_EXHAUSTED",
            Self::FailedPrecondition => "FAILED_PRECONDITION",
            Self::Aborted => "ABORTED",
            Self::OutOfRange => "OUT_OF_RANGE",
            Self::Unimplemented => "UNIMPLEMENTED",
            Self::Internal => "INTERNAL",
            Self::Unavailable => "UNAVAILABLE",
            Self::DataLoss => "DATA_LOSS",
            Self::Unauthenticated => "UNAUTHENTICATED",
        }
    }
}

impl std::fmt::Display for GrpcCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why the Workload API client could not serve what was asked.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SpireError {
    /// The endpoint address is not one the Workload API allows.
    #[error("workload API endpoint refused: {0}")]
    Endpoint(String),
    /// The call was refused before it was sent: what was asked for is not
    /// something the Workload API can be asked.
    #[error("workload API request refused: {0}")]
    Request(String),
    /// The agent's socket could not be reached: no agent is listening, the
    /// path does not exist, or the connection was refused.
    #[error("workload API connection failed: {0}")]
    Connect(String),
    /// The connection or the stream failed after it was opened.
    #[error("workload API transport failed: {0}")]
    Transport(String),
    /// The agent answered the call with a gRPC status other than OK.
    #[error("workload API answered {code}: {message}")]
    Status {
        /// The status code.
        code: GrpcCode,
        /// The agent's message, escaped and cut.
        message: String,
    },
    /// The agent's answer is not a Workload API message this client reads:
    /// a frame, a field or an encoding is wrong.
    #[error("workload API response refused: {0}")]
    Malformed(String),
    /// The agent's answer reads as a message, but what it carries is not an
    /// SVID or a bundle this workload accepts.
    #[error("workload API credential refused: {0}")]
    Refused(String),
    /// The agent issued an SVID for another trust domain than the one this
    /// client was built for.
    #[error("trust domain mismatch: expected {expected}, the agent issued for {presented}")]
    TrustDomainMismatch {
        /// The trust domain the client was built for.
        expected: TrustDomain,
        /// The trust domain the agent's SVID names, escaped and cut.
        presented: String,
    },
    /// The agent did not answer within the configured time.
    #[error("workload API call timed out after {0:?}")]
    Timeout(Duration),
    /// The watcher has not received its first value yet.
    #[error("no {0} has been fetched yet")]
    NotYetFetched(WorkloadCredentialKind),
    /// What the watcher held has expired, and no replacement has arrived.
    #[error("the {0} has expired and no replacement has arrived")]
    Expired(WorkloadCredentialKind),
    /// The agent has not confirmed the bundle set within the client's
    /// maximum bundle age, so it is no longer served: authorities or keys
    /// the agent has withdrawn since would otherwise stay trusted.
    #[error("the {0} is stale: the agent has not confirmed it within the maximum bundle age")]
    Stale(WorkloadCredentialKind),
    /// The agent stopped issuing what the watcher held: it answered
    /// `PERMISSION_DENIED`, or its answer no longer holds the identity the
    /// client selects. The Workload API has a client cease using what the
    /// agent has redacted, so it is no longer served.
    #[error("the agent no longer issues the {0} to this workload")]
    Withdrawn(WorkloadCredentialKind),
    /// An answer of the agent holds SVIDs, and none for the identity the
    /// client's selector names.
    #[error("workload API issued no SVID for the selected identity: {0}")]
    NotIssued(String),
    /// Every authority in a trust domain's X.509 bundle is past its
    /// `notAfter`: the bundle holds no trust anchor.
    #[error("every authority in the X.509 bundle of {0} has expired")]
    AuthoritiesExpired(TrustDomain),
    /// A watcher was started outside a tokio runtime, where it has no task
    /// to run on.
    #[error("a workload API watcher needs a tokio runtime to run on")]
    NoRuntime,
    /// A TLS configuration could not be built from what the agent served.
    #[error("TLS configuration from the workload API failed: {0}")]
    Tls(String),
}

impl SpireError {
    /// A refusal of a credential, from a reason this crate wrote and text
    /// the agent wrote.
    pub(crate) fn refused(reason: &str, remote: &str) -> Self {
        Self::Refused(format!("{reason}: {}", remote_text(remote)))
    }
}

impl From<WireError> for SpireError {
    fn from(error: WireError) -> Self {
        Self::Malformed(error.to_string())
    }
}

impl From<ProtoError> for SpireError {
    fn from(error: ProtoError) -> Self {
        Self::Malformed(error.to_string())
    }
}
