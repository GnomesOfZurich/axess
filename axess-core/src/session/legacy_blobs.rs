//! The policy for reading data that is not in the current at-rest format.
//!
//! It lives outside the feature-gated `crypto` module because the OTP secret
//! cipher uses it too, and that cipher is available with every feature set.

use chrono::{DateTime, Utc};

/// Whether blobs written before row binding (no marker, empty AAD) and the
/// 0.11.0 zero-joined device formats are read.
///
/// Blobs in the current format are never affected: they are always opened
/// under their row's AAD. The session crypto applies this to session and
/// device blobs; the OTP secret cipher applies it to a secret still stored
/// in plain text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LegacyBlobs {
    /// Refuse a blob without the current format marker, including the 0.11.0
    /// device formats. The default. A deployment that still holds rows from
    /// before row binding sets [`AcceptUntil`](Self::AcceptUntil) for the
    /// upgrade window.
    #[default]
    Reject,
    /// Read such a blob until this instant on the crypto's clock, and refuse
    /// it from then on. The stores re-seal what they read in the current
    /// format.
    AcceptUntil(DateTime<Utc>),
    /// Read such a blob with no end date. A blob without a binding opens
    /// under any row id, so prefer [`AcceptUntil`](Self::AcceptUntil).
    Accept,
}
