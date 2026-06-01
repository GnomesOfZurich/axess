//! [`EventStatus`]: coarse outcome bucket. Detailed reason lives in
//! the payload.

/// Three-valued event outcome. Drives dashboard pivots cheaply
/// (success-rate, failure-rate) without parsing payload contents.
///
/// - [`Success`](EventStatus::Success): the operation completed as intended
/// - [`Failure`](EventStatus::Failure): the operation was attempted and refused / errored
/// - [`Info`](EventStatus::Info): a state change that is neither success nor
///   failure (e.g. a device re-sighted with no transition, an
///   informational state-change event)
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum EventStatus {
    /// Operation completed as intended.
    Success,
    /// Operation refused or errored.
    Failure,
    /// State-change with no success/failure semantics.
    #[default]
    Info,
}
