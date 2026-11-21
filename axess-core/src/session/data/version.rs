//! The schema version of a stored session, read before the rest of it.
//!
//! A row below [`SESSION_DATA_VERSION`](super::SESSION_DATA_VERSION) is no
//! session of this release: sessions stored before it are not carried over,
//! so the version decides before the shape. Such a row is refused as a row
//! below the version whatever state it carries, and never as a shape that
//! happened not to decode.

use super::SessionData;

/// What [`stored_version`] reads of a row: its `version` member and nothing
/// else. A row with no `version` member reads as 1, as
/// [`SessionData::version`] does.
#[cfg(any(
    feature = "sqlite",
    feature = "sqlite-unbundled",
    feature = "postgres",
    feature = "mysql",
    feature = "valkey"
))]
#[derive(serde::Deserialize)]
struct StoredVersion {
    #[serde(default = "super::default_version")]
    version: u8,
}

/// The schema version a stored session carries, read without reading the
/// rest of it. A row with no `version` member reads as 1.
#[cfg(any(
    feature = "sqlite",
    feature = "sqlite-unbundled",
    feature = "postgres",
    feature = "mysql",
    feature = "valkey"
))]
pub(crate) fn stored_version(msgpack: &[u8]) -> Result<u8, rmp_serde::decode::Error> {
    rmp_serde::from_slice::<StoredVersion>(msgpack).map(|row| row.version)
}

impl SessionData {
    /// What a store hands up for a row below the current schema version:
    /// the row's version and nothing else of it.
    #[cfg(any(
        test,
        feature = "sqlite",
        feature = "sqlite-unbundled",
        feature = "postgres",
        feature = "mysql",
        feature = "valkey"
    ))]
    pub(crate) fn below_version(version: u8) -> Self {
        Self {
            version,
            ..Self::default()
        }
    }
}
