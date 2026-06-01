//! Storage backends for [`SessionStore`](super::store::SessionStore) and
//! [`SessionRegistry`](super::store::SessionRegistry).

#[cfg(any(test, feature = "testing"))]
pub mod in_memory_backend;

#[cfg(any(
    feature = "sqlite",
    feature = "postgres",
    feature = "mysql",
    feature = "valkey"
))]
pub mod session_codec;

#[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
pub(crate) mod sql_helpers;

#[cfg(feature = "sqlite")]
pub mod sqlite;

#[cfg(feature = "postgres")]
pub mod postgres;

#[cfg(feature = "mysql")]
pub mod mysql;

#[cfg(feature = "valkey")]
pub mod valkey;
