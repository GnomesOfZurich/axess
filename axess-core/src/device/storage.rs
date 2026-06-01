//! Persistent backends for [`DeviceStore`](super::store::DeviceStore).
//!
//! Mirrors [`session::storage`](crate::session::storage): one submodule
//! per backend, plus a shared `sql_common` for the codec + error
//! surface every SQL backend reuses.
//!
//! # Backends
//!
//! - [`SqliteDeviceStore`] (`device,sqlite`): production-grade store
//!   backed by sqlx. Optional AES-256-GCM envelope on the bindings
//!   column.
//! - [`PostgresDeviceStore`] (`device,postgres`): same shape as the
//!   SQLite backend with `$1`-style bind syntax.
//! - [`MysqlDeviceStore`] (`device,mysql`): same shape as the SQLite
//!   backend with `?`-style binds + `ON DUPLICATE KEY UPDATE` upsert.
//!   Compatible with MySQL 8.x and MariaDB 10.5+.
//! - `ValkeyDeviceStore` (`device,valkey`): Valkey-backed store with TTL eviction.

#[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
pub(crate) mod sql_common;

#[cfg(feature = "mysql")]
pub mod mysql;
#[cfg(feature = "postgres")]
pub mod postgres;
#[cfg(feature = "sqlite")]
pub mod sqlite;
#[cfg(feature = "valkey")]
pub mod valkey;

#[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
pub use sql_common::SqlDeviceStoreError;

#[cfg(feature = "mysql")]
pub use mysql::MysqlDeviceStore;
#[cfg(feature = "postgres")]
pub use postgres::PostgresDeviceStore;
#[cfg(feature = "sqlite")]
pub use sqlite::SqliteDeviceStore;
#[cfg(feature = "valkey")]
pub use valkey::{ValkeyDeviceStore, ValkeyDeviceStoreError};
