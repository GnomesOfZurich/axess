//! Shared boilerplate for SQL-backed session stores.
//!
//! `SqliteSessionStore`, `PostgresSessionStore`, and `MysqlSessionStore`
//! each own their dialect-specific SQL (placeholders, schema types,
//! `INSERT … ON CONFLICT` vs `ON DUPLICATE KEY UPDATE`), but the
//! surrounding plumbing (cleanup-loop logging, the spawned-task body
//! shape, the `HealthCheck` 2-second `SELECT 1` timeout) is identical
//! across them. Those pieces live here so a future fourth backend
//! lands with the same operational defaults instead of re-deriving
//! them.
//!
//! A fully generic `SqlStore<K, V>` parameterised over `sqlx::Database`
//! plus a per-value serialization trait was considered (and tried); see
//! the closed entry in `CHANGELOG.md`. Cost-prohibitive given
//! how thin the dialect-specific bodies actually are. This module
//! captures the slice that *does* dedupe cleanly. The
//! `Store<SessionId, SessionData>` trait impls on each backend
//! (`sqlite.rs` / `postgres.rs` / `mysql.rs` / `valkey.rs`) provide the
//! cross-backend generic surface adopters can program against; each
//! backend owns its own per-value codec (`SessionCodec` etc.) rather
//! than sharing a `Codec<V>` trait.

use crate::health::HealthStatus;
use std::future::Future;

/// Log a single `cleanup_expired` outcome.
///
/// `label` is the backend tag emitted as part of the message
/// (`"sqlite session cleanup"`, `"postgres session cleanup"`, etc.):
/// keeps a single dispatch point so future changes to log format,
/// fields, or metric emission only need to land once.
///
/// `Ok(0)` is silent because zero-row sweeps are the steady state;
/// emitting a debug record per tick would drown out genuine activity.
/// `Ok(n>0)` emits at `debug`; `Err(_)` emits at `warn` and is
/// swallowed by the caller so a transient blip doesn't halt the loop.
pub(crate) fn log_cleanup_outcome(label: &'static str, result: Result<u64, sqlx::Error>) {
    match result {
        Ok(removed) if removed > 0 => {
            tracing::debug!(removed, "{label} session cleanup");
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(error = %e, "{label} session cleanup failed");
        }
    }
}

/// Run a backend health probe under the standard 2-second timeout and
/// normalise the outcome into a [`HealthStatus`].
///
/// `label` is the backend tag emitted in the unhealthy-status message
/// (`"sqlite"` / `"postgres"` / `"mysql"`). `probe` is the per-backend
/// `SELECT 1` future; each caller supplies it directly because the
/// `sqlx::Pool<DB>` generic bounds required to build the query inside a
/// shared helper add more noise than they save.
///
/// Centralising the timeout + result mapping keeps the operator-facing
/// strings (`"<label> SELECT 1 failed: …"`, `"<label> SELECT 1 timeout
/// (2s)"`) identical across SQL backends so downstream alerting regexes
/// don't need per-backend variants.
pub(crate) async fn sql_health_probe<F, E>(label: &'static str, probe: F) -> HealthStatus
where
    F: Future<Output = Result<i32, E>> + Send,
    E: std::fmt::Display,
{
    match tokio::time::timeout(std::time::Duration::from_secs(2), probe).await {
        Ok(Ok(_)) => HealthStatus::Healthy,
        Ok(Err(e)) => HealthStatus::Unhealthy(format!("{label} SELECT 1 failed: {e}")),
        Err(_) => HealthStatus::Unhealthy(format!("{label} SELECT 1 timeout (2s)")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::mock_tracing::TracingCapture;

    #[test]
    fn ok_zero_does_not_log() {
        let capture = TracingCapture::install();
        log_cleanup_outcome("sqlite", Ok(0));
        assert!(
            !capture.contains_at_level(tracing::Level::DEBUG, "sqlite session cleanup"),
            "zero-row sweep must stay silent; kills `true` / `== 0` / `>= 0` guard mutants"
        );
    }

    #[test]
    fn ok_positive_emits_debug() {
        let capture = TracingCapture::install();
        log_cleanup_outcome("postgres", Ok(42));
        assert!(
            capture.contains_at_level(tracing::Level::DEBUG, "postgres session cleanup"),
            "non-zero sweep must log at debug; kills `false` / `< 0` guard mutants"
        );
    }

    #[test]
    fn err_emits_warn() {
        let capture = TracingCapture::install();
        log_cleanup_outcome("mysql", Err(sqlx::Error::PoolClosed));
        assert!(
            capture.contains_at_level(tracing::Level::WARN, "mysql session cleanup failed"),
            "error must surface at warn; guards against accidental arm reordering"
        );
    }

    #[tokio::test]
    async fn health_probe_ok_is_healthy() {
        let status = sql_health_probe("sqlite", async { Ok::<_, std::io::Error>(1i32) }).await;
        assert_eq!(status, HealthStatus::Healthy);
    }

    #[tokio::test]
    async fn health_probe_err_is_unhealthy_with_label() {
        let probe = async { Err::<i32, _>(std::io::Error::other("boom")) };
        let status = sql_health_probe("postgres", probe).await;
        match status {
            HealthStatus::Unhealthy(msg) => {
                assert!(msg.starts_with("postgres SELECT 1 failed: "), "got: {msg}");
                assert!(msg.contains("boom"), "got: {msg}");
            }
            other => panic!("expected Unhealthy, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn health_probe_timeout_reports_two_second_window() {
        // `pause()` + `advance()` keeps the test fast; the probe is
        // `pending` so the 2-second timeout fires deterministically
        // once we advance past it.
        tokio::time::pause();
        let probe = std::future::pending::<Result<i32, std::io::Error>>();
        let handle = tokio::spawn(sql_health_probe("mysql", probe));
        tokio::time::advance(std::time::Duration::from_secs(3)).await;
        let status = handle.await.expect("join");
        assert_eq!(
            status,
            HealthStatus::Unhealthy("mysql SELECT 1 timeout (2s)".into()),
        );
    }

    #[test]
    fn label_is_interpolated() {
        let capture = TracingCapture::install();
        log_cleanup_outcome("sqlite", Ok(1));
        assert!(
            capture.contains_at_level(tracing::Level::DEBUG, "sqlite session cleanup"),
            "label must appear in the message; guards against hard-coded label drift"
        );
        let capture2 = TracingCapture::install();
        log_cleanup_outcome("postgres", Ok(1));
        assert!(
            capture2.contains_at_level(tracing::Level::DEBUG, "postgres session cleanup"),
            "second-label call must use the new label, not a cached one"
        );
    }
}
