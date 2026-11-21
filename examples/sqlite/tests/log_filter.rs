//! The log filter the example starts with when `RUST_LOG` is not set.

use axess_example_sqlite::DEFAULT_LOG_FILTER;
use axess_testing::mock_tracing::PrintedLines;
use tracing_subscriber::EnvFilter;

/// What the default filter lets through of one debug event on `target`.
fn printed_by_default(target: &str) -> bool {
    let sink = PrintedLines::new();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(sink.clone())
        .with_env_filter(EnvFilter::new(DEFAULT_LOG_FILTER))
        .finish();
    tracing::subscriber::with_default(subscriber, || match target {
        "dev_mail" => tracing::debug!(target: "dev_mail", "link"),
        _ => tracing::debug!(target: "axess_example_sqlite", "link"),
    });
    !sink.text().is_empty()
}

/// A debug build writes the password reset link to the `dev_mail` target and
/// tells the reader to look there, so the default filter must let it out
/// without asking anyone to widen `RUST_LOG`.
#[test]
fn the_default_filter_prints_the_dev_mail_link() {
    assert!(printed_by_default("dev_mail"));
}

#[test]
fn the_default_filter_still_prints_the_example_s_own_debug() {
    assert!(printed_by_default("axess_example_sqlite"));
}
