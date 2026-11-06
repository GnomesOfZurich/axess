//! The log filter the example starts with when `RUST_LOG` is not set.

use axess_example_sqlite::DEFAULT_LOG_FILTER;
use std::sync::{Arc, Mutex};
use tracing_subscriber::{EnvFilter, fmt::MakeWriter};

#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Sink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("lock").extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Sink {
    type Writer = Sink;
    fn make_writer(&'a self) -> Sink {
        self.clone()
    }
}

/// What the default filter lets through of one debug event on `target`.
fn printed_by_default(target: &str) -> bool {
    let sink = Sink::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(sink.clone())
        .with_env_filter(EnvFilter::new(DEFAULT_LOG_FILTER))
        .finish();
    tracing::subscriber::with_default(subscriber, || match target {
        "dev_mail" => tracing::debug!(target: "dev_mail", "link"),
        _ => tracing::debug!(target: "axess_example_sqlite", "link"),
    });
    !sink.0.lock().expect("lock").is_empty()
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
