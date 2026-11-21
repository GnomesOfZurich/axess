//! The printed lines: a span's fields reach the lines written inside it, and
//! what the code wrote is kept as it was.

use super::*;

/// A line written inside a span carries the span's fields, which an event
/// capture does not show, and the span prints a line as it opens and as it
/// closes.
#[test]
fn a_line_inside_a_span_carries_the_span_fields() {
    let lines = LineCapture::install();
    let span = tracing::info_span!("login", provider = "acme");
    span.in_scope(|| tracing::warn!("refused"));
    drop(span);

    let printed = lines.lines();
    assert!(
        printed.iter().any(|l| l.contains("WARN")
            && l.contains("login{provider=\"acme\"}")
            && l.contains("refused")),
        "{printed:#?}"
    );
    assert!(printed.iter().any(|l| l.contains("new")), "{printed:#?}");
    assert!(printed.iter().any(|l| l.contains("close")), "{printed:#?}");
}

/// The formatter neither colours a line nor cleans what the code wrote: a
/// control character the code let through a `Display` field is in the line.
#[test]
fn a_raw_control_character_reaches_the_line() {
    let lines = LineCapture::install();
    tracing::info!(value = %"a\u{1b}[2Jb", "written");
    let text = lines.text();
    assert!(text.contains('\u{1b}'), "{text:?}");
    assert!(!text.contains("\u{1b}[3m"), "no colours: {text:?}");
}

/// Every level is printed, trace included.
#[test]
fn every_level_is_printed() {
    let lines = LineCapture::install();
    tracing::trace!("quietest");
    assert!(lines.text().contains("quietest"));
}

/// A formatter of the test's own can write into a buffer.
#[test]
fn a_buffer_takes_a_formatter_of_the_test_own() {
    let printed = PrintedLines::new();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(printed.clone())
        .with_max_level(Level::WARN)
        .with_ansi(false)
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        tracing::info!("filtered out");
        tracing::warn!("kept");
    });
    let text = printed.text();
    assert!(
        text.contains("kept") && !text.contains("filtered out"),
        "{text}"
    );
    assert_eq!(printed.lines().len(), 1);
}
