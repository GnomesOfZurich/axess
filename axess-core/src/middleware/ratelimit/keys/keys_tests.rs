//! The wiring-mistake log throttle runs on tokio's monotonic clock, so a
//! paused runtime moves it.

use super::log_due;
use std::time::Duration;

/// A line is due once, then not again until its interval has passed on the
/// runtime's clock, which `advance` moves without waiting.
#[tokio::test(start_paused = true)]
async fn a_log_line_is_due_again_once_its_interval_passes_on_the_runtime_clock() {
    let every = Duration::from_secs(60);
    assert!(log_due("paused-clock", every), "the first line is due");
    assert!(
        !log_due("paused-clock", every),
        "a second line at once is not"
    );
    tokio::time::advance(Duration::from_secs(59)).await;
    assert!(
        !log_due("paused-clock", every),
        "59 s on: still within the interval"
    );
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(
        log_due("paused-clock", every),
        "61 s on the paused clock: due again"
    );
}
