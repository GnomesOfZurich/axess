//! The cancellation gate fails a test whose task never reaches it instead
//! of hanging it, and every wait on it ends at the gate's bound.

use axess_testing::stall::{Gate, abort_inside, never_completes};
use std::time::Duration;

/// The happy path: a task parked in the gate is aborted there.
#[tokio::test]
async fn a_task_parked_in_the_gate_is_aborted_there() {
    let gate = Gate::new();
    let parked = gate.clone();
    let handle = tokio::spawn(async move { parked.wait().await });
    abort_inside(&gate, handle).await;
    assert!(gate.is_entered());
}

/// A task that ends without reaching the gated call fails the test at once.
#[tokio::test]
#[should_panic(expected = "the task finished without entering the gate")]
async fn a_task_that_ends_before_the_gate_fails_at_once() {
    let gate = Gate::new();
    let handle = tokio::spawn(async {});
    abort_inside(&gate, handle).await;
}

/// A task that hangs short of the gate fails the test at the gate's bound.
#[tokio::test(start_paused = true)]
#[should_panic(expected = "the task neither entered the gate nor finished within 10s")]
async fn a_task_that_hangs_before_the_gate_fails_at_the_bound() {
    let gate = Gate::new();
    let handle = tokio::spawn(never_completes::<()>());
    abort_inside(&gate, handle).await;
}

/// `until_entered` fails at the bound when nobody enters.
#[tokio::test(start_paused = true)]
#[should_panic(expected = "no caller entered the gate within 2s")]
async fn until_entered_fails_at_the_bound_when_nobody_enters() {
    Gate::with_bound(Duration::from_secs(2))
        .until_entered()
        .await;
}

/// `wait` fails at the bound when the gate is never opened and its caller
/// never cancelled.
#[tokio::test(start_paused = true)]
#[should_panic(expected = "the gate was neither opened nor its caller cancelled within 10s")]
async fn wait_fails_at_the_bound_when_nobody_opens_or_cancels() {
    Gate::new().wait().await;
}

/// An opened gate lets its caller through.
#[tokio::test]
async fn an_opened_gate_lets_its_caller_through() {
    let gate = Gate::new();
    gate.open();
    gate.wait().await;
    assert_eq!(gate.bound(), Gate::DEFAULT_BOUND);
}
