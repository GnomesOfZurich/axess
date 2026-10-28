//! Bounded-concurrency fan-out for the registry calls one login makes.
//!
//! A login can owe the session registry dozens of calls: a liveness check for
//! each candidate of the subject sweep, one per mapping the capacity eviction
//! dropped, an invalidation per displaced session. Awaited one after another
//! each waits on a network round trip of its own, and the login's latency is
//! their sum. They are independent, so they run in waves of at most
//! [`REGISTRY_CONCURRENCY`] at a time: the cost is the number of waves, and a
//! slow registry is never asked for more than a wave at once.

use std::future::Future;

/// Registry calls in flight at once within one login.
pub(super) const REGISTRY_CONCURRENCY: usize = 16;

/// Run `op` for every item, at most [`REGISTRY_CONCURRENCY`] at a time, and
/// return each item with its output. The order is completion order within a
/// wave. An item whose call panicked is left out of the result, which callers
/// read as "no answer".
pub(super) async fn bounded<T, O, F, Fut>(items: Vec<T>, op: F) -> Vec<(T, O)>
where
    T: Clone + Send + 'static,
    O: Send + 'static,
    F: Fn(T) -> Fut,
    Fut: Future<Output = O> + Send + 'static,
{
    let mut out = Vec::with_capacity(items.len());
    for wave in items.chunks(REGISTRY_CONCURRENCY) {
        let mut set = tokio::task::JoinSet::new();
        for item in wave {
            let item = item.clone();
            let call = op(item.clone());
            set.spawn(async move { (item, call.await) });
        }
        while let Some(done) = set.join_next().await {
            match done {
                Ok(pair) => out.push(pair),
                Err(e) => tracing::error!(error = %e, "registry call task failed"),
            }
        }
    }
    out
}
