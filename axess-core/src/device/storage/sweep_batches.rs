//! Bounded statements for the SQL retention sweeps.
//!
//! A sweep stage is one `UPDATE` or `DELETE` over every row of a tenant that
//! matches a predicate. Run as a single statement it holds its row locks and
//! its undo or WAL space for the whole tenant, which on a large table blocks
//! writers for as long as it takes. A stage instead runs in batches of
//! [`SWEEP_BATCH`] rows and repeats until a batch comes up short, so no
//! statement touches more than a batch and the stage's total is the sum.
//!
//! Every stage moves the rows it touches out of its own predicate (a level
//! changes, a time is stamped, a row is deleted), so each batch makes progress
//! and the loop ends.

use std::future::Future;

use crate::device::storage::sql_common::SqlDeviceStoreError;

/// Rows one sweep statement may change.
pub(crate) const SWEEP_BATCH: i64 = 1_000;

/// Run `statement` until it changes fewer than `batch` rows, and return how
/// many rows it changed in all together with how many statements ran.
pub(crate) async fn in_batches<F, Fut>(
    batch: i64,
    mut statement: F,
) -> Result<(u64, u32), SqlDeviceStoreError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<u64, sqlx::Error>>,
{
    let limit = u64::try_from(batch.max(1)).unwrap_or(1);
    let mut total = 0u64;
    let mut statements = 0u32;
    loop {
        let changed = statement().await?;
        statements += 1;
        total += changed;
        if changed < limit {
            return Ok((total, statements));
        }
    }
}
