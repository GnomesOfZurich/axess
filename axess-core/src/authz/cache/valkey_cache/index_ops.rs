//! The commands the entity index needs, behind a seam a test can fake.
//!
//! [`ValkeyEntityCache::invalidate_resource`](super::ValkeyEntityCache::invalidate_resource)
//! empties an index SET while other pods may be adding to it, and a load
//! stores an entry while another pod may be emptying its index. The steps
//! each takes, and the order they run in, are what keep an entry from being
//! stored without an index, so the steps sit behind this trait: production
//! forwards to `fred`, and a test substitutes a keyspace that runs a hook
//! between two commands.

use std::time::Duration;

use fred::error::Error;
use fred::prelude::*;

/// Members taken from an index SET per round trip.
const POP_BATCH: usize = 256;

/// The Valkey commands the entity index is maintained with.
pub(crate) trait IndexOps: Send + Sync {
    /// Remove up to `count` members of the SET at `key` and return them, in
    /// one atomic command (`SPOP`). An absent key gives an empty list.
    async fn pop_members(&self, key: &str, count: usize) -> Result<Vec<String>, Error>;

    /// Delete `keys` (`DEL`).
    async fn delete(&self, keys: Vec<String>) -> Result<(), Error>;

    /// Add `member` to the SET at each of `indexes` and give each SET
    /// `ttl_ms` to live (`SADD` then `PEXPIRE`, one pipeline).
    async fn add_members(&self, indexes: &[String], member: &str, ttl_ms: i64)
    -> Result<(), Error>;

    /// Store `value` at `key` for `ttl_ms` (`SET` with `PX`).
    async fn set_entry(&self, key: &str, value: &str, ttl_ms: i64) -> Result<(), Error>;
}

impl IndexOps for Client {
    async fn pop_members(&self, key: &str, count: usize) -> Result<Vec<String>, Error> {
        self.spop(key, Some(count)).await
    }

    async fn delete(&self, keys: Vec<String>) -> Result<(), Error> {
        let _: () = self.del(keys).await?;
        Ok(())
    }

    async fn add_members(
        &self,
        indexes: &[String],
        member: &str,
        ttl_ms: i64,
    ) -> Result<(), Error> {
        let pipeline = self.pipeline();
        for index in indexes {
            let _: () = pipeline.sadd(index, member).await?;
            let _: () = pipeline.pexpire(index, ttl_ms, None).await?;
        }
        let _: Vec<Value> = pipeline.all().await?;
        Ok(())
    }

    async fn set_entry(&self, key: &str, value: &str, ttl_ms: i64) -> Result<(), Error> {
        self.set(key, value, Some(Expiration::PX(ttl_ms)), None, false)
            .await
    }
}

/// A cache TTL as the milliseconds of a `PX` or `PEXPIRE` argument. Written
/// in milliseconds so a TTL under a second is not rounded to zero (which
/// Valkey refuses, silently disabling the cache); never less than 1 ms.
pub(crate) fn ttl_millis(ttl: Duration) -> i64 {
    ttl.as_millis().clamp(1, i64::MAX as u128) as i64
}

/// Delete every entry the index SET at `index` names, and empty the SET.
///
/// The members leave the SET as they are read (`SPOP`), so a member another
/// pod adds after one of these reads stays in the SET and is read by the
/// next round, and the SET is never deleted as a whole: deleting it after
/// reading it would also delete a member added in between, leaving that
/// member's entry cached with no index to find it by. The loop ends when a
/// read returns nothing.
pub(crate) async fn drain_index<O: IndexOps>(ops: &O, index: &str) -> Result<(), Error> {
    loop {
        let members = ops.pop_members(index, POP_BATCH).await?;
        if members.is_empty() {
            return Ok(());
        }
        ops.delete(members).await?;
    }
}

/// Store the entry `value` at `entry_key` and name it in every index SET of
/// `indexes`, all living `ttl_ms`.
///
/// The index is written before the entry, so an entry whose index cannot be
/// written is not stored, and again after it: a [`drain_index`] on another
/// pod that runs between the two writes pops the member and deletes an entry
/// that is not there yet, and the entry written next would otherwise be
/// cached with no index naming it. The second write puts the member back,
/// so the next invalidation of that index finds the entry. When the second
/// write fails, the entry is deleted again before the error is returned,
/// since that drain may have run and nothing would then name the entry.
/// Where the entry and its index SETs share one slot (a single node, or a
/// cluster under a hash-tag prefix), one transaction could cover the writes;
/// where they do not, it cannot. The order above holds in both, so the
/// writes stay single commands on every topology.
///
/// An error leaves the entry unstored or indexed. The one exception is an
/// error from that delete too, after the second write failed: the error
/// returned is then the delete's, and the entry may stay unindexed until its
/// TTL ends, as it would after any write a pod could not take back because
/// Valkey stopped answering it.
pub(crate) async fn store_indexed<O: IndexOps>(
    ops: &O,
    indexes: &[String],
    entry_key: &str,
    value: &str,
    ttl_ms: i64,
) -> Result<(), Error> {
    ops.add_members(indexes, entry_key, ttl_ms).await?;
    ops.set_entry(entry_key, value, ttl_ms).await?;
    if let Err(e) = ops.add_members(indexes, entry_key, ttl_ms).await {
        ops.delete(vec![entry_key.to_owned()]).await?;
        return Err(e);
    }
    Ok(())
}
