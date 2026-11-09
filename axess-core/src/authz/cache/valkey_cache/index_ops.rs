//! The commands the entity index needs, behind a seam a test can fake.
//!
//! [`ValkeyEntityCache::invalidate_resource`](super::ValkeyEntityCache::invalidate_resource)
//! empties an index SET while other pods may be adding to it. The steps it
//! takes, and the order they run in, are what keep an entry from being
//! stored without an index, so the steps sit behind this trait: production
//! forwards to `fred`, and a test substitutes a keyspace that runs a hook
//! between two commands.

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
}

impl IndexOps for Client {
    async fn pop_members(&self, key: &str, count: usize) -> Result<Vec<String>, Error> {
        self.spop(key, Some(count)).await
    }

    async fn delete(&self, keys: Vec<String>) -> Result<(), Error> {
        let _: () = self.del(keys).await?;
        Ok(())
    }
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
