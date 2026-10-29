//! The bucket table: sliding-window counters per key, with a hard cap, a
//! per-address-group budget and expiry sweeps.

use super::keys::{GROUP_BUCKET_CAP, Target};
use axess_clock::Clock;
use chrono::{DateTime, Utc};
use dashmap::{DashMap, mapref::entry::Entry};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

/// Number of buckets at which a request for a key with no bucket is refused.
/// Live buckets are never evicted to make room: a flood of distinct keys
/// cannot push a real client's bucket out and reset its count, so the
/// limiter answers the flood with 429 until the next expiry sweep frees room.
pub(super) const HARD_BUCKET_CAP: usize = 256 * 1024;

/// Smallest gap between two expiry sweeps.
const MIN_SWEEP_INTERVAL_MS: u64 = 1_000;

/// Milliseconds since the Unix epoch, floored at zero.
fn epoch_millis(now: DateTime<Utc>) -> u64 {
    u64::try_from(now.timestamp_millis()).unwrap_or(0)
}

/// One key's sliding-window counter: the requests admitted in the current
/// fixed window and in the one before it.
///
/// The estimate of requests in the trailing window is the previous window's
/// count weighted by how much of it still overlaps, plus the current count,
/// all in integer arithmetic. It never undercounts a burst that straddles a
/// window boundary, so about `max_requests` pass in any trailing window and
/// not twice that.
#[derive(Debug)]
pub(super) struct TokenBucket {
    /// Requests admitted in the window that began at `window_start_ms`.
    curr: u32,
    /// Requests admitted in the window before it.
    prev: u32,
    /// When the current window started, in epoch milliseconds from the
    /// injected clock.
    window_start_ms: u64,
    /// The address group this bucket is counted against, if any.
    group: Option<String>,
}

impl TokenBucket {
    fn new(now_ms: u64, group: Option<String>) -> Self {
        Self {
            curr: 0,
            prev: 0,
            window_start_ms: now_ms,
            group,
        }
    }
}

/// Shared bucket store.  [`DashMap`] gives lock-free concurrent reads/writes.
#[derive(Clone)]
pub(super) struct BucketStore {
    pub(super) buckets: Arc<DashMap<String, TokenBucket>>,
    max_requests: u32,
    window_ms: u64,
    clock: Arc<dyn Clock>,
    /// Live buckets per address group (see [`GROUP_BUCKET_CAP`]).
    group_counts: Arc<DashMap<String, usize>>,
    /// Table size at which a request for a key with no bucket is refused.
    hard_cap: usize,
    /// Per-group bucket budget.
    group_cap: usize,
    /// Number of entries in `buckets`, kept beside the map so the per-request
    /// cap check does not read-lock every shard the way `DashMap::len` does.
    pub(super) bucket_count: Arc<AtomicUsize>,
    /// Clock time (epoch milliseconds) of the last expiry sweep. The caller
    /// that wins the compare-exchange on it runs the sweep; the rest carry on.
    last_sweep_ms: Arc<AtomicU64>,
}

/// Whether an acquire created the bucket it drew from.
enum Created {
    Yes,
    No,
}

/// Result of trying to acquire a token.
pub(super) enum Acquire {
    /// Token granted; remaining count returned for `X-RateLimit-Remaining` header.
    Allowed { remaining: u32 },
    /// Rate limited; seconds until the bucket resets.
    Limited { retry_after_secs: u64 },
    /// The bucket table is at its hard cap and this key has no bucket yet;
    /// refused until a sweep frees room.
    Saturated { retry_after_secs: u64 },
}

impl BucketStore {
    pub(super) fn new(max_requests: u32, window: Duration, clock: Arc<dyn Clock>) -> Self {
        let now_ms = epoch_millis(clock.now());
        Self {
            buckets: Arc::new(DashMap::new()),
            max_requests,
            window_ms: u64::try_from(window.as_millis()).unwrap_or(u64::MAX),
            clock,
            group_counts: Arc::new(DashMap::new()),
            hard_cap: HARD_BUCKET_CAP,
            group_cap: GROUP_BUCKET_CAP,
            bucket_count: Arc::new(AtomicUsize::new(0)),
            last_sweep_ms: Arc::new(AtomicU64::new(now_ms)),
        }
    }

    /// Gap between sweeps: an eighth of the window, never under a second.
    pub(super) fn sweep_interval_ms(&self) -> u64 {
        (self.window_ms / 8).max(MIN_SWEEP_INTERVAL_MS)
    }

    /// A store with its own caps, so a test fills the table with a few keys
    /// instead of a quarter of a million.
    #[cfg(test)]
    pub(super) fn with_caps(mut self, hard_cap: usize, group_cap: usize) -> Self {
        self.hard_cap = hard_cap;
        self.group_cap = group_cap;
        self
    }

    /// Buckets in the table.
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.bucket_count.load(Ordering::Acquire)
    }

    /// The injected clock's current time.
    pub(super) fn now(&self) -> DateTime<Utc> {
        self.clock.now()
    }

    #[cfg(test)]
    pub(super) fn try_acquire(&self, key: &str) -> Acquire {
        self.try_acquire_at(key, self.clock.now())
    }

    /// Take a token for the plain key `key` at an explicit `now`.
    #[cfg(test)]
    pub(super) fn try_acquire_at(&self, key: &str, now: DateTime<Utc>) -> Acquire {
        self.try_acquire_target(&Target::plain(key), now)
    }

    /// Take a token for `target` at `now`.
    ///
    /// A key that already has a bucket uses it. A new key gets a bucket of its
    /// own unless its address group already holds its budget, or (for a key
    /// that asks for it) the table is three quarters full; it then folds into
    /// the target's shared overflow bucket, which limits the whole overflow
    /// together instead of letting it grow the table.
    pub(super) fn try_acquire_target(&self, target: &Target, now: DateTime<Utc>) -> Acquire {
        let now_ms = epoch_millis(now);
        self.sweep_if_due(now_ms);

        // A key that already has a bucket is never refused for capacity.
        if let Some(mut bucket) = self.buckets.get_mut(target.key.as_str()) {
            return self.take(&mut bucket, now_ms);
        }

        let near_cap = target.fold_near_cap
            && self.bucket_count.load(Ordering::Acquire) >= self.hard_cap / 4 * 3;
        let reserved_group = match &target.group {
            Some(group) if !near_cap => self.reserve_group(group).then_some(group.as_str()),
            _ => None,
        };
        let own_bucket = !near_cap && (target.group.is_none() || reserved_group.is_some());
        if !own_bucket && let Some(overflow) = &target.fold_into {
            return self.acquire_new_or_existing(overflow, None, now_ms).0;
        }
        let outcome = self.acquire_new_or_existing(&target.key, reserved_group, now_ms);
        if let Some(group) = reserved_group
            && !matches!(outcome.1, Created::Yes)
        {
            self.release_group(group);
        }
        outcome.0
    }

    /// Take a token from `key`, creating its bucket (counted against `group`)
    /// when none exists and the table has room.
    fn acquire_new_or_existing(
        &self,
        key: &str,
        group: Option<&str>,
        now_ms: u64,
    ) -> (Acquire, Created) {
        if let Some(mut bucket) = self.buckets.get_mut(key) {
            return (self.take(&mut bucket, now_ms), Created::No);
        }
        // Reserve a slot before inserting so concurrent first requests for
        // distinct keys cannot overshoot the cap.
        if self.bucket_count.fetch_add(1, Ordering::AcqRel) >= self.hard_cap {
            self.bucket_count.fetch_sub(1, Ordering::AcqRel);
            return (
                Acquire::Saturated {
                    retry_after_secs: (self.sweep_interval_ms() / 1_000).max(1),
                },
                Created::No,
            );
        }
        match self.buckets.entry(key.to_owned()) {
            Entry::Occupied(mut occupied) => {
                self.bucket_count.fetch_sub(1, Ordering::AcqRel);
                (self.take(occupied.get_mut(), now_ms), Created::No)
            }
            Entry::Vacant(vacant) => {
                let mut bucket = vacant.insert(TokenBucket::new(now_ms, group.map(str::to_owned)));
                (self.take(&mut bucket, now_ms), Created::Yes)
            }
        }
    }

    /// Count one more bucket against `group`; false when it is at its budget.
    pub(super) fn reserve_group(&self, group: &str) -> bool {
        let mut count = self.group_counts.entry(group.to_owned()).or_insert(0);
        if *count >= self.group_cap {
            return false;
        }
        *count += 1;
        true
    }

    pub(super) fn release_group(&self, group: &str) {
        if let Some(mut count) = self.group_counts.get_mut(group) {
            *count = count.saturating_sub(1);
        }
    }

    pub(super) fn take(&self, bucket: &mut TokenBucket, now_ms: u64) -> Acquire {
        self.roll(bucket, now_ms);
        let estimate = self.estimate(bucket, now_ms);
        if estimate < u128::from(self.max_requests) {
            bucket.curr += 1;
            let remaining = u128::from(self.max_requests) - estimate - 1;
            Acquire::Allowed {
                remaining: u32::try_from(remaining).unwrap_or(u32::MAX),
            }
        } else {
            Acquire::Limited {
                retry_after_secs: self.wait_ms(bucket, now_ms).div_ceil(1_000).max(1),
            }
        }
    }

    /// Advance `bucket` to the window containing `now_ms`.
    ///
    /// One window on, the current count becomes the previous one; two or
    /// more on, both are zero. A clock that steps backwards re-anchors the
    /// window at the earlier time and keeps the counts, so the bucket does
    /// not stay limited until the clock catches up with a future start.
    pub(super) fn roll(&self, bucket: &mut TokenBucket, now_ms: u64) {
        if now_ms < bucket.window_start_ms {
            bucket.window_start_ms = now_ms;
            return;
        }
        let windows = (now_ms - bucket.window_start_ms) / self.window_ms;
        match windows {
            0 => {}
            1 => {
                bucket.prev = bucket.curr;
                bucket.curr = 0;
                bucket.window_start_ms += self.window_ms;
            }
            _ => {
                bucket.prev = 0;
                bucket.curr = 0;
                bucket.window_start_ms =
                    now_ms - (now_ms - bucket.window_start_ms) % self.window_ms;
            }
        }
    }

    /// Requests counted in the trailing window ending at `now_ms`.
    pub(super) fn estimate(&self, bucket: &TokenBucket, now_ms: u64) -> u128 {
        let into = u128::from(now_ms.saturating_sub(bucket.window_start_ms));
        let window = u128::from(self.window_ms);
        let overlap = window.saturating_sub(into);
        u128::from(bucket.prev) * overlap / window + u128::from(bucket.curr)
    }

    /// Milliseconds until a request would be admitted, for a bucket that has
    /// just refused one.
    pub(super) fn wait_ms(&self, bucket: &TokenBucket, now_ms: u64) -> u64 {
        let window = u128::from(self.window_ms);
        let max = u128::from(self.max_requests);
        let into = u128::from(now_ms.saturating_sub(bucket.window_start_ms));
        // Room left in the current window once the next request is counted.
        let (prev, headroom, wait_to_window_end) =
            match max.checked_sub(u128::from(bucket.curr) + 1) {
                Some(headroom) => (u128::from(bucket.prev), headroom, 0),
                // The current window is full: wait for it to end, after which its
                // count is the previous window's.
                None => (
                    u128::from(bucket.curr),
                    max - 1,
                    window.saturating_sub(into),
                ),
            };
        // The estimate is admitting once `prev * overlap / window <= headroom`
        // in integer division, that is `overlap <= ((headroom + 1) * window - 1) / prev`.
        let needed_into = ((headroom + 1) * window - 1)
            .checked_div(prev)
            .map_or(0, |largest_overlap| window - largest_overlap.min(window));
        let wait = if wait_to_window_end > 0 {
            wait_to_window_end + needed_into
        } else {
            needed_into.saturating_sub(into)
        };
        u64::try_from(wait).unwrap_or(u64::MAX)
    }

    /// Run an expiry sweep when one is due, on at most one caller.
    ///
    /// Due means a sweep interval has passed on the injected clock since the
    /// last one. The compare-exchange on the stamp picks the caller that
    /// sweeps; every other request in the same interval skips straight on,
    /// so the full-table scan runs once per interval instead of once per
    /// request.
    pub(super) fn sweep_if_due(&self, now_ms: u64) {
        let last = self.last_sweep_ms.load(Ordering::Acquire);
        // A clock that stepped back leaves the stamp in the future; that
        // counts as due, so the stamp re-anchors instead of the sweep
        // waiting for the clock to catch up while the table fills.
        if now_ms >= last && now_ms - last < self.sweep_interval_ms() {
            return;
        }
        if self
            .last_sweep_ms
            .compare_exchange(last, now_ms, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.evict_expired_ms(now_ms);
        }
    }

    /// Remove buckets that no longer weigh on the estimate at the injected clock's time.
    #[cfg(test)]
    pub(super) fn evict_expired(&self) {
        self.evict_expired_at(self.clock.now());
    }

    /// Remove buckets that no longer weigh on the estimate at `now`.
    #[cfg(test)]
    pub(super) fn evict_expired_at(&self, now: DateTime<Utc>) {
        self.evict_expired_ms(epoch_millis(now));
    }

    pub(super) fn evict_expired_ms(&self, now_ms: u64) {
        let mut removed = 0usize;
        let mut freed_groups: Vec<String> = Vec::new();
        self.buckets.retain(|_, bucket| {
            // A bucket dated in the future (the clock stepped back after it
            // was written) would otherwise outlive every sweep until the
            // clock caught up, holding table slots. Re-anchor it at `now`:
            // its counts stay, and it ages out two windows from here.
            if bucket.window_start_ms > now_ms {
                bucket.window_start_ms = now_ms;
            }
            // A bucket still weighs on the estimate for one window past the
            // one it was last rolled into, so it lives for two.
            let live = now_ms - bucket.window_start_ms < self.window_ms.saturating_mul(2);
            if !live {
                removed += 1;
                if let Some(group) = bucket.group.take() {
                    freed_groups.push(group);
                }
            }
            live
        });
        self.bucket_count.fetch_sub(removed, Ordering::AcqRel);
        for group in &freed_groups {
            self.release_group(group);
        }
        if !freed_groups.is_empty() {
            self.group_counts.retain(|_, count| *count > 0);
        }
    }
}
