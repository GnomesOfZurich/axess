//! The record behind the password reset cooldown.

use axess_cache::ClockTtlCache;
use axess_clock::Clock;
use sha2::Digest as _;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Identifiers that asked for a reset recently, keyed by a digest of tenant
/// and identifier so the record holds no identifier and has a fixed key size.
pub(crate) struct ResetCooldowns {
    seen: ClockTtlCache<[u8; 32], ()>,
    /// Makes the read and the write of one request a single step: without
    /// it two requests arriving together both read "not seen" and both pass.
    gate: Mutex<()>,
}

impl ResetCooldowns {
    pub(crate) fn new(capacity: usize, cooldown: Duration, clock: Arc<dyn Clock>) -> Self {
        let capacity = NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::MIN);
        Self {
            seen: ClockTtlCache::new(capacity, cooldown, clock),
            gate: Mutex::new(()),
        }
    }

    /// Whether this tenant and identifier asked within the cooldown. When
    /// they did not, the request is noted (and starts the cooldown) before
    /// returning `false`.
    pub(crate) fn already_asked(&self, tenant_identifier: &str, identifier: &str) -> bool {
        let mut hasher = sha2::Sha256::new();
        for part in [tenant_identifier, identifier] {
            hasher.update((part.len() as u64).to_be_bytes());
            hasher.update(part.as_bytes());
        }
        let key: [u8; 32] = hasher.finalize().into();
        // A poisoned gate guards no data, so its poison carries no meaning.
        let _gate = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        if self.seen.get(&key).is_some() {
            return true;
        }
        self.seen.insert(key, ());
        false
    }
}
