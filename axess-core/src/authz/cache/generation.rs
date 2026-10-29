//! Invalidation generations, so a load that raced an invalidation cannot
//! put its stale result back.
//!
//! A cache miss reads the provider, which takes time. If an invalidation
//! lands while the read is in flight, the read still returns the old state
//! and, without a guard, writes it into the cache after the invalidation
//! has already run: the entry the invalidation was meant to remove is back
//! for a whole TTL. A [`Generations`] value counts invalidations. A loader
//! takes a [`Generation`] snapshot before it reads the provider; an
//! in-process cache folds it into the key (so a stale result lands under a
//! key nobody looks up again) and the Valkey cache compares it before and
//! after its write.
//!
//! Counters are striped by a hash of the principal or tenant, so memory is
//! fixed no matter how many principals are invalidated. Two principals that
//! share a stripe only cost each other an extra cache miss.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};

use cedar_policy::EntityUid;

const STRIPES: usize = 256;

/// The invalidation counters that apply to one cache key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Generation {
    all: u64,
    principal: u64,
    tenant: u64,
    resource: u64,
}

/// Invalidation counters for one cache.
pub(crate) struct Generations {
    all: AtomicU64,
    principals: Box<[AtomicU64]>,
    tenants: Box<[AtomicU64]>,
    resources: Box<[AtomicU64]>,
}

fn stripe(value: &impl Hash) -> usize {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    (hasher.finish() % STRIPES as u64) as usize
}

fn counters() -> Box<[AtomicU64]> {
    (0..STRIPES).map(|_| AtomicU64::new(0)).collect()
}

impl Generations {
    pub(crate) fn new() -> Self {
        Self {
            all: AtomicU64::new(0),
            principals: counters(),
            tenants: counters(),
            resources: counters(),
        }
    }

    /// Snapshot the counters that govern `(principal, tenant, resource)`.
    /// Take this before reading the provider.
    pub(crate) fn snapshot(
        &self,
        principal: &EntityUid,
        tenant: Option<&str>,
        resource: &EntityUid,
    ) -> Generation {
        Generation {
            all: self.all.load(Ordering::SeqCst),
            principal: self.principals[stripe(principal)].load(Ordering::SeqCst),
            tenant: tenant.map_or(0, |t| self.tenants[stripe(&t)].load(Ordering::SeqCst)),
            resource: self.resources[stripe(resource)].load(Ordering::SeqCst),
        }
    }

    /// Whether an invalidation that applies to the snapshot's key has run
    /// since the snapshot was taken.
    pub(crate) fn is_current(
        &self,
        taken: Generation,
        principal: &EntityUid,
        tenant: Option<&str>,
        resource: &EntityUid,
    ) -> bool {
        self.snapshot(principal, tenant, resource) == taken
    }

    /// Record an invalidation of everything. Call before evicting.
    pub(crate) fn bump_all(&self) {
        self.all.fetch_add(1, Ordering::SeqCst);
    }

    /// Record an invalidation of one principal. Call before evicting.
    pub(crate) fn bump_principal(&self, principal: &EntityUid) {
        self.principals[stripe(principal)].fetch_add(1, Ordering::SeqCst);
    }

    /// Record an invalidation of one resource. Call before evicting.
    pub(crate) fn bump_resource(&self, resource: &EntityUid) {
        self.resources[stripe(resource)].fetch_add(1, Ordering::SeqCst);
    }

    /// Record an invalidation of one tenant. Call before evicting.
    pub(crate) fn bump_tenant(&self, tenant: &str) {
        self.tenants[stripe(&tenant)].fetch_add(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn uid(name: &str) -> EntityUid {
        EntityUid::from_str(&format!("App::User::\"{name}\"")).unwrap()
    }

    #[test]
    fn an_invalidation_that_applies_changes_the_snapshot() {
        let g = Generations::new();
        let alice = uid("alice");
        let doc = uid("doc");
        let before = g.snapshot(&alice, Some("t1"), &doc);
        assert!(g.is_current(before, &alice, Some("t1"), &doc));

        g.bump_principal(&alice);
        assert!(!g.is_current(before, &alice, Some("t1"), &doc));

        let before = g.snapshot(&alice, Some("t1"), &doc);
        g.bump_tenant("t1");
        assert!(!g.is_current(before, &alice, Some("t1"), &doc));

        let before = g.snapshot(&alice, Some("t1"), &doc);
        g.bump_resource(&doc);
        assert!(!g.is_current(before, &alice, Some("t1"), &doc));

        let before = g.snapshot(&alice, None, &doc);
        g.bump_all();
        assert!(!g.is_current(before, &alice, None, &doc));
    }

    #[test]
    fn an_unrelated_invalidation_leaves_the_snapshot_current() {
        let g = Generations::new();
        let alice = uid("alice");
        let doc = uid("doc");
        let before = g.snapshot(&alice, Some("t1"), &doc);
        // Pick a name that does not share alice's stripe.
        let other = (0..)
            .map(|i| uid(&format!("other{i}")))
            .find(|u| stripe(u) != stripe(&alice))
            .unwrap();
        g.bump_principal(&other);
        assert!(g.is_current(before, &alice, Some("t1"), &doc));
    }
}
