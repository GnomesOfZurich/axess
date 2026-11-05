//! A safe O(1) LRU map: a `HashMap` from key to slot plus a slab-backed
//! doubly linked list that orders the slots from most to least recently used.
//!
//! The list links are slab indices, not pointers, so the module needs no
//! `unsafe`. Freed slots are chained through `free` and reused.

use std::collections::HashMap;
use std::hash::Hash;
use std::num::NonZeroUsize;

/// Marks "no neighbour" in the list links and "no free slot" in the free list.
const NIL: usize = usize::MAX;

struct Node<K, V> {
    key: K,
    value: V,
    /// Towards the most recently used end.
    prev: usize,
    /// Towards the least recently used end.
    next: usize,
}

/// A slab slot: a live list node, or a link in the free list.
enum Slot<K, V> {
    Live(Node<K, V>),
    Free { next_free: usize },
}

/// Fixed-capacity map that evicts the least recently used entry on overflow.
pub(crate) struct LruMap<K, V> {
    map: HashMap<K, usize>,
    slab: Vec<Slot<K, V>>,
    /// Most recently used slot, or `NIL` when empty.
    head: usize,
    /// Least recently used slot, or `NIL` when empty.
    tail: usize,
    /// First free slot, or `NIL` when the slab has no holes.
    free: usize,
    cap: NonZeroUsize,
}

impl<K: Hash + Eq + Clone, V> LruMap<K, V> {
    pub(crate) fn new(cap: NonZeroUsize) -> Self {
        Self {
            map: HashMap::new(),
            slab: Vec::new(),
            head: NIL,
            tail: NIL,
            free: NIL,
            cap,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.map.len()
    }

    pub(crate) fn cap(&self) -> NonZeroUsize {
        self.cap
    }

    /// Look up `key` and mark it most recently used.
    pub(crate) fn get(&mut self, key: &K) -> Option<&V> {
        let idx = *self.map.get(key)?;
        self.unlink(idx);
        self.push_front(idx);
        Some(&self.node(idx).value)
    }

    /// Insert or replace `key`, making it most recently used. At capacity a
    /// new key first evicts the least recently used entry.
    pub(crate) fn put(&mut self, key: K, value: V) {
        if let Some(&idx) = self.map.get(&key) {
            self.node_mut(idx).value = value;
            self.unlink(idx);
            self.push_front(idx);
            return;
        }
        if self.map.len() >= self.cap.get() {
            self.evict_tail();
        }
        let idx = self.alloc(Node {
            key: key.clone(),
            value,
            prev: NIL,
            next: NIL,
        });
        self.push_front(idx);
        self.map.insert(key, idx);
    }

    /// Remove `key` and return its value.
    pub(crate) fn pop(&mut self, key: &K) -> Option<V> {
        let idx = self.map.remove(key)?;
        self.unlink(idx);
        Some(self.release(idx).value)
    }

    pub(crate) fn clear(&mut self) {
        self.map.clear();
        self.slab.clear();
        self.head = NIL;
        self.tail = NIL;
        self.free = NIL;
    }

    /// Entries from most to least recently used. Does not touch recency.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        let mut at = self.head;
        std::iter::from_fn(move || {
            if at == NIL {
                return None;
            }
            let node = self.node(at);
            at = node.next;
            Some((&node.key, &node.value))
        })
    }

    fn node(&self, idx: usize) -> &Node<K, V> {
        match &self.slab[idx] {
            Slot::Live(node) => node,
            Slot::Free { .. } => unreachable!("list or map points at a freed slot"),
        }
    }

    fn node_mut(&mut self, idx: usize) -> &mut Node<K, V> {
        match &mut self.slab[idx] {
            Slot::Live(node) => node,
            Slot::Free { .. } => unreachable!("list or map points at a freed slot"),
        }
    }

    fn alloc(&mut self, node: Node<K, V>) -> usize {
        if self.free == NIL {
            self.slab.push(Slot::Live(node));
            return self.slab.len() - 1;
        }
        let idx = self.free;
        match self.slab[idx] {
            Slot::Free { next_free } => self.free = next_free,
            Slot::Live(_) => unreachable!("free list points at a live slot"),
        }
        self.slab[idx] = Slot::Live(node);
        idx
    }

    /// Free `idx` (already unlinked) and hand back its node.
    fn release(&mut self, idx: usize) -> Node<K, V> {
        let old = std::mem::replace(
            &mut self.slab[idx],
            Slot::Free {
                next_free: self.free,
            },
        );
        self.free = idx;
        match old {
            Slot::Live(node) => node,
            Slot::Free { .. } => unreachable!("released a freed slot"),
        }
    }

    fn evict_tail(&mut self) {
        let idx = self.tail;
        if idx == NIL {
            return;
        }
        self.unlink(idx);
        let node = self.release(idx);
        self.map.remove(&node.key);
    }

    /// Detach `idx` from the list, fixing its neighbours, head and tail.
    fn unlink(&mut self, idx: usize) {
        let (prev, next) = {
            let node = self.node(idx);
            (node.prev, node.next)
        };
        if prev == NIL {
            self.head = next;
        } else {
            self.node_mut(prev).next = next;
        }
        if next == NIL {
            self.tail = prev;
        } else {
            self.node_mut(next).prev = prev;
        }
    }

    /// Link the detached `idx` in as the most recently used slot.
    fn push_front(&mut self, idx: usize) {
        let old_head = self.head;
        {
            let node = self.node_mut(idx);
            node.prev = NIL;
            node.next = old_head;
        }
        if old_head == NIL {
            self.tail = idx;
        } else {
            self.node_mut(old_head).prev = idx;
        }
        self.head = idx;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(cap: usize) -> LruMap<u32, &'static str> {
        LruMap::new(NonZeroUsize::new(cap).unwrap())
    }

    fn order(m: &LruMap<u32, &'static str>) -> Vec<u32> {
        m.iter().map(|(k, _)| *k).collect()
    }

    #[test]
    fn get_moves_the_entry_to_the_front() {
        let mut m = map(3);
        m.put(1, "a");
        m.put(2, "b");
        m.put(3, "c");
        assert_eq!(order(&m), [3, 2, 1]);
        assert_eq!(m.get(&1), Some(&"a"));
        assert_eq!(order(&m), [1, 3, 2]);
        assert_eq!(m.get(&1), Some(&"a"));
        assert_eq!(order(&m), [1, 3, 2]);
    }

    #[test]
    fn a_miss_changes_nothing() {
        let mut m = map(2);
        m.put(1, "a");
        assert_eq!(m.get(&9), None);
        assert_eq!(order(&m), [1]);
    }

    #[test]
    fn put_at_capacity_evicts_the_least_recently_used() {
        let mut m = map(2);
        m.put(1, "a");
        m.put(2, "b");
        m.get(&1);
        m.put(3, "c");
        assert_eq!(m.len(), 2);
        assert_eq!(m.get(&2), None);
        assert_eq!(order(&m), [3, 1]);
    }

    #[test]
    fn re_put_of_an_existing_key_replaces_the_value_and_moves_it_to_the_front() {
        let mut m = map(3);
        m.put(1, "a");
        m.put(2, "b");
        m.put(3, "c");
        m.put(1, "z");
        assert_eq!(m.len(), 3);
        assert_eq!(order(&m), [1, 3, 2]);
        assert_eq!(m.get(&1), Some(&"z"));
    }

    #[test]
    fn re_put_at_capacity_evicts_nothing() {
        let mut m = map(2);
        m.put(1, "a");
        m.put(2, "b");
        m.put(1, "z");
        assert_eq!(m.len(), 2);
        assert_eq!(m.get(&2), Some(&"b"));
    }

    #[test]
    fn pop_from_the_middle_keeps_the_list_linked() {
        let mut m = map(4);
        for k in 1..=4 {
            m.put(k, "v");
        }
        assert_eq!(order(&m), [4, 3, 2, 1]);
        assert_eq!(m.pop(&3), Some("v"));
        assert_eq!(order(&m), [4, 2, 1]);
        assert_eq!(m.pop(&3), None);
        // The freed slot is reused and the ends still evict correctly.
        m.put(5, "v");
        m.put(6, "v");
        assert_eq!(order(&m), [6, 5, 4, 2]);
        assert_eq!(m.get(&1), None);
    }

    #[test]
    fn pop_of_head_and_tail_updates_both_ends() {
        let mut m = map(3);
        m.put(1, "a");
        m.put(2, "b");
        m.put(3, "c");
        assert_eq!(m.pop(&3), Some("c"));
        assert_eq!(m.pop(&1), Some("a"));
        assert_eq!(order(&m), [2]);
        assert_eq!(m.pop(&2), Some("b"));
        assert_eq!(m.len(), 0);
        assert_eq!(order(&m), Vec::<u32>::new());
        m.put(7, "g");
        assert_eq!(order(&m), [7]);
    }

    #[test]
    fn capacity_one_keeps_only_the_latest() {
        let mut m = map(1);
        m.put(1, "a");
        m.put(2, "b");
        assert_eq!(m.len(), 1);
        assert_eq!(m.get(&1), None);
        assert_eq!(m.get(&2), Some(&"b"));
        m.put(2, "c");
        assert_eq!(m.get(&2), Some(&"c"));
        assert_eq!(m.cap().get(), 1);
    }

    #[test]
    fn clear_empties_and_the_map_is_reusable() {
        let mut m = map(2);
        m.put(1, "a");
        m.put(2, "b");
        m.clear();
        assert_eq!(m.len(), 0);
        assert_eq!(m.get(&1), None);
        m.put(3, "c");
        assert_eq!(order(&m), [3]);
    }

    #[test]
    fn the_slab_does_not_grow_past_capacity_under_churn() {
        let mut m = map(3);
        for k in 0..1000 {
            m.put(k, "v");
            if k % 3 == 0 {
                m.pop(&(k.saturating_sub(1)));
            }
        }
        assert!(m.slab.len() <= 3);
        assert!(m.len() <= 3);
    }
}
