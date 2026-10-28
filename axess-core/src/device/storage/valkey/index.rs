//! The membership indexes a device row belongs to, and the changes to them
//! that one row write carries.
//!
//! A row is listed in the tenant's index, its owner's index and one index per
//! refresh family it is bound to. When a row is written, the script that
//! writes it also adds the row to the indexes it now belongs to and removes
//! it from the ones it no longer does (see `WRITE_ROW`), so an index is never
//! updated by a separate command that could run in the other order.

use std::collections::BTreeMap;

use super::row::{
    family_index_key, fingerprint_hex, fingerprint_key, fingerprint_set_key, tenant_index_key,
    user_index_key,
};
use crate::device::types::{Device, DeviceBinding};

/// What a script does to one index key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum IndexOp {
    /// Add the device to the set.
    Add,
    /// Remove the device from the set.
    Remove,
    /// Delete a stale single-id fingerprint key, only if it still points at
    /// the device.
    DropFingerprint,
}

impl IndexOp {
    /// The one-letter code the scripts read.
    pub(super) fn code(self) -> &'static str {
        match self {
            Self::Add => "A",
            Self::Remove => "R",
            Self::DropFingerprint => "F",
        }
    }
}

/// The index keys a write touches, in script key order, with their ops.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct IndexPlan {
    entries: Vec<(String, IndexOp)>,
}

impl IndexPlan {
    /// The index keys, to follow the row and fingerprint keys.
    pub(super) fn keys(&self) -> impl Iterator<Item = String> + '_ {
        self.entries.iter().map(|(k, _)| k.clone())
    }

    /// The op codes, in key order.
    pub(super) fn ops(&self) -> Vec<&'static str> {
        self.entries.iter().map(|(_, op)| op.code()).collect()
    }

    /// The op planned for `key`, if any.
    #[cfg(test)]
    pub(super) fn op_for(&self, key: &str) -> Option<IndexOp> {
        self.entries
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, op)| *op)
    }
}

fn families(device: &Device) -> Vec<&str> {
    device
        .bindings
        .iter()
        .filter_map(|b| match b {
            DeviceBinding::Refresh { family_id, .. } => Some(family_id.as_str()),
            _ => None,
        })
        .collect()
}

/// The index changes for moving a row from `before` to `after`. `before`
/// `None` is a new row; `after` `None` is a removal (the fingerprint keys are
/// handled by the script itself then, and only removals are listed).
pub(super) fn plan_indexes(
    prefix: &str,
    before: Option<&Device>,
    after: Option<&Device>,
) -> IndexPlan {
    let Some(subject) = after.or(before) else {
        return IndexPlan::default();
    };
    let tenant = subject.tenant_id.to_string();
    // One op per key; a key never needs two.
    let mut ops: BTreeMap<String, IndexOp> = BTreeMap::new();
    let mut set = |key: String, op: IndexOp| {
        ops.insert(key, op);
    };

    set(
        tenant_index_key(prefix, &tenant),
        if after.is_some() {
            IndexOp::Add
        } else {
            IndexOp::Remove
        },
    );

    let user_key = |d: &Device| {
        d.user_id
            .map(|u| user_index_key(prefix, &tenant, &u.to_string()))
    };
    if let Some(key) = before.and_then(user_key) {
        set(key, IndexOp::Remove);
    }
    if let Some(key) = after.and_then(user_key) {
        set(key, IndexOp::Add);
    }

    for family in before.map(families).unwrap_or_default() {
        set(family_index_key(prefix, &tenant, family), IndexOp::Remove);
    }
    for family in after.map(families).unwrap_or_default() {
        set(family_index_key(prefix, &tenant, family), IndexOp::Add);
    }

    if let (Some(b), Some(a)) = (before, after)
        && b.fingerprint_hash != a.fingerprint_hash
    {
        let old = fingerprint_hex(&b.fingerprint_hash);
        set(fingerprint_set_key(prefix, &tenant, &old), IndexOp::Remove);
        set(
            fingerprint_key(prefix, &tenant, &old),
            IndexOp::DropFingerprint,
        );
    }
    IndexPlan {
        entries: ops.into_iter().collect(),
    }
}
