//! The retention sweep of the Valkey device store.

use chrono::{DateTime, Utc};
use fred::prelude::*;

use super::apply::{Applied, Step};
use super::policy::{SweepStep, plan_sweep};
use super::row::tenant_index_key;
use super::{MGET_CHUNK, ValkeyDeviceStore, ValkeyDeviceStoreError};
use crate::device::store::{SweepCounts, demotion_stamp};
use crate::device::types::DeviceTrustLevel;

impl ValkeyDeviceStore {
    /// Walk the tenant's device index and move each row one step along the
    /// ladder.
    ///
    /// Native key TTLs would eventually evict stale rows on their own, but
    /// TTL alone cannot move a Trusted device to Seen; only the explicit
    /// demotion ladder can. Hence the walk. A row that cannot be decoded is
    /// logged and left alone, so one damaged row does not stop retention for
    /// the rest of the tenant.
    pub(super) async fn sweep_tenant(
        &self,
        tenant: &str,
        now: DateTime<Utc>,
    ) -> Result<SweepCounts, ValkeyDeviceStoreError> {
        let mut counts = SweepCounts::default();
        let tenant_idx = tenant_index_key(&self.prefix, tenant);
        let members: Vec<String> = self.client.smembers(&tenant_idx).await?;
        let cfg = self.sweep_config;

        for chunk in members.chunks(MGET_CHUNK) {
            // Rows are read a chunk at a time. A row that needs no change is
            // settled by that read alone; only a row that must be demoted,
            // stamped or purged goes on to its own compare-and-swap, which
            // reads it again.
            let read = self.read_rows(tenant, chunk).await?;
            // Rows already TTL-evicted: clean the tenant index.
            self.prune_absent(&tenant_idx, tenant, &read.gone).await;
            for (member, error) in &read.undecodable {
                tracing::warn!(device = %member, error = %error, "device row skipped by the sweep: it cannot be decoded");
            }
            for row in read.live {
                if matches!(plan_sweep(&row.device, &cfg, now), SweepStep::Keep) {
                    if row.stale {
                        self.reseal_row(&row.device, &row.raw).await;
                    }
                    continue;
                }
                let member = row.id;
                // Each row is planned against the bytes it is then swapped
                // or deleted under, so a revocation that lands mid-sweep
                // re-plans the row instead of being overwritten.
                let applied = self
                    .apply(tenant, &member, now, |d| match plan_sweep(d, &cfg, now) {
                        SweepStep::Keep => Step::Skip,
                        SweepStep::Purge => Step::Remove,
                        SweepStep::StampRevoked => {
                            let mut next = d.clone();
                            next.revoked_at = Some(now);
                            Step::Write(next)
                        }
                        SweepStep::Demote { level, .. } => {
                            let mut next = d.clone();
                            next.demoted_at =
                                demotion_stamp(d.trust_level, level, d.demoted_at, now);
                            next.trust_level = level;
                            if level == DeviceTrustLevel::Revoked {
                                next.revoked_at = Some(now);
                            }
                            Step::Write(next)
                        }
                    })
                    .await;
                match applied {
                    // Vanished between the chunk read and the swap.
                    Ok(Applied::Missing) => {
                        self.prune_absent(&tenant_idx, tenant, std::slice::from_ref(&member))
                            .await;
                    }
                    Ok(Applied::Skipped(_)) => {}
                    Ok(Applied::Written { before }) => {
                        if let SweepStep::Demote {
                            trusted_to_seen,
                            seen_to_revoked,
                            ..
                        } = plan_sweep(&before, &cfg, now)
                        {
                            counts.trusted_to_seen += u64::from(trusted_to_seen);
                            counts.seen_to_revoked += u64::from(seen_to_revoked);
                        }
                    }
                    Ok(Applied::Removed) => counts.revoked_purged += 1,
                    // A row that stays contended is retried by the next
                    // sweep; it must not abort the rest of the walk.
                    Err(ValkeyDeviceStoreError::Contended { .. }) => {}
                    // The row was readable in the chunk read and is not when
                    // the swap reads it again (it was rewritten under another
                    // key, or damaged): skip it like an undecodable row of
                    // the chunk read, so one row cannot stop the tenant.
                    Err(
                        error @ (ValkeyDeviceStoreError::Crypto(_)
                        | ValkeyDeviceStoreError::Decode(_)),
                    ) => {
                        tracing::warn!(device = %member, %error, "device row skipped by the sweep: it cannot be decoded");
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(counts)
    }
}
