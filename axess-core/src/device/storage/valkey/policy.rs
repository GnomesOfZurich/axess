//! Pure retention decisions: native key TTLs and the sweep ladder.

use chrono::{DateTime, Utc};

use crate::device::store::SweepConfig;
use crate::device::types::{Device, DeviceTrustLevel};

/// Native key TTL in seconds for a row, or `None` for a row that must not
/// expire.
///
/// The TTL is a backstop that has to cover the whole ladder the sweep walks,
/// otherwise the key vanishes before the sweep can demote it:
///
/// | Level | TTL |
/// |-------|-----|
/// | `Unknown` | none (never removed by retention) |
/// | `Trusted` | `last_seen_at + trusted_idle + seen_idle + revoked_grace` |
/// | `Seen` | `max(last_seen_at, demoted_at) + seen_idle + revoked_grace` |
/// | `Revoked` | `revoked_at + revoked_grace` |
///
/// A `Trusted` row has to outlive its demotion and then its whole Seen
/// window, so it carries both. A `Seen` row's Revoked stage is due
/// `seen_idle` after the later of its last sighting and its demotion, and the
/// grace follows. Positive results are floored at 1 second so an
/// already-late key still exists briefly.
pub(super) fn ttl_seconds(cfg: &SweepConfig, device: &Device, now: DateTime<Utc>) -> Option<i64> {
    let expiry = match device.trust_level {
        DeviceTrustLevel::Unknown => return None,
        DeviceTrustLevel::Trusted => {
            device.last_seen_at + cfg.trusted_idle + cfg.seen_idle + cfg.revoked_grace
        }
        DeviceTrustLevel::Seen => seen_clock(device) + cfg.seen_idle + cfg.revoked_grace,
        DeviceTrustLevel::Revoked => device.revoked_at.unwrap_or(now) + cfg.revoked_grace,
    };
    Some(expiry.signed_duration_since(now).num_seconds().max(1))
}

/// The instant a `Seen` row's idle window runs from: the later of its last
/// sighting and its demotion from `Trusted`.
fn seen_clock(device: &Device) -> DateTime<Utc> {
    device
        .demoted_at
        .map_or(device.last_seen_at, |d| d.max(device.last_seen_at))
}

/// What the sweep decided for one row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SweepStep {
    /// Nothing is due.
    Keep,
    /// Demote (never promote) to the given level.
    Demote {
        level: DeviceTrustLevel,
        trusted_to_seen: bool,
        seen_to_revoked: bool,
    },
    /// The revoked grace has elapsed.
    Purge,
}

/// Decide the sweep action for a row.
///
/// One step per row per sweep, by the same rule as the other backends
/// ([`SweepConfig::level_after`]): a `Trusted` row idle for more than
/// `trusted_idle` becomes `Seen` (stamped by the caller) and is never revoked
/// in that pass; a `Seen` row becomes `Revoked` once `seen_idle` has passed
/// since the later of its last sighting and its demotion. `Revoked` rows are
/// purged once `revoked_grace` has passed since `revoked_at`; a row revoked
/// by this very pass is not purged. `Unknown` rows and `Revoked` rows are
/// never moved to a less-revoked level.
pub(super) fn plan_sweep(device: &Device, cfg: &SweepConfig, now: DateTime<Utc>) -> SweepStep {
    if device.trust_level == DeviceTrustLevel::Revoked {
        return match device.revoked_at {
            Some(r) if now.signed_duration_since(r) > cfg.revoked_grace => SweepStep::Purge,
            _ => SweepStep::Keep,
        };
    }
    let next = cfg.level_after(
        device.trust_level,
        device.last_seen_at,
        device.demoted_at,
        now,
    );
    match (device.trust_level, next) {
        (DeviceTrustLevel::Trusted, DeviceTrustLevel::Seen) => SweepStep::Demote {
            level: DeviceTrustLevel::Seen,
            trusted_to_seen: true,
            seen_to_revoked: false,
        },
        (DeviceTrustLevel::Seen, DeviceTrustLevel::Revoked) => SweepStep::Demote {
            level: DeviceTrustLevel::Revoked,
            trusted_to_seen: false,
            seen_to_revoked: true,
        },
        _ => SweepStep::Keep,
    }
}
