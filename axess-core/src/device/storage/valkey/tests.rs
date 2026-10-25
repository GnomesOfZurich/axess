//! Pure tests (script text, argument assembly, status mapping, TTL and sweep
//! decisions) plus `#[ignore]` integration tests that need a live server:
//! `VALKEY_URL=redis://127.0.0.1:6399 cargo test -p axess-core --features valkey -- --ignored valkey_device`.

use chrono::{DateTime, Duration, TimeZone, Utc};
use fred::bytes::Bytes;

use super::policy::{SweepStep, plan_sweep, ttl_seconds};
use super::scripts::{
    CAS_WRITE, DELETE_IF_POINTS_AT, PRUNE_ABSENT, REMOVE_DEVICE, ScriptStatus, cas_write_args,
    pair_replies, parse_status, prune_args, remove_args, row_keys,
};
use super::*;

fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
}

fn device(level: DeviceTrustLevel, last_seen: DateTime<Utc>) -> Device {
    Device {
        id: axess_identity::testing::device("dev-1"),
        tenant_id: axess_identity::testing::tenant("tenant-1"),
        user_id: Some(axess_identity::testing::user("user-1")),
        trust_level: level,
        fingerprint_hash: FingerprintHash::from_bytes([0xaa; 32]),
        first_seen_at: last_seen,
        last_seen_at: last_seen,
        revoked_at: (level == DeviceTrustLevel::Revoked).then_some(last_seen),
        demoted_at: None,
        bindings: Vec::new(),
    }
}

const DAY: i64 = 86_400;

#[test]
fn ttl_covers_the_whole_ladder_per_level() {
    let cfg = SweepConfig::default(); // 90 / 30 / 7
    let now = t0();
    let idle = |days: i64| now - Duration::days(days);
    // (level, last_seen, expected ttl seconds)
    let mut revoked = device(DeviceTrustLevel::Revoked, idle(1));
    revoked.revoked_at = Some(idle(2));
    let mut demoted_seen = device(DeviceTrustLevel::Seen, idle(100));
    demoted_seen.demoted_at = Some(idle(2));
    let mut sighted_after_demotion = device(DeviceTrustLevel::Seen, now);
    sighted_after_demotion.demoted_at = Some(idle(40));
    let cases = [
        // Trusted lives 90 + 30 + 7 days past the last sighting.
        (device(DeviceTrustLevel::Trusted, now), Some(127 * DAY)),
        (device(DeviceTrustLevel::Trusted, idle(100)), Some(27 * DAY)),
        // Never-Trusted Seen lives seen_idle + grace past the last sighting.
        (device(DeviceTrustLevel::Seen, now), Some(37 * DAY)),
        (demoted_seen, Some(35 * DAY)),
        // A sighting after the demotion restarts the window.
        (sighted_after_demotion, Some(37 * DAY)),
        // Unknown is never removed by retention.
        (device(DeviceTrustLevel::Unknown, idle(400)), None),
        // Revoked: grace from revoked_at.
        (revoked, Some(5 * DAY)),
        // Past due floors at one second.
        (device(DeviceTrustLevel::Seen, idle(500)), Some(1)),
    ];
    for (d, want) in cases {
        assert_eq!(ttl_seconds(&cfg, &d, now), want, "{:?}", d.trust_level);
    }
}

#[test]
fn trusted_ttl_outlives_the_demotion_and_its_seen_window() {
    let cfg = SweepConfig::default();
    let d = device(DeviceTrustLevel::Trusted, t0());
    let ttl = ttl_seconds(&cfg, &d, t0()).unwrap();
    // A Trusted key must not expire at 90 days, before the sweep can demote
    // it, nor before the Seen window that follows the demotion.
    assert!(ttl > (cfg.trusted_idle + cfg.seen_idle).num_seconds());
}

/// The shared ladder, through the Valkey planner and the stamp the sweep
/// writes: the level each row settles at matches the other backends.
#[test]
fn sweep_plan_follows_the_ladder_table() {
    use crate::device::store::{demotion_stamp, ladder::LADDER};
    let cfg = SweepConfig::default();
    let now = t0();
    for r in LADDER {
        let mut d = device(r.level, r.last_seen(now));
        d.demoted_at = r.demoted_at(now);
        let (level, stamp) = match plan_sweep(&d, &cfg, now) {
            SweepStep::Demote { level, .. } => (
                level,
                demotion_stamp(d.trust_level, level, d.demoted_at, now),
            ),
            _ => (d.trust_level, d.demoted_at),
        };
        let what = (r.level, r.idle_days, r.demoted_days_ago);
        assert_eq!(level, r.want, "{what:?}");
        // A Trusted row demoted by this pass is stamped with `now`; nothing
        // else gains a stamp.
        let demoted_now = r.level == DeviceTrustLevel::Trusted && level == DeviceTrustLevel::Seen;
        assert_eq!(stamp == Some(now), demoted_now, "{what:?}");
    }
}

#[test]
fn sweep_plan_table() {
    let cfg = SweepConfig::default();
    let now = t0();
    let ago = |days: i64| now - Duration::days(days);
    let demote = |level, t2s, s2r| SweepStep::Demote {
        level,
        trusted_to_seen: t2s,
        seen_to_revoked: s2r,
    };
    let mut old_revoked = device(DeviceTrustLevel::Revoked, ago(40));
    old_revoked.revoked_at = Some(ago(8));
    let mut fresh_revoked = device(DeviceTrustLevel::Revoked, ago(40));
    fresh_revoked.revoked_at = Some(ago(2));
    let cases = [
        (device(DeviceTrustLevel::Trusted, ago(89)), SweepStep::Keep),
        (
            device(DeviceTrustLevel::Trusted, ago(100)),
            demote(DeviceTrustLevel::Seen, true, false),
        ),
        // Idle past both windows still stops at Seen: one step per pass.
        (
            device(DeviceTrustLevel::Trusted, ago(400)),
            demote(DeviceTrustLevel::Seen, true, false),
        ),
        (device(DeviceTrustLevel::Seen, ago(29)), SweepStep::Keep),
        (
            device(DeviceTrustLevel::Seen, ago(31)),
            demote(DeviceTrustLevel::Revoked, false, true),
        ),
        (device(DeviceTrustLevel::Unknown, ago(900)), SweepStep::Keep),
        (old_revoked, SweepStep::Purge),
        (fresh_revoked, SweepStep::Keep),
    ];
    for (d, want) in cases {
        assert_eq!(plan_sweep(&d, &cfg, now), want, "{:?}", d.trust_level);
    }
}

#[test]
fn sweep_never_plans_a_revoked_row_to_a_less_revoked_level() {
    let cfg = SweepConfig::default();
    for days in [0, 5, 31, 121, 1000] {
        let d = device(DeviceTrustLevel::Revoked, t0() - Duration::days(days));
        let step = plan_sweep(&d, &cfg, t0());
        assert!(
            matches!(step, SweepStep::Keep | SweepStep::Purge),
            "{step:?}"
        );
    }
}

#[test]
fn status_mapping() {
    assert_eq!(parse_status("ok"), Some(ScriptStatus::Ok));
    assert_eq!(parse_status("missing"), Some(ScriptStatus::Missing));
    assert_eq!(parse_status("conflict"), Some(ScriptStatus::Conflict));
    assert_eq!(parse_status("OK"), None);
    assert_eq!(parse_status(""), None);
}

#[test]
fn cas_write_args_are_ordered_and_binary_safe() {
    let args = cas_write_args(&[0, 255, 1], &[9, 0], Some(42), "dev-1");
    assert_eq!(
        args,
        vec![
            Value::Bytes(Bytes::from_static(&[0, 255, 1])),
            Value::Bytes(Bytes::from_static(&[9, 0])),
            Value::Integer(42),
            Value::Bytes(Bytes::from_static(b"dev-1")),
        ]
    );
    // No expiry is encoded as 0, which the script treats as "persist".
    assert_eq!(cas_write_args(b"a", b"b", None, "d")[2], Value::Integer(0));
}

#[test]
fn remove_args_encode_unconditional_as_empty() {
    assert_eq!(
        remove_args(None, "d"),
        vec![
            Value::Bytes(Bytes::new()),
            Value::Bytes(Bytes::from_static(b"d"))
        ]
    );
    assert_eq!(
        remove_args(Some(b"row"), "d")[0],
        Value::Bytes(Bytes::from_static(b"row"))
    );
}

#[test]
fn scripts_compare_before_they_write_or_delete() {
    let pos = |s: &str, needle: &str| s.find(needle).unwrap_or_else(|| panic!("{needle}"));
    // The row swap compares the stored bytes to the expectation before SET.
    assert!(pos(CAS_WRITE, "current ~= ARGV[1]") < pos(CAS_WRITE, "'SET'"));
    // The fingerprint index is touched only while it points at this device.
    assert!(pos(CAS_WRITE, "GET', KEYS[2]) == ARGV[4]") < pos(CAS_WRITE, "'EXPIRE'"));
    assert!(pos(REMOVE_DEVICE, "current ~= ARGV[1]") < pos(REMOVE_DEVICE, "'DEL', KEYS[1]"));
    assert!(pos(REMOVE_DEVICE, "GET', KEYS[2]) == ARGV[2]") < pos(REMOVE_DEVICE, "'DEL', KEYS[2]"));
    assert!(
        pos(DELETE_IF_POINTS_AT, "GET', KEYS[1]) == ARGV[1]") < pos(DELETE_IF_POINTS_AT, "'DEL'")
    );
}

// ── row binding (no server needed: encode/decode never touch the client) ──

fn offline_store() -> ValkeyDeviceStore {
    let client = Client::new(Config::default(), None, None, None);
    ValkeyDeviceStore::new(client, [7u8; 32])
}

/// A sealed row moved to another device's key must not open there.
#[test]
fn a_sealed_row_does_not_open_under_another_device_id() {
    let s = offline_store();
    let a = device(DeviceTrustLevel::Trusted, t0());
    let sealed = s.encode_row(&a).unwrap();
    assert!(sealed.starts_with(b"AXR\x01"));
    let (tenant, id) = (a.tenant_id.to_string(), a.id.to_string());
    assert_eq!(s.decode_row(&tenant, &id, &sealed).unwrap(), a);
    assert!(s.decode_row(&tenant, "dev-2", &sealed).is_err());
    assert!(s.decode_row("tenant-2", &id, &sealed).is_err());
}

/// A row written before binding (plain AES-GCM, no marker) still reads, and
/// the next encode seals it in the bound form.
#[test]
fn a_legacy_row_reads_and_is_resealed_bound() {
    let s = offline_store();
    let a = device(DeviceTrustLevel::Seen, t0());
    let legacy = s
        .crypto
        .as_ref()
        .unwrap()
        .encrypt_unbound(&rmp_serde::to_vec_named(&a).unwrap())
        .unwrap();
    assert!(!legacy.starts_with(b"AXR\x01"));
    let (tenant, id) = (a.tenant_id.to_string(), a.id.to_string());
    let read = s.decode_row(&tenant, &id, &legacy).unwrap();
    assert_eq!(read, a);
    let resealed = s.encode_row(&read).unwrap();
    assert!(resealed.starts_with(b"AXR\x01"));
    assert!(s.decode_row(&tenant, "dev-2", &resealed).is_err());
}

/// A row from before `demoted_at` existed reads with no demotion.
#[test]
fn a_row_without_demoted_at_reads_as_never_trusted() {
    #[derive(serde::Serialize)]
    struct OldRow {
        id: crate::authn::ids::DeviceId,
        tenant_id: crate::authn::ids::TenantId,
        user_id: Option<crate::authn::ids::UserId>,
        trust_level: DeviceTrustLevel,
        fingerprint_hash: FingerprintHash,
        first_seen_at: DateTime<Utc>,
        last_seen_at: DateTime<Utc>,
        revoked_at: Option<DateTime<Utc>>,
        bindings: Vec<DeviceBinding>,
    }
    let d = device(DeviceTrustLevel::Seen, t0());
    let old = OldRow {
        id: d.id,
        tenant_id: d.tenant_id,
        user_id: d.user_id,
        trust_level: d.trust_level,
        fingerprint_hash: d.fingerprint_hash,
        first_seen_at: d.first_seen_at,
        last_seen_at: d.last_seen_at,
        revoked_at: None,
        bindings: Vec::new(),
    };
    let bytes = rmp_serde::to_vec_named(&old).unwrap();
    let got: Device = rmp_serde::from_slice(&bytes).unwrap();
    assert_eq!(got.demoted_at, None);
}

// ── live-server tests (ignored by default) ──────────────────────────────

async fn live_store(prefix: &str) -> ValkeyDeviceStore {
    let url = std::env::var("VALKEY_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
    let client = Client::new(Config::from_url(&url).expect("url"), None, None, None);
    client.init().await.expect("connect");
    ValkeyDeviceStore::plaintext(client).with_prefix(prefix.to_string())
}

fn named(id: &str, fp: u8, level: DeviceTrustLevel, last_seen: DateTime<Utc>) -> Device {
    let mut d = device(level, last_seen);
    d.id = axess_identity::testing::device(id);
    d.fingerprint_hash = FingerprintHash::from_bytes([fp; 32]);
    d
}

#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_device_missing_row_is_not_found() {
    let s = live_store("axt_missing").await;
    let (t, i) = (
        axess_identity::testing::tenant("tenant-1"),
        axess_identity::testing::device("nope"),
    );
    assert!(matches!(
        s.record_sighting(&t, &i, Utc::now()).await,
        Err(ValkeyDeviceStoreError::NotFound { .. })
    ));
    assert!(matches!(
        s.set_trust_level(&t, &i, DeviceTrustLevel::Seen, Utc::now())
            .await,
        Err(ValkeyDeviceStoreError::NotFound { .. })
    ));
}

#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_device_stale_swap_conflicts_and_revocation_survives() {
    let s = live_store("axt_cas").await;
    let now = Utc::now();
    let d = named("dev-1", 0xaa, DeviceTrustLevel::Seen, now);
    s.save(&d, Utc::now()).await.unwrap();
    let (tenant, id) = (d.tenant_id.to_string(), d.id.to_string());
    let row_key = device_key(&s.prefix, &tenant, &id);
    // A writer read the row ...
    let stale: Vec<u8> = s.client.get(&row_key).await.unwrap();
    // ... then a revocation lands.
    s.set_trust_level(&d.tenant_id, &d.id, DeviceTrustLevel::Revoked, now)
        .await
        .unwrap();
    // The stale swap must be refused rather than resurrect the row.
    let mut resurrected = d.clone();
    resurrected.last_seen_at = now + Duration::seconds(5);
    let args = cas_write_args(&stale, &s.encode_row(&resurrected).unwrap(), Some(600), &id);
    let fp = fingerprint_key(&s.prefix, &tenant, &fingerprint_hex(&d.fingerprint_hash));
    let status = s
        .run_script(CAS_WRITE, vec![row_key, fp], args)
        .await
        .unwrap();
    assert_eq!(status, ScriptStatus::Conflict);
    // A sighting after revocation changes nothing.
    s.record_sighting(&d.tenant_id, &d.id, now + Duration::seconds(9))
        .await
        .unwrap();
    let got = s.load(&d.tenant_id, &d.id).await.unwrap().unwrap();
    assert_eq!(got.trust_level, DeviceTrustLevel::Revoked);
    assert_eq!(got.last_seen_at, now);
    s.delete(&d.tenant_id, &d.id).await.unwrap();
}

#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_device_delete_keeps_a_shared_fingerprint_lookup() {
    let s = live_store("axt_fp").await;
    let now = Utc::now();
    let a = named("dev-a", 0xbb, DeviceTrustLevel::Seen, now);
    let b = named("dev-b", 0xbb, DeviceTrustLevel::Seen, now);
    s.save(&a, Utc::now()).await.unwrap();
    s.save(&b, Utc::now()).await.unwrap(); // b saved last: the index points at b
    s.delete(&a.tenant_id, &a.id).await.unwrap();
    let found = s
        .find_by_fingerprint(&b.tenant_id, &b.fingerprint_hash)
        .await
        .unwrap();
    assert_eq!(found.map(|d| d.id), Some(b.id));
    s.delete(&b.tenant_id, &b.id).await.unwrap();
    let gone = s
        .find_by_fingerprint(&b.tenant_id, &b.fingerprint_hash)
        .await
        .unwrap();
    assert!(gone.is_none());
}

#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_device_ttls_follow_the_ladder_and_sweep_uses_120_days() {
    let s = live_store("axt_ttl").await;
    let now = Utc::now();
    let tenant = axess_identity::testing::tenant("tenant-1");
    let trusted = named("dev-t", 1, DeviceTrustLevel::Trusted, now);
    let unknown = named("dev-u", 2, DeviceTrustLevel::Unknown, now);
    s.save(&trusted, Utc::now()).await.unwrap();
    s.save(&unknown, Utc::now()).await.unwrap();
    let ttl = |d: &Device| device_key(&s.prefix, &d.tenant_id.to_string(), &d.id.to_string());
    let t: i64 = s.client.ttl(ttl(&trusted)).await.unwrap();
    let u: i64 = s.client.ttl(ttl(&unknown)).await.unwrap();
    assert!(t > 126 * DAY && t <= 127 * DAY, "trusted ttl {t}");
    assert_eq!(u, -1, "unknown must not expire");
    // 100 days idle: demoted to Seen, not Revoked.
    let old = named(
        "dev-o",
        3,
        DeviceTrustLevel::Trusted,
        now - Duration::days(100),
    );
    s.save(&old, Utc::now()).await.unwrap();
    let counts = s.sweep(&tenant, now).await.unwrap();
    assert_eq!((counts.trusted_to_seen, counts.seen_to_revoked), (1, 0));
    let got = s.load(&tenant, &old.id).await.unwrap().unwrap();
    assert_eq!(got.trust_level, DeviceTrustLevel::Seen);
    for d in [&trusted, &unknown, &old] {
        s.delete(&d.tenant_id, &d.id).await.unwrap();
    }
}

#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_device_conditional_writes_refuse_a_revoked_row() {
    use crate::device::store::{BindingsUpdate, TrustTransition};
    let s = live_store("axt_cond").await;
    let now = Utc::now();
    let d = named("dev-1", 0xc1, DeviceTrustLevel::Seen, now);
    s.save(&d, Utc::now()).await.unwrap();
    s.set_trust_level(&d.tenant_id, &d.id, DeviceTrustLevel::Revoked, now)
        .await
        .unwrap();

    let got = s
        .set_trust_level_if(
            &d.tenant_id,
            &d.id,
            DeviceTrustLevel::Seen,
            DeviceTrustLevel::Trusted,
            now,
        )
        .await
        .unwrap();
    assert_eq!(
        got,
        TrustTransition::Refused {
            current: DeviceTrustLevel::Revoked
        }
    );
    let binding = DeviceBinding::Refresh {
        family_id: "fam-x".into(),
        issued_at: now,
        last_used_at: now,
    };
    assert_eq!(
        s.replace_bindings(&d.tenant_id, &d.id, &[], &[binding], Utc::now())
            .await
            .unwrap(),
        BindingsUpdate::Revoked
    );
    let row = s.load(&d.tenant_id, &d.id).await.unwrap().unwrap();
    assert_eq!(row.trust_level, DeviceTrustLevel::Revoked);
    assert!(row.bindings.is_empty());

    let ghost = axess_identity::testing::device("ghost");
    assert_eq!(
        s.set_trust_level_if(
            &d.tenant_id,
            &ghost,
            DeviceTrustLevel::Seen,
            DeviceTrustLevel::Trusted,
            now
        )
        .await
        .unwrap(),
        TrustTransition::Missing
    );
    s.delete(&d.tenant_id, &d.id).await.unwrap();
}

/// A promotion decided from an earlier read races a revocation on the same
/// row. Whatever the interleaving, the revocation is never undone.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_device_a_racing_promotion_never_undoes_a_revocation() {
    let s = live_store("axt_race").await;
    for round in 0..25u8 {
        let now = Utc::now();
        let d = named("dev-1", 0xc2 ^ round, DeviceTrustLevel::Seen, now);
        s.save(&d, Utc::now()).await.unwrap();
        let (a, b) = tokio::join!(
            s.set_trust_level_if(
                &d.tenant_id,
                &d.id,
                DeviceTrustLevel::Seen,
                DeviceTrustLevel::Trusted,
                now
            ),
            s.set_trust_level(&d.tenant_id, &d.id, DeviceTrustLevel::Revoked, now),
        );
        let _promotion = a.unwrap();
        b.unwrap();
        let row = s.load(&d.tenant_id, &d.id).await.unwrap().unwrap();
        assert_eq!(row.trust_level, DeviceTrustLevel::Revoked, "round {round}");
        s.delete(&d.tenant_id, &d.id).await.unwrap();
    }
}

#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_device_replace_bindings_moves_the_family_index() {
    use crate::device::store::BindingsUpdate;
    let s = live_store("axt_fam").await;
    let now = Utc::now();
    let refresh = |f: &str| DeviceBinding::Refresh {
        family_id: f.into(),
        issued_at: now,
        last_used_at: now,
    };
    let mut d = named("dev-1", 0xc3, DeviceTrustLevel::Seen, now);
    d.bindings = vec![refresh("fam-a")];
    s.save(&d, Utc::now()).await.unwrap();
    let written = s
        .replace_bindings(
            &d.tenant_id,
            &d.id,
            &[refresh("fam-a")],
            &[refresh("fam-b")],
            Utc::now(),
        )
        .await
        .unwrap();
    assert_eq!(written, BindingsUpdate::Written);
    let by = |f: &'static str| {
        let (s, t) = (s.clone(), d.tenant_id);
        async move { s.find_by_refresh_family(&t, f).await.unwrap().len() }
    };
    assert_eq!(by("fam-a").await, 0, "dropped family leaves the index");
    assert_eq!(by("fam-b").await, 1, "new family enters the index");
    s.delete(&d.tenant_id, &d.id).await.unwrap();
}

/// The shared ladder, end to end against a live server.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_device_sweep_follows_the_ladder_table() {
    use crate::device::store::ladder::LADDER;
    let s = live_store("axt_ladder").await;
    let now = Utc::now();
    let tenant = axess_identity::testing::tenant("tenant-1");
    for (i, r) in LADDER.iter().enumerate() {
        let mut d = named(&format!("row-{i}"), i as u8, r.level, r.last_seen(now));
        d.demoted_at = r.demoted_at(now);
        s.save(&d, Utc::now()).await.unwrap();
    }
    s.sweep(&tenant, now).await.unwrap();
    for (i, r) in LADDER.iter().enumerate() {
        let id = axess_identity::testing::device(&format!("row-{i}"));
        let got = s.load(&tenant, &id).await.unwrap().unwrap();
        let what = (r.level, r.idle_days, r.demoted_days_ago);
        assert_eq!(got.trust_level, r.want, "{what:?}");
        s.delete(&tenant, &id).await.unwrap();
    }
}

#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_device_racing_claims_have_one_winner() {
    use crate::device::store::OwnerClaim;
    let s = live_store("axt_claim").await;
    let now = Utc::now();
    for round in 0..15u8 {
        let mut d = named("dev-1", 0xd0 ^ round, DeviceTrustLevel::Unknown, now);
        d.user_id = None;
        s.save(&d, Utc::now()).await.unwrap();
        let (a, b) = (
            axess_identity::testing::user("a"),
            axess_identity::testing::user("b"),
        );
        let (ra, rb) = tokio::join!(
            s.claim_owner(&d.tenant_id, &d.id, &a, Utc::now()),
            s.claim_owner(&d.tenant_id, &d.id, &b, Utc::now())
        );
        let (ra, rb) = (ra.unwrap(), rb.unwrap());
        let wins = [ra, rb]
            .iter()
            .filter(|c| **c == OwnerClaim::Claimed)
            .count();
        assert_eq!(wins, 1, "round {round}: {ra:?} {rb:?}");
        let winner = if ra == OwnerClaim::Claimed { a } else { b };
        let row = s.load(&d.tenant_id, &d.id).await.unwrap().unwrap();
        assert_eq!(row.user_id, Some(winner));
        let listed = s.find_for_user(&d.tenant_id, &winner, 10).await.unwrap();
        assert!(listed.iter().any(|x| x.id == d.id), "owner index updated");
        s.delete(&d.tenant_id, &d.id).await.unwrap();
    }
}

#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_device_a_stale_bindings_write_conflicts() {
    use crate::device::store::BindingsUpdate;
    let s = live_store("axt_bindcas").await;
    let now = Utc::now();
    let refresh = |f: &str| DeviceBinding::Refresh {
        family_id: f.into(),
        issued_at: now,
        last_used_at: now,
    };
    let d = named("dev-1", 0xd1, DeviceTrustLevel::Seen, now);
    s.save(&d, Utc::now()).await.unwrap();
    let first = s
        .replace_bindings(&d.tenant_id, &d.id, &[], &[refresh("fam-1")], Utc::now())
        .await
        .unwrap();
    assert_eq!(first, BindingsUpdate::Written);
    let second = s
        .replace_bindings(&d.tenant_id, &d.id, &[], &[refresh("fam-2")], Utc::now())
        .await
        .unwrap();
    assert_eq!(second, BindingsUpdate::Conflict);
    let row = s.load(&d.tenant_id, &d.id).await.unwrap().unwrap();
    assert_eq!(row.bindings, vec![refresh("fam-1")]);
    s.delete(&d.tenant_id, &d.id).await.unwrap();
}

fn ids(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("dev-{i}")).collect()
}

/// A batched read addresses every member's row key, in member order, in a
/// single key list: one command however many members the index holds.
#[test]
fn a_batched_read_names_every_row_key_once_in_order() {
    let members = ids(50);
    let keys = row_keys("axess", "t1", &members);
    assert_eq!(keys.len(), 50);
    assert_eq!(keys[0], "axess:dev:t1:dev-0");
    assert_eq!(keys[49], "axess:dev:t1:dev-49");
}

#[test]
fn replies_pair_with_members_and_nil_means_gone() {
    let members = ids(3);
    let replies = vec![
        Value::Bytes(Bytes::from_static(b"row-0")),
        Value::Null,
        Value::Bytes(Bytes::from_static(b"row-2")),
    ];
    let paired = pair_replies(&members, replies).expect("paired");
    assert_eq!(paired[0], ("dev-0".to_string(), Some(b"row-0".to_vec())));
    assert_eq!(paired[1], ("dev-1".to_string(), None));
    assert_eq!(paired[2].1.as_deref(), Some(&b"row-2"[..]));
}

#[test]
fn a_short_or_malformed_batch_reply_is_an_error_not_a_silent_gap() {
    assert!(pair_replies(&ids(2), vec![Value::Null]).is_err());
    assert!(pair_replies(&ids(1), vec![Value::Integer(7)]).is_err());
}

/// The prune removes a member only while its row key is absent, in the same
/// script, and its arguments line up with the row keys.
#[test]
fn pruning_rechecks_absence_inside_the_script() {
    let exists = PRUNE_ABSENT.find("EXISTS").expect("checks existence");
    let srem = PRUNE_ABSENT.find("SREM").expect("removes members");
    assert!(exists < srem, "existence is checked before the removal");
    let members = ids(3);
    assert_eq!(
        prune_args(&members).len(),
        row_keys("p", "t", &members).len()
    );
}
