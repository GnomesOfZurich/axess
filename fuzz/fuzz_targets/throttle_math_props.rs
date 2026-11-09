// Invariants over the real public API
// axess_core::authn::{Throttle, ThrottleKey, ThrottleState}:
//  - delay_after / retry_after never panic;
//  - delay_after is non-decreasing in the failure count and never exceeds max_delay;
//  - with failures >= 1, first_delay > 0 and the guess at the instant of the
//    last failure, retry_after is Some(non-zero)  [a huge max_delay overflows
//    the conversion and the throttle fails open while the gap is open];
//  - two IPv6 addresses in one /64 give the same subject, different /64s give
//    different subjects  [fails until the throttle keys on the /64].
#![no_main]

use axess_core::authn::ids::{TenantId, UserId};
use axess_core::authn::{Throttle, ThrottleKey, ThrottleState};
use libfuzzer_sys::arbitrary::{Result, Unstructured};
use libfuzzer_sys::fuzz_target;
use std::net::{IpAddr, Ipv6Addr};
use std::time::Duration;

fn run(u: &mut Unstructured<'_>) -> Result<()> {
    // Bias towards extremes: zero, small, and Duration::MAX-ish values.
    let dur = |u: &mut Unstructured<'_>| -> Result<Duration> {
        Ok(match u.int_in_range(0u8..=3)? {
            0 => Duration::ZERO,
            1 => Duration::from_millis(u.int_in_range(1..=600_000)?),
            2 => Duration::MAX,
            _ => Duration::new(u.arbitrary()?, u.int_in_range(0..=999_999_999)?),
        })
    };
    let first_delay = dur(u)?;
    let max_delay = dur(u)?;
    let t = Throttle {
        first_delay,
        max_delay,
        key: ThrottleKey::AccountAndAddress,
    };
    let failures: u32 = u.arbitrary()?;
    let secs = u.int_in_range(0i64..=4_102_444_800)?; // 1970..2100
    let last = chrono::DateTime::from_timestamp(secs, 0).expect("in range");

    let d = t.delay_after(failures);
    assert!(d <= max_delay, "delay {d:?} above max {max_delay:?}");
    if failures < u32::MAX {
        assert!(
            t.delay_after(failures + 1) >= d,
            "delay decreased at {failures}"
        );
    }

    let state = ThrottleState {
        failures,
        last_failure_at: last,
    };
    let r = t.retry_after(Some(&state), last);
    if failures >= 1 && !first_delay.is_zero() && !max_delay.is_zero() {
        assert!(
            matches!(r, Some(x) if !x.is_zero()),
            "throttle fails open: failures={failures} first={first_delay:?} max={max_delay:?} -> {r:?}"
        );
    }
    // Later instants: never panics.
    let dt = u.int_in_range(0i64..=10_000_000)?;
    let _ = t.retry_after(Some(&state), last + chrono::Duration::seconds(dt));

    // /64 keying.
    let p: u64 = u.arbitrary()?;
    let (i1, i2): (u64, u64) = (u.arbitrary()?, u.arbitrary()?);
    let q: u64 = u.arbitrary()?;
    // An IPv4-mapped address (::ffff:0:0/96, inside ::/64) is keyed as the
    // IPv4 address it carries, by design, so the /64 rule is drawn outside it.
    let iid_of = |iid: u64, pre: u64| if pre == 0 && iid >> 32 == 0xffff { iid ^ (1 << 48) } else { iid };
    let mk = |pre: u64, iid: u64| IpAddr::V6(Ipv6Addr::from(((pre as u128) << 64) | iid_of(iid, pre) as u128));
    let (tid, uid) = (TenantId::SYSTEM, UserId::SYSTEM);
    assert_eq!(
        t.subject(&tid, &uid, Some(mk(p, i1))),
        t.subject(&tid, &uid, Some(mk(p, i2))),
        "same /64 must share a throttle subject"
    );
    if p != q {
        assert_ne!(
            t.subject(&tid, &uid, Some(mk(p, i1))),
            t.subject(&tid, &uid, Some(mk(q, i1))),
            "different /64s must not share a subject"
        );
    }
    Ok(())
}

fuzz_target!(|data: &[u8]| {
    let _ = run(&mut Unstructured::new(data));
});
