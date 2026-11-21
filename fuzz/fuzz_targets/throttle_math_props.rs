// Invariants over the real public API
// axess_core::authn::{Throttle, ThrottleKey, ThrottleState}:
//  - delay_after / retry_after never panic;
//  - delay_after is non-decreasing in the failure count and never exceeds max_delay;
//  - with failures >= 1, first_delay > 0 and the guess at the instant of the
//    last failure, retry_after is Some(non-zero)  [a huge max_delay overflows
//    the conversion and the throttle fails open while the gap is open];
//  - two IPv6 addresses in one /64 give the same subject, different /64s give
//    different subjects, for a /64 that holds no form carrying an IPv4
//    client;
//  - the clients of one NAT64 gateway (64:ff9b::/96, RFC 6052) are one
//    subject each: two addresses there share a subject exactly when they
//    carry one IPv4 address in their last 32 bits.
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
    let last = axess_clock::Timestamp::from_unix_seconds(secs).expect("in range");

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
    let later = last
        .checked_add(axess_clock::SignedDuration::seconds(dt))
        .expect("in range");
    let _ = t.retry_after(Some(&state), later);

    // /64 keying.
    let p: u64 = u.arbitrary()?;
    let (i1, i2): (u64, u64) = (u.arbitrary()?, u.arbitrary()?);
    let q: u64 = u.arbitrary()?;
    let mk = |pre: u64, iid: u64| IpAddr::V6(Ipv6Addr::from(((pre as u128) << 64) | iid as u128));
    let (tid, uid) = (TenantId::SYSTEM, UserId::SYSTEM);
    let subject = |address: IpAddr| t.subject(&tid, &uid, Some(address));
    if !carries_ipv4_clients(p) {
        assert_eq!(
            subject(mk(p, i1)),
            subject(mk(p, i2)),
            "same /64 must share a throttle subject"
        );
        if p != q && !carries_ipv4_clients(q) {
            assert_ne!(
                subject(mk(p, i1)),
                subject(mk(q, i1)),
                "different /64s must not share a subject"
            );
        }
    }

    // One NAT64 gateway: each client is the IPv4 address in the last 32
    // bits of `64:ff9b::/96`.
    let nat64 = |client: u64| mk(NAT64_PREFIX, client & 0xffff_ffff);
    assert_eq!(
        subject(nat64(i1)) == subject(nat64(i2)),
        i1 & 0xffff_ffff == i2 & 0xffff_ffff,
        "the clients of one NAT64 gateway are one subject each"
    );
    Ok(())
}

/// The /64 prefix of the NAT64 well-known prefix `64:ff9b::/96`.
const NAT64_PREFIX: u64 = 0x0064_ff9b_0000_0000;

/// Whether the /64 `prefix` holds addresses that stand for an IPv4 client,
/// which the throttle keys on that client and not on the /64: `::/64` (the
/// IPv4-mapped, IPv4-translated and IPv4-compatible forms), the NAT64
/// prefixes `64:ff9b::/96` and `64:ff9b:1::/48` (RFC 6052, RFC 8215), 6to4
/// `2002::/16` (RFC 3056) and Teredo `2001::/32` (RFC 4380).
fn carries_ipv4_clients(prefix: u64) -> bool {
    prefix == 0
        || prefix == NAT64_PREFIX
        || prefix >> 16 == 0x0064_ff9b_0001
        || prefix >> 48 == 0x2002
        || prefix >> 32 == 0x2001_0000
}

fuzz_target!(|data: &[u8]| {
    let _ = run(&mut Unstructured::new(data));
});
