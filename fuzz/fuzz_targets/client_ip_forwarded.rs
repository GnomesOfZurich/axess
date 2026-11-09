// Invariant: the resolved client address is never attacker-chosen when the
// peer is untrusted, and with a trusted peer it is exactly the right-most
// X-Forwarded-For entry that is not a trusted hop (or the peer when there is
// none / an entry is malformed). Real public API:
// axess_core::{TrustedProxies, ClientIp}::client_ip(&HeaderMap, Option<IpAddr>).
// Reference model written from client_ip.rs (X-Real-IP is not
// enabled here, so it is ignored).
#![no_main]

use axess_core::TrustedProxies;
use axess_core::client_ip::Source;
use axum::http::{HeaderMap, HeaderValue};
use libfuzzer_sys::arbitrary::{Result, Unstructured};
use libfuzzer_sys::fuzz_target;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn ip(u: &mut Unstructured<'_>, pool: &[IpAddr]) -> Result<IpAddr> {
    Ok(match u.int_in_range(0u8..=3)? {
        0 => *u.choose(pool)?,
        1 => IpAddr::V4(Ipv4Addr::from(u.arbitrary::<u32>()?)),
        2 => IpAddr::V6(Ipv4Addr::from(u.arbitrary::<u32>()?).to_ipv6_mapped()),
        _ => IpAddr::V6(Ipv6Addr::from(u.arbitrary::<u128>()?)),
    })
}

fn run(u: &mut Unstructured<'_>) -> Result<()> {
    let n = u.int_in_range(1..=4)?;
    let pool: Vec<IpAddr> = (0..n)
        .map(|_| Ok(IpAddr::V4(Ipv4Addr::from(u.arbitrary::<u32>()?))))
        .collect::<Result<_>>()?;
    let trusted = TrustedProxies::new(pool.iter().copied());
    let peer = ip(u, &pool)?;

    // One or more X-Forwarded-For lines; entries are IPs or junk.
    let mut headers = HeaderMap::new();
    let mut entries: Vec<String> = Vec::new();
    let mut opaque_line = false; // a line HeaderValue::to_str rejects stops the walk
    for _ in 0..u.int_in_range(0..=2)? {
        let mut line = Vec::new();
        for _ in 0..u.int_in_range(1..=4)? {
            let e = if u.ratio(1, 8)? {
                let n = u.int_in_range(0..=6)?;
                String::from_utf8_lossy(u.bytes(n)?).into_owned()
            } else {
                ip(u, &pool)?.to_string()
            };
            line.push(e);
        }
        let joined = line.join(", ");
        if let Ok(v) = HeaderValue::from_str(&joined) {
            opaque_line |= v.to_str().is_err();
            headers.append("x-forwarded-for", v);
            entries.extend(joined.split(',').map(str::to_string));
        }
    }

    let got = trusted.client_ip(&headers, Some(peer));
    let peer_c = peer.to_canonical();
    if !trusted.trusts_peer(peer_c) {
        assert_eq!(
            got.get(),
            Some(peer_c),
            "untrusted peer: forwarded header must be ignored"
        );
        assert_eq!(got.source(), Source::Peer);
        return Ok(());
    }
    // Reference walk, right to left.
    let mut want = peer_c;
    for e in entries.iter().rev().take_while(|_| !opaque_line) {
        match e.trim().parse::<IpAddr>().map(|a| a.to_canonical()) {
            Ok(a) if trusted.trusts_hop(a) => continue,
            Ok(a) => {
                want = a;
                break;
            }
            Err(_) => break,
        }
    }
    assert_eq!(got.get(), Some(want), "peer={peer} xff={entries:?}");
    if let Some(a) = got.get() {
        if got.source() == Source::Forwarded {
            assert!(
                !trusted.trusts_hop(a),
                "resolved a trusted hop as the client"
            );
        }
    }
    Ok(())
}

fuzz_target!(|data: &[u8]| {
    let _ = run(&mut Unstructured::new(data));
});
