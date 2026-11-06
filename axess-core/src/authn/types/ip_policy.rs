//! A tenant's IP policy: which client addresses may log in.

use super::*;

/// Per-tenant IP access policy.
///
/// Specifies allowed and/or denied IP addresses and CIDR ranges.
/// If `allow` is non-empty, only those IPs are permitted (allowlist mode).
/// If `allow` is empty and `deny` is non-empty, all IPs except those are
/// permitted (denylist mode). If both are empty, all IPs are permitted.
///
/// An IPv4 address that arrives as IPv4-mapped IPv6 (`::ffff:10.0.0.1`, as a
/// dual-stack listener reports it) is judged as the IPv4 address it carries,
/// so an IPv4 entry covers it and the mapped form cannot step around one; an
/// IPv6 entry wide enough to cover the mapped range covers IPv4 clients too.
/// An entry that does not parse denies everything in a deny list and matches
/// nothing in an allow list. See [`is_allowed`](Self::is_allowed).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IpPolicy {
    /// Allowed IP addresses and CIDR ranges (e.g. `"10.0.0.0/8"`, `"192.168.1.1"`).
    /// If non-empty, only these IPs may authenticate.
    pub allow: Vec<Arc<str>>,
    /// Denied IP addresses and CIDR ranges.
    /// Checked only when `allow` is empty.
    pub deny: Vec<Arc<str>>,
}

impl IpPolicy {
    /// Whether this policy restricts anything at all.
    ///
    /// An empty policy permits every address, so a request whose address is
    /// unknown is no less compliant with it than one whose address is
    /// known. A non-empty one cannot be evaluated without an address, which
    /// is why [`AuthnService::with_audit_context`](crate::authn::AuthnService::with_audit_context)
    /// is the only way to reach a login: the answer has to come from
    /// somewhere the caller cannot choose.
    pub fn restricts(&self) -> bool {
        !self.allow.is_empty() || !self.deny.is_empty()
    }

    /// Check whether the given IP address is permitted by this policy.
    ///
    /// Returns `true` if the IP is allowed, `false` if denied.
    ///
    /// An IPv4-mapped IPv6 address (`::ffff:10.0.0.1`) is judged as the IPv4
    /// address it carries, so a dual-stack listener cannot be used to step
    /// around an IPv4 entry. A deny entry that does not parse (a typo, a
    /// prefix out of range) fails closed: it denies every address, because
    /// skipping it would leave the denylist silently weaker than written. An
    /// allow entry that does not parse matches nothing.
    pub fn is_allowed(&self, ip: std::net::IpAddr) -> bool {
        let ip = canonical_ip(ip);
        let matches = |entry: &Arc<str>| {
            parse_entry(entry).map(|(net, len)| match (net, ip) {
                // An IPv6 network wider than the mapped prefix covers the
                // IPv4 clients too, as `::ffff:a.b.c.d`.
                (std::net::IpAddr::V6(_), std::net::IpAddr::V4(v4)) => {
                    cidr_contains(net, len, std::net::IpAddr::V6(v4.to_ipv6_mapped()))
                }
                _ => cidr_contains(net, len, ip),
            })
        };
        if !self.allow.is_empty() {
            // Allowlist mode: IP must match at least one entry.
            return self.allow.iter().any(|entry| matches(entry) == Some(true));
        }
        if !self.deny.is_empty() {
            // Denylist mode: IP must not match any entry, and every entry
            // must be readable.
            return self.deny.iter().all(|entry| matches(entry) == Some(false));
        }
        // No restrictions.
        true
    }
}

/// Fold an IPv4-mapped IPv6 address to the IPv4 address it carries.
fn canonical_ip(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip {
        std::net::IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map_or(std::net::IpAddr::V6(v6), std::net::IpAddr::V4),
        v4 => v4,
    }
}

/// Parse a policy entry (`"10.0.0.0/8"` or a bare address) into a canonical
/// network and prefix length. `None` when the entry is malformed or its
/// prefix is out of range for its family.
fn parse_entry(entry: &str) -> Option<(std::net::IpAddr, u32)> {
    let (addr_str, prefix) = match entry.split_once('/') {
        Some((a, p)) => (a, Some(p.parse::<u32>().ok()?)),
        None => (entry, None),
    };
    let addr = addr_str.parse::<std::net::IpAddr>().ok()?;
    match (addr, prefix) {
        (std::net::IpAddr::V4(_), p) => {
            let len = p.unwrap_or(32);
            (len <= 32).then_some((addr, len))
        }
        (std::net::IpAddr::V6(v6), p) => {
            let len = p.unwrap_or(128);
            if len > 128 {
                return None;
            }
            // `::ffff:a.b.c.d/N` with N >= 96 is the IPv4 network a.b.c.d/(N-96).
            match v6.to_ipv4_mapped() {
                Some(v4) if len >= 96 => Some((std::net::IpAddr::V4(v4), len - 96)),
                _ => Some((addr, len)),
            }
        }
    }
}

/// Check if `ip` falls within the CIDR block `network/prefix_len`.
fn cidr_contains(network: std::net::IpAddr, prefix_len: u32, ip: std::net::IpAddr) -> bool {
    match (network, ip) {
        (std::net::IpAddr::V4(net), std::net::IpAddr::V4(addr)) => {
            if prefix_len > 32 {
                return false;
            }
            let mask = if prefix_len == 0 {
                0u32
            } else {
                u32::MAX << (32 - prefix_len)
            };
            (u32::from(net) & mask) == (u32::from(addr) & mask)
        }
        (std::net::IpAddr::V6(net), std::net::IpAddr::V6(addr)) => {
            if prefix_len > 128 {
                return false;
            }
            let net_bits = u128::from(net);
            let addr_bits = u128::from(addr);
            let mask = if prefix_len == 0 {
                0u128
            } else {
                u128::MAX << (128 - prefix_len)
            };
            (net_bits & mask) == (addr_bits & mask)
        }
        _ => false, // v4/v6 mismatch
    }
}

#[cfg(test)]
mod ip_policy_tests {
    use super::*;

    #[test]
    fn an_ipv6_deny_rule_wider_than_96_bits_blocks_ipv4_clients() {
        let policy = IpPolicy {
            allow: vec![],
            deny: vec!["::/0".into()],
        };
        assert!(!policy.is_allowed("1.2.3.4".parse().unwrap()));
        assert!(!policy.is_allowed("::ffff:1.2.3.4".parse().unwrap()));
        let policy = IpPolicy {
            allow: vec![],
            deny: vec!["::ffff:0:0/80".into()],
        };
        assert!(!policy.is_allowed("1.2.3.4".parse().unwrap()));
        let policy = IpPolicy {
            allow: vec!["::/0".into()],
            deny: vec![],
        };
        assert!(policy.is_allowed("1.2.3.4".parse().unwrap()));
        let narrow = IpPolicy {
            allow: vec![],
            deny: vec!["2001:db8::/32".into()],
        };
        assert!(narrow.is_allowed("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn empty_policy_allows_all() {
        let policy = IpPolicy::default();
        assert!(policy.is_allowed("1.2.3.4".parse().unwrap()));
        assert!(policy.is_allowed("::1".parse().unwrap()));
    }

    #[test]
    fn allowlist_permits_listed_ip() {
        let policy = IpPolicy {
            allow: vec!["10.0.0.0/8".into(), "192.168.1.1".into()],
            deny: vec![],
        };
        assert!(policy.is_allowed("10.0.0.1".parse().unwrap()));
        assert!(policy.is_allowed("10.255.255.255".parse().unwrap()));
        assert!(policy.is_allowed("192.168.1.1".parse().unwrap()));
        assert!(!policy.is_allowed("172.16.0.1".parse().unwrap()));
    }

    #[test]
    fn denylist_blocks_listed_ip() {
        let policy = IpPolicy {
            allow: vec![],
            deny: vec!["10.0.0.0/8".into()],
        };
        assert!(!policy.is_allowed("10.0.0.1".parse().unwrap()));
        assert!(policy.is_allowed("172.16.0.1".parse().unwrap()));
    }

    #[test]
    fn exact_ip_match() {
        let policy = IpPolicy {
            allow: vec!["192.168.1.100".into()],
            deny: vec![],
        };
        assert!(policy.is_allowed("192.168.1.100".parse().unwrap()));
        assert!(!policy.is_allowed("192.168.1.101".parse().unwrap()));
    }

    #[test]
    fn ipv6_cidr() {
        let policy = IpPolicy {
            allow: vec!["fd00::/8".into()],
            deny: vec![],
        };
        assert!(policy.is_allowed("fd00::1".parse().unwrap()));
        assert!(!policy.is_allowed("2001:db8::1".parse().unwrap()));
    }

    /// Pin the v4 prefix-length boundary at 32. Mask
    /// computation depends on `prefix_len <= 32`; an `>=`/`==`
    /// mutation would either reject the legitimate /32 host route
    /// or accept an invalid /33.
    #[test]
    fn cidr_v4_prefix_boundary_at_32() {
        let policy = IpPolicy {
            allow: vec!["192.168.1.100/32".into()],
            deny: vec![],
        };
        // /32 covers exactly one address; the exact match must work.
        assert!(policy.is_allowed("192.168.1.100".parse().unwrap()));
        // A different host inside the /24 must reject.
        assert!(!policy.is_allowed("192.168.1.101".parse().unwrap()));

        // /33 is structurally invalid and must reject everything.
        let bad = IpPolicy {
            allow: vec!["192.168.1.100/33".into()],
            deny: vec![],
        };
        assert!(!bad.is_allowed("192.168.1.100".parse().unwrap()));
    }

    /// Pin the v6 prefix-length boundary at 128. Same shape
    /// as the v4 test.
    #[test]
    fn cidr_v6_prefix_boundary_at_128() {
        let policy = IpPolicy {
            allow: vec!["fd00::1/128".into()],
            deny: vec![],
        };
        assert!(policy.is_allowed("fd00::1".parse().unwrap()));
        assert!(!policy.is_allowed("fd00::2".parse().unwrap()));

        let bad = IpPolicy {
            allow: vec!["fd00::1/129".into()],
            deny: vec![],
        };
        assert!(!bad.is_allowed("fd00::1".parse().unwrap()));
    }

    /// Pin the v6 mask shift `u128::MAX << (128 - prefix_len)`.
    /// A `-` to `/` mutation makes the shift `u128::MAX << (128 / prefix_len)`,
    /// which produces the wrong mask for any `prefix_len > 1`. Construct a
    /// case where original and mutant disagree.
    ///
    /// With prefix=8: original shift = 120 → mask = top 8 bits.
    /// Mutant shift = 128/8 = 16 → mask = top 112 bits.
    /// Address `fd80::` has top-8 bits = `0xFD` (matches `fd00::/8`) but
    /// differs from `fd00::` in bit 9. Original ACCEPTS; mutant REJECTS.
    #[test]
    fn cidr_v6_mask_uses_subtraction_not_division() {
        let policy = IpPolicy {
            allow: vec!["fd00::/8".into()],
            deny: vec![],
        };
        assert!(
            policy.is_allowed("fd80::".parse().unwrap()),
            "fd80:: must match fd00::/8 (kills `-` → `/` mutation on the v6 mask shift)"
        );
    }
}
