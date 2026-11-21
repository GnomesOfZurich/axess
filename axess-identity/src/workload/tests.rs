use super::*;

#[test]
fn trust_domain_accepts_valid_forms() {
    assert!(TrustDomain::new("example.org").is_ok());
    assert!(TrustDomain::new("example.internal").is_ok());
    assert!(TrustDomain::new("example.com").is_ok());
    assert!(TrustDomain::new("a").is_ok());
    assert!(TrustDomain::new("prod-1.example.com").is_ok());
}

/// SPIFFE-ID section 2.1 allows letters, numbers, dots, dashes and
/// underscores, and nothing about where in the name each may stand: a trust
/// domain name is not a DNS name.
#[test]
fn trust_domain_accepts_every_name_the_standard_allows() {
    for name in [
        "trust_domain_name.example.com",
        "with_underscore",
        "_leading_underscore",
        "-leading-hyphen",
        "trailing-",
        "192.168.1.1",
        "9",
    ] {
        assert!(TrustDomain::new(name).is_ok(), "{name}");
        let id = format!("spiffe://{name}/service/tenant");
        let parsed = WorkloadId::parse(&id).unwrap();
        assert_eq!(parsed.trust_domain().as_str(), name);
    }
    let longest = "a".repeat(TrustDomain::MAX_LEN);
    assert!(TrustDomain::new(&longest).is_ok());
}

#[test]
fn trust_domain_rejects_invalid_forms() {
    assert!(TrustDomain::new("").is_err());
    assert!(TrustDomain::new("UPPER.case").is_err());
    assert!(TrustDomain::new("has~tilde").is_err());
    assert!(TrustDomain::new("per%63ent").is_err());
    assert!(TrustDomain::new("\u{fc}mlaut.example").is_err());
    assert!(TrustDomain::new("[::1]").is_err());
    assert!(TrustDomain::new("has spaces").is_err());
    assert!(TrustDomain::new("has/slash").is_err());
    assert!(TrustDomain::new("has:port").is_err());
    let too_long = "a".repeat(TrustDomain::MAX_LEN + 1);
    assert!(TrustDomain::new(&too_long).is_err());
}

#[test]
fn workload_id_build_round_trips_through_parse() {
    let trust = TrustDomain::new("example.org").unwrap();
    let wid = WorkloadId::build(&trust, "compute-worker", "acme").unwrap();
    assert_eq!(wid.as_str(), "spiffe://example.org/compute-worker/acme");
    let reparsed = WorkloadId::parse(wid.as_str()).unwrap();
    assert_eq!(wid, reparsed);
}

#[test]
fn workload_id_build_rejects_empty_service() {
    let trust = TrustDomain::new("example.org").unwrap();
    assert!(WorkloadId::build(&trust, "", "acme").is_err());
}

#[test]
fn workload_id_build_rejects_empty_tenant_slug() {
    let trust = TrustDomain::new("example.org").unwrap();
    assert!(WorkloadId::build(&trust, "compute-worker", "").is_err());
}

#[test]
fn workload_id_build_rejects_invalid_chars_in_segment() {
    let trust = TrustDomain::new("example.org").unwrap();
    assert!(WorkloadId::build(&trust, "compute worker", "acme").is_err());
    assert!(WorkloadId::build(&trust, "compute-worker", "eke/krantz").is_err());
    assert!(WorkloadId::build(&trust, "compute-worker", "eke?krantz").is_err());
}

#[test]
fn workload_id_parse_accepts_canonical_spiffe_uri() {
    let raw = "spiffe://example.org/compute-worker/acme";
    let parsed = WorkloadId::parse(raw).unwrap();
    assert_eq!(parsed.as_str(), raw);
}

#[test]
fn workload_id_parse_accepts_trust_domain_only() {
    let parsed = WorkloadId::parse("spiffe://example.org").unwrap();
    assert_eq!(parsed.as_str(), "spiffe://example.org");
}

#[test]
fn workload_id_parse_rejects_non_spiffe_scheme() {
    assert!(WorkloadId::parse("https://example.org/x/y").is_err());
    assert!(WorkloadId::parse("http://example.org/x/y").is_err());
    assert!(WorkloadId::parse("/example.org/x/y").is_err());
}

#[test]
fn workload_id_parse_rejects_userinfo() {
    assert!(WorkloadId::parse("spiffe://user@example.org/x").is_err());
}

#[test]
fn workload_id_parse_rejects_port() {
    assert!(WorkloadId::parse("spiffe://example.org:8443/x").is_err());
}

#[test]
fn workload_id_parse_rejects_query_and_fragment() {
    assert!(WorkloadId::parse("spiffe://example.org/x?y=1").is_err());
    assert!(WorkloadId::parse("spiffe://example.org/x#frag").is_err());
}

#[test]
fn workload_id_parse_rejects_empty_segment() {
    assert!(WorkloadId::parse("spiffe://example.org//x").is_err());
    assert!(WorkloadId::parse("spiffe://example.org/x//y").is_err());
}

#[test]
fn workload_id_parse_rejects_over_length_uri() {
    let trust = "example.org";
    let path: String = std::iter::repeat_n('a', WorkloadId::MAX_LEN).collect();
    let raw = format!("spiffe://{trust}/{path}");
    assert!(WorkloadId::parse(&raw).is_err());
}

#[test]
fn workload_id_parse_rejects_uppercase_trust_domain() {
    assert!(WorkloadId::parse("spiffe://Example.Org/x").is_err());
}

#[test]
fn workload_id_display_matches_as_str() {
    let trust = TrustDomain::new("example.org").unwrap();
    let wid = WorkloadId::build(&trust, "feed-worker", "acme").unwrap();
    assert_eq!(format!("{wid}"), wid.as_str());
}

#[cfg(feature = "serde")]
#[test]
fn workload_id_serializes_as_transparent_string() {
    let trust = TrustDomain::new("example.org").unwrap();
    let wid = WorkloadId::build(&trust, "compute-worker", "acme").unwrap();
    let json = serde_json::to_string(&wid).unwrap();
    assert_eq!(json, "\"spiffe://example.org/compute-worker/acme\"");
    let back: WorkloadId = serde_json::from_str(&json).unwrap();
    assert_eq!(wid, back);
}

#[cfg(feature = "serde")]
#[test]
fn trust_domain_serializes_as_transparent_string() {
    let trust = TrustDomain::new("example.org").unwrap();
    let json = serde_json::to_string(&trust).unwrap();
    assert_eq!(json, "\"example.org\"");
    let back: TrustDomain = serde_json::from_str(&json).unwrap();
    assert_eq!(trust, back);
}

/// `parse` rejects only when `?` OR `#` is present. Test the
/// `?`-only path explicitly so the `|| → &&` mutation can be
/// observed: with `&&`, a URI containing only `?` would slip past
/// the early reject and (potentially) succeed via downstream
/// segment validation.
#[test]
fn workload_id_parse_rejects_question_mark_without_hash() {
    let result = WorkloadId::parse("spiffe://example.org/x?y");
    assert!(result.is_err());
    let err = result.unwrap_err();
    let msg = err.to_string();
    // The early-reject branch yields a specific message; if the
    // mutation fell through to segment validation, the rejection
    // message would mention the segment instead.
    assert!(
        msg.contains("query and fragment"),
        "must reject at the early `?/#` guard, got: {msg}"
    );
}

/// `TrustDomain::Display` writes the trust-domain string. Mutation
/// `-> Ok(())` would yield an empty format output.
#[test]
fn trust_domain_display_matches_as_str() {
    let trust = TrustDomain::new("example.org").unwrap();
    assert_eq!(format!("{trust}"), "example.org");
}

/// `WorkloadId::build` rejects URIs ABOVE `MAX_LEN` with strict
/// `>`. At exactly `MAX_LEN` bytes the result must succeed.
/// Mutations `==` and `>=` would reject at the boundary.
#[test]
fn workload_id_build_accepts_uri_at_exact_max_len() {
    let trust = TrustDomain::new("a").unwrap();
    // Build a URI exactly at MAX_LEN: "spiffe://a/svc/" = 15 chars,
    // then pad tenant_slug to (MAX_LEN - 15) chars.
    let prefix_len = "spiffe://a/svc/".len();
    let pad = WorkloadId::MAX_LEN - prefix_len;
    let tenant = "a".repeat(pad);
    let result = WorkloadId::build(&trust, "svc", &tenant);
    assert!(
        result.is_ok(),
        "URI of EXACTLY MAX_LEN must build successfully"
    );
    assert_eq!(result.unwrap().as_str().len(), WorkloadId::MAX_LEN);
}

/// `WorkloadId::parse` rejects URIs ABOVE `MAX_LEN`. At exactly
/// `MAX_LEN` bytes the parse must succeed. Mutation `>=` would
/// reject at the boundary.
#[test]
fn workload_id_parse_accepts_uri_at_exact_max_len() {
    let prefix_len = "spiffe://a/svc/".len();
    let pad = WorkloadId::MAX_LEN - prefix_len;
    let raw = format!("spiffe://a/svc/{}", "a".repeat(pad));
    assert_eq!(raw.len(), WorkloadId::MAX_LEN);
    let result = WorkloadId::parse(&raw);
    assert!(
        result.is_ok(),
        "URI of EXACTLY MAX_LEN must parse successfully"
    );
}

#[test]
fn workload_id_rejects_dot_segments() {
    assert!(WorkloadId::parse("spiffe://example.org/a/../b").is_err());
    assert!(WorkloadId::parse("spiffe://example.org/./b").is_err());
    assert!(WorkloadId::parse("spiffe://example.org/a/..").is_err());
    let trust = TrustDomain::new("example.org").unwrap();
    assert!(WorkloadId::build(&trust, "..", "acme").is_err());
    assert!(WorkloadId::parse("spiffe://example.org/a/..b/c.d").is_ok());
}

#[cfg(feature = "serde")]
#[test]
fn deserialization_validates_workload_id_and_trust_domain() {
    assert!(serde_json::from_str::<WorkloadId>(r#""https://evil/x""#).is_err());
    assert!(serde_json::from_str::<WorkloadId>(r#""spiffe://a/../b""#).is_err());
    assert!(serde_json::from_str::<WorkloadId>(r#""""#).is_err());
    assert!(serde_json::from_str::<TrustDomain>(r#""UPPER Case""#).is_err());
    assert!(serde_json::from_str::<TrustDomain>(r#""""#).is_err());
}

/// Every refusal of `parse` is `InvalidSpiffeId`, the path's as much as the
/// authority's: `InvalidComponent` names a `build` argument, and `parse` has
/// none.
#[test]
fn workload_id_parse_refuses_a_bad_path_as_an_invalid_spiffe_id() {
    for raw in [
        "spiffe://example.org//x",
        "spiffe://example.org/x/../y",
        "spiffe://example.org/x/a b",
        "spiffe://example.org/",
    ] {
        assert!(
            matches!(
                WorkloadId::parse(raw),
                Err(IdentityError::InvalidSpiffeId(_))
            ),
            "{raw}"
        );
    }
}

/// `components` is the inverse of `build`: the three parts that went in come
/// out, whatever characters a segment may hold.
#[test]
fn workload_id_components_are_what_build_was_given() {
    for (domain, service, tenant) in [
        ("example.org", "compute-worker", "acme"),
        ("a", "s", "t"),
        ("prod-1.example.com", "Billing.API_v2-x", "acme-co"),
        ("under_score.example", "a.b", "c_d"),
    ] {
        let trust = TrustDomain::new(domain).unwrap();
        let wid = WorkloadId::build(&trust, service, tenant).unwrap();
        let parts = wid.components().unwrap();
        assert_eq!(
            parts,
            WorkloadIdComponents {
                trust_domain: trust.clone(),
                service,
                tenant_slug: tenant,
            }
        );
        assert_eq!(wid.trust_domain(), trust);
        // And back: the parts build the same ID.
        let rebuilt =
            WorkloadId::build(&parts.trust_domain, parts.service, parts.tenant_slug).unwrap();
        assert_eq!(rebuilt, wid);
    }
}

/// A SPIFFE ID that parses and is not of the platform's shape has a trust
/// domain and no components: no path, one segment, three or more.
#[test]
fn workload_id_components_refuse_any_other_shape() {
    for raw in [
        "spiffe://example.org",
        "spiffe://example.org/compute-worker",
        "spiffe://example.org/compute-worker/acme/extra",
        "spiffe://example.org/ns/payments/sa/api",
    ] {
        let wid = WorkloadId::parse(raw).unwrap();
        let Err(IdentityError::InvalidSpiffeId(text)) = wid.components() else {
            panic!("{raw} is not <service>/<tenant_slug>");
        };
        assert_eq!(
            text,
            format!("SPIFFE path is not <service>/<tenant_slug>: {raw}")
        );
        assert_eq!(wid.trust_domain().as_str(), "example.org");
    }
}

/// The trust domain is the URI's authority, whether or not a path follows,
/// and it is one `TrustDomain::new` accepts.
#[test]
fn workload_id_trust_domain_is_the_authority() {
    for (raw, domain) in [
        ("spiffe://example.org", "example.org"),
        ("spiffe://example.org/a", "example.org"),
        ("spiffe://prod-1.example.com/a/b/c", "prod-1.example.com"),
        ("spiffe://x/a/b", "x"),
    ] {
        let trust = WorkloadId::parse(raw).unwrap().trust_domain();
        assert_eq!(trust.as_str(), domain, "{raw}");
        assert_eq!(TrustDomain::new(trust.as_str()).unwrap(), trust);
    }
}

/// SPIFFE-ID section 2.4: the scheme is case-insensitive and the path is
/// case-sensitive. An ID written with an upper-case scheme is the same ID,
/// kept in lower case; one whose path differs in case is another ID; and an
/// upper-case trust domain is refused, as section 2.1 has it in lower case.
#[test]
fn workload_id_scheme_is_read_without_regard_to_case() {
    let canonical = WorkloadId::parse("spiffe://example.org/Compute/acme").unwrap();
    for spelling in [
        "SPIFFE://example.org/Compute/acme",
        "Spiffe://example.org/Compute/acme",
    ] {
        let parsed = WorkloadId::parse(spelling).unwrap();
        assert_eq!(parsed, canonical, "{spelling}");
        assert_eq!(parsed.as_str(), "spiffe://example.org/Compute/acme");
    }
    let other_path = WorkloadId::parse("spiffe://example.org/compute/acme").unwrap();
    assert_ne!(other_path, canonical);
    assert!(WorkloadId::parse("SPIFFE://Example.org/Compute/acme").is_err());
    assert!(WorkloadId::parse("spiffe:/example.org/x").is_err());
    assert!(WorkloadId::parse("sp\u{ee}ffe://example.org/x").is_err());
}

/// SPIFFE-ID section 2.2: a path segment holds letters, numbers, dots, dashes
/// and underscores. A tilde, a percent-encoded character and a space are
/// refused by both constructors.
#[test]
fn workload_id_path_segments_hold_only_what_the_standard_allows() {
    let trust = TrustDomain::new("example.org").unwrap();
    for segment in ["with~tilde", "per%2Fcent", "a b", "caf\u{e9}", "semi;colon"] {
        assert!(
            matches!(
                WorkloadId::build(&trust, segment, "acme"),
                Err(IdentityError::InvalidComponent(_))
            ),
            "{segment} as a service"
        );
        assert!(
            matches!(
                WorkloadId::parse(&format!("spiffe://example.org/{segment}/acme")),
                Err(IdentityError::InvalidSpiffeId(_))
            ),
            "{segment} in a path"
        );
    }
    assert!(WorkloadId::build(&trust, "A-Z_a.z-0_9", "acme").is_ok());
}

/// A refused value is whatever the caller was handed, a token's `sub` or a
/// certificate's URI name: the error quotes it with every character the
/// one predicate names escaped and cut at 64 bytes, so a refused value can
/// neither forge a log line, make it read otherwise, nor fill one.
#[test]
fn a_refused_value_is_quoted_cut_and_escaped() {
    let forged = format!(
        "x\nWARN forged line\r\u{1b}[31m\u{2028}\u{202E}\u{200B}\u{FEFF}\u{3164}{}",
        "A".repeat(1500)
    );
    let errors = [
        WorkloadId::parse(&forged).expect_err("no scheme"),
        WorkloadId::parse(&format!("spiffe://{forged}")).expect_err("a bad trust domain"),
        WorkloadId::parse(&format!("spiffe://td.example/{forged}")).expect_err("a bad segment"),
        TrustDomain::new(&forged[..200]).expect_err("a bad character"),
        TrustDomain::new(&format!("-{}", &forged[..200]))
            .expect_err("a bad character after a leading dash"),
        WorkloadId::build(&TrustDomain::new("td.example").unwrap(), &forged, "acme")
            .expect_err("a bad service"),
    ];
    for err in errors {
        let text = err.to_string();
        assert!(text.len() <= 256, "{} bytes: {text}", text.len());
        assert!(!text.contains(&"A".repeat(64)), "quoted whole: {text}");
        assert!(!text.chars().any(crate::log_text::escapes), "{text:?}");
    }
}

/// Each class the one predicate names is escaped where an error quotes a
/// refused value, whichever validator refused it.
#[test]
fn every_class_the_predicate_names_is_escaped_in_a_quoted_value() {
    for c in [
        '\u{202E}', '\u{200B}', '\u{FEFF}', '\u{3164}', '\u{2028}', '\n',
    ] {
        let value = format!("bad{c}value");
        let errors = [
            WorkloadId::parse(&value).expect_err("no scheme"),
            WorkloadId::parse(&format!("spiffe://td.example/{value}")).expect_err("a bad segment"),
            TrustDomain::new(&value).expect_err("a bad character"),
            WorkloadId::build(&TrustDomain::new("td.example").unwrap(), &value, "acme")
                .expect_err("a bad service"),
        ];
        for err in errors {
            let text = err.to_string();
            assert!(!text.contains(c), "U+{:04X} raw in {text:?}", u32::from(c));
            assert!(
                !text.chars().any(crate::log_text::escapes),
                "U+{:04X}: {text:?}",
                u32::from(c)
            );
        }
    }
}

/// The quoting is the one predicate's escape and cut, character for
/// character, so the two cannot drift apart.
#[test]
fn a_quoted_value_is_the_log_safe_text_at_the_bound() {
    for sample in [
        "plain",
        "a\nb\u{202E}c\u{200B}d\u{FEFF}e\u{3164}f\u{2028}g",
        &"é".repeat(40),
        &format!("{}\u{202E}", "x".repeat(70)),
    ] {
        assert_eq!(quoted(sample), crate::log_text::log_safe(sample, 64));
    }
}

/// The character an error names is quoted escaped too, and a short value
/// is quoted whole.
#[test]
fn a_refused_character_is_named_escaped_and_a_short_value_whole() {
    let err = TrustDomain::new("td\n.example").expect_err("a line break");
    assert_eq!(
        err.to_string(),
        "invalid trust domain: invalid character '\\n' in trust domain 'td\\n.example' \
         (expected [a-z0-9._-])"
    );
    let err = WorkloadId::parse("http://td.example/svc").expect_err("no scheme");
    assert_eq!(
        err.to_string(),
        "invalid SPIFFE identifier: missing 'spiffe://' scheme prefix: http://td.example/svc"
    );
    assert_eq!(quoted(&"é".repeat(40)), format!("{}...", "é".repeat(30)));
}
