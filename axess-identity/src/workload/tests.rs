use super::*;

#[test]
fn trust_domain_accepts_valid_forms() {
    assert!(TrustDomain::new("gnomes.local").is_ok());
    assert!(TrustDomain::new("gnomes.internal").is_ok());
    assert!(TrustDomain::new("example.com").is_ok());
    assert!(TrustDomain::new("a").is_ok());
    assert!(TrustDomain::new("prod-1.example.com").is_ok());
}

#[test]
fn trust_domain_rejects_invalid_forms() {
    assert!(TrustDomain::new("").is_err());
    assert!(TrustDomain::new("UPPER.case").is_err());
    assert!(TrustDomain::new("-leading-hyphen").is_err());
    assert!(TrustDomain::new("has spaces").is_err());
    assert!(TrustDomain::new("has/slash").is_err());
    assert!(TrustDomain::new("has:port").is_err());
    let too_long = "a".repeat(TrustDomain::MAX_LEN + 1);
    assert!(TrustDomain::new(&too_long).is_err());
}

#[test]
fn workload_id_build_round_trips_through_parse() {
    let trust = TrustDomain::new("gnomes.local").unwrap();
    let wid = WorkloadId::build(&trust, "compute-worker", "ekekrantz").unwrap();
    assert_eq!(
        wid.as_str(),
        "spiffe://gnomes.local/compute-worker/ekekrantz"
    );
    let reparsed = WorkloadId::parse(wid.as_str()).unwrap();
    assert_eq!(wid, reparsed);
}

#[test]
fn workload_id_build_rejects_empty_service() {
    let trust = TrustDomain::new("gnomes.local").unwrap();
    assert!(WorkloadId::build(&trust, "", "ekekrantz").is_err());
}

#[test]
fn workload_id_build_rejects_empty_tenant_slug() {
    let trust = TrustDomain::new("gnomes.local").unwrap();
    assert!(WorkloadId::build(&trust, "compute-worker", "").is_err());
}

#[test]
fn workload_id_build_rejects_invalid_chars_in_segment() {
    let trust = TrustDomain::new("gnomes.local").unwrap();
    assert!(WorkloadId::build(&trust, "compute worker", "ekekrantz").is_err());
    assert!(WorkloadId::build(&trust, "compute-worker", "eke/krantz").is_err());
    assert!(WorkloadId::build(&trust, "compute-worker", "eke?krantz").is_err());
}

#[test]
fn workload_id_parse_accepts_canonical_spiffe_uri() {
    let raw = "spiffe://gnomes.local/compute-worker/ekekrantz";
    let parsed = WorkloadId::parse(raw).unwrap();
    assert_eq!(parsed.as_str(), raw);
}

#[test]
fn workload_id_parse_accepts_trust_domain_only() {
    let parsed = WorkloadId::parse("spiffe://gnomes.local").unwrap();
    assert_eq!(parsed.as_str(), "spiffe://gnomes.local");
}

#[test]
fn workload_id_parse_rejects_non_spiffe_scheme() {
    assert!(WorkloadId::parse("https://gnomes.local/x/y").is_err());
    assert!(WorkloadId::parse("http://gnomes.local/x/y").is_err());
    assert!(WorkloadId::parse("/gnomes.local/x/y").is_err());
}

#[test]
fn workload_id_parse_rejects_userinfo() {
    assert!(WorkloadId::parse("spiffe://user@gnomes.local/x").is_err());
}

#[test]
fn workload_id_parse_rejects_port() {
    assert!(WorkloadId::parse("spiffe://gnomes.local:8443/x").is_err());
}

#[test]
fn workload_id_parse_rejects_query_and_fragment() {
    assert!(WorkloadId::parse("spiffe://gnomes.local/x?y=1").is_err());
    assert!(WorkloadId::parse("spiffe://gnomes.local/x#frag").is_err());
}

#[test]
fn workload_id_parse_rejects_empty_segment() {
    assert!(WorkloadId::parse("spiffe://gnomes.local//x").is_err());
    assert!(WorkloadId::parse("spiffe://gnomes.local/x//y").is_err());
}

#[test]
fn workload_id_parse_rejects_over_length_uri() {
    let trust = "gnomes.local";
    let path: String = std::iter::repeat_n('a', WorkloadId::MAX_LEN).collect();
    let raw = format!("spiffe://{trust}/{path}");
    assert!(WorkloadId::parse(&raw).is_err());
}

#[test]
fn workload_id_parse_rejects_uppercase_trust_domain() {
    assert!(WorkloadId::parse("spiffe://Gnomes.Local/x").is_err());
}

#[test]
fn workload_id_display_matches_as_str() {
    let trust = TrustDomain::new("gnomes.local").unwrap();
    let wid = WorkloadId::build(&trust, "feed-worker", "ekekrantz").unwrap();
    assert_eq!(format!("{wid}"), wid.as_str());
}

#[cfg(feature = "serde")]
#[test]
fn workload_id_serializes_as_transparent_string() {
    let trust = TrustDomain::new("gnomes.local").unwrap();
    let wid = WorkloadId::build(&trust, "compute-worker", "ekekrantz").unwrap();
    let json = serde_json::to_string(&wid).unwrap();
    assert_eq!(json, "\"spiffe://gnomes.local/compute-worker/ekekrantz\"");
    let back: WorkloadId = serde_json::from_str(&json).unwrap();
    assert_eq!(wid, back);
}

#[cfg(feature = "serde")]
#[test]
fn trust_domain_serializes_as_transparent_string() {
    let trust = TrustDomain::new("gnomes.local").unwrap();
    let json = serde_json::to_string(&trust).unwrap();
    assert_eq!(json, "\"gnomes.local\"");
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
    let result = WorkloadId::parse("spiffe://gnomes.local/x?y");
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
    let trust = TrustDomain::new("gnomes.local").unwrap();
    assert_eq!(format!("{trust}"), "gnomes.local");
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
    assert!(WorkloadId::parse("spiffe://gnomes.local/a/../b").is_err());
    assert!(WorkloadId::parse("spiffe://gnomes.local/./b").is_err());
    assert!(WorkloadId::parse("spiffe://gnomes.local/a/..").is_err());
    let trust = TrustDomain::new("gnomes.local").unwrap();
    assert!(WorkloadId::build(&trust, "..", "acme").is_err());
    assert!(WorkloadId::parse("spiffe://gnomes.local/a/..b/c.d").is_ok());
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
