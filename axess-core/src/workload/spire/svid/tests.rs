//! Admission: which SVIDs a client keeps, and which it refuses and why.

use proptest::prelude::*;
use rcgen::{BasicConstraints, IsCa};
use serde_json::json;

use super::*;
use crate::workload::spire::proto::{RawJwtSvid, RawX509Svid, RawX509SvidResponse};
use crate::workload::spire::test_support::{
    Day, Minted, REFERENCE, TestCa, jwt_svid, unsigned_jwt, uri, without_public_key,
};

const ID: &str = "spiffe://example.org/billing/acme";

fn trust_domain(name: &str) -> TrustDomain {
    TrustDomain::new(name).expect("a trust domain")
}

fn at(seconds_after_reference: i64) -> Timestamp {
    Timestamp::from_unix_seconds(REFERENCE + seconds_after_reference).expect("in range")
}

fn raw(minted: &Minted, bundle: &[u8]) -> RawX509Svid {
    RawX509Svid {
        spiffe_id: minted.spiffe_id.clone(),
        cert_chain: minted.cert_der.clone(),
        private_key: Zeroizing::new(minted.key_der.clone()),
        bundle: bundle.to_vec(),
        hint: String::new(),
    }
}

fn response(svids: Vec<RawX509Svid>) -> RawX509SvidResponse {
    RawX509SvidResponse {
        svids,
        crls: Vec::new(),
        federated_bundles: Vec::new(),
    }
}

fn admit(svids: Vec<RawX509Svid>) -> Result<X509Context, SpireError> {
    admit_x509(
        response(svids),
        &trust_domain("example.org"),
        &SvidSelector::First,
        at(60),
    )
}

fn refusal(outcome: Result<X509Context, SpireError>) -> String {
    match outcome {
        Err(SpireError::Refused(text)) => text,
        other => panic!("expected a refusal, got {:?}", other.map(|_| "a context")),
    }
}

#[test]
fn a_well_formed_svid_is_admitted_with_its_bundle() {
    let ca = TestCa::new("example.org authority");
    let minted = ca.svid(ID, Day(1), Day(2));
    let context = admit(vec![raw(&minted, &ca.bundle_der())]).expect("a valid SVID");

    let svid = context.svid();
    assert_eq!(svid.spiffe_id().as_str(), ID);
    assert_eq!(svid.trust_domain().as_str(), "example.org");
    assert_eq!(svid.cert_chain().len(), 1);
    assert_eq!(svid.leaf().as_ref(), minted.cert_der.as_slice());
    assert_eq!(
        svid.private_key().secret_pkcs8_der(),
        minted.key_der.as_slice()
    );
    assert_eq!(svid.not_before(), at(0));
    assert_eq!(svid.not_after(), at(24 * 3600));
    assert_eq!(svid.hint(), "");
    assert_eq!(context.svids().len(), 1);
    let bundle = context
        .bundles()
        .get(&trust_domain("example.org"))
        .expect("the SVID's own bundle");
    assert_eq!(bundle.authorities()[0].as_ref(), ca.bundle_der().as_slice());
}

#[test]
fn the_private_key_is_not_in_the_debug_text() {
    let ca = TestCa::new("example.org authority");
    let minted = ca.svid(ID, Day(1), Day(2));
    let context = admit(vec![raw(&minted, &ca.bundle_der())]).expect("a valid SVID");
    let text = format!("{:?}", context.svid());
    assert!(text.contains("<redacted>"), "{text}");
    // The key's bytes would print as a list of numbers.
    let key_as_debug = format!("{:?}", minted.key_der);
    assert!(
        !text.contains(key_as_debug.trim_matches(['[', ']'])),
        "{text}"
    );
}

#[test]
fn an_svid_for_another_trust_domain_is_refused() {
    let ca = TestCa::new("other authority");
    let minted = ca.svid("spiffe://other.test/billing/acme", Day(1), Day(2));
    let outcome = admit(vec![raw(&minted, &ca.bundle_der())]);
    assert_eq!(
        outcome.err(),
        Some(SpireError::TrustDomainMismatch {
            expected: trust_domain("example.org"),
            presented: "other.test".to_owned(),
        })
    );
}

#[test]
fn an_expired_svid_is_refused() {
    let ca = TestCa::new("example.org authority");
    let minted = ca.svid(ID, Day(1), Day(2));
    let now = at(24 * 3600);
    let outcome = admit_x509(
        response(vec![raw(&minted, &ca.bundle_der())]),
        &trust_domain("example.org"),
        &SvidSelector::First,
        now,
    );
    assert!(refusal(outcome).contains("expired at 2026-01-02T00:00:00"));
    // One second earlier it is still admitted.
    assert!(
        admit_x509(
            response(vec![raw(&minted, &ca.bundle_der())]),
            &trust_domain("example.org"),
            &SvidSelector::First,
            at(24 * 3600 - 1),
        )
        .is_ok()
    );
}

#[test]
fn a_leaf_that_names_another_identity_is_refused() {
    let ca = TestCa::new("example.org authority");
    let mut minted = ca.svid("spiffe://example.org/billing/other", Day(1), Day(2));
    minted.spiffe_id = ID.to_owned();
    let text = refusal(admit(vec![raw(&minted, &ca.bundle_der())]));
    assert!(text.contains("names another SPIFFE ID"), "{text}");
}

#[test]
fn a_leaf_with_two_uri_names_is_refused() {
    let ca = TestCa::new("example.org authority");
    let minted = ca.leaf(
        vec![uri(ID), uri("spiffe://example.org/billing/second")],
        IsCa::NoCa,
        Day(1),
        Day(2),
        ID,
    );
    let text = refusal(admit(vec![raw(&minted, &ca.bundle_der())]));
    assert!(text.contains("more than one URI name"), "{text}");
}

#[test]
fn a_leaf_with_no_uri_name_is_refused() {
    let ca = TestCa::new("example.org authority");
    let dns = rcgen::SanType::DnsName("billing.example.org".try_into().expect("a DNS name"));
    let minted = ca.leaf(vec![dns], IsCa::NoCa, Day(1), Day(2), ID);
    let text = refusal(admit(vec![raw(&minted, &ca.bundle_der())]));
    assert!(text.contains("no URI name"), "{text}");
}

#[test]
fn a_leaf_that_is_a_certificate_authority_is_refused() {
    let ca = TestCa::new("example.org authority");
    let minted = ca.leaf(
        vec![uri(ID)],
        IsCa::Ca(BasicConstraints::Unconstrained),
        Day(1),
        Day(2),
        ID,
    );
    let text = refusal(admit(vec![raw(&minted, &ca.bundle_der())]));
    assert!(text.contains("certificate authority"), "{text}");
}

#[test]
fn an_svid_with_a_missing_part_is_refused() {
    let ca = TestCa::new("example.org authority");
    let minted = ca.svid(ID, Day(1), Day(2));

    let mut no_key = raw(&minted, &ca.bundle_der());
    no_key.private_key = Zeroizing::new(Vec::new());
    assert!(refusal(admit(vec![no_key])).contains("no private key"));

    let mut no_chain = raw(&minted, &ca.bundle_der());
    no_chain.cert_chain = Vec::new();
    assert!(refusal(admit(vec![no_chain])).contains("no certificate"));

    let no_bundle = raw(&minted, &[]);
    assert!(refusal(admit(vec![no_bundle])).contains("holds no certificate"));

    let mut bad_id = raw(&minted, &ca.bundle_der());
    bad_id.spiffe_id = "https://example.org/billing".to_owned();
    assert!(refusal(admit(vec![bad_id])).contains("SPIFFE ID is not valid"));

    assert!(refusal(admit(Vec::new())).contains("holds no SVID"));
}

#[test]
fn a_malformed_certificate_is_refused_with_bounded_escaped_text() {
    let ca = TestCa::new("example.org authority");
    let minted = ca.svid(ID, Day(1), Day(2));
    let mut garbled = raw(&minted, &ca.bundle_der());
    garbled.cert_chain = b"\x30\x82\xff\xff not a certificate \n\x1b[2J".repeat(64);
    let text = refusal(admit(vec![garbled]));
    assert!(
        text.contains("certificate 1 of the SVID's certificate chain"),
        "{text}"
    );
    assert!(!text.contains('\n') && !text.contains('\u{1b}'), "{text:?}");
    assert!(text.len() < 400, "the text is {} bytes", text.len());

    let mut hostile_id = raw(&minted, &ca.bundle_der());
    hostile_id.spiffe_id = format!("spiffe://example.org/a\n\u{1b}[31m{}", "x".repeat(5000));
    let text = refusal(admit(vec![hostile_id]));
    assert!(!text.contains('\n') && !text.contains('\u{1b}'), "{text:?}");
    assert!(text.len() < 400, "the text is {} bytes", text.len());
}

#[test]
fn the_selector_picks_among_several_svids() {
    let ca = TestCa::new("example.org authority");
    let first = ca.svid(ID, Day(1), Day(2));
    let second = ca.svid("spiffe://example.org/reports/acme", Day(1), Day(3));
    let svids = || {
        let mut hinted = raw(&second, &ca.bundle_der());
        hinted.hint = "reports".to_owned();
        response(vec![raw(&first, &ca.bundle_der()), hinted])
    };
    let admit_with = |selector: SvidSelector| {
        admit_x509(svids(), &trust_domain("example.org"), &selector, at(60))
    };

    let by_default = admit_with(SvidSelector::First).expect("the first");
    assert_eq!(by_default.svid().spiffe_id().as_str(), ID);
    assert_eq!(by_default.svids().len(), 2);

    let by_hint = admit_with(SvidSelector::Hint("reports".to_owned())).expect("the hinted");
    assert_eq!(by_hint.svid().spiffe_id().as_str(), second.spiffe_id);
    assert_eq!(by_hint.svid().hint(), "reports");

    let wanted = WorkloadId::parse(&second.spiffe_id).expect("a SPIFFE ID");
    let by_id = admit_with(SvidSelector::SpiffeId(wanted)).expect("the named");
    assert_eq!(by_id.svid().spiffe_id().as_str(), second.spiffe_id);

    // SVIDs, and none for the identity selected: the agent does not issue
    // it, which is another answer than a malformed one.
    let missing = admit_with(SvidSelector::Hint("absent".to_owned()));
    assert_eq!(
        missing.err(),
        Some(SpireError::NotIssued("the hint absent".to_owned()))
    );
    let absent = WorkloadId::parse("spiffe://example.org/absent/acme").expect("a SPIFFE ID");
    assert_eq!(
        admit_with(SvidSelector::SpiffeId(absent)).err(),
        Some(SpireError::NotIssued(
            "spiffe://example.org/absent/acme".to_owned()
        ))
    );
}

/// X509-SVID standard, sections 3.1 and 5.2: a leaf's SPIFFE ID has a path.
/// A certificate that names a trust domain alone is not a workload's.
#[test]
fn a_leaf_whose_spiffe_id_has_no_path_is_refused() {
    let ca = TestCa::new("example.org authority");
    let domain_only = "spiffe://example.org";
    let minted = ca.leaf(
        vec![uri(domain_only)],
        IsCa::NoCa,
        Day(1),
        Day(2),
        domain_only,
    );
    let text = refusal(admit(vec![raw(&minted, &ca.bundle_der())]));
    assert!(text.contains("not a SPIFFE ID with a path"), "{text}");
    let leaf = CertificateDer::from(minted.cert_der);
    assert!(read_leaf(&leaf).is_err());
}

#[test]
fn an_svid_of_another_trust_domain_that_was_not_selected_is_left_out() {
    let ca = TestCa::new("example.org authority");
    let other = TestCa::new("other authority");
    let own = ca.svid(ID, Day(1), Day(2));
    let foreign = other.svid("spiffe://other.test/billing/acme", Day(1), Day(2));
    let context = admit(vec![
        raw(&own, &ca.bundle_der()),
        raw(&foreign, &other.bundle_der()),
    ])
    .expect("the first SVID is the client's");
    assert_eq!(context.svids().len(), 1);
    assert!(context.bundles().get(&trust_domain("other.test")).is_none());
}

#[test]
fn federated_bundles_are_kept_beside_the_svids_own() {
    let ca = TestCa::new("example.org authority");
    let partner = TestCa::new("partner authority");
    let minted = ca.svid(ID, Day(1), Day(2));
    let context = admit_x509(
        RawX509SvidResponse {
            svids: vec![raw(&minted, &ca.bundle_der())],
            crls: vec![b"crl".to_vec()],
            federated_bundles: vec![
                ("spiffe://partner.test".to_owned(), partner.bundle_der()),
                // A federated entry under the workload's own name does not
                // replace the bundle that came with its SVID.
                ("example.org".to_owned(), partner.bundle_der()),
            ],
        },
        &trust_domain("example.org"),
        &SvidSelector::First,
        at(60),
    )
    .expect("a valid response");
    let bundles = context.bundles();
    assert_eq!(bundles.len(), 2);
    assert_eq!(
        bundles
            .get(&trust_domain("partner.test"))
            .expect("the partner's")
            .authorities()[0]
            .as_ref(),
        partner.bundle_der().as_slice()
    );
    assert_eq!(
        bundles
            .get(&trust_domain("example.org"))
            .expect("the own")
            .authorities()[0]
            .as_ref(),
        ca.bundle_der().as_slice()
    );
    assert_eq!(bundles.crls(), [b"crl".to_vec()]);
}

#[test]
fn a_federated_bundle_that_does_not_read_is_left_out_and_the_svid_admitted() {
    let ca = TestCa::new("example.org authority");
    let partner = TestCa::new("partner authority");
    let minted = ca.svid(ID, Day(1), Day(2));
    let context = admit_x509(
        RawX509SvidResponse {
            svids: vec![raw(&minted, &ca.bundle_der())],
            crls: Vec::new(),
            federated_bundles: vec![
                ("partner.test".to_owned(), b"junk".to_vec()),
                ("spiffe://Under_Score".to_owned(), partner.bundle_der()),
                ("spiffe://other.test".to_owned(), partner.bundle_der()),
            ],
        },
        &trust_domain("example.org"),
        &SvidSelector::First,
        at(60),
    )
    .expect("the workload's own SVID does not depend on a partner's bundle");
    assert_eq!(context.svid().spiffe_id().as_str(), ID);
    let bundles = context.bundles();
    assert_eq!(
        bundles
            .trust_domains()
            .map(TrustDomain::as_str)
            .collect::<Vec<_>>(),
        ["example.org", "other.test"]
    );
    let skipped: Vec<&str> = bundles.skipped().iter().map(|entry| entry.key()).collect();
    assert_eq!(skipped, ["partner.test", "spiffe://Under_Score"]);
    assert!(
        bundles.skipped()[0]
            .error()
            .to_string()
            .contains("certificate 1 of the bundle")
    );
}

#[test]
fn an_expired_svid_the_selector_did_not_choose_is_left_out() {
    let ca = TestCa::new("example.org authority");
    let current = ca.svid(ID, Day(1), Day(3));
    let stale = ca.svid("spiffe://example.org/reports/acme", Day(1), Day(2));
    let context = admit_x509(
        response(vec![
            raw(&current, &ca.bundle_der()),
            raw(&stale, &ca.bundle_der()),
        ]),
        &trust_domain("example.org"),
        &SvidSelector::First,
        at(24 * 3600),
    )
    .expect("the selected SVID is valid");
    assert_eq!(context.svids().len(), 1);
    assert_eq!(context.svids()[0].spiffe_id().as_str(), ID);
}

#[test]
fn a_context_read_later_leaves_out_what_expired_since() {
    let ca = TestCa::new("example.org authority");
    let current = ca.svid(ID, Day(1), Day(3));
    let other = ca.svid("spiffe://example.org/reports/acme", Day(1), Day(2));
    let third = ca.svid("spiffe://example.org/audit/acme", Day(1), Day(4));
    let context = admit_x509(
        response(vec![
            raw(&other, &ca.bundle_der()),
            raw(&current, &ca.bundle_der()),
            raw(&third, &ca.bundle_der()),
        ]),
        &trust_domain("example.org"),
        &SvidSelector::SpiffeId(WorkloadId::parse(ID).expect("a SPIFFE ID")),
        at(60),
    )
    .expect("three valid SVIDs");
    assert_eq!(context.svids().len(), 3);
    assert!(
        context.without_expired(at(60)).is_none(),
        "nothing has expired"
    );

    let later = context
        .without_expired(at(24 * 3600))
        .expect("the second SVID has expired");
    let ids: Vec<&str> = later
        .svids()
        .iter()
        .map(|svid| svid.spiffe_id().as_str())
        .collect();
    assert_eq!(ids, [ID, "spiffe://example.org/audit/acme"]);
    assert_eq!(
        later.svid().spiffe_id().as_str(),
        ID,
        "the selection follows"
    );
    assert_eq!(later.bundles(), context.bundles());
}

#[test]
fn a_private_key_that_is_not_the_leafs_is_refused() {
    let ca = TestCa::new("example.org authority");
    let minted = ca.svid(ID, Day(1), Day(2));
    let stranger = ca.svid(ID, Day(1), Day(2));
    let with_key = |key: Vec<u8>| {
        let mut svid = raw(&minted, &ca.bundle_der());
        svid.private_key = Zeroizing::new(key);
        refusal(admit(vec![svid]))
    };

    // The key of another certificate, issued to the same identity.
    let text = with_key(stranger.key_der.clone());
    assert!(
        text.contains("the private key is not the leaf certificate's"),
        "{text}"
    );
    // Bytes that are no key.
    let text = with_key(b"not a private key".to_vec());
    assert!(text.contains("the private key is not PKCS#8"), "{text}");
    // A key of another algorithm than the certificate's.
    let other_kind = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("an Ed25519 key");
    let text = with_key(other_kind.serialize_der());
    assert!(text.contains("another algorithm or curve"), "{text}");
    // The right key, one byte of its public half changed.
    let mut damaged = minted.key_der.clone();
    let last = damaged.len() - 1;
    damaged[last] ^= 0x01;
    let text = with_key(damaged);
    assert!(
        text.contains("the private key is not the leaf certificate's"),
        "{text}"
    );
}

/// A key that does not say whose it is: with a TLS stack in the build its
/// public key is derived and compared, so the right key is admitted and
/// another's refused.
#[cfg(feature = "outbound-mtls")]
#[test]
fn a_private_key_that_carries_no_public_key_is_checked_by_deriving_it() {
    let ca = TestCa::new("example.org authority");
    let minted = ca.svid(ID, Day(1), Day(2));
    let stranger = ca.svid(ID, Day(1), Day(2));

    let mut own = raw(&minted, &ca.bundle_der());
    own.private_key = Zeroizing::new(without_public_key(&minted.key_der));
    let context = admit(vec![own]).expect("the leaf's own key");
    assert_eq!(context.svid().spiffe_id().as_str(), ID);

    let mut swapped = raw(&minted, &ca.bundle_der());
    swapped.private_key = Zeroizing::new(without_public_key(&stranger.key_der));
    let text = refusal(admit(vec![swapped]));
    assert!(
        text.contains("the private key is not the leaf certificate's"),
        "{text}"
    );
}

/// Without a TLS stack in the build nothing derives the public key, and a
/// key that cannot be shown to be the certificate's is refused.
#[cfg(not(feature = "outbound-mtls"))]
#[test]
fn a_private_key_that_carries_no_public_key_is_refused_where_nothing_derives_it() {
    let ca = TestCa::new("example.org authority");
    let minted = ca.svid(ID, Day(1), Day(2));
    let mut own = raw(&minted, &ca.bundle_der());
    own.private_key = Zeroizing::new(without_public_key(&minted.key_der));
    let text = refusal(admit(vec![own]));
    assert!(text.contains("carries no public key"), "{text}");
}

#[test]
fn a_leaf_whose_validity_runs_backwards_is_refused() {
    let ca = TestCa::new("example.org authority");
    let backwards = ca.svid(ID, Day(3), Day(2));
    let text = refusal(admit(vec![raw(&backwards, &ca.bundle_der())]));
    assert!(text.contains("validity ends before it begins"), "{text}");
}

#[test]
fn an_svid_whose_bundle_holds_only_expired_authorities_is_refused() {
    // The authority's own certificate ran out at the reference time; the
    // SVID is admitted a minute after it.
    let retired = TestCa::expiring("example.org authority, retired", Day(1));
    let minted = retired.svid(ID, Day(1), Day(2));
    let outcome = admit(vec![raw(&minted, &retired.bundle_der())]);
    assert_eq!(
        outcome.err(),
        Some(SpireError::AuthoritiesExpired(trust_domain("example.org")))
    );

    // Beside an authority that is valid, the retired one is kept in the
    // bundle and is no trust anchor.
    let current = TestCa::new("example.org authority");
    let renewed = current.svid(ID, Day(1), Day(2));
    let both = [retired.bundle_der(), current.bundle_der()].concat();
    let context = admit(vec![raw(&renewed, &both)]).expect("one valid authority");
    let bundle = context
        .bundles()
        .get(&trust_domain("example.org"))
        .expect("the own bundle");
    assert_eq!(bundle.authorities().len(), 2);
    let anchors: Vec<&[u8]> = bundle
        .valid_at(at(60))
        .map(|authority| authority.as_ref())
        .collect();
    assert_eq!(anchors, [current.bundle_der().as_slice()]);
}

#[test]
fn a_federated_bundle_of_expired_authorities_is_left_out_and_recorded() {
    let ca = TestCa::new("example.org authority");
    let retired = TestCa::expiring("partner authority, retired", Day(1));
    let minted = ca.svid(ID, Day(1), Day(2));
    let context = admit_x509(
        RawX509SvidResponse {
            svids: vec![raw(&minted, &ca.bundle_der())],
            crls: Vec::new(),
            federated_bundles: vec![("partner.test".to_owned(), retired.bundle_der())],
        },
        &trust_domain("example.org"),
        &SvidSelector::First,
        at(60),
    )
    .expect("the workload's own SVID does not depend on a partner's bundle");
    assert!(
        context
            .bundles()
            .get(&trust_domain("partner.test"))
            .is_none()
    );
    assert_eq!(
        context.bundles().skipped()[0].error(),
        &SpireError::AuthoritiesExpired(trust_domain("partner.test"))
    );
}

fn raw_jwt(spiffe_id: &str, token: String) -> RawJwtSvid {
    RawJwtSvid {
        spiffe_id: spiffe_id.to_owned(),
        token: Zeroizing::new(token),
        hint: "h".to_owned(),
    }
}

fn admit_token(spiffe_id: &str, token: String) -> Result<JwtSvid, SpireError> {
    admit_jwt(
        raw_jwt(spiffe_id, token),
        &trust_domain("example.org"),
        &["api".to_owned()],
        at(60),
    )
}

fn jwt_refusal(outcome: Result<JwtSvid, SpireError>) -> String {
    match outcome {
        Err(SpireError::Refused(text)) => text,
        other => panic!("expected a refusal, got {:?}", other.map(|_| "an SVID")),
    }
}

#[test]
fn a_well_formed_jwt_svid_is_admitted() {
    let token = jwt_svid(ID, &["api", "second"], REFERENCE, REFERENCE + 300);
    let svid = admit_token(ID, token.clone()).expect("a valid SVID");
    assert_eq!(svid.spiffe_id().as_str(), ID);
    assert_eq!(svid.trust_domain().as_str(), "example.org");
    assert_eq!(svid.token(), token);
    assert_eq!(svid.audience(), ["api", "second"]);
    assert_eq!(svid.issued_at(), at(0));
    assert_eq!(svid.expires_at(), at(300));
    assert_eq!(svid.hint(), "h");
    let text = format!("{svid:?}");
    assert!(
        text.contains("<redacted>") && !text.contains(&token),
        "{text}"
    );
}

#[test]
fn a_single_string_audience_and_a_missing_iat_are_read() {
    let token = unsigned_jwt(&json!({ "sub": ID, "aud": "api", "exp": REFERENCE + 300 }));
    let svid = admit_token(ID, token).expect("a valid SVID");
    assert_eq!(svid.audience(), ["api"]);
    // With no `iat`, the lifetime is counted from when it was fetched.
    assert_eq!(svid.issued_at(), at(60));
}

#[test]
fn a_jwt_svid_for_another_trust_domain_is_refused() {
    let other = "spiffe://other.test/billing/acme";
    let token = jwt_svid(other, &["api"], REFERENCE, REFERENCE + 300);
    assert_eq!(
        admit_token(other, token).err(),
        Some(SpireError::TrustDomainMismatch {
            expected: trust_domain("example.org"),
            presented: "other.test".to_owned(),
        })
    );
}

#[test]
fn a_jwt_svid_that_does_not_say_what_was_asked_is_refused() {
    let other_subject = jwt_svid(
        "spiffe://example.org/billing/other",
        &["api"],
        REFERENCE,
        REFERENCE + 300,
    );
    assert!(jwt_refusal(admit_token(ID, other_subject)).contains("another subject"));

    let other_audience = jwt_svid(ID, &["elsewhere"], REFERENCE, REFERENCE + 300);
    assert!(jwt_refusal(admit_token(ID, other_audience)).contains("not for the audience"));

    let no_audience = unsigned_jwt(&json!({ "sub": ID, "exp": REFERENCE + 300 }));
    assert!(jwt_refusal(admit_token(ID, no_audience)).contains("no audience"));

    let odd_audience =
        unsigned_jwt(&json!({ "sub": ID, "aud": ["api", 7], "exp": REFERENCE + 300 }));
    assert!(jwt_refusal(admit_token(ID, odd_audience)).contains("not a string"));

    let no_expiry = unsigned_jwt(&json!({ "sub": ID, "aud": "api" }));
    assert!(jwt_refusal(admit_token(ID, no_expiry)).contains("no expiry"));
}

#[test]
fn an_expired_jwt_svid_is_refused() {
    let at_expiry = jwt_svid(ID, &["api"], REFERENCE - 300, REFERENCE + 60);
    assert!(jwt_refusal(admit_token(ID, at_expiry)).contains("expired at 2026-01-01T00:01:00"));
    let one_second_left = jwt_svid(ID, &["api"], REFERENCE - 300, REFERENCE + 61);
    assert!(admit_token(ID, one_second_left).is_ok());
}

#[test]
fn a_jwt_svid_issued_after_its_expiry_is_refused() {
    let backwards = jwt_svid(ID, &["api"], REFERENCE + 400, REFERENCE + 300);
    assert!(jwt_refusal(admit_token(ID, backwards)).contains("was issued after it expires"));
    // An `iat` in milliseconds, as some issuers write it by mistake.
    let milliseconds = jwt_svid(ID, &["api"], REFERENCE * 1000, REFERENCE + 300);
    assert!(jwt_refusal(admit_token(ID, milliseconds)).contains("was issued after it expires"));
    // Issued at its expiry: the shortest validity there is, and it is read.
    let instant = jwt_svid(ID, &["api"], REFERENCE + 300, REFERENCE + 300);
    let svid = admit_token(ID, instant).expect("a validity of no length");
    assert_eq!(svid.issued_at(), svid.expires_at());
}

#[test]
fn a_token_that_is_not_a_jwt_is_refused() {
    for token in [
        "",
        "only-one-segment",
        "two.segments",
        "four.seg.men.ts",
        ".payload.signature",
        "header.payload.",
        "header.!!!.signature",
        "header.bm90IGpzb24.signature",
        "header.WzEsMl0.signature",
    ] {
        assert!(
            matches!(
                admit_token(ID, token.to_owned()),
                Err(SpireError::Refused(_))
            ),
            "{token:?} must be refused"
        );
    }
    let long = format!("h.{}.s", "A".repeat(MAX_JWT_SVID_BYTES));
    assert!(jwt_refusal(admit_token(ID, long)).contains("longer than this client reads"));
}

#[test]
fn a_refused_jwt_payload_is_quoted_escaped_and_cut() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let payload = format!("{{\"sub\": \"{}\n\u{1b}[0m\"}}", "v".repeat(8000));
    let token = format!("h.{}.s", URL_SAFE_NO_PAD.encode(payload));
    let text = jwt_refusal(admit_token(ID, token));
    assert!(text.contains("payload is not JSON"), "{text}");
    assert!(!text.contains('\n') && !text.contains('\u{1b}'), "{text:?}");
    assert!(text.len() < 400, "the text is {} bytes", text.len());
}

proptest! {
    /// No text makes the token reader panic.
    #[test]
    fn any_token_is_admitted_or_refused(token in "[A-Za-z0-9_.=-]{0,200}") {
        let outcome = admit_token(ID, token);
        prop_assert!(outcome.is_err() || outcome.is_ok_and(|svid| svid.expires_at() > at(60)));
    }

    /// No payload makes the token reader panic, and one it admits has an
    /// expiry in the future and the audience that was asked for.
    #[test]
    fn any_payload_is_admitted_or_refused(payload in proptest::collection::vec(any::<u8>(), 0..200)) {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let token = format!("h.{}.s", URL_SAFE_NO_PAD.encode(payload));
        if let Ok(svid) = admit_token(ID, token) {
            prop_assert!(svid.expires_at() > at(60));
            prop_assert!(svid.audience().iter().any(|audience| audience == "api"));
        }
    }

    /// A token with any expiry is admitted exactly when the expiry is
    /// after the clock.
    #[test]
    fn a_token_is_admitted_exactly_until_its_expiry(offset in -100_000i64..100_000) {
        let token = jwt_svid(ID, &["api"], REFERENCE - 200_000, REFERENCE + offset);
        prop_assert_eq!(admit_token(ID, token).is_ok(), offset > 60);
    }

    /// No bytes make the leaf reader panic, and its refusal stays short
    /// enough for a log line whatever it was given.
    #[test]
    fn any_leaf_is_read_or_refused(der in proptest::collection::vec(any::<u8>(), 0..300)) {
        let leaf = CertificateDer::from(der);
        if let Err(error) = read_leaf(&leaf) {
            prop_assert!(error.to_string().len() < 400);
        }
    }
}
