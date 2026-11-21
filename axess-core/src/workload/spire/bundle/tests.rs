//! Bundles: the keys they are filed under, the certificates they hold, and
//! the key sets a JOSE library is given.

use axess_clock::testing::Shift;
use proptest::prelude::*;
use serde_json::json;

use super::*;
use crate::workload::spire::test_support::{Day, REFERENCE, TestCa};

fn trust_domain(name: &str) -> TrustDomain {
    TrustDomain::new(name).expect("a trust domain")
}

/// A minute after the reference time, when the bundles here are read.
fn now() -> Timestamp {
    Timestamp::from_unix_seconds(REFERENCE + 60).expect("in range")
}

#[test]
fn a_bundle_key_is_a_trust_domain_name_or_its_spiffe_id() {
    assert_eq!(
        trust_domain_key("example.org"),
        Ok(trust_domain("example.org"))
    );
    assert_eq!(
        trust_domain_key("spiffe://example.org"),
        Ok(trust_domain("example.org"))
    );
    // The scheme is case-insensitive, and a trust domain name may hold an
    // underscore (SPIFFE-ID standard, sections 2.4 and 2.1).
    assert_eq!(
        trust_domain_key("SPIFFE://trust_domain.example.org"),
        Ok(trust_domain("trust_domain.example.org"))
    );
}

#[test]
fn a_bundle_key_with_a_path_or_no_name_is_refused() {
    for key in [
        "",
        "spiffe://",
        "spiffe://example.org/workload",
        "example.org/workload",
        "Example.Org",
        "https://example.org",
    ] {
        assert!(
            matches!(trust_domain_key(key), Err(SpireError::Refused(_))),
            "{key:?} must be refused"
        );
    }
}

#[test]
fn a_refused_bundle_key_is_quoted_escaped_and_cut() {
    let hostile = format!("evil\n\u{1b}[31m{}", "k".repeat(2000));
    let Err(SpireError::Refused(text)) = trust_domain_key(&hostile) else {
        panic!("a key with a line break is refused");
    };
    assert!(!text.contains('\n') && !text.contains('\u{1b}'), "{text:?}");
    assert!(text.len() < 400, "the text is {} bytes", text.len());
}

#[test]
fn certificates_end_to_end_are_split_at_their_own_lengths() {
    let first = TestCa::new("one").bundle_der();
    let second = TestCa::new("two").bundle_der();
    let both = [first.clone(), second.clone()].concat();
    let split = split_certificates(&both, "bundle").expect("two certificates");
    assert_eq!(split.len(), 2);
    assert_eq!(split[0].as_ref(), first.as_slice());
    assert_eq!(split[1].as_ref(), second.as_slice());
    assert!(
        split_certificates(&[], "bundle")
            .expect("no certificate is no error here")
            .is_empty()
    );
}

#[test]
fn a_cut_or_trailing_certificate_is_refused() {
    let whole = TestCa::new("one").bundle_der();
    let cut = &whole[..whole.len() - 1];
    assert!(matches!(
        split_certificates(cut, "bundle"),
        Err(SpireError::Refused(_))
    ));
    let trailing = [whole.as_slice(), b"junk"].concat();
    let Err(SpireError::Refused(text)) = split_certificates(&trailing, "bundle") else {
        panic!("bytes after the last certificate are refused");
    };
    assert!(text.contains("certificate 2 of the bundle"), "{text}");
}

#[test]
fn more_certificates_than_the_limit_are_refused() {
    let one = TestCa::new("one").bundle_der();
    let many = one.repeat(MAX_CERTIFICATES + 1);
    let Err(SpireError::Refused(text)) = split_certificates(&many, "bundle") else {
        panic!("a bundle over the limit is refused");
    };
    assert!(text.contains("more than 64 certificates"), "{text}");
    assert_eq!(
        split_certificates(&one.repeat(MAX_CERTIFICATES), "bundle")
            .expect("a bundle at the limit")
            .len(),
        MAX_CERTIFICATES
    );
}

#[test]
fn an_x509_bundle_with_no_certificate_is_refused() {
    assert!(matches!(
        X509Bundle::from_der(trust_domain("example.org"), &[], now()),
        Err(SpireError::Refused(_))
    ));
}

#[test]
fn an_authority_past_its_validity_is_no_trust_anchor() {
    // Retired at the start of the second of January.
    let retired = TestCa::expiring("retired", Day(2));
    let current = TestCa::new("current");
    let der = [retired.bundle_der(), current.bundle_der()].concat();
    let bundle = X509Bundle::from_der(trust_domain("example.org"), &der, now())
        .expect("two authorities, both valid on the first");
    let anchors = |at: Timestamp| -> Vec<Vec<u8>> {
        bundle
            .valid_at(at)
            .map(|authority| authority.as_ref().to_vec())
            .collect()
    };
    let retirement = Timestamp::from_unix_seconds(REFERENCE + 86_400).expect("in range");
    assert_eq!(anchors(now()), [retired.bundle_der(), current.bundle_der()]);
    assert_eq!(
        anchors(retirement),
        [retired.bundle_der(), current.bundle_der()],
        "valid through the last second of its validity"
    );
    let after = retirement.plus(axess_clock::SignedDuration::seconds(1));
    assert_eq!(anchors(after), [current.bundle_der()]);
    // Every authority the agent served is still listed.
    assert_eq!(bundle.authorities().len(), 2);

    // Read after the retirement, the bundle is the same and so are its
    // anchors; with no authority left it is refused.
    let later = X509Bundle::from_der(trust_domain("example.org"), &der, after)
        .expect("one valid authority");
    assert_eq!(later, bundle);
    assert_eq!(
        X509Bundle::from_der(trust_domain("example.org"), &retired.bundle_der(), after),
        Err(SpireError::AuthoritiesExpired(trust_domain("example.org")))
    );
}

#[test]
fn a_bundle_made_by_hand_reads_the_validity_of_its_authorities() {
    let current = TestCa::new("current");
    let bundle = X509Bundle::new(
        trust_domain("example.org"),
        vec![CertificateDer::from(current.bundle_der())],
    )
    .expect("a certificate");
    assert_eq!(bundle.valid_at(now()).count(), 1);
    let not_a_certificate = X509Bundle::new(
        trust_domain("example.org"),
        vec![CertificateDer::from(b"junk".to_vec())],
    );
    assert!(matches!(not_a_certificate, Err(SpireError::Refused(_))));
}

#[test]
fn an_x509_bundle_set_is_read_by_trust_domain() {
    let own = TestCa::new("own");
    let partner = TestCa::new("partner");
    let set = X509BundleSet::from_raw(
        RawBundles {
            crls: vec![b"crl".to_vec()],
            bundles: vec![
                ("spiffe://partner.test".to_owned(), partner.bundle_der()),
                ("example.org".to_owned(), own.bundle_der()),
            ],
        },
        &trust_domain("example.org"),
        now(),
    )
    .expect("two well-formed bundles");
    assert_eq!(set.len(), 2);
    assert!(!set.is_empty());
    assert_eq!(
        set.trust_domains()
            .map(TrustDomain::as_str)
            .collect::<Vec<_>>(),
        ["example.org", "partner.test"]
    );
    let own_bundle = set
        .get(&trust_domain("example.org"))
        .expect("the own bundle");
    assert_eq!(
        own_bundle.authorities()[0].as_ref(),
        own.bundle_der().as_slice()
    );
    assert_eq!(own_bundle.trust_domain().as_str(), "example.org");
    assert!(set.get(&trust_domain("other.test")).is_none());
    assert_eq!(set.crls(), [b"crl".to_vec()]);
}

#[test]
fn a_partners_bundle_that_does_not_read_is_left_out_and_recorded() {
    let own = TestCa::new("own");
    let set = X509BundleSet::from_raw(
        RawBundles {
            crls: Vec::new(),
            bundles: vec![
                ("example.org".to_owned(), own.bundle_der()),
                ("partner.test".to_owned(), b"not a certificate".to_vec()),
                // A trust domain name the parser refuses, as an agent of
                // another implementation might write one.
                ("spiffe://Other_Domain".to_owned(), own.bundle_der()),
            ],
        },
        &trust_domain("example.org"),
        now(),
    )
    .expect("the workload's own bundle reads");
    assert_eq!(
        set.trust_domains()
            .map(TrustDomain::as_str)
            .collect::<Vec<_>>(),
        ["example.org"]
    );
    let skipped: Vec<&str> = set.skipped().iter().map(SkippedBundle::key).collect();
    assert_eq!(skipped, ["partner.test", "spiffe://Other_Domain"]);
    assert!(
        set.skipped()
            .iter()
            .all(|entry| matches!(entry.error(), SpireError::Refused(_)))
    );
    assert!(
        set.skipped()[0]
            .to_string()
            .starts_with("bundle entry partner.test left out: "),
        "{}",
        set.skipped()[0]
    );
}

#[test]
fn the_workloads_own_bundle_that_does_not_read_refuses_the_set() {
    let outcome = X509BundleSet::from_raw(
        RawBundles {
            crls: Vec::new(),
            bundles: vec![
                (
                    "partner.test".to_owned(),
                    TestCa::new("partner").bundle_der(),
                ),
                (
                    "spiffe://example.org".to_owned(),
                    b"not a certificate".to_vec(),
                ),
            ],
        },
        &trust_domain("example.org"),
        now(),
    );
    assert!(matches!(outcome, Err(SpireError::Refused(_))));
    let jwt = JwtBundleSet::from_raw(
        RawBundles {
            crls: Vec::new(),
            bundles: vec![("example.org".to_owned(), b"not json".to_vec())],
        },
        &trust_domain("example.org"),
    );
    assert!(matches!(jwt, Err(SpireError::Refused(_))));
}

#[test]
fn an_answer_with_no_bundle_for_the_workloads_own_trust_domain_is_refused() {
    let own = trust_domain("example.org");
    let partner = TestCa::new("partner");
    let x509 = |bundles: Vec<(String, Vec<u8>)>| {
        let raw = RawBundles {
            crls: Vec::new(),
            bundles,
        };
        X509BundleSet::from_raw(raw, &own, now()).err()
    };
    let jwt = |bundles: Vec<(String, Vec<u8>)>| {
        let raw = RawBundles {
            crls: Vec::new(),
            bundles,
        };
        JwtBundleSet::from_raw(raw, &own).err()
    };
    let no_x509 = Some(SpireError::Refused(
        "the answer holds no X.509 bundle for example.org".to_owned(),
    ));
    let no_jwt = Some(SpireError::Refused(
        "the answer holds no JWT bundle for example.org".to_owned(),
    ));

    // An empty answer.
    assert_eq!(x509(Vec::new()), no_x509);
    assert_eq!(jwt(Vec::new()), no_jwt);
    // Partners only.
    assert_eq!(
        x509(vec![("partner.test".to_owned(), partner.bundle_der())]),
        no_x509
    );
    assert_eq!(
        jwt(vec![(
            "partner.test".to_owned(),
            br#"{"keys":[]}"#.to_vec()
        )]),
        no_jwt
    );
    // The own bundle under a key that does not read as a trust domain: the
    // entry is left out as any unreadable one is, and the own is missing.
    assert_eq!(
        x509(vec![(
            "spiffe://Example_Org".to_owned(),
            partner.bundle_der()
        )]),
        no_x509
    );
    assert_eq!(
        jwt(vec![(
            "example.org/path".to_owned(),
            br#"{"keys":[]}"#.to_vec()
        )]),
        no_jwt
    );
    // The own bundle with authorities that have all expired says so.
    let retired = TestCa::expiring("retired", Day(1));
    assert_eq!(
        x509(vec![("example.org".to_owned(), retired.bundle_der())]),
        Some(SpireError::AuthoritiesExpired(own.clone()))
    );
}

#[test]
fn a_skipped_key_is_recorded_escaped_and_cut() {
    let hostile = format!("evil\n\u{1b}[31m{}", "k".repeat(2000));
    let set = JwtBundleSet::from_raw(
        RawBundles {
            crls: Vec::new(),
            bundles: vec![
                (hostile, br#"{"keys":[]}"#.to_vec()),
                ("example.org".to_owned(), br#"{"keys":[]}"#.to_vec()),
            ],
        },
        &trust_domain("example.org"),
    )
    .expect("only a partner's entry fails");
    let entry = &set.skipped()[0];
    assert!(!entry.key().contains('\n') && !entry.key().contains('\u{1b}'));
    assert!(
        entry.key().len() <= 256,
        "the key is {} bytes",
        entry.key().len()
    );
    assert!(entry.to_string().len() < 800);
}

#[test]
fn a_jwt_bundle_is_given_to_a_jose_library_without_the_spiffe_use_values() {
    let document = json!({
        "spiffe_sequence": 12,
        "keys": [
            { "kty": "EC", "kid": "jwt-1", "use": "jwt-svid", "crv": "P-256", "x": "x", "y": "y" },
            { "kty": "EC", "kid": "x509-1", "use": "x509-svid", "crv": "P-256", "x": "x", "y": "y" },
            { "kty": "RSA", "kid": "plain", "n": "n", "e": "AQAB" },
            { "kty": "EC", "kid": "sig-1", "use": "sig", "crv": "P-256", "x": "x", "y": "y" },
            // Keys for another kind of SVID, for encryption, and for a use
            // this client has not heard of: none signs a JWT-SVID.
            { "kty": "EC", "kid": "wit-1", "use": "wit-svid", "crv": "P-256", "x": "x", "y": "y" },
            { "kty": "RSA", "kid": "enc-1", "use": "enc", "n": "n", "e": "AQAB" },
            { "kty": "EC", "kid": "new-1", "use": "future-svid", "crv": "P-256", "x": "x", "y": "y" },
            { "kty": "EC", "kid": "odd-1", "use": 7, "crv": "P-256", "x": "x", "y": "y" },
        ],
    });
    let bundle = JwtBundle::from_json(trust_domain("example.org"), document.to_string().as_bytes())
        .expect("a well-formed bundle");
    assert_eq!(bundle.key_ids(), ["jwt-1", "plain", "sig-1"]);
    assert_eq!(
        bundle.jwks(),
        &json!({
            "keys": [
                { "kty": "EC", "kid": "jwt-1", "crv": "P-256", "x": "x", "y": "y" },
                { "kty": "RSA", "kid": "plain", "n": "n", "e": "AQAB" },
                { "kty": "EC", "kid": "sig-1", "use": "sig", "crv": "P-256", "x": "x", "y": "y" },
            ],
        })
    );
    assert_eq!(bundle.trust_domain().as_str(), "example.org");
}

#[test]
fn a_jwt_bundle_that_is_not_a_key_set_is_refused() {
    for document in [
        "not json",
        "[]",
        "{}",
        r#"{"keys": {}}"#,
        r#"{"keys": ["a string"]}"#,
        r#"{"keys": [{"kid": "no kty"}]}"#,
        r#"{"keys": [{"kty": 7}]}"#,
    ] {
        assert!(
            matches!(
                JwtBundle::from_json(trust_domain("example.org"), document.as_bytes()),
                Err(SpireError::Refused(_))
            ),
            "{document} must be refused"
        );
    }
}

#[test]
fn a_refused_jwt_bundle_does_not_carry_what_it_quotes_at_length() {
    let hostile = format!("{{\"keys\": \"{}\n\u{1b}[0m\"}}", "v".repeat(100_000));
    let Err(SpireError::Refused(text)) =
        JwtBundle::from_json(trust_domain("example.org"), hostile.as_bytes())
    else {
        panic!("a control character inside a JSON string is refused");
    };
    assert!(!text.contains('\n') && !text.contains('\u{1b}'), "{text:?}");
    assert!(text.len() < 400, "the text is {} bytes", text.len());
}

#[test]
fn a_jwt_bundle_set_is_read_by_trust_domain() {
    let set = JwtBundleSet::from_raw(
        RawBundles {
            crls: Vec::new(),
            bundles: vec![
                (
                    "spiffe://example.org".to_owned(),
                    br#"{"keys":[]}"#.to_vec(),
                ),
                (
                    "partner.test".to_owned(),
                    br#"{"keys":[{"kty":"EC","kid":"p"}]}"#.to_vec(),
                ),
            ],
        },
        &trust_domain("example.org"),
    )
    .expect("two well-formed bundles");
    assert_eq!(set.len(), 2);
    assert!(!set.is_empty());
    assert_eq!(
        set.trust_domains()
            .map(TrustDomain::as_str)
            .collect::<Vec<_>>(),
        ["example.org", "partner.test"]
    );
    assert_eq!(
        set.get(&trust_domain("partner.test"))
            .expect("the partner's")
            .key_ids(),
        ["p"]
    );
    assert!(JwtBundleSet::default().is_empty());
}

proptest! {
    /// No bytes make the certificate splitter panic, and what it accepts is
    /// the input cut into pieces, nothing added and nothing lost.
    #[test]
    fn splitting_ends_on_any_input(der in proptest::collection::vec(any::<u8>(), 0..512)) {
        if let Ok(certificates) = split_certificates(&der, "bundle") {
            let joined: Vec<u8> = certificates.iter().flat_map(|c| c.as_ref().to_vec()).collect();
            prop_assert_eq!(joined, der);
        }
    }

    /// A real certificate with bytes changed is split or refused, never
    /// a panic.
    #[test]
    fn splitting_ends_on_a_damaged_certificate(
        position in 0usize..400,
        value in any::<u8>(),
        keep in 0usize..600,
    ) {
        let mut der = TestCa::new("one").bundle_der();
        let position = position % der.len();
        der[position] = value;
        der.truncate(keep.min(der.len()));
        if let Ok(certificates) = split_certificates(&der, "bundle") {
            prop_assert!(certificates.len() <= 1);
        }
    }

    /// No bytes make the JWT bundle reader panic, and a bundle it accepts
    /// holds no key marked for X.509 and no `jwt-svid` use value.
    #[test]
    fn jwt_bundles_end_on_any_input(json in "\\PC{0,200}") {
        if let Ok(bundle) = JwtBundle::from_json(trust_domain("example.org"), json.as_bytes()) {
            let keys = bundle.jwks()["keys"].as_array().expect("a keys array").clone();
            for key in keys {
                let marked = key.get("use").and_then(|value| value.as_str());
                prop_assert!(marked != Some("x509-svid") && marked != Some("jwt-svid"));
            }
        }
    }

    /// No text makes the bundle-key reader panic.
    #[test]
    fn bundle_keys_end_on_any_input(key in "\\PC{0,300}") {
        if let Ok(trust_domain) = trust_domain_key(&key) {
            prop_assert!(key.ends_with(trust_domain.as_str()));
        }
    }
}
