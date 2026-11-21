use super::*;
use crate::session::id::SessionId;
use axess_clock::SignedDuration;
use axess_clock::testing::MockClock;
use axess_clock::testing::Shift;
use std::time::Duration;

fn keys() -> KeyCookieKeys {
    KeyCookieKeys {
        current: [1; 32],
        previous: None,
    }
}

fn proven() -> ProvenKey {
    ProvenKey {
        tenant: crate::authn::ids::testing::tenant("t"),
        device: crate::authn::ids::testing::device("d"),
        thumbprint: KeyThumbprint::from_bytes([9; 32]),
    }
}

fn now() -> Timestamp {
    MockClock::reference_time()
}

fn grace() -> Duration {
    Duration::from_secs(30)
}

#[test]
fn a_minted_proof_reads_back_as_the_key_it_was_minted_for() {
    let value = mint_proof(
        &keys(),
        &proven(),
        axess_clock::Until::At(now().plus(SignedDuration::seconds(600))),
    );
    assert_eq!(read_proof(&keys(), &value, now(), grace()), Some(proven()));
    assert!(value.len() < MAX_PROOF_COOKIE_BYTES, "{}", value.len());
}

/// Accepted up to one second before its expiry plus the grace, refused at
/// that instant and after it.
#[test]
fn a_proof_ends_exactly_at_its_expiry_plus_the_grace() {
    let expires = now().plus(SignedDuration::seconds(600));
    let value = mint_proof(&keys(), &proven(), axess_clock::Until::At(expires));
    let end = expires.plus(SignedDuration::seconds(30));
    assert!(
        read_proof(
            &keys(),
            &value,
            end.minus(SignedDuration::seconds(1)),
            grace()
        )
        .is_some()
    );
    assert_eq!(read_proof(&keys(), &value, end, grace()), None);
    assert_eq!(
        read_proof(
            &keys(),
            &value,
            end.plus(SignedDuration::seconds(1)),
            grace()
        ),
        None
    );
    // With no grace the expiry itself is the end.
    let before = expires.minus(SignedDuration::seconds(1));
    assert!(read_proof(&keys(), &value, before, Duration::ZERO).is_some());
    assert_eq!(read_proof(&keys(), &value, expires, Duration::ZERO), None);
}

/// Every field is under the MAC: a value with any one of them changed is not
/// one this layer minted.
#[test]
fn changing_any_field_of_a_proof_makes_it_fail() {
    let value = mint_proof(
        &keys(),
        &proven(),
        axess_clock::Until::At(now().plus(SignedDuration::seconds(600))),
    );
    let parts: Vec<&str> = value.split('.').collect();
    assert_eq!(parts.len(), 6);
    let other_tenant = crate::authn::ids::testing::tenant("other").to_string();
    let other_device = crate::authn::ids::testing::device("other").to_string();
    let other_thumbprint = KeyThumbprint::from_bytes([8; 32]).to_text();
    let later = (now().plus(SignedDuration::seconds(6000)))
        .unix_seconds()
        .to_string();
    let replacements: [(usize, &str); 5] = [
        (0, "v2"),
        (1, &other_tenant),
        (2, &other_device),
        (3, &other_thumbprint),
        (4, &later),
    ];
    for (index, replacement) in replacements {
        let mut edited = parts.clone();
        edited[index] = replacement;
        assert_eq!(
            read_proof(&keys(), &edited.join("."), now(), grace()),
            None,
            "field {index}"
        );
    }
    let flipped = if parts[5].starts_with('A') { "B" } else { "A" };
    let tag = format!("{flipped}{}", &parts[5][1..]);
    let mut damaged = parts.clone();
    damaged[5] = &tag;
    assert_eq!(
        read_proof(&keys(), &damaged.join("."), now(), grace()),
        None
    );
}

#[test]
fn malformed_values_are_refused_without_a_panic() {
    let good = mint_proof(
        &keys(),
        &proven(),
        axess_clock::Until::At(now().plus(SignedDuration::seconds(600))),
    );
    let padded_expiry = {
        let parts: Vec<&str> = good.split('.').collect();
        format!(
            "{}.{}.{}.{}.0{}.{}",
            parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
        )
    };
    for value in [
        String::new(),
        "v1".to_string(),
        "v1.a.b.c.1.d".to_string(),
        format!("{good}.extra"),
        padded_expiry,
        "x".repeat(MAX_PROOF_COOKIE_BYTES + 1),
        "v1.t.d.AAAA.99999999999999999999.AAAA".to_string(),
    ] {
        assert_eq!(read_proof(&keys(), &value, now(), grace()), None, "{value}");
    }
}

/// A proof minted under the previous signing key still reads during the
/// rotation, one under an unknown key never does, and a new one is minted
/// under the current key.
#[test]
fn a_rotation_reads_the_previous_keys_proofs() {
    let old = keys();
    let rotated = KeyCookieKeys {
        current: [2; 32],
        previous: Some([1; 32]),
    };
    let unrelated = KeyCookieKeys {
        current: [3; 32],
        previous: None,
    };
    let under_old = mint_proof(
        &old,
        &proven(),
        axess_clock::Until::At(now().plus(SignedDuration::seconds(600))),
    );
    assert_eq!(
        read_proof(&rotated, &under_old, now(), grace()),
        Some(proven())
    );
    assert_eq!(read_proof(&unrelated, &under_old, now(), grace()), None);
    let under_new = mint_proof(
        &rotated,
        &proven(),
        axess_clock::Until::At(now().plus(SignedDuration::seconds(600))),
    );
    assert_eq!(read_proof(&old, &under_new, now(), grace()), None);
    assert_eq!(
        read_proof(&rotated, &under_new, now(), grace()),
        Some(proven())
    );
}

/// A rotation that names the same key as current and previous still reads
/// the proofs minted under it, and the keys are wiped when dropped.
#[test]
fn a_rotation_naming_one_key_twice_still_reads_its_proofs() {
    let twice = KeyCookieKeys {
        current: [1; 32],
        previous: Some([1; 32]),
    };
    let once = KeyCookieKeys {
        current: [1; 32],
        previous: None,
    };
    let value = mint_proof(
        &once,
        &proven(),
        axess_clock::Until::At(now().plus(SignedDuration::seconds(600))),
    );
    assert_eq!(read_proof(&twice, &value, now(), grace()), Some(proven()));
    fn wipes_on_drop<T: zeroize::ZeroizeOnDrop>(_: &T) {}
    wipes_on_drop(&twice);
}

fn headers(cookie: &str) -> axum::http::HeaderMap {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::COOKIE,
        axum::http::HeaderValue::from_str(cookie).unwrap(),
    );
    headers
}

/// The name's suffix is a digest of the tenant and the device, so two ids
/// that share their leading digits (as time-ordered ids do) keep separate
/// cookies, and so does one device id under two tenants.
#[test]
fn the_cookie_name_gives_each_device_a_slot_of_its_own() {
    let base = "__Host-axess_device_proof";
    let tenant = proven().tenant;
    let first = DeviceId::try_new("018f0000-0000-7000-8000-000000000001").unwrap();
    let second = DeviceId::try_new("018f0000-0000-7000-8000-000000000002").unwrap();
    let name = proof_cookie_name(base, &tenant, &first);
    let suffix = name.strip_prefix("__Host-axess_device_proof_").unwrap();
    assert_eq!(suffix.len(), 16);
    assert!(suffix.bytes().all(|b| b.is_ascii_hexdigit()));
    assert!(!first.to_string().replace('-', "").starts_with(suffix));
    assert_ne!(name, proof_cookie_name(base, &tenant, &second));
    let other_tenant = crate::authn::ids::testing::tenant("other");
    assert_ne!(name, proof_cookie_name(base, &other_tenant, &first));
    assert_eq!(name, proof_cookie_name(base, &tenant, &first));
}

/// Two devices registered in one profile each prove their own key; cookies
/// of other names are not read, and a forged one proves nothing.
#[test]
fn the_proofs_of_a_request_are_read_by_name_prefix() {
    let base = "__Host-axess_device_proof";
    let first = proven();
    let second = ProvenKey {
        device: crate::authn::ids::testing::device("second"),
        ..proven()
    };
    let expires = now().plus(SignedDuration::seconds(600));
    let cookie = format!(
        "sid=abc; {}={}; {base}x=ignored; {}={}; {base}_ffffffff=v1.forged",
        proof_cookie_name(base, &first.tenant, &first.device),
        mint_proof(&keys(), &first, axess_clock::Until::At(expires)),
        proof_cookie_name(base, &second.tenant, &second.device),
        mint_proof(&keys(), &second, axess_clock::Until::At(expires)),
    );
    assert_eq!(
        read_proofs(&keys(), &headers(&cookie), base, now(), grace()),
        vec![first, second]
    );
    assert!(read_proofs(&keys(), &headers("sid=abc"), base, now(), grace()).is_empty());
}

/// A request cannot make the layer verify an unbounded number of cookies.
#[test]
fn at_most_the_bound_of_proof_cookies_is_read() {
    let base = "proof";
    let expires = now().plus(SignedDuration::seconds(600));
    let genuine = mint_proof(&keys(), &proven(), axess_clock::Until::At(expires));
    let mut cookie = String::new();
    for index in 0..MAX_PROOF_COOKIES {
        cookie.push_str(&format!("{base}_{index:08}=junk; "));
    }
    cookie.push_str(&format!("{base}_last={genuine}"));
    assert!(
        read_proofs(&keys(), &headers(&cookie), base, now(), grace()).is_empty(),
        "the genuine cookie sits past the bound"
    );

    // The last cookie inside the bound is read.
    let mut cookie = String::new();
    for index in 1..MAX_PROOF_COOKIES {
        cookie.push_str(&format!("{base}_{index:08}=junk; "));
    }
    cookie.push_str(&format!("{base}_last={genuine}"));
    assert_eq!(
        read_proofs(&keys(), &headers(&cookie), base, now(), grace()),
        vec![proven()]
    );
}

#[test]
fn an_offer_holds_for_its_session_tenant_and_device_until_it_expires() {
    let rng = crate::testing::mock_random::MockRng::new(5);
    // The offer binds the session's key, as the layer hands it over.
    let session = SessionKey::of(&SessionId::new(&rng));
    let other_session = SessionKey::of(&SessionId::new(&rng));
    let (tenant, device) = (proven().tenant, proven().device);
    let expires = now().plus(SignedDuration::seconds(120));
    let offer = mint_offer(
        &keys(),
        &session,
        &tenant,
        &device,
        axess_clock::Until::At(expires),
    );

    let holds = |session: &SessionKey, tenant: &TenantId, device: &DeviceId, at| {
        offer_holds(&keys(), &offer, session, tenant, device, at)
    };
    assert!(holds(&session, &tenant, &device, now()));
    assert!(holds(
        &session,
        &tenant,
        &device,
        expires.minus(SignedDuration::seconds(1))
    ));
    assert!(!holds(&session, &tenant, &device, expires), "expired");
    assert!(!holds(&other_session, &tenant, &device, now()));
    let other_tenant = crate::authn::ids::testing::tenant("other");
    assert!(!holds(&session, &other_tenant, &device, now()));
    let other_device = crate::authn::ids::testing::device("other");
    assert!(!holds(&session, &tenant, &other_device, now()));
    let extended = format!("{offer}.x");
    for forged in ["", "v1", "v1.1.AAAA", "v2.1.AAAA", extended.as_str()] {
        assert!(!offer_holds(
            &keys(),
            forged,
            &session,
            &tenant,
            &device,
            now()
        ));
    }
    // An offer has another shape than a proof, so it reads as none.
    assert_eq!(read_proof(&keys(), &offer, now(), grace()), None);
}

/// The proof cookie and the offer are MAC'd under one key and told apart by
/// their domain labels alone: the same fields under the two labels give
/// different tags, and a tag made under one label does not hold under the
/// other.
#[test]
fn the_two_domains_do_not_verify_each_others_tags() {
    let fields: [&[u8]; 4] = [b"tenant", b"device", b"thumbprint", b"expires"];
    let as_proof = mac(&keys().current, PROOF_DOMAIN, &fields);
    let as_offer = mac(&keys().current, OFFER_DOMAIN, &fields);
    assert_ne!(as_proof, as_offer);
    assert!(mac_holds(&keys(), PROOF_DOMAIN, &fields, &as_proof));
    assert!(mac_holds(&keys(), OFFER_DOMAIN, &fields, &as_offer));
    assert!(!mac_holds(&keys(), OFFER_DOMAIN, &fields, &as_proof));
    assert!(!mac_holds(&keys(), PROOF_DOMAIN, &fields, &as_offer));
    // The field boundaries are under the MAC too: the same bytes split
    // elsewhere are another message.
    let shifted: [&[u8]; 4] = [b"tenantd", b"evice", b"thumbprint", b"expires"];
    assert_ne!(as_proof, mac(&keys().current, PROOF_DOMAIN, &shifted));
}
