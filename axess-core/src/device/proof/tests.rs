//! How the device cookie is named and sent: the strict form, and the form
//! for a development server on plain HTTP.

use super::*;
use crate::testing::mock_random::MockRng;

/// The `Set-Cookie` value `config` sends for a device.
fn sent(config: &DeviceCookieConfig) -> String {
    let id = axess_identity::testing::device("dev-cookie");
    let token = DeviceToken::mint(&MockRng::new(7));
    config
        .set_cookie(&id, &token, &[])
        .expect("a header value")
        .to_str()
        .expect("visible ASCII")
        .to_string()
}

#[test]
fn the_default_cookie_is_the_strict_host_form() {
    let config = DeviceCookieConfig::default();
    assert_eq!(config.name(), "__Host-axess_device");
    let sent = sent(&config);
    assert!(sent.starts_with("__Host-axess_device="), "{sent}");
    for attribute in ["HttpOnly", "Secure", "SameSite=Strict", "Path=/"] {
        assert!(sent.contains(attribute), "{attribute} in {sent}");
    }
}

/// A browser refuses a `__Host-` cookie, and drops a `Secure` one, from a
/// server on plain HTTP: the development form has neither, and is otherwise
/// the default.
#[test]
fn the_local_development_cookie_has_a_plain_name_and_no_secure_attribute() {
    let config = DeviceCookieConfig::insecure_for_local_development();
    assert_eq!(config.name(), "axess_device");
    let sent = sent(&config);
    assert!(sent.starts_with("axess_device="), "{sent}");
    assert!(!sent.contains("Secure"), "{sent}");
    for attribute in ["HttpOnly", "SameSite=Strict", "Path=/"] {
        assert!(sent.contains(attribute), "{attribute} in {sent}");
    }
    assert_eq!(config.max_age(), DeviceCookieConfig::default().max_age());
}

/// The token's bytes are held in a `Zeroizing` buffer, which wipes itself
/// when the token is dropped. The token has no `Drop` of its own to keep in
/// step with its field: taking the buffer out of it compiles only while it
/// has none.
#[test]
fn the_device_token_is_held_in_a_zeroizing_buffer() {
    let token = DeviceToken::mint(&MockRng::new(7));
    let expected = *token.raw_for_tests();
    let DeviceToken(held) = token;
    let held: &Zeroizing<[u8; 32]> = &held;
    assert_eq!(**held, expected);
}

/// A device cookie parses only with a token of exactly 32 bytes, and the
/// token it parses is the one the cookie was written with.
#[test]
fn a_device_cookie_parses_only_with_a_token_of_32_bytes() {
    let id = axess_identity::testing::device("dev-parse");
    let token = DeviceToken::mint(&MockRng::new(9));
    let parsed = PresentedDevice::parse(&cookie_value(&id, &token)).expect("a cookie it wrote");
    assert_eq!(parsed.id, id);
    assert_eq!(parsed.token, token);
    for length in [31, 33, 0] {
        let value = format!("{id}.{}", URL_SAFE_NO_PAD.encode(vec![7u8; length]));
        assert!(PresentedDevice::parse(&value).is_none(), "{length} bytes");
    }
}

fn entry(label: &str, seed: u64) -> PresentedDevice {
    PresentedDevice {
        id: axess_identity::testing::device(label),
        token: DeviceToken::mint(&MockRng::new(seed)),
    }
}

/// The `name=value` value of a `Set-Cookie` header.
fn value_of(header: &HeaderValue) -> String {
    let text = header.to_str().unwrap();
    let pair = text.split(';').next().unwrap();
    pair.split_once('=').unwrap().1.to_string()
}

/// A cookie holds the new device first and keeps the entries of the other
/// devices of the profile, newest first, one per device.
#[test]
fn a_cookie_keeps_the_other_devices_of_the_profile() {
    let config = DeviceCookieConfig::default();
    let (a, b) = (entry("a", 1), entry("b", 2));
    let c = entry("c", 3);
    let header = config
        .set_cookie(&c.id, &c.token, &[a.clone(), b.clone()])
        .unwrap();
    assert_eq!(
        PresentedDevice::parse_all(&value_of(&header)),
        vec![c, a, b]
    );

    // A new token for a device already in the cookie replaces its entry.
    let renewed = entry("a", 9);
    let header = config
        .set_cookie(&renewed.id, &renewed.token, &[entry("a", 1), entry("b", 2)])
        .unwrap();
    assert_eq!(
        PresentedDevice::parse_all(&value_of(&header)),
        vec![renewed, entry("b", 2)]
    );
}

/// A full cookie drops the oldest entry, and a request that presents more
/// entries than the bound is read up to it.
#[test]
fn a_cookie_holds_at_most_the_bound_of_entries() {
    let config = DeviceCookieConfig::default();
    let kept: Vec<PresentedDevice> = (0..MAX_DEVICE_COOKIE_ENTRIES as u64)
        .map(|n| entry(&format!("d{n}"), n))
        .collect();
    let newest = entry("newest", 99);
    let header = config.set_cookie(&newest.id, &newest.token, &kept).unwrap();
    let value = value_of(&header);
    assert!(value.len() <= MAX_DEVICE_COOKIE_BYTES, "{}", value.len());
    let read = PresentedDevice::parse_all(&value);
    assert_eq!(read.len(), MAX_DEVICE_COOKIE_ENTRIES);
    assert_eq!(read[0], newest);
    assert_eq!(&read[1..], &kept[..MAX_DEVICE_COOKIE_ENTRIES - 1]);

    let too_many: Vec<String> = (0..MAX_DEVICE_COOKIE_ENTRIES as u64 + 2)
        .map(|n| {
            let e = entry(&format!("x{n}"), n);
            cookie_value(&e.id, &e.token)
        })
        .collect();
    assert_eq!(
        PresentedDevice::parse_all(&too_many.join("~")).len(),
        MAX_DEVICE_COOKIE_ENTRIES
    );
}

/// An entry that does not parse is left out and the others read; a value of
/// one entry, as earlier releases wrote it, reads as that entry.
#[test]
fn entries_that_do_not_parse_are_left_out() {
    let (a, b) = (entry("a", 1), entry("b", 2));
    let value = format!(
        "{}~garbage~~{}~{}",
        cookie_value(&a.id, &a.token),
        cookie_value(&b.id, &b.token),
        cookie_value(&a.id, &entry("a", 7).token)
    );
    assert_eq!(PresentedDevice::parse_all(&value), vec![a.clone(), b]);
    assert_eq!(
        PresentedDevice::parse_all(&cookie_value(&a.id, &a.token)),
        vec![a]
    );
    assert!(PresentedDevice::parse_all("").is_empty());
}
