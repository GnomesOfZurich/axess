use super::*;

#[tokio::test]
async fn mock_accepts_correct_password() {
    let provider = MockLdapProvider::new("uid={user},ou=people,dc=example,dc=com").with_user(
        "alice",
        "Gnomes2+",
        vec!["engineers", "admins"],
    );

    let dn = provider.build_bind_dn("alice");
    assert_eq!(dn, "uid=alice,ou=people,dc=example,dc=com");

    let result = provider
        .verify_bind("alice", &dn, "Gnomes2+")
        .await
        .unwrap();
    assert_eq!(result.bind_dn, dn);
    assert_eq!(result.groups, vec!["engineers", "admins"]);
}

#[tokio::test]
async fn mock_rejects_wrong_password() {
    let provider =
        MockLdapProvider::new("{user}@corp.example.com").with_user("bob", "correct", vec![]);

    let dn = provider.build_bind_dn("bob");
    let err = provider.verify_bind("bob", &dn, "wrong").await.unwrap_err();
    assert!(matches!(err, LdapError::InvalidCredentials));
}

/// An empty password is an unauthenticated bind (RFC 4513 §5.1.2), which a
/// permissive directory answers with rc=0 for any known DN; the provider
/// refuses it before connecting, and so does the mock.
#[tokio::test]
async fn empty_password_is_refused_as_an_unauthenticated_bind() {
    let provider = MockLdapProvider::new("{user}@corp.example.com").with_user("alice", "", vec![]);
    let dn = provider.build_bind_dn("alice");
    let err = provider.verify_bind("alice", &dn, "").await.unwrap_err();
    assert!(matches!(err, LdapError::InvalidCredentials));
}

/// A directory that accepts the socket and then never answers the bind
/// ends in `Timeout` after the configured bound; it used to hold the
/// login open for as long as the peer cared to stay silent.
#[tokio::test]
async fn a_directory_that_goes_quiet_after_connecting_times_out() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ldap://{}", listener.local_addr().unwrap());
    // Accept and hold the socket open without ever replying.
    let _quiet = tokio::spawn(async move {
        let held = listener.accept().await;
        tokio::time::sleep(Duration::from_secs(30)).await;
        drop(held);
    });
    let provider = LdapProviderConfig::new(url, "uid={user},dc=example")
        .with_timeout(Duration::from_millis(300));

    let outcome = tokio::time::timeout(
        Duration::from_secs(10),
        provider.verify_bind("alice", "uid=alice,dc=example", "secret"),
    )
    .await
    .expect("verify_bind must give up by itself, not hang");
    assert!(matches!(outcome, Err(LdapError::Timeout)), "{outcome:?}");
}

#[tokio::test]
async fn mock_rejects_unknown_user() {
    let provider = MockLdapProvider::new("{user}@corp.example.com");

    let dn = provider.build_bind_dn("nobody");
    let err = provider
        .verify_bind("nobody", &dn, "anything")
        .await
        .unwrap_err();
    assert!(matches!(err, LdapError::InvalidCredentials));
}

#[test]
fn loopback_test_is_an_exact_host_match() {
    for ok in [
        "ldap://localhost",
        "ldap://localhost:389",
        "ldap://127.0.0.1:389/",
        "ldap://[::1]:389",
    ] {
        assert!(is_loopback_url(ok), "{ok}");
    }
    for bad in [
        "ldap://localhost.evil.example",
        "ldap://127.0.0.1.evil.example",
        "ldap://evil.example/localhost",
        "ldap://localhost@evil.example",
        "ldap://ad.example.com://localhost",
        "ldap://evil.example?x=://127.0.0.1",
    ] {
        assert!(!is_loopback_url(bad), "{bad}");
    }
}

#[tokio::test]
async fn cleartext_bind_to_a_remote_host_is_refused_before_connecting() {
    let p = LdapProviderConfig::new("ldap://localhost.evil.example:389", "uid={user}");
    let err = p.verify_bind("a", "uid=a", "pw").await.unwrap_err();
    assert!(matches!(err, LdapError::Config(_)), "{err:?}");
    assert!(p.refuses_cleartext());
    let opted = LdapProviderConfig::new("ldap://ad.example.com", "uid={user}").allow_cleartext();
    assert!(!opted.refuses_cleartext());
    let tls = LdapProviderConfig::new("ldap://ad.example.com", "uid={user}").with_starttls();
    assert!(!tls.refuses_cleartext());
    let ldaps = LdapProviderConfig::new("LDAPS://ad.example.com", "uid={user}");
    assert!(!ldaps.refuses_cleartext());
}

#[test]
fn ad_upn_template() {
    let provider = MockLdapProvider::new("{user}@corp.example.com");
    assert_eq!(provider.build_bind_dn("alice"), "alice@corp.example.com");
}

#[test]
fn openldap_dn_template() {
    let provider = MockLdapProvider::new("uid={user},ou=people,dc=example,dc=com");
    assert_eq!(
        provider.build_bind_dn("bob"),
        "uid=bob,ou=people,dc=example,dc=com"
    );
}

#[test]
fn ldap_dn_escape_passes_through_plain_ascii() {
    assert_eq!(ldap_dn_escape("alice"), "alice");
    assert_eq!(ldap_dn_escape("user.name_99"), "user.name_99");
}

#[test]
fn ldap_dn_escape_handles_null_byte() {
    assert_eq!(ldap_dn_escape("a\0b"), "a\\00b");
}

#[test]
fn ldap_dn_escape_handles_dn_special_chars() {
    for (input, expected) in [
        ("a\"b", "a\\\"b"),
        ("a+b", "a\\+b"),
        ("a,b", "a\\,b"),
        ("a;b", "a\\;b"),
        ("a<b", "a\\<b"),
        ("a>b", "a\\>b"),
        ("a\\b", "a\\\\b"),
    ] {
        assert_eq!(ldap_dn_escape(input), expected, "input={input:?}");
    }
}

#[test]
fn ldap_dn_escape_hash_only_at_start_of_dn() {
    assert_eq!(ldap_dn_escape("#alice"), "\\#alice");
    assert_eq!(ldap_dn_escape("a#b"), "a#b");
    assert_eq!(ldap_dn_escape("alice#"), "alice#");
}

#[test]
fn ldap_dn_escape_space_at_dn_boundary() {
    // Leading/trailing spaces use the `\ ` form (line 437 match arm).
    assert_eq!(ldap_dn_escape(" alice"), "\\ alice");
    assert_eq!(ldap_dn_escape("alice "), "alice\\ ");
    assert_eq!(ldap_dn_escape(" "), "\\ ");
    // Interior spaces don't hit the boundary arm; 0x20 is below the
    // 0x21..=0x7E printable range, so they hex-escape via the fallback.
    assert_eq!(ldap_dn_escape("a b"), "a\\20b");
}

#[test]
fn ldap_dn_escape_non_ascii_hex_escapes() {
    assert_eq!(ldap_dn_escape("ü"), "\\c3\\bc");
}

#[test]
fn ldap_provider_config_build_bind_dn_substitutes_user() {
    let cfg = LdapProviderConfig::new(
        "ldap://localhost:389",
        "uid={user},ou=people,dc=example,dc=com",
    );
    assert_eq!(
        cfg.build_bind_dn("alice"),
        "uid=alice,ou=people,dc=example,dc=com"
    );
}

#[test]
fn ldap_provider_config_build_bind_dn_escapes_user() {
    let cfg = LdapProviderConfig::new("ldap://localhost:389", "uid={user},ou=people");
    assert_eq!(cfg.build_bind_dn("a,b"), "uid=a\\,b,ou=people");
}

#[test]
fn ldap_filter_escape_special_chars() {
    assert_eq!(ldap_filter_escape("alice"), "alice");
    assert_eq!(ldap_filter_escape("*)(|(*)"), "\\2a\\29\\28|\\28\\2a\\29");
    assert_eq!(ldap_filter_escape("user\\name"), "user\\5cname");
    assert_eq!(ldap_filter_escape("a\0b"), "a\\00b");
    // Control characters must be escaped.
    assert_eq!(ldap_filter_escape("a\tb"), "a\\09b");
    assert_eq!(ldap_filter_escape("a\nb"), "a\\0ab");
    assert_eq!(ldap_filter_escape("a\rb"), "a\\0db");
    // High-bit bytes (UTF-8 multi-byte) must be escaped.
    assert_eq!(ldap_filter_escape("ü"), "\\c3\\bc");
}
