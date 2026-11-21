use super::*;

#[tokio::test]
async fn mock_accepts_correct_password() {
    let provider = MockLdapProvider::new("uid={user},ou=people,dc=example,dc=com").with_user(
        "alice",
        "Sample2+",
        vec!["engineers", "admins"],
    );

    let dn = provider.build_bind_dn("alice");
    assert_eq!(dn, "uid=alice,ou=people,dc=example,dc=com");

    let result = provider
        .verify_bind("alice", &dn, "Sample2+")
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
/// ends in `Timeout` after the configured bound, and does not hold the
/// login open for as long as the peer cares to stay silent.
#[tokio::test]
async fn a_directory_that_goes_quiet_after_connecting_times_out() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ldap://{}", listener.local_addr().unwrap());
    // Accept and hold the socket open without ever replying.
    let quiet = tokio::spawn(async move {
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
    // The silent peer's task is left to run out: dropping its handle
    // detaches it, here at the end of the test as before.
    drop(quiet);
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
    // Leading/trailing spaces use the `\ ` form (its own match arm).
    assert_eq!(ldap_dn_escape(" alice"), "\\ alice");
    assert_eq!(ldap_dn_escape("alice "), "alice\\ ");
    assert_eq!(ldap_dn_escape(" "), "\\ ");
    assert_eq!(ldap_dn_escape("a b"), "a b");
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

// ── Result codes that are not a verdict on the credential ─────────────────

/// The LDAPMessage of a BindResponse: `SEQUENCE { messageID, [APPLICATION 1]
/// { resultCode ENUMERATED, matchedDN "", diagnosticMessage "" } }`.
fn bind_response(message_id: u8, rc: u8) -> Vec<u8> {
    bind_response_saying(message_id, rc, "")
}

/// One BER element: `tag`, the length of `content` in short or long form,
/// then `content`.
fn ber(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match content.len() {
        n @ 0..=0x7f => out.push(n as u8),
        n @ 0x80..=0xff => out.extend([0x81, n as u8]),
        n => out.extend([0x82, (n >> 8) as u8, n as u8]),
    }
    out.extend_from_slice(content);
    out
}

/// As [`bind_response`], with `diagnostic` as the diagnosticMessage.
fn bind_response_saying(message_id: u8, rc: u8, diagnostic: &str) -> Vec<u8> {
    let mut result = vec![0x0a, 0x01, rc];
    result.extend(ber(0x04, b""));
    result.extend(ber(0x04, diagnostic.as_bytes()));
    let mut message = vec![0x02, 0x01, message_id];
    message.extend(ber(0x61, &result));
    ber(0x30, &message)
}

/// The messageID of an LDAPMessage: the INTEGER after the outer SEQUENCE
/// header, whose length is in short or long form.
fn ber_message_id(message: &[u8]) -> Option<u8> {
    let length = *message.get(1)?;
    let mut at = 2;
    if length & 0x80 != 0 {
        at += usize::from(length & 0x7f);
    }
    (message.get(at) == Some(&0x02) && message.get(at + 1) == Some(&0x01))
        .then(|| message.get(at + 2).copied())
        .flatten()
}

/// A directory that answers the first bind with `rc` and then waits for
/// the client to go. Returns the URL to reach it on.
async fn directory_answering(rc: u8) -> String {
    directory_saying(rc, String::new()).await
}

/// As [`directory_answering`], with `diagnostic` as the answer's
/// diagnostic message.
async fn directory_saying(rc: u8, diagnostic: String) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ldap://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };
        let mut buf = [0u8; 512];
        let n = socket.read(&mut buf).await.unwrap_or(0);
        let id = ber_message_id(&buf[..n]).unwrap_or(1);
        let _ = socket
            .write_all(&bind_response_saying(id, rc, &diagnostic))
            .await;
        let _ = socket.read(&mut buf).await;
    });
    url
}

async fn bind_against(rc: u8) -> Result<LdapBindResult, LdapError> {
    bind_at(directory_answering(rc).await).await
}

async fn bind_at(url: String) -> Result<LdapBindResult, LdapError> {
    let provider =
        LdapProviderConfig::new(url, "uid={user},dc=example").with_timeout(Duration::from_secs(5));
    tokio::time::timeout(
        Duration::from_secs(10),
        provider.verify_bind("alice", "uid=alice,dc=example", "secret"),
    )
    .await
    .expect("the bind answers")
}

/// `busy`, `unavailable`, `unwillingToPerform`, `operationsError` and
/// `other` say the directory could not judge the password. Answered as
/// `InvalidCredentials`, which the orchestrator counts towards the lockout,
/// they would let a directory outage lock every user out.
#[tokio::test]
async fn a_directory_that_cannot_answer_is_not_a_credential_verdict() {
    for rc in [1u8, 51, 52, 53, 80] {
        let outcome = bind_against(rc).await;
        assert!(
            matches!(&outcome, Err(LdapError::Directory { rc: got, .. }) if *got == u32::from(rc)),
            "rc {rc}: {outcome:?}"
        );
    }
}

/// The empty diagnostic the encoder writes is the fixed form the other
/// tests have always sent.
#[test]
fn the_encoded_bind_response_with_no_diagnostic_is_the_fixed_form() {
    assert_eq!(
        bind_response(7, 51),
        [
            0x30, 0x0c, 0x02, 0x01, 7, 0x61, 0x07, 0x0a, 0x01, 51, 0x04, 0x00, 0x04, 0x00
        ]
    );
}

/// The diagnostic message is the directory's text: the error carries it
/// with control characters escaped and cut at 256 bytes, so a directory
/// can neither forge a log line nor fill one.
#[tokio::test]
async fn a_directory_diagnostic_is_carried_cut_and_escaped() {
    let diagnostic = format!(
        "busy\nWARN forged line\r\u{1b}[31m\u{2028}{}",
        "A".repeat(3000)
    );
    let outcome = bind_at(directory_saying(51, diagnostic).await).await;
    let Err(LdapError::Directory { rc: 51, text }) = &outcome else {
        panic!("expected the directory's refusal, got {outcome:?}");
    };
    assert!(text.len() <= 256, "{} bytes", text.len());
    assert!(text.ends_with("..."), "the cut is marked: {text}");
    assert!(
        !text
            .chars()
            .any(|c| c.is_control() || matches!(c, '\u{2028}' | '\u{2029}')),
        "{text:?}"
    );
    assert!(text.starts_with("busy\\nWARN forged line\\r"), "{text}");
}

/// `invalidCredentials`, `inappropriateAuthentication` and `noSuchObject`
/// are verdicts on the DN and password the user gave.
#[tokio::test]
async fn a_verdict_on_the_credential_is_still_invalid_credentials() {
    for rc in [49u8, 48, 32] {
        let outcome = bind_against(rc).await;
        assert!(
            matches!(outcome, Err(LdapError::InvalidCredentials)),
            "rc {rc}: {outcome:?}"
        );
    }
}

/// `ldapi://` is a Unix domain socket on this host: nothing crosses a
/// network, so it is as local as loopback.
#[test]
fn a_unix_socket_url_is_local_not_cleartext() {
    for url in [
        "ldapi://%2Fvar%2Frun%2Fslapd%2Fldapi",
        "LDAPI://%2Fvar%2Frun%2Fldapi",
        "ldapi:///",
    ] {
        let p = LdapProviderConfig::new(url, "uid={user}");
        assert!(!p.refuses_cleartext(), "{url}");
    }
    let remote = LdapProviderConfig::new("ldap://ldapi.example.com", "uid={user}");
    assert!(
        remote.refuses_cleartext(),
        "a host named ldapi is still remote"
    );
}

#[test]
fn ldap_dn_escape_keeps_interior_spaces_and_non_ascii() {
    assert_eq!(ldap_dn_escape("a b"), "a b");
    assert_eq!(ldap_dn_escape("ü"), "ü");
    assert_eq!(ldap_dn_escape("Zoë Müller"), "Zoë Müller");
}

#[test]
fn group_filter_does_not_rewrite_user_placeholder_inside_dn() {
    let filter = expand_group_filter("(member={dn})", "uid={user}x,ou=p", "alice");
    assert_eq!(filter, "(member=uid={user}x,ou=p)");
}
