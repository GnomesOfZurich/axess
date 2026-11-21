//! The sanitiser upstream error text passes through, and the bounded error snippet.

use super::*;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[test]
fn log_safe_escapes_control_characters_and_the_line_separators() {
    let text = "a\r\nINFO forged\x1b[2J\u{2028}b\u{2029}c";
    let safe = log_safe(text, 512);
    assert!(!safe.chars().any(char::is_control), "{safe:?}");
    assert!(
        !safe.contains('\u{2028}') && !safe.contains('\u{2029}'),
        "{safe:?}"
    );
    assert!(
        safe.contains("\\r\\n") && safe.contains("\\u{1b}"),
        "{safe:?}"
    );
    assert!(safe.ends_with('c'));
}

#[test]
fn log_safe_cuts_on_a_character_boundary() {
    let text = "é".repeat(400);
    let safe = log_safe(&text, 101);
    assert!(safe.len() <= 101, "{}", safe.len());
    assert!(safe.ends_with("..."));
}

#[tokio::test]
async fn a_long_error_snippet_is_cut_and_marked() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(500).set_body_raw("A".repeat(10_000), "text/plain"))
        .mount(&server)
        .await;
    let mut response = reqwest::Client::new()
        .get(format!("{}/token", server.uri()))
        .send()
        .await
        .unwrap();

    let snippet = read_error_snippet(&mut response).await;

    assert!(snippet.ends_with(TRUNCATED_SUFFIX), "{snippet:?}");
    assert!(snippet.len() <= ERROR_BODY_BYTES + TRUNCATED_SUFFIX.len());
}

/// A snippet the reader cut keeps its truncation suffix through the
/// sanitiser: the reader bounded it, so it is escaped and not cut again.
#[test]
fn a_cut_snippet_keeps_its_truncation_suffix_when_made_log_safe() {
    let snippet = format!("{}{TRUNCATED_SUFFIX}", "x".repeat(ERROR_BODY_BYTES));

    let safe = log_safe_snippet(&snippet);

    assert_eq!(safe, snippet);
    assert!(safe.ends_with(TRUNCATED_SUFFIX), "{safe:?}");
}

/// Every control character of a snippet at the reader's cap is written as
/// an escape in full, within the bound the sanitiser promises.
#[test]
fn a_snippet_of_control_characters_is_escaped_in_full() {
    let snippet = format!("{}{TRUNCATED_SUFFIX}", "\x1b".repeat(ERROR_BODY_BYTES));

    let safe = log_safe_snippet(&snippet);

    assert!(!safe.chars().any(char::is_control), "{safe:?}");
    assert_eq!(safe.matches("\\u{1b}").count(), ERROR_BODY_BYTES);
    assert!(safe.ends_with(TRUNCATED_SUFFIX), "{safe:?}");
    assert_eq!(safe.len(), ERROR_SNIPPET_LOG_BYTES);
    assert!(!safe.ends_with("..."));
}

/// The public sanitiser of a parse error answers what the crate's own
/// callers get: the head of serde's message, its cut marked, and the
/// position serde reported after it.
#[test]
fn a_parse_error_made_log_safe_keeps_its_head_and_its_position() {
    // A body of this shape holds numbers only.
    type Expects = std::collections::BTreeMap<String, u64>;
    let body = format!(r#"{{"expires_in": "{}"}}"#, "A".repeat(60 * 1024));
    let error = serde_json::from_str::<Expects>(&body).expect_err("a string is not a u64");

    let safe = log_safe_parse_error(&error);

    assert!(safe.starts_with("invalid type: string"), "{safe}");
    assert!(safe.contains("..."), "the cut is marked: {safe}");
    assert!(
        safe.ends_with(&format!(" at line 1 column {}", error.column())),
        "{safe}"
    );
    assert!(safe.len() < ERROR_BODY_BYTES, "{}", safe.len());
}

/// A refusal a loopback server answers with `sent`, read for what it says.
async fn refusal_body(sent: &str) -> ErrorBody {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(400).set_body_raw(sent.to_owned(), "application/json"))
        .mount(&server)
        .await;
    let mut response = reqwest::Client::new()
        .post(format!("{}/token", server.uri()))
        .send()
        .await
        .unwrap();
    ErrorBody::read(&mut response).await
}

/// A refusal's body read for what it says is the body the server sent: its
/// bytes for a parser of the whole document, its string members by name,
/// and its start as the snippet.
#[tokio::test]
async fn a_refusal_body_is_its_bytes_its_members_and_its_snippet() {
    let sent = r#"{"error":"invalid_grant","error_description":"expired"}"#;

    let body = refusal_body(sent).await;

    assert_eq!(body.as_bytes(), sent.as_bytes());
    assert_eq!(
        body.string_member("error").as_deref(),
        Some("invalid_grant")
    );
    assert_eq!(
        body.string_member("error_description").as_deref(),
        Some("expired")
    );
    assert_eq!(body.string_member("error_uri"), None);
    assert_eq!(body.snippet(), sent);
}

/// The debug form of a refusal's body names its length and none of its
/// text, which is the remote party's.
#[tokio::test]
async fn the_debug_form_of_a_refusal_body_is_its_length_only() {
    let sent = r#"{"error":"invalid_grant"}"#;

    let body = refusal_body(sent).await;

    assert_eq!(
        format!("{body:?}"),
        format!("ErrorBody {{ len: {} }}", sent.len())
    );
}

/// A body of exactly the snippet's bound is whole: nothing followed it, so
/// nothing marks a cut.
#[test]
fn a_body_of_exactly_the_snippet_bound_is_unmarked() {
    let body = "E".repeat(ERROR_BODY_BYTES);

    assert_eq!(error_snippet_of(body.as_bytes()), body);
}

/// The address of a refusal a raw socket serves as `chunks` chunks of
/// `chunk_len` bytes each with no declared length, so the body reaches the
/// reader in pieces no longer than a chunk.
fn refusal_in_chunks(chunk_len: usize, chunks: usize) -> String {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let Ok((mut socket, _)) = listener.accept() else {
            return;
        };
        let mut request = [0u8; 2048];
        let _ = socket.read(&mut request);
        let head = "HTTP/1.1 500 Internal Server Error\r\ncontent-type: text/plain\r\n\
                    transfer-encoding: chunked\r\nconnection: close\r\n\r\n";
        let _ = socket.write_all(head.as_bytes());
        for _ in 0..chunks {
            let chunk = format!("{chunk_len:x}\r\n{}\r\n", "B".repeat(chunk_len));
            if socket.write_all(chunk.as_bytes()).is_err() {
                return;
            }
        }
        let _ = socket.write_all(b"0\r\n\r\n");
    });
    format!("http://{addr}/token")
}

/// The bound counts what the earlier pieces of a body already filled: a
/// body that passes it in a later piece is cut at the bound and marked, not
/// read on for as long as each piece is short.
#[tokio::test]
async fn a_body_that_passes_the_bound_in_a_later_piece_is_cut_at_the_bound() {
    let uri = refusal_in_chunks(600, 2);
    let mut response = reqwest::Client::new().get(uri).send().await.unwrap();

    let snippet = read_error_snippet(&mut response).await;

    assert_eq!(
        snippet,
        format!("{}{TRUNCATED_SUFFIX}", "B".repeat(ERROR_BODY_BYTES))
    );
}

/// The `error` code of a refusal is escaped and cut as any upstream text,
/// and a body without one names the status.
#[cfg(feature = "oauth")]
#[test]
fn the_error_code_of_a_refusal_is_escaped_and_a_body_without_one_names_the_status() {
    let body = br#"{"error": "invalid_scope\r\nINFO forged\u2028"}"#;
    let code = log_safe_error_code(body, reqwest::StatusCode::BAD_REQUEST);
    assert!(
        !code.chars().any(char::is_control) && !code.contains('\u{2028}'),
        "{code:?}"
    );
    assert!(
        code.starts_with("invalid_scope") && code.contains("forged"),
        "{code}"
    );

    let long = format!(r#"{{"error": "{}"}}"#, "a".repeat(300));
    let code = log_safe_error_code(long.as_bytes(), reqwest::StatusCode::BAD_REQUEST);
    assert!(
        code.len() <= ERROR_CODE_LOG_BYTES && code.ends_with("..."),
        "{} bytes",
        code.len()
    );

    assert_eq!(
        log_safe_error_code(b"not json", reqwest::StatusCode::FORBIDDEN),
        "HTTP 403 Forbidden"
    );
}

#[cfg(feature = "oauth")]
#[test]
fn a_member_is_read_from_a_body_cut_after_it() {
    let long = "D".repeat(4096);
    let whole = format!(r#"{{"error":"invalid_grant","error_description":"{long}"}}"#);
    assert_eq!(
        string_member(&whole.as_bytes()[..1024], "error").as_deref(),
        Some("invalid_grant"),
        "the cut falls inside the description, after the code"
    );
    let last = format!(r#"{{"error_description":"{long}","error":"slow_down"}}"#);
    assert_eq!(
        string_member(last.as_bytes(), "error").as_deref(),
        Some("slow_down")
    );
    assert_eq!(string_member(&last.as_bytes()[..1024], "error"), None);
    assert_eq!(string_member(br#"{"error":42}"#, "error"), None);
    assert_eq!(string_member(br#"["error"]"#, "error"), None);
    assert_eq!(string_member(b"not json", "error"), None);
    assert_eq!(
        string_member(br#"{"nested":{"error":"x"},"error":"y"}"#, "error").as_deref(),
        Some("y"),
        "only a member of the outer object counts"
    );
}

#[cfg(feature = "oauth")]
#[test]
fn the_snippet_of_a_body_read_for_its_code_is_cut_at_a_kib() {
    let body = "E".repeat(4096);
    let snippet = error_snippet_of(body.as_bytes());
    assert_eq!(snippet.len(), ERROR_BODY_BYTES + TRUNCATED_SUFFIX.len());
    assert!(snippet.ends_with(TRUNCATED_SUFFIX));
    assert_eq!(error_snippet_of(b"short"), "short");
}

/// The snippet a status read hands back in wiping memory is the snippet's
/// bytes exactly: invalid sequences replaced as lossy UTF-8 replaces them,
/// and the mark of a cut.
#[test]
fn the_wiped_snippet_is_the_snippet_byte_for_byte() {
    for (body, truncated) in [
        (&b"plain"[..], false),
        (&b"a\xffb\xe2\x82c"[..], true),
        (&b"\xf0\x9f\x98"[..], false),
        (&b""[..], true),
        ("\u{e9}t\u{e9}".as_bytes(), false),
    ] {
        let wiped = wiped_snippet(body, truncated);
        assert_eq!(wiped.as_slice(), snippet(body, truncated).as_bytes());
        assert_eq!(wiped.capacity(), wiped.len(), "sized once: {body:?}");
    }
}

/// A body read up to its cap keeps the first bytes, says when a chunk was
/// cut, and never holds more than the cap, whatever length was declared.
#[test]
fn a_body_read_up_to_its_cap_keeps_the_first_bytes_and_says_it_cut() {
    let mut body = BoundedBody::up_to(Some(1 << 40), 10);
    assert!(!body.push_up_to(b"abcd"));
    assert!(body.push_up_to(b"efghijkl"));
    assert!(body.push_up_to(b"m"));
    assert!(!body.push_up_to(b""));
    let bytes = body.into_bytes();
    assert_eq!(bytes.as_slice(), b"abcdefghij");
    assert_eq!(bytes.capacity(), 10);
}
