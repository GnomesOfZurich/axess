//! The pieces of the transport that need no socket; the calls themselves
//! are exercised against the fake agent in the client's tests.

use axum::http::{HeaderMap, HeaderValue};
use proptest::prelude::*;

use super::*;

fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        map.insert(*name, HeaderValue::from_str(value).expect("a header value"));
    }
    map
}

#[test]
fn percent_escapes_are_undone() {
    assert_eq!(percent_decoded(b"no identity issued"), "no identity issued");
    assert_eq!(percent_decoded(b"line%0Abreak"), "line\nbreak");
    assert_eq!(percent_decoded(b"100%25"), "100%");
    assert_eq!(percent_decoded(b"caf%C3%A9"), "caf\u{e9}");
}

#[test]
fn an_escape_that_is_not_two_hex_digits_is_kept() {
    assert_eq!(percent_decoded(b"50%"), "50%");
    assert_eq!(percent_decoded(b"50%2"), "50%2");
    assert_eq!(percent_decoded(b"%zz"), "%zz");
    assert_eq!(percent_decoded(b"%%41"), "%A");
}

#[test]
fn a_status_of_zero_is_success() {
    assert_eq!(grpc_status(&headers(&[("grpc-status", "0")])), Some(Ok(())));
    assert_eq!(grpc_status(&HeaderMap::new()), None);
}

#[test]
fn a_status_carries_its_code_and_its_message() {
    let outcome = grpc_status(&headers(&[
        ("grpc-status", "7"),
        ("grpc-message", "no identity issued"),
    ]));
    assert_eq!(
        outcome,
        Some(Err(SpireError::Status {
            code: GrpcCode::PermissionDenied,
            message: "no identity issued".to_owned(),
        }))
    );
    assert_eq!(
        grpc_status(&headers(&[("grpc-status", "99")])),
        Some(Err(SpireError::Status {
            code: GrpcCode::Unknown,
            message: String::new(),
        }))
    );
}

#[test]
fn a_status_message_is_escaped_and_cut() {
    let hostile = format!("%0A%1B[2Jforged%0D%0A{}", "A".repeat(4000));
    let Some(Err(SpireError::Status { message, .. })) = grpc_status(&headers(&[
        ("grpc-status", "13"),
        ("grpc-message", &hostile),
    ])) else {
        panic!("a status of 13 is an error");
    };
    assert!(
        !message.contains('\n') && !message.contains('\r') && !message.contains('\u{1b}'),
        "{message:?}"
    );
    assert!(
        message.starts_with("\\n\\u{1b}[2Jforged\\r\\n"),
        "{message:?}"
    );
    assert!(
        message.len() <= 256,
        "the message is {} bytes",
        message.len()
    );
    assert!(message.ends_with("..."), "{message:?}");
}

#[test]
fn a_status_that_is_not_a_number_is_refused() {
    assert!(matches!(
        grpc_status(&headers(&[("grpc-status", "ok")])),
        Some(Err(SpireError::Malformed(_)))
    ));
}

#[test]
fn only_a_grpc_content_type_is_grpc() {
    assert!(is_grpc(&headers(&[("content-type", "application/grpc")])));
    assert!(is_grpc(&headers(&[(
        "content-type",
        "application/grpc+proto"
    )])));
    assert!(!is_grpc(&headers(&[("content-type", "text/html")])));
    assert!(!is_grpc(&HeaderMap::new()));
}

#[test]
fn every_defined_status_has_its_code() {
    let names = [
        (1, "CANCELLED"),
        (2, "UNKNOWN"),
        (3, "INVALID_ARGUMENT"),
        (4, "DEADLINE_EXCEEDED"),
        (5, "NOT_FOUND"),
        (6, "ALREADY_EXISTS"),
        (7, "PERMISSION_DENIED"),
        (8, "RESOURCE_EXHAUSTED"),
        (9, "FAILED_PRECONDITION"),
        (10, "ABORTED"),
        (11, "OUT_OF_RANGE"),
        (12, "UNIMPLEMENTED"),
        (13, "INTERNAL"),
        (14, "UNAVAILABLE"),
        (15, "DATA_LOSS"),
        (16, "UNAUTHENTICATED"),
    ];
    for (status, name) in names {
        assert_eq!(GrpcCode::from_status(status).to_string(), name);
    }
    assert_eq!(GrpcCode::from_status(17), GrpcCode::Unknown);
}

proptest! {
    /// No bytes make the decoder panic, and what holds no percent sign
    /// comes back as it went in.
    #[test]
    fn percent_decoding_ends_on_any_input(value in proptest::collection::vec(any::<u8>(), 0..128)) {
        let decoded = percent_decoded(&value);
        if !value.contains(&b'%') {
            prop_assert_eq!(decoded, String::from_utf8_lossy(&value).into_owned());
        }
    }

    /// Text escaped byte by byte decodes to itself.
    #[test]
    fn fully_escaped_text_round_trips(text in "\\PC{0,48}") {
        let escaped: String = text.bytes().map(|byte| format!("%{byte:02X}")).collect();
        prop_assert_eq!(percent_decoded(escaped.as_bytes()), text);
    }
}
