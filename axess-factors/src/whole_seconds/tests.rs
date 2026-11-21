//! A span stored as whole seconds reads and writes the integer it was, and a
//! span the integer cannot hold is refused, never rounded.

use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;

#[cfg(any(feature = "totp", feature = "email_otp"))]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct U32Row {
    #[serde(rename = "span_secs", with = "super::u32_seconds")]
    span: Duration,
}

#[cfg(any(feature = "totp", feature = "email_otp"))]
#[test]
fn a_u32_row_keeps_its_bytes() {
    let row: U32Row = serde_json::from_value(json!({ "span_secs": 30 })).unwrap();
    assert_eq!(row.span, Duration::from_secs(30));
    assert_eq!(serde_json::to_string(&row).unwrap(), r#"{"span_secs":30}"#);
    let widest = U32Row {
        span: Duration::from_secs(u64::from(u32::MAX)),
    };
    assert_eq!(
        serde_json::to_string(&widest).unwrap(),
        format!(r#"{{"span_secs":{}}}"#, u32::MAX)
    );
}

#[cfg(any(feature = "totp", feature = "email_otp"))]
#[test]
fn a_u32_row_refuses_what_it_cannot_hold() {
    for span in [
        Duration::from_millis(30_500),
        Duration::from_nanos(1),
        Duration::from_secs(u64::from(u32::MAX) + 1),
    ] {
        let err = serde_json::to_string(&U32Row { span }).unwrap_err();
        assert!(err.to_string().contains("whole count of seconds"), "{err}");
    }
    assert!(serde_json::from_value::<U32Row>(json!({ "span_secs": -1 })).is_err());
    assert!(serde_json::from_value::<U32Row>(json!({ "span_secs": 1.5 })).is_err());
}

#[cfg(any(feature = "oauth", feature = "outbound-oauth"))]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct OptionRow {
    #[serde(
        rename = "span_secs",
        default,
        skip_serializing_if = "Option::is_none",
        with = "super::option_u64_seconds"
    )]
    span: Option<Duration>,
}

#[cfg(any(feature = "oauth", feature = "outbound-oauth"))]
#[test]
fn an_optional_row_keeps_its_bytes() {
    let row: OptionRow = serde_json::from_value(json!({ "span_secs": 20 })).unwrap();
    assert_eq!(row.span, Some(Duration::from_secs(20)));
    assert_eq!(serde_json::to_string(&row).unwrap(), r#"{"span_secs":20}"#);
    let absent: OptionRow = serde_json::from_value(json!({})).unwrap();
    assert_eq!(absent.span, None);
    assert_eq!(serde_json::to_string(&absent).unwrap(), "{}");
    let null: OptionRow = serde_json::from_value(json!({ "span_secs": null })).unwrap();
    assert_eq!(null.span, None);
}

#[cfg(any(feature = "oauth", feature = "outbound-oauth"))]
#[test]
fn an_optional_row_refuses_a_fraction() {
    let err = serde_json::to_string(&OptionRow {
        span: Some(Duration::from_millis(20_500)),
    })
    .unwrap_err();
    assert!(err.to_string().contains("whole count of seconds"), "{err}");
}
