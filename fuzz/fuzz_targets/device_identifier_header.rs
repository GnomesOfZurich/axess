// Fuzz the reader of the identifier header, `Sec-Secure-Session-Id`, which
// names a device to the refresh path and beside a request proof, and is
// the one value there that any caller chooses.
//
// The target holds the reader to a statement of the contract written
// without its code: the value is a structured-field string, quoted or bare,
// with parameters ignored, whose content is a tenant id, one dot and a
// device id. The reader is private to axess-core and is reached through the
// entry point the crate keeps for this target.

#![no_main]

use axess_core::authn::ids::{DeviceId, TenantId};
use axess_core::testing::device_key_parsers::named_device;
use libfuzzer_sys::fuzz_target;

/// The content of the header's string, read byte by byte: between the
/// quotes of a quoted string that is closed and holds no backslash, or the
/// bare value up to a semicolon, with the spaces around it dropped.
fn content(value: &str) -> Option<String> {
    let value = value.trim_matches(' ');
    let mut bytes = value.bytes();
    if value.starts_with('"') {
        bytes.next();
        let mut inside = Vec::new();
        for byte in bytes {
            match byte {
                b'"' => return String::from_utf8(inside).ok(),
                b'\\' => return None,
                other => inside.push(other),
            }
        }
        None
    } else {
        let bare: Vec<u8> = bytes.take_while(|byte| *byte != b';').collect();
        String::from_utf8(bare)
            .ok()
            .map(|bare| bare.trim_end_matches(' ').to_owned())
    }
}

fn expected(value: &str) -> Option<(TenantId, DeviceId)> {
    // A header value is read as text only when it is visible ASCII.
    if !value
        .bytes()
        .all(|byte| byte == b'\t' || (0x20..0x7f).contains(&byte))
    {
        return None;
    }
    let content = content(value)?;
    let (tenant, device) = content.split_once('.')?;
    Some((
        TenantId::try_new(tenant).ok()?,
        DeviceId::try_new(device).ok()?,
    ))
}

fuzz_target!(|data: &[u8]| {
    let Ok(value) = std::str::from_utf8(data) else {
        return;
    };
    // A value no header can carry names nothing either way.
    if axum::http::HeaderValue::from_str(value).is_err() {
        assert_eq!(named_device(value), None);
        return;
    }
    assert_eq!(named_device(value), expected(value), "{value:?}");
});
