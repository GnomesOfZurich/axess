// Invariant: any cookie name whose lowercase form starts with
// `__host-` / `__secure-` meets that prefix's rules, or the config is refused.
// (Browsers match the prefixes case-insensitively, RFC 6265bis.)
// Real public API: axess_core::session::config::SessionConfig::builder().
// The builder REFUSES BY PANICKING (`validate` uses assert!). libfuzzer-sys
// installs an aborting panic hook, so we swap in a silent hook and use
// catch_unwind to tell "refused" from "accepted"; our own invariant failures
// call process::abort so the fuzzer records them. While the gap is open it finds
// e.g. "__HOST-x" with secure=false.
#![no_main]

use axess_core::session::config::{SameSite, SessionConfig};
use libfuzzer_sys::fuzz_target;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Once;
use std::time::Duration;

static HOOK: Once = Once::new();

fn violated(msg: String) -> ! {
    eprintln!("INVARIANT VIOLATED: {msg}");
    std::process::abort();
}

fuzz_target!(|data: &[u8]| {
    HOOK.call_once(|| std::panic::set_hook(Box::new(|_| {})));
    if data.len() < 2 {
        return;
    }
    let flags = data[0];
    let secure = flags & 1 != 0;
    let same_site = match (flags >> 1) & 3 {
        0 => SameSite::Strict,
        1 => SameSite::Lax,
        _ => SameSite::None,
    };
    let rest = String::from_utf8_lossy(&data[1..]);
    let (name, path) = rest.split_once('\n').unwrap_or((&rest, "/"));
    // Mix in prefix spellings so the interesting space is reached quickly.
    let name = match (flags >> 3) & 3 {
        0 => format!("__HoSt-{name}"),
        1 => format!("__SECURE-{name}"),
        _ => name.to_string(),
    };

    let built = catch_unwind(AssertUnwindSafe(|| {
        SessionConfig::builder()
            .ttl(Duration::from_secs(3600))
            .cookie_name(name.clone())
            .secure(secure)
            .same_site(same_site)
            .path(path.to_string())
            .build()
    }));
    let Ok(cfg) = built else { return }; // refused: fine
    let lower = cfg.cookie_name().to_ascii_lowercase();
    if lower.starts_with("__host-") && !(cfg.secure() && cfg.path() == "/") {
        violated(format!(
            "accepted {:?} secure={} path={:?}",
            cfg.cookie_name(),
            cfg.secure(),
            cfg.path()
        ));
    }
    if lower.starts_with("__secure-") && !cfg.secure() {
        violated(format!("accepted {:?} without Secure", cfg.cookie_name()));
    }
    // SessionConfig has no Domain setting today; if one is added, assert
    // `__host-` names have none.
});
