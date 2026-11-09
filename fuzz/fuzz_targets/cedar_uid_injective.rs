// Invariant: distinct (tenant, id) pairs never render to the same
// resource UID for a tenant-qualified template; build_uids may refuse instead.
// Real public API: axess_macros::__macro_support::build_uids (doc-hidden but
// `pub`; needs axess-macros feature `authz`). While the gap is open it finds:
// ("t1","a/b") and ("t1/a","b") both give Doc::"t1/a/b".
#![no_main]

use axess_macros::__macro_support::build_uids;
use libfuzzer_sys::arbitrary::{Result, Unstructured};
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

const TEMPLATES: &[&str] = &[
    "Doc:{$tenant}/{id}",
    "Doc:{$tenant}:{id}",
    "Doc:{$tenant}{id}",
    "Doc:{$tenant}:{$user}",
    "Ledger:{$tenant}/{id}",
];

fn small(u: &mut Unstructured<'_>) -> Result<String> {
    // Alphabet heavy in separators and template metacharacters.
    const A: &[u8] = b"ab1/:{}$\\\"";
    let n = u.int_in_range(0..=6)?;
    (0..n).map(|_| Ok(*u.choose(A)? as char)).collect()
}

fn run(u: &mut Unstructured<'_>) -> Result<()> {
    let tpl = *u.choose(TEMPLATES)?;
    let (t1, i1, u1) = (small(u)?, small(u)?, small(u)?);
    let (t2, i2, u2) = (small(u)?, small(u)?, small(u)?);
    let p = |id: &str| HashMap::from([("id".to_string(), id.to_string())]);
    let uses_user = tpl.contains("{$user}");
    let a = build_uids("App", "Read", tpl, &p(&i1), &u1, &t1);
    let b = build_uids("App", "Read", tpl, &p(&i2), &u2, &t2);
    let same_inputs = t1 == t2 && (if uses_user { u1 == u2 } else { i1 == i2 });
    if let (Ok(a), Ok(b)) = (a, b) {
        if !same_inputs {
            assert_ne!(
                a.2, b.2,
                "{tpl}: (tenant={t1:?}, id={i1:?}, user={u1:?}) and (tenant={t2:?}, id={i2:?}, user={u2:?}) collide"
            );
        }
    }
    Ok(())
}

fuzz_target!(|data: &[u8]| {
    let _ = run(&mut Unstructured::new(data));
});
