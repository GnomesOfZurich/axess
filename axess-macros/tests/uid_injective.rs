//! A resource id built from a template with session and path values reads
//! back as one (tenant, id) pair, or the request is refused.

use std::collections::HashMap;

use axess_macros::__macro_support::build_uids;

fn id_param(id: &str) -> HashMap<String, String> {
    HashMap::from([("id".to_string(), id.to_string())])
}

fn render(template: &str, id: &str, user: &str, tenant: &str) -> Option<String> {
    build_uids("App", "Read", template, &id_param(id), user, tenant)
        .ok()
        .map(|(_, _, resource)| resource.id().unescaped().to_string())
}

/// Tenant `t1` with id `a/b` and tenant `t1/a` with id `b` must not both be
/// answered with the same resource id.
#[test]
fn a_separator_in_a_value_cannot_move_the_boundary_between_tenant_and_id() {
    let one = render("Doc:{$tenant}/{id}", "a/b", "u", "t1");
    let two = render("Doc:{$tenant}/{id}", "b", "u", "t1/a");
    assert!(
        one.is_none() || two.is_none() || one != two,
        "both give {one:?}"
    );
}

/// The same holds when only the id carries the separator, and for the colon
/// template that joins the tenant to the user.
#[test]
fn every_template_keeps_distinct_pairs_apart() {
    let cases = [
        ("Doc:{$tenant}/{id}", ("t1", "x/y"), ("t1/x", "y")),
        ("Doc:{$tenant}:{id}", ("t1", "x:y"), ("t1:x", "y")),
        ("Doc:{$tenant}{id}", ("ab", "c1"), ("a", "bc1")),
    ];
    for (template, (t1, i1), (t2, i2)) in cases {
        let a = render(template, i1, "u", t1);
        let b = render(template, i2, "u", t2);
        assert!(
            a.is_none() || b.is_none() || a != b,
            "{template}: ({t1:?}, {i1:?}) and ({t2:?}, {i2:?}) both give {a:?}"
        );
    }
    let a = build_uids(
        "App",
        "Read",
        "Doc:{$tenant}:{$user}",
        &HashMap::new(),
        "b:c",
        "a",
    );
    let b = build_uids(
        "App",
        "Read",
        "Doc:{$tenant}:{$user}",
        &HashMap::new(),
        "c",
        "a:b",
    );
    let same = matches!((&a, &b), (Ok(x), Ok(y)) if x.2 == y.2);
    assert!(!same, "tenant and user re-split");
}

/// A template that puts two placeholders directly together is refused for
/// every value, since no value could be told from another.
#[test]
fn adjacent_placeholders_are_refused() {
    assert!(render("Doc:{$tenant}{id}", "c1", "u", "ab").is_none());
    assert!(render("Doc:{$tenant}{$user}", "c1", "u", "ab").is_none());
}

/// Plain values still render, so the check refuses only what is ambiguous.
#[test]
fn values_without_a_separator_still_render() {
    assert_eq!(
        render("Doc:{$tenant}/{id}", "d1", "u", "t1").as_deref(),
        Some("t1/d1")
    );
    assert_eq!(
        render("Doc:{id}", "a/b:c", "u", "t1").as_deref(),
        Some("a/b:c")
    );
}
