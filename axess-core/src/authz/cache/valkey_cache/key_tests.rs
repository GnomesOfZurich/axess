//! The cache key: its parts cannot run into each other, the glob
//! characters a part may carry are escaped, and the TTL is never zero.

use super::*;
use crate::authz::cache::test_support::{CountingProvider, uid};

/// A sub-second TTL must still be a positive expiry.
#[test]
fn a_sub_second_ttl_is_a_positive_expiry() {
    for ttl in [Duration::from_millis(500), Duration::ZERO] {
        let ms = ttl_millis(ttl);
        assert!(ms >= 1, "{ttl:?} gave {ms}");
    }
    assert_eq!(ttl_millis(Duration::from_secs(60)), 60_000);
}

/// The glob characters a principal or tenant may carry are escaped, so a
/// principal `a[1]` matches its own key and a tenant `*` matches only
/// the tenant spelled `*`.
#[test]
fn glob_escape_neutralises_pattern_characters() {
    assert_eq!(
        glob_escape(r#"App::User::"a[1]""#),
        r#"App::User::"a\[1\]""#
    );
    assert_eq!(glob_escape("*"), r"\*");
    assert_eq!(glob_escape("plain-tenant"), "plain-tenant");
    assert_eq!(glob_escape(r"a\b?"), r"a\\b\?");
}

fn cache() -> ValkeyEntityCache<CountingProvider> {
    ValkeyEntityCache::new(CountingProvider::default(), Client::default())
}

#[test]
fn cache_key_distinguishes_inputs_and_carries_components() {
    let c = cache();
    let p = uid("App::User::\"alice\"");
    let r1 = uid("App::Doc::\"doc-1\"");
    let r2 = uid("App::Doc::\"doc-2\"");
    let a = uid("App::Action::\"View\"");

    let k1 = c.cache_key(&p, Some("t1"), &r1, &a, None);
    let k2 = c.cache_key(&p, Some("t1"), &r2, &a, None);
    let k3 = c.cache_key(&p, Some("t2"), &r1, &a, None);
    let k_none = c.cache_key(&p, None, &r1, &a, None);

    assert!(
        k1.contains("alice") && k1.contains("doc-1") && k1.contains("View"),
        "key must carry principal/resource/action: {k1}"
    );
    assert!(
        k1.starts_with(&format!("{DEFAULT_PREFIX}:authz-entities:")),
        "key must carry prefix namespace: {k1}"
    );
    assert_ne!(k1, k2, "different resources must yield different keys");
    assert_ne!(k1, k3, "different tenants must yield different keys");
    assert_ne!(
        k1, k_none,
        "Some(tenant) and None must yield different keys"
    );
    assert!(
        !k1.is_empty() && k1 != "xyzzy",
        "kills `String::new()` and `xyzzy` mutations"
    );
}

/// The parts of a key cannot run into each other: no tenant and an
/// empty tenant are different keys, a tenant that carries the separator
/// does not produce the segments of another tenant, and the pattern an
/// invalidation runs matches the key the same inputs produced.
#[test]
fn cache_key_parts_cannot_collide() {
    let c = cache();
    let p = uid("App::User::\"alice\"");
    let r = uid("App::Doc::\"doc-1\"");
    let a = uid("App::Action::\"View\"");

    assert_ne!(
        c.cache_key(&p, None, &r, &a, None),
        c.cache_key(&p, Some(""), &r, &a, None),
        "no tenant and an empty tenant share a key"
    );
    let piped = c.cache_key(&p, Some("x|y"), &r, &a, None);
    assert!(
        !piped.contains("|x|") && !piped.contains("|t:x|"),
        "a tenant carrying the separator produced the tenant `x`: {piped}"
    );
    assert_ne!(
        tenant_part(Some("a|b")),
        tenant_part(Some("a%7Cb")),
        "an escaped separator and a literal one stay apart"
    );
    assert_eq!(key_part("a%|b"), "a%25%7Cb");
    assert_eq!(tenant_part(None), "");
    assert_eq!(tenant_part(Some("")), "t:");
}

/// A session-state discriminator separates entries of one user and
/// tenant, and reaches the key only as a hash.
#[test]
fn cache_key_separates_sessions_by_discriminator_without_leaking_it() {
    let c = cache();
    let p = uid("App::User::\"alice\"");
    let r = uid("App::Doc::\"doc-1\"");
    let a = uid("App::Action::\"View\"");

    let plain = c.cache_key(&p, Some("t1"), &r, &a, None);
    let mfa = c.cache_key(&p, Some("t1"), &r, &a, Some("mfa=1"));
    let no_mfa = c.cache_key(&p, Some("t1"), &r, &a, Some("mfa=0"));
    assert_ne!(mfa, no_mfa);
    assert_ne!(plain, mfa);
    assert!(!mfa.contains("mfa=1"), "the discriminator is hashed: {mfa}");
    assert_eq!(mfa, c.cache_key(&p, Some("t1"), &r, &a, Some("mfa=1")));
    assert_eq!(hash_discriminator("mfa=1").len(), 64);
}

/// A resource or action of entity type `t` writes a segment that begins
/// `t:`, as the tenant segment does: invalidating the tenant its text would
/// spell leaves its entry alone, and invalidating the entry's own tenant
/// still drops it.
#[test]
fn a_resource_or_action_named_like_a_tenant_segment_is_not_that_tenant() {
    let c = cache();
    let p = uid(r#"App::User::"alice""#);
    let r = uid(r#"t::"acme""#);
    let a = uid(r#"t::"View""#);
    let key = c.cache_key(&p, Some("home"), &r, &a, None);

    for spelled in [r#":"acme""#, r#":"View""#, r#":"alice""#] {
        assert!(
            !glob_matches(&c.tenant_pattern(spelled), &key),
            "invalidating the tenant {spelled:?} reaches {key}"
        );
    }
    assert!(glob_matches(&c.tenant_pattern("home"), &key));
    assert!(glob_matches(
        &c.tenant_pattern("a:b"),
        &c.cache_key(&p, Some("a:b"), &r, &a, None)
    ));
    assert_ne!(tenant_part(Some("a:b")), tenant_part(Some("a%3Ab")));
}

/// SCAN MATCH as the server reads it, for the patterns this cache writes:
/// `*` any run, `?` any one character, `\` the next character literally.
fn glob_matches(pattern: &str, text: &str) -> bool {
    fn go(p: &[char], t: &[char]) -> bool {
        match p.split_first() {
            None => t.is_empty(),
            Some(('*', rest)) => (0..=t.len()).any(|i| go(rest, &t[i..])),
            Some(('?', rest)) => !t.is_empty() && go(rest, &t[1..]),
            Some(('\\', rest)) => match rest.split_first() {
                Some((c, rest)) => t.first() == Some(c) && go(rest, &t[1..]),
                None => false,
            },
            Some((c, rest)) => t.first() == Some(c) && go(rest, &t[1..]),
        }
    }
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    go(&p, &t)
}

/// A hash tag is the prefix's first `{` and the first `}` after it, with
/// something between them, as the cluster reads a key.
#[test]
fn a_hash_tag_is_read_from_the_prefix_as_the_cluster_reads_it() {
    for tagged in ["{axess}", "{axess}:authz", "app:{t1}", "{a}{b}"] {
        assert!(has_hash_tag(tagged), "{tagged}");
    }
    for untagged in ["axess", "{}axess", "axess{", "axess}", "}{axess"] {
        assert!(!has_hash_tag(untagged), "{untagged}");
    }
}
