//! `tests`: extracted from `lib.rs` per the
//! 200-LoC inline-test rule in AGENTS.md.

use super::*;
use std::collections::HashMap;

#[test]
fn new_round_trips() {
    let s = ShortString::new("hello");
    assert_eq!(s.as_str(), "hello");
    assert_eq!(s.len(), 5);
    assert!(!s.is_empty());
}

#[test]
fn from_static_round_trips() {
    const S: ShortString = ShortString::from_static("auth.login_attempt.v2");
    assert_eq!(S.as_str(), "auth.login_attempt.v2");
    assert_eq!(S.len(), 21);
}

/// `from_static` of edge-case lengths (0..=4) must not panic. The
/// `len > N` guards (lines 224..=227 in `repr.rs`) prevent indexing
/// `bytes[N]` for strings shorter than that. Mutating any guard to
/// `>=` would index one byte past the input for the threshold length.
/// We exercise each length so cargo-mutants observes a panic for
/// every flipped guard.
#[test]
fn from_static_handles_short_lengths_without_panic() {
    const E0: ShortString = ShortString::from_static("");
    const E1: ShortString = ShortString::from_static("a");
    const E2: ShortString = ShortString::from_static("ab");
    const E3: ShortString = ShortString::from_static("abc");
    const E4: ShortString = ShortString::from_static("abcd");
    assert_eq!(E0.as_str(), "");
    assert_eq!(E1.as_str(), "a");
    assert_eq!(E2.as_str(), "ab");
    assert_eq!(E3.as_str(), "abc");
    assert_eq!(E4.as_str(), "abcd");
}

#[test]
fn default_is_empty() {
    let s = ShortString::default();
    assert!(s.is_empty());
    assert_eq!(s.len(), 0);
    assert_eq!(s.as_str(), "");
}

#[test]
fn equality_across_repr() {
    let heap = ShortString::new("kind.v1");
    let static_ = ShortString::from_static("kind.v1");
    assert_eq!(heap, static_);
}

#[test]
fn hash_matches_equality() {
    use std::collections::hash_map::DefaultHasher;
    let heap = ShortString::new("kind.v1");
    let static_ = ShortString::from_static("kind.v1");
    let mut h1 = DefaultHasher::new();
    let mut h2 = DefaultHasher::new();
    heap.hash(&mut h1);
    static_.hash(&mut h2);
    assert_eq!(h1.finish(), h2.finish());
}

#[test]
fn ordering_is_lexicographic() {
    let mut v: Vec<ShortString> = ["banana", "apple", "cherry"]
        .into_iter()
        .map(ShortString::new)
        .collect();
    v.sort();
    assert_eq!(
        v.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        vec!["apple", "banana", "cherry"]
    );
}

#[test]
fn display_formats_as_string() {
    let s = ShortString::new("hello");
    assert_eq!(format!("{s}"), "hello");
}

#[test]
fn debug_formats_as_quoted_string() {
    let s = ShortString::new("hello");
    assert_eq!(format!("{s:?}"), "\"hello\"");
}

#[test]
fn from_str_round_trips() {
    let s: ShortString = "hello".parse().unwrap();
    assert_eq!(s.as_str(), "hello");
}

#[test]
fn from_string_takes_ownership() {
    let owned = String::from("kind.v2");
    let s = ShortString::from(owned);
    assert_eq!(s.as_str(), "kind.v2");
}

#[test]
fn from_box_takes_ownership() {
    let b: Box<str> = "kind.v3".into();
    let s = ShortString::from(b);
    assert_eq!(s.as_str(), "kind.v3");
}

#[test]
fn deref_to_str_works() {
    let s = ShortString::new("hello");
    assert!(s.starts_with("hel"));
    assert_eq!(&s[1..4], "ell");
}

#[test]
fn use_as_hashmap_key() {
    let mut map: HashMap<ShortString, u32> = HashMap::new();
    map.insert(ShortString::new("kind.v1"), 1);
    assert_eq!(map.get(&ShortString::from_static("kind.v1")), Some(&1));
}

#[test]
fn cross_str_equality() {
    let s = ShortString::new("hello");
    assert_eq!(s, "hello");
    assert_eq!(s, String::from("hello"));
}

#[cfg(feature = "serde")]
#[test]
fn serde_json_round_trips() {
    let s = ShortString::new("auth.login_attempt.v2");
    let json = serde_json::to_string(&s).unwrap();
    assert_eq!(json, "\"auth.login_attempt.v2\"");
    let back: ShortString = serde_json::from_str(&json).unwrap();
    assert_eq!(back, s);
}

#[cfg(feature = "serde")]
#[test]
fn serde_handles_empty_string() {
    let s = ShortString::default();
    let json = serde_json::to_string(&s).unwrap();
    assert_eq!(json, "\"\"");
    let back: ShortString = serde_json::from_str(&json).unwrap();
    assert_eq!(back, s);
    assert!(back.is_empty());
}

#[cfg(feature = "rkyv")]
#[test]
fn rkyv_round_trips() {
    use rkyv::{from_bytes, rancor::Error, to_bytes};
    let s = ShortString::new("auth.login_attempt.v2");
    let bytes = to_bytes::<Error>(&s).unwrap();
    let back: ShortString = from_bytes::<ShortString, Error>(&bytes).unwrap();
    assert_eq!(back, s);
}

/// Hash impl must delegate to `str`'s hash, not return a constant
/// (which would silently lose entries from a HashMap with mixed
/// `ShortString` keys). Pin by comparing against `str::hash` of
/// the same content.
#[test]
fn hash_delegates_to_str_hash() {
    use std::collections::hash_map::DefaultHasher;
    let payload = "kind.v1";
    let s = ShortString::new(payload);
    let mut h1 = DefaultHasher::new();
    let mut h2 = DefaultHasher::new();
    s.hash(&mut h1);
    payload.hash(&mut h2);
    assert_eq!(
        h1.finish(),
        h2.finish(),
        "ShortString::hash must match str::hash of identical content"
    );
}

/// `AsRef<str>` returns the actual content, not a constant. Mutations
/// `-> ""` and `-> "xyzzy"` change the borrowed payload.
#[test]
fn as_ref_str_returns_content() {
    let s = ShortString::new("kind.v1");
    let borrowed: &str = s.as_ref();
    assert_eq!(borrowed, "kind.v1");
}

/// `AsRef<[u8]>` returns the UTF-8 bytes of the content. The
/// mutations leak constant Vecs (empty / `[0]` / `[1]`), all of
/// which differ from real content bytes.
#[test]
fn as_ref_bytes_returns_utf8() {
    let s = ShortString::new("ab");
    let bytes: &[u8] = s.as_ref();
    assert_eq!(bytes, b"ab");
}

/// `PartialEq<str>` discriminates equal from unequal content.
/// Body-mutations `true` / `false` would conflate the two.
#[test]
fn partial_eq_str_distinguishes_equal_from_unequal() {
    let s = ShortString::new("hello");
    assert!(<ShortString as PartialEq<str>>::eq(&s, "hello"));
    assert!(!<ShortString as PartialEq<str>>::eq(&s, "world"));
}

/// `PartialEq<&str>` body-mutation `-> true` would equate every
/// `&str`. Pin with an unequal pair.
#[test]
fn partial_eq_amp_str_distinguishes_unequal() {
    let s = ShortString::new("hello");
    let other = "world";
    assert!(!<ShortString as PartialEq<&str>>::eq(&s, &other));
}

/// `PartialEq<String>` body-mutation `-> true` would equate every
/// owned String. Pin with an unequal pair.
#[test]
fn partial_eq_string_distinguishes_unequal() {
    let s = ShortString::new("hello");
    let other = String::from("world");
    assert!(!<ShortString as PartialEq<String>>::eq(&s, &other));
}

/// `From<&str>` must construct a ShortString carrying the input;
/// `-> Default::default()` would always yield an empty string.
#[test]
fn from_str_carries_input() {
    let s: ShortString = "kind.v9".into();
    assert_eq!(s.as_str(), "kind.v9");
}

#[test]
fn borrow_str_allows_map_lookup_without_allocating_a_key() {
    // A `HashMap<ShortString, _>` queried from a literal needs
    // `Borrow<str>`; without it every lookup would have to build a key.
    use std::collections::HashMap;
    let mut m: HashMap<ShortString, u32> = HashMap::new();
    m.insert(ShortString::new("EURIBOR_3M"), 3);
    assert_eq!(m.get("EURIBOR_3M"), Some(&3));
    assert_eq!(m.get("missing"), None);
}

#[test]
fn new_accepts_anything_that_looks_like_a_str() {
    // `impl AsRef<str>` so `String`, `&String` and `&str` all work at the
    // call site, matching what a `CompactString`-shaped API offers.
    let owned = String::from("inst-aapl");
    assert_eq!(ShortString::new(&owned).as_str(), "inst-aapl");
    assert_eq!(ShortString::new(owned.clone()).as_str(), "inst-aapl");
    assert_eq!(ShortString::new("inst-aapl").as_str(), "inst-aapl");
}

#[test]
fn inline_capacity_is_the_inlining_boundary() {
    let at_cap = "a".repeat(ShortString::INLINE_CAPACITY);
    let over_cap = "a".repeat(ShortString::INLINE_CAPACITY + 1);

    assert!(
        ShortString::new(&at_cap).is_inline(),
        "exactly at the cap must inline"
    );
    assert!(!ShortString::new(&at_cap).is_allocated());
    assert!(
        !ShortString::new(&over_cap).is_inline(),
        "one past the cap must not inline"
    );
    assert!(ShortString::new(&over_cap).is_allocated());
}

#[test]
fn from_static_is_never_inline_but_never_allocates() {
    // The two predicates disagree here, which is the whole reason both
    // exist: `Static` is allocation-free without carrying its bytes.
    const SHORT: ShortString = ShortString::from_static("ab");
    const LONG: ShortString =
        ShortString::from_static("spiffe://gnomes.local/feed-worker/ekekrantz");

    for s in [SHORT, LONG] {
        assert!(
            !s.is_inline(),
            "from_static points at 'static memory, it does not copy"
        );
        assert!(!s.is_allocated(), "from_static must never allocate");
    }
}

#[test]
fn clone_of_an_allocated_value_shares_rather_than_copies() {
    // The property this crate exists for. A clone of an over-cap value
    // must reach the same buffer, not a fresh copy of it: that is what
    // makes the clone a refcount bump. `CompactString` fails this by
    // design, and a change here that quietly reverted to copying would
    // remove the only reason not to depend on it.
    let original = ShortString::new("spiffe://gnomes.local/feed-worker/ekekrantz");
    assert!(
        original.is_allocated(),
        "precondition: the case must be over the cap"
    );

    let copy = original.clone();
    assert_eq!(original, copy);
    assert!(
        std::ptr::eq(original.as_str().as_ptr(), copy.as_str().as_ptr()),
        "clone must share the original buffer, not allocate a second one"
    );
}

#[test]
// `cmp_owned` is right in general and wrong here: building the `String`
// is the point, since it is the only way to reach
// `PartialEq<ShortString> for String` rather than the `&str` impl.
#[allow(clippy::cmp_owned)]
fn reverse_equality_holds_from_the_std_side() {
    let s = ShortString::new("case-42");

    assert!(*"case-42" == s);
    assert!("case-42" == s);
    assert!(String::from("case-42") == s);

    assert!(*"other" != s);
    assert!("other" != s);
    assert!(String::from("other") != s);
}

#[test]
fn into_string_carries_content_for_every_repr() {
    // One case per form, since each reaches `as_str` differently.
    let inline = ShortString::new("case-42");
    let stat = ShortString::from_static("spiffe://gnomes.local/feed-worker/ekekrantz");
    let shared = ShortString::new("spiffe://gnomes.local/feed-worker/ekekrantz");

    assert!(inline.is_inline());
    assert!(!stat.is_allocated() && !stat.is_inline());
    assert!(shared.is_allocated());

    assert_eq!(String::from(inline), "case-42");
    assert_eq!(
        String::from(stat),
        "spiffe://gnomes.local/feed-worker/ekekrantz"
    );
    assert_eq!(
        String::from(shared),
        "spiffe://gnomes.local/feed-worker/ekekrantz"
    );
}
