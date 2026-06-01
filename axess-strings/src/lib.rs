//! Short, hot-path string primitive for the axess workspace.
//!
//! [`ShortString`] is a value type optimized for short identifiers that
//! are hashed, compared, and cloned at high volume: event taxonomy tags,
//! factor names, routing discriminators, and similar.
//!
//! The internal representation is an Umbra-style 16-byte stack value
//! ("German string" / Umbra-DB string): strings up to 12 bytes are
//! inlined with no allocation, `&'static str` is referenced in place
//! (also no allocation), and longer owned strings use a single
//! refcounted heap buffer that is shared on clone. The four-byte
//! prefix that powers the equality fast-path lives at a fixed offset
//! across all three variants, so prefix comparison is variant-agnostic.
//!
//! The internal layout is documented in `src/repr.rs` and is the only
//! place in the axess workspace where `unsafe` is permitted; every
//! `unsafe` block there cites the invariant it relies on.
//!
//! # Quick start
//!
//! ```
//! use axess_strings::ShortString;
//!
//! let s = ShortString::new("auth.login_attempt.v2");
//! assert_eq!(s.as_str(), "auth.login_attempt.v2");
//! assert_eq!(s.len(), 21);
//!
//! const KIND_LOGIN_V2: ShortString =
//!     ShortString::from_static("auth.login_attempt.v2");
//! assert_eq!(KIND_LOGIN_V2, s);
//! ```
//!
//! # Feature flags
//!
//! | Feature | Default | Effect |
//! |---------|---------|--------|
//! | `serde` | yes | [`serde::Serialize`] / [`serde::Deserialize`] forwarding to/from a string. |
//! | `rkyv`  | no  | rkyv `Archive` / `Serialize` / `Deserialize` forwarding to [`rkyv::string::ArchivedString`]. |
//! | `full`  | no  | Both `serde` and `rkyv`. |

// `deny(unsafe_code)` rather than `forbid` because `repr.rs` carries
// a localised `#![allow(unsafe_code)]` for the raw-heap representation
// (allocation, NonNull dereference, `unsafe impl Sync`). `forbid`
// cannot be overridden module-locally, so the inner pragma would be a
// hard error. Every `unsafe` block in `repr.rs` is in scope of that
// allow; no other module in this crate may use `unsafe`.
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod repr;

use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::ops::Deref;
use std::str::FromStr;

use crate::repr::Repr;

/// Short, hot-path string primitive.
///
/// Umbra-style 16-byte stack representation:
///
/// - strings up to 12 bytes are inlined on the stack with no allocation
/// - strings constructed via [`ShortString::from_static`] reference
///   `&'static str` memory, also without allocation
/// - strings longer than 12 bytes that are not static use a single
///   refcounted heap allocation; cloning increments the refcount
///
/// The discriminator and the four-byte prefix used by the equality
/// fast-path live in the same offset across all three variants, so
/// length and prefix comparison are variant-agnostic.
///
/// # Equality and hashing
///
/// Two `ShortString` values are equal when their string contents are
/// equal, regardless of which variant backs each. Hash output depends
/// only on the string contents.
#[derive(Clone)]
pub struct ShortString(Repr);

impl ShortString {
    /// Construct from any string slice. Inlines if ≤ 12 bytes; allocates
    /// a single refcounted buffer otherwise. For compile-time-known
    /// strings prefer [`ShortString::from_static`] which never
    /// allocates.
    #[inline]
    pub fn new(s: &str) -> Self {
        Self(Repr::from_str(s))
    }

    /// Construct from a `&'static str` without allocating. `const fn` so
    /// callers can build module-level constants regardless of length.
    #[inline]
    pub const fn from_static(s: &'static str) -> Self {
        Self(Repr::from_static(s))
    }

    /// Borrow the contents as a `&str`.
    #[inline]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Number of UTF-8 bytes (matches [`str::len`]).
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the string is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.len() == 0
    }

    /// First four bytes of the string, zero-padded if shorter.
    ///
    /// Lives at the same offset in every internal variant, so the read
    /// is variant-agnostic and is the fast path for equality / hashing
    /// when the full byte compare would otherwise dereference the heap
    /// buffer. Sliced at the byte level; not guaranteed to fall on a
    /// UTF-8 boundary.
    #[inline]
    pub fn prefix(&self) -> [u8; 4] {
        self.0.prefix()
    }
}

impl Default for ShortString {
    fn default() -> Self {
        Self(Repr::empty())
    }
}

impl fmt::Display for ShortString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for ShortString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_str(), f)
    }
}

impl PartialEq for ShortString {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for ShortString {}

impl PartialOrd for ShortString {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ShortString {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl Hash for ShortString {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_str().hash(state);
    }
}

impl Deref for ShortString {
    type Target = str;
    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<str> for ShortString {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<[u8]> for ShortString {
    fn as_ref(&self) -> &[u8] {
        self.as_str().as_bytes()
    }
}

impl PartialEq<str> for ShortString {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for ShortString {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl PartialEq<String> for ShortString {
    fn eq(&self, other: &String) -> bool {
        self.as_str() == other.as_str()
    }
}

impl From<&str> for ShortString {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl From<String> for ShortString {
    fn from(s: String) -> Self {
        Self(Repr::from_str(&s))
    }
}

impl From<Box<str>> for ShortString {
    fn from(s: Box<str>) -> Self {
        Self(Repr::from_str(&s))
    }
}

impl FromStr for ShortString {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::new(s))
    }
}

// ── serde ──────────────────────────────────────────────────────────────

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl serde::Serialize for ShortString {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl<'de> serde::Deserialize<'de> for ShortString {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = ShortString;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a string")
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(ShortString::new(v))
            }
            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(ShortString::from(v))
            }
            fn visit_borrowed_str<E: serde::de::Error>(
                self,
                v: &'de str,
            ) -> Result<Self::Value, E> {
                Ok(ShortString::new(v))
            }
        }
        deserializer.deserialize_str(V)
    }
}

// ── rkyv ───────────────────────────────────────────────────────────────

#[cfg(feature = "rkyv")]
#[cfg_attr(docsrs, doc(cfg(feature = "rkyv")))]
const _: () = {
    use rkyv::{
        Archive, Place, Serialize,
        rancor::{Fallible, Source},
        ser::{Allocator, Writer},
        string::{ArchivedString, StringResolver},
    };

    impl Archive for ShortString {
        type Archived = ArchivedString;
        type Resolver = StringResolver;

        fn resolve(&self, resolver: Self::Resolver, out: Place<Self::Archived>) {
            ArchivedString::resolve_from_str(self.as_str(), resolver, out);
        }
    }

    impl<S> Serialize<S> for ShortString
    where
        S: Allocator + Fallible + Writer + ?Sized,
        S::Error: Source,
    {
        fn serialize(&self, serializer: &mut S) -> Result<Self::Resolver, S::Error> {
            ArchivedString::serialize_from_str(self.as_str(), serializer)
        }
    }

    impl<D> rkyv::Deserialize<ShortString, D> for ArchivedString
    where
        D: Fallible + ?Sized,
    {
        fn deserialize(&self, _: &mut D) -> Result<ShortString, D::Error> {
            Ok(ShortString::new(self.as_str()))
        }
    }
};

#[cfg(test)]
mod tests {
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
    fn prefix_pads_short_strings() {
        assert_eq!(ShortString::new("ab").prefix(), *b"ab\0\0");
        assert_eq!(ShortString::new("abcd").prefix(), *b"abcd");
        assert_eq!(ShortString::new("abcdef").prefix(), *b"abcd");
        assert_eq!(ShortString::new("").prefix(), [0u8; 4]);
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
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn round_trip_preserves_string(s in any::<String>()) {
            let ss = ShortString::new(&s);
            prop_assert_eq!(ss.as_str(), s.as_str());
            prop_assert_eq!(ss.len(), s.len());
        }

        #[test]
        fn equality_consistent_with_str(a in any::<String>(), b in any::<String>()) {
            let aa = ShortString::new(&a);
            let bb = ShortString::new(&b);
            prop_assert_eq!(aa == bb, a == b);
        }

        #[test]
        fn ordering_consistent_with_str(a in any::<String>(), b in any::<String>()) {
            let aa = ShortString::new(&a);
            let bb = ShortString::new(&b);
            prop_assert_eq!(aa.cmp(&bb), a.cmp(&b));
        }

        #[test]
        fn hash_consistent_with_eq(a in any::<String>()) {
            use std::collections::hash_map::DefaultHasher;
            let aa = ShortString::new(&a);
            let bb = ShortString::new(&a);
            let mut h1 = DefaultHasher::new();
            let mut h2 = DefaultHasher::new();
            aa.hash(&mut h1);
            bb.hash(&mut h2);
            prop_assert_eq!(h1.finish(), h2.finish());
        }

        #[cfg(feature = "serde")]
        #[test]
        fn serde_json_round_trips_arbitrary(s in any::<String>()) {
            let ss = ShortString::new(&s);
            let j = serde_json::to_string(&ss).unwrap();
            let back: ShortString = serde_json::from_str(&j).unwrap();
            prop_assert_eq!(back, ss);
        }
    }
}
