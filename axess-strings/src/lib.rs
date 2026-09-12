//! Short, hot-path string primitive for the axess workspace.
//!
//! [`ShortString`] is a value type optimized for short identifiers that
//! are hashed, compared, and cloned at high volume: event taxonomy tags,
//! event subject identifiers, key ids, and similar.
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
mod tests;

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
