//! Short, hot-path string primitive for the axess workspace.
//!
//! [`ShortString`] is a value type optimized for short identifiers that
//! are hashed, compared, and cloned at high volume: event taxonomy tags,
//! event subject identifiers, key ids, and similar.
//!
//! The internal representation is a 24-byte enum: strings up to 22
//! bytes are inlined with no allocation, `&'static str` is referenced
//! in place (also no allocation), and anything longer is an `Arc<str>`
//! shared on clone.
//!
//! The internal layout is documented in `src/repr.rs`.
//!
//! # Why not `compact_str`
//!
//! `compact_str` is the better-known crate in this space and the org
//! already uses it in nomos. It is not a substitute here, because the
//! two crates optimize opposite ends of the same trade.
//!
//! `CompactString` is a `String` that usually avoids allocating: it is
//! mutable, growable, and carries no refcount. Cloning a value that
//! exceeded its inline buffer therefore allocates a fresh buffer and
//! copies into it, exactly as `String` does. `ShortString` is immutable,
//! so anything past the inline buffer can be shared, and a clone is a
//! refcount bump.
//!
//! For identifiers that is the whole game. A subject id is built once
//! and then cloned into every event, span, audit row and cache key that
//! mentions it. The `short_string` benchmark measures the shape that
//! dominates, a 42-byte SPIFFE-derived id, above both inline buffers:
//!
//! | 42-byte SPIFFE id | `ShortString` | `CompactString` | `Arc<str>` |
//! |---|---|---|---|
//! | clone     | 3.75 ns | 20.9 ns | 3.85 ns |
//! | equality  | 3.18 ns | 5.80 ns | 1.70 ns |
//! | construct | 23.5 ns | 22.0 ns | 23.8 ns |
//!
//! Above the inline cap, cloning a `CompactString` costs about what
//! cloning a `String` costs; the crate's advantage has simply run out.
//! `ShortString` measures level with `Arc<str>` there because that is
//! what it is. Below the cap the two are in the same low-single-digit
//! band, and `compact_str` is marginally ahead on the shortest inputs.
//!
//! Figures are an M4 Max; the ratio is the durable part, and it follows
//! from the representations rather than from the timing: one allocates
//! per clone and the other does not.
//!
//! # Why not a bare `Arc<str>`
//!
//! It is 16 bytes against 24, and it compares faster: 1.53 ns against
//! 3.05 ns at 42 bytes, because it has no discriminant to match. Those
//! are real, and if identifiers were long, dynamic and mostly compared,
//! `Arc<str>` would be the better type.
//!
//! Identifiers are mostly built from constants and cloned:
//!
//! | 42-byte id | `ShortString` | `Arc<str>` |
//! |---|---|---|
//! | build from a `&'static str` | 1.08 ns | 23.0 ns |
//! | clone that value            | 1.65 ns | 3.61 ns |
//! | equality                    | 3.05 ns | 1.53 ns |
//!
//! `Arc<str>` has no `&'static str` form. Every construction allocates
//! and copies, and none can appear in a `const`, so a module-level id
//! needs a `LazyLock` or an allocation at each use.
//!
//! Cloning a [`from_static`](ShortString::from_static) value also
//! performs **no atomic operation**: it copies a pointer; where every
//! `Arc` clone is a refcount increment. That is the per-message cost
//! wherever a subject is built once and cloned into each event, and
//! across threads sharing one id the gap is wider than the
//! single-threaded figure, because the refcount is a contended cache
//! line and the pointer copy touches nothing shared.
//!
//! The 1.5 ns equality loss is what that costs.
//!
//! # What `forbid(unsafe_code)` costs
//!
//! One thing, and it is worth knowing before anyone proposes taking the
//! restriction off. With `unsafe` this would be `from_utf8_unchecked`
//! and free; without it, [`as_str`](ShortString::as_str) on an *inline*
//! value revalidates UTF-8 on every call:
//!
//! | `as_str` | `ShortString` | `CompactString` | `Arc<str>` |
//! |---|---|---|---|
//! | 7-byte, inline  | 3.61 ns  | 0.57 ns | 0.49 ns |
//! | 22-byte, inline | 3.86 ns  | 0.62 ns | 0.52 ns |
//! | 42-byte, shared | 0.58 ns  | 0.58 ns | 0.48 ns |
//!
//! The tax lands only on the inline form. `Static` and `Shared` already
//! hold a `&str` and measure level with the alternatives. Equality,
//! ordering and hashing were moved off this path onto the bytes, so what
//! still pays is `Deref`, `Display`, and handing the value to a `&str`
//! API.
//!
//! For the ids this crate exists for it is therefore zero, since at 42
//! bytes they are in the shared form. That is the argument against
//! reintroducing the union: it would buy back a cost the dominant
//! workload does not pay, and its own inline buffer was 12 bytes where
//! this one is 22.
//!
//! Its inline buffer is 24 bytes against 22 here, but that margin does
//! not reach the ids this crate exists for: at 42 bytes neither inlines,
//! so the wider buffer decides nothing. It matters only for inputs of
//! exactly 23 or 24 bytes.
//!
//! Reaching 24 would require niche-packing the length into unused UTF-8
//! bit patterns, which requires `unsafe`. That is the trade `compact_str`
//! makes, across roughly 165 `unsafe` blocks. It is a reasonable trade
//! for a general-purpose string; it is not one this crate needs to make
//! for two bytes it cannot use.
//!
//! Both archive to [`rkyv::string::ArchivedString`], so the choice is
//! not a wire-format commitment in either direction.
//!
//! **Use `CompactString` instead** when the value is mutable text that
//! gets pushed to, truncated, or built up incrementally. Use
//! [`ShortString`] when the value is an identifier: fixed at
//! construction, and copied far more often than it is created.
//!
//! # Why this is not an Umbra string
//!
//! It was one: a 16-byte union with a tag bit in the length field, a
//! hand-rolled heap allocation carrying its own `AtomicU32` refcount,
//! and an `unsafe impl Sync`. It was the only `unsafe` in the axess
//! workspace.
//!
//! It was replaced by the enum above because the measured cost of doing
//! so, on the workload that actually runs, is nil. Those 42-byte ids
//! exceed every inline buffer in play, so the union and the enum both
//! allocate and both bump a refcount, and they land in the same band:
//! construct 31.2 ns against 37.2 ns for a bare `Arc<str>`, clone
//! 4.74 ns against 4.96 ns.
//!
//! Where the buffer does engage, between 13 and 22 bytes, the wider one
//! is a clear gain over the old 12-byte limit: constructing a 22-byte id
//! fell from ~24 ns to ~4 ns and cloning one from ~7.7 ns to ~3.0 ns,
//! because it stopped allocating. The old layout won only on cloning ids
//! of twelve bytes or fewer, by about 1.4 ns.
//!
//! What the union really bought was eight bytes of struct footprint and
//! a twelve-byte-leaner allocation header for long strings. Those are
//! real, and they are memory rather than time. They were judged not to
//! be worth twenty `unsafe` blocks in an authentication library.
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
//!
//! There is deliberately no `sqlx` feature. `compact_str` has one, and it
//! is a fair thing to miss, but every `ShortString` in this org is an
//! event actor or subject id travelling the rkyv path: none is bound to
//! a query, so it would add a `sqlx` dependency to a leaf crate for no
//! caller. Bind with [`as_str`](ShortString::as_str) in the meantime; the
//! impls are about fifteen lines per backend if that changes.

#![forbid(unsafe_code)]
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
/// A 24-byte value in three forms:
///
/// - strings up to 22 bytes are inlined, with no allocation
/// - strings constructed via [`ShortString::from_static`] reference
///   `&'static str` memory, also without allocation
/// - anything longer is an `Arc<str>`; cloning bumps the refcount
///
/// Which form a value takes is an implementation detail; see
/// `src/repr.rs`.
#[derive(Clone)]
pub struct ShortString(Repr);

impl ShortString {
    /// Construct from any string slice. Inlines if ≤ 22 bytes; allocates
    /// a single refcounted buffer otherwise. For compile-time-known
    /// strings prefer [`ShortString::from_static`] which never
    /// allocates.
    #[inline]
    pub fn new(s: impl AsRef<str>) -> Self {
        Self(Repr::from_str(s.as_ref()))
    }

    /// Bytes that fit without allocating.
    ///
    /// Twenty-two is the ceiling for a safe 24-byte value, not a tuning
    /// choice: the two non-inline forms each hold a 16-byte fat pointer,
    /// and a discriminant and a length byte take the rest. Reaching 24,
    /// as `compact_str` does, needs niche-packing the length into unused
    /// UTF-8 bit patterns, which needs `unsafe`.
    ///
    /// Worth checking against your own identifiers. Subject ids built
    /// from SPIFFE URIs run to about 42 bytes and always allocate;
    /// instrument and case ids of the `inst-aapl-123` shape do not.
    pub const INLINE_CAPACITY: usize = crate::repr::INLINE_CAP;

    /// Whether this value carries its bytes in the struct itself.
    ///
    /// True exactly when the value was built from a string of at most
    /// [`INLINE_CAPACITY`](Self::INLINE_CAPACITY) bytes by a path that
    /// copies, such as [`new`](Self::new). **A value from
    /// [`from_static`](Self::from_static) is never inline** whatever its
    /// length: it points at `'static` memory instead of copying.
    ///
    /// To ask the question that usually matters: whether anything was
    /// allocated: use [`is_allocated`](Self::is_allocated), which is
    /// false for both of the allocation-free forms.
    ///
    /// For diagnostics and for tests pinning an id shape; nothing about
    /// behaviour depends on it.
    pub fn is_inline(&self) -> bool {
        self.0.is_inline()
    }

    /// Whether a heap allocation stands behind this value.
    ///
    /// False for inline values and for [`from_static`](Self::from_static)
    /// values alike, true only where the string exceeded
    /// [`INLINE_CAPACITY`](Self::INLINE_CAPACITY) and had to be copied
    /// into a shared buffer.
    ///
    /// This is the predicate to assert against when a test wants to fix
    /// that some identifier shape stays allocation-free, since the two
    /// allocation-free forms are not distinguishable by
    /// [`is_inline`](Self::is_inline) alone.
    ///
    /// ```
    /// use axess_strings::ShortString;
    ///
    /// // A 42-byte SPIFFE-derived subject id does allocate; a clone of
    /// // it is then a refcount bump rather than a copy.
    /// let id = ShortString::new("spiffe://gnomes.local/feed-worker/ekekrantz");
    /// assert!(id.is_allocated());
    ///
    /// // A compile-time-known one of the same length does not.
    /// const ID: ShortString =
    ///     ShortString::from_static("spiffe://gnomes.local/feed-worker/ekekrantz");
    /// assert!(!ID.is_allocated());
    /// assert!(!ID.is_inline());
    /// ```
    pub fn is_allocated(&self) -> bool {
        self.0.is_allocated()
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
        // Bytes, not `as_str`: equal UTF-8 is equal bytes, and this
        // skips the validation an inline `as_str` would pay twice.
        self.0.as_bytes() == other.0.as_bytes()
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
        // `str` orders bytewise, so this is the same order for less work.
        self.0.as_bytes().cmp(other.0.as_bytes())
    }
}

impl Hash for ShortString {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Byte-for-byte what `impl Hash for str` does: the bytes, then a
        // `0xff` terminator that keeps prefixes from colliding. Written
        // out rather than delegated so the inline form skips validation.
        //
        // This must stay in lockstep with `str` or the `Borrow<str>`
        // contract breaks and `HashMap::get(&str)` silently misses on
        // keys that are present. `hash_delegates_to_str_hash` in
        // `tests.rs` compares against a real `str` hash and fails if
        // std ever changes the encoding.
        state.write(self.0.as_bytes());
        state.write_u8(0xff);
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

/// Lets a `HashMap<ShortString, V>` be looked up with a `&str`, without
/// constructing a `ShortString` for the key. Required by any map keyed on
/// this type that is queried from a literal or a borrowed slice.
impl std::borrow::Borrow<str> for ShortString {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<[u8]> for ShortString {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl PartialEq<str> for ShortString {
    fn eq(&self, other: &str) -> bool {
        self.0.as_bytes() == other.as_bytes()
    }
}

// The remaining cross-type comparisons all defer to the `str` impl
// above, so there is one definition of what equality means here and it
// is the validation-free one.

impl PartialEq<&str> for ShortString {
    fn eq(&self, other: &&str) -> bool {
        self == *other
    }
}

impl PartialEq<String> for ShortString {
    fn eq(&self, other: &String) -> bool {
        self == other.as_str()
    }
}

impl PartialEq<ShortString> for str {
    fn eq(&self, other: &ShortString) -> bool {
        other == self
    }
}

impl PartialEq<ShortString> for &str {
    fn eq(&self, other: &ShortString) -> bool {
        other == *self
    }
}

impl PartialEq<ShortString> for String {
    fn eq(&self, other: &ShortString) -> bool {
        other == self.as_str()
    }
}

impl From<ShortString> for String {
    fn from(s: ShortString) -> Self {
        s.as_str().to_owned()
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
