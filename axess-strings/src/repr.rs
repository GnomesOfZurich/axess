//! Internal representation for [`ShortString`](crate::ShortString).
//!
//! Three forms, discriminated by the enum tag:
//!
//! - `Inline`: up to [`INLINE_CAP`] bytes held in the value itself, no
//!   allocation. Cloning copies the bytes.
//! - `Static`: a `&'static str` referenced in place, no allocation.
//!   Cloning copies the reference.
//! - `Shared`: an `Arc<str>` for anything longer. Cloning bumps a
//!   refcount rather than copying the bytes.
//!
//! # Why this is not the Umbra layout it used to be
//!
//! This module previously packed the three forms into a 16-byte union
//! with a tag bit in the length field, a manual heap allocation carrying
//! its own `AtomicU32` refcount, and an `unsafe impl Sync`. It was the
//! only `unsafe` in the workspace.
//!
//! It was replaced because it cost nothing measurable to do so. The
//! consumer that matters is `platform/domain/messaging/core`, which
//! builds event subject ids from SPIFFE URIs of roughly 42 bytes. Those
//! exceed every inline buffer here, so the union and this enum both
//! allocate and both bump a refcount, and the `short_string` benchmark
//! finds them in the same band: construction 31 ns against 37 ns for a
//! bare `Arc<str>`, cloning 4.7 ns against 5.0 ns.
//!
//! Where the inline buffer does engage, 13 to 22 bytes, widening it from
//! the old 12-byte limit is a clear gain: those ids stopped allocating
//! entirely. The union won only on cloning ids of twelve bytes or fewer.
//!
//! The enum costs eight bytes of footprint, 24 against 16, and a
//! twelve-byte-larger allocation header on long strings, since `Arc`
//! carries strong and weak counts where the union carried one. Both are
//! memory rather than time, and neither was judged worth twenty
//! `unsafe` blocks in an authentication library.
//!
//! # Invariants
//!
//! 1. `Inline.len <= INLINE_CAP`.
//! 2. `Inline.data[..len]` is valid UTF-8.
//!
//! Both are established at construction: every path into this module
//! takes a `&str`, so the bytes are UTF-8 by the caller's type, and the
//! zero padding comes from the `[0u8; INLINE_CAP]` the data is copied
//! into. Nothing here can observe a partially initialised value.

use std::sync::Arc;

/// Bytes held inline before falling back to a shared allocation.
///
/// Sized so the enum lands on 24 bytes: a fat pointer is 16, the
/// discriminant and length take one each, and the rest is padding that
/// may as well be capacity.
pub(crate) const INLINE_CAP: usize = 22;

/// The three forms a [`ShortString`](crate::ShortString) can take.
#[derive(Clone)]
pub(crate) enum Repr {
    /// Short enough to live in the value.
    Inline {
        /// Bytes used in `data`. Never exceeds [`INLINE_CAP`].
        len: u8,
        /// The bytes; positions at and beyond `len` are unread.
        data: [u8; INLINE_CAP],
    },
    /// Borrowed from `'static` memory; no allocation, no refcount.
    Static(&'static str),
    /// Anything longer, shared between clones.
    Shared(Arc<str>),
}

impl Repr {
    /// Construct an empty (Inline, len 0) repr.
    pub(crate) const fn empty() -> Self {
        Self::Inline {
            len: 0,
            data: [0; INLINE_CAP],
        }
    }

    /// Reference `s` in place. `const` so callers can build a
    /// `ShortString` in a constant.
    pub(crate) const fn from_static(s: &'static str) -> Self {
        Self::Static(s)
    }

    /// Inline when it fits, otherwise a single shared allocation.
    pub(crate) fn from_str(s: &str) -> Self {
        let bytes = s.as_bytes();
        if bytes.len() <= INLINE_CAP {
            let mut data = [0u8; INLINE_CAP];
            data[..bytes.len()].copy_from_slice(bytes);
            Self::Inline {
                len: bytes.len() as u8,
                data,
            }
        } else {
            Self::Shared(Arc::from(s))
        }
    }

    /// Whether the value carries its bytes rather than pointing at them.
    #[inline]
    pub(crate) fn is_inline(&self) -> bool {
        matches!(self, Self::Inline { .. })
    }

    /// Whether a heap allocation stands behind this value. False for
    /// both `Inline` and `Static`, which are allocation-free by
    /// different means.
    #[inline]
    pub(crate) fn is_allocated(&self) -> bool {
        matches!(self, Self::Shared(_))
    }

    #[inline]
    pub(crate) fn len(&self) -> usize {
        match self {
            Self::Inline { len, .. } => *len as usize,
            Self::Static(s) => s.len(),
            Self::Shared(s) => s.len(),
        }
    }

    /// The bytes, without the UTF-8 validation [`as_str`](Self::as_str)
    /// pays on every inline access.
    ///
    /// Equality, ordering and hashing all go through here rather than
    /// through `as_str`. They are byte-wise operations on UTF-8
    /// `str` compares and orders bytewise, and `str`'s `Hash` writes its
    /// bytes plus a `0xff` terminator, so routing them past the
    /// validation changes no result, only the cost. Validating inline
    /// bytes on each comparison made equality several times slower than
    /// a plain `Arc<str>`, which defeated the point of the inline buffer.
    #[inline]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Inline { len, data } => &data[..*len as usize],
            Self::Static(s) => s.as_bytes(),
            Self::Shared(s) => s.as_bytes(),
        }
    }

    #[inline]
    pub(crate) fn as_str(&self) -> &str {
        match self {
            Self::Inline { len, data } => {
                // UTF-8 by construction: `from_str` copied it out of a
                // `&str` and `empty` is zero-length.
                std::str::from_utf8(&data[..*len as usize]).unwrap_or_default()
            }
            Self::Static(s) => s,
            Self::Shared(s) => s,
        }
    }
}

#[cfg(test)]
mod repr_tests {
    use super::*;

    #[test]
    fn empty_is_inline() {
        let r = Repr::empty();
        assert_eq!(r.len(), 0);
        assert_eq!(r.as_str(), "");
    }

    #[test]
    fn short_string_uses_inline() {
        let r = Repr::from_str("hi");
        assert_eq!(r.len(), 2);
        assert_eq!(r.as_str(), "hi");
    }

    #[test]
    fn boundary_string_inline_at_capacity() {
        let s = "a".repeat(INLINE_CAP);
        let r = Repr::from_str(&s);
        assert!(
            matches!(r, Repr::Inline { .. }),
            "exactly INLINE_CAP must inline"
        );
        assert_eq!(r.len(), INLINE_CAP);
        assert_eq!(r.as_str(), s);
    }

    #[test]
    fn one_past_capacity_goes_to_the_heap() {
        let s = "a".repeat(INLINE_CAP + 1);
        let r = Repr::from_str(&s);
        assert!(matches!(r, Repr::Shared(_)), "one over must allocate");
        assert_eq!(r.len(), INLINE_CAP + 1);
        assert_eq!(r.as_str(), s);
    }

    #[test]
    fn heap_form_round_trips() {
        let r = Repr::from_str("auth.login_attempt.and.then.some.more.v2");
        assert_eq!(r.len(), 40);
        assert_eq!(r.as_str(), "auth.login_attempt.and.then.some.more.v2");
    }

    #[test]
    fn static_form_short_string() {
        let r = Repr::from_static("hi");
        assert_eq!(r.len(), 2);
        assert_eq!(r.as_str(), "hi");
    }

    #[test]
    fn static_form_long_string() {
        let r = Repr::from_static("auth.login_attempt.v2");
        assert_eq!(r.len(), 21);
        assert_eq!(r.as_str(), "auth.login_attempt.v2");
    }

    #[test]
    fn clone_inline_is_independent() {
        let r1 = Repr::from_str("hi");
        let r2 = r1.clone();
        assert_eq!(r1.as_str(), r2.as_str());
        drop(r1);
        assert_eq!(r2.as_str(), "hi");
    }

    #[test]
    fn clone_heap_shares_buffer() {
        let r1 = Repr::from_str("auth.login_attempt.v2");
        let r2 = r1.clone();
        let r3 = r1.clone();
        // All three see the same content.
        assert_eq!(r1.as_str(), "auth.login_attempt.v2");
        assert_eq!(r2.as_str(), "auth.login_attempt.v2");
        assert_eq!(r3.as_str(), "auth.login_attempt.v2");
        // Drop in arbitrary order; invariant 3 must hold.
        drop(r2);
        assert_eq!(r1.as_str(), "auth.login_attempt.v2");
        drop(r1);
        assert_eq!(r3.as_str(), "auth.login_attempt.v2");
        drop(r3);
        // No panic on the final drop ⇒ refcount math is consistent.
    }

    #[test]
    fn clone_static_is_pointer_copy() {
        let r1 = Repr::from_static("auth.login_attempt.v2");
        let r2 = r1.clone();
        assert_eq!(r1.as_str(), r2.as_str());
    }

    #[test]
    fn struct_stays_small() {
        // A fat pointer is 16 bytes and the discriminant rounds the enum
        // to 24. Pin it: an accidental `String` or a widened variant
        // would show up here as growth in a type embedded in every event.
        assert_eq!(std::mem::size_of::<Repr>(), 24);
    }

    #[test]
    fn long_heap_string_round_trips() {
        let s = "a".repeat(10_000);
        let r = Repr::from_str(&s);
        assert_eq!(r.len(), 10_000);
        assert_eq!(r.as_str(), s.as_str());
    }
}
