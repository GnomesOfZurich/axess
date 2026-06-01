//! Internal Umbra-style 16-byte representation for [`ShortString`](crate::ShortString).
//!
//! # Layout
//!
//! ```text
//!         offset 0   offset 4   offset 8         offset 16
//!         |          |          |                |
//!  Inline | len:u32  | data: [u8; 12]            |   len ≤ 12, no tag bit
//!  Static | len|TAG  | prefix:[u8;4] | ptr:*u8   |   high bit of len-field set
//!  Heap   | len:u32  | prefix:[u8;4] | ptr:Heap  |   len > 12, no tag bit
//! ```
//!
//! All three variants share the first eight bytes:
//!  - bytes `0..4`: length (low 31 bits) plus the static-tag high bit
//!  - bytes `4..8`: prefix, first four bytes of the string, zero-padded
//!
//! The shared layout is what makes [`Repr::prefix`] and the prefix
//! fast-path of equality work without first deciding the variant.
//!
//! # Discriminator
//!
//! - high bit of the length field set ⇒ **Static** (immutable `&'static [u8]`)
//! - high bit clear, length ≤ 12 ⇒ **Inline** (bytes live in `data`)
//! - high bit clear, length > 12 ⇒ **Heap** (refcounted heap allocation)
//!
//! # Heap allocation layout
//!
//! Heap form stores a single allocation with an atomic refcount header
//! followed by the string bytes:
//!
//! ```text
//!  [ refcount: AtomicU32 ][ bytes: [u8; len] ]
//!  ^                       ^
//!  ptr                     ptr + DATA_OFFSET
//! ```
//!
//! `DATA_OFFSET` is `align_up(size_of::<AtomicU32>(), 1)`: for
//! `AtomicU32` with 4-byte alignment and `u8` with 1-byte alignment that
//! is just `4`. Computed via `Layout::extend` to stay forward-compatible
//! with any future alignment changes.
//!
//! # Soundness invariants
//!
//! 1. After construction, the active variant is determined entirely by
//!    the length field at offset 0..4 of the union. Every read site
//!    consults the discriminator before accessing variant-specific
//!    fields.
//! 2. `Heap` form's pointer is always non-null and always points to a
//!    valid allocation made via [`alloc_heap`] (and not yet freed).
//! 3. `Heap` form's refcount is decremented on drop; the allocation is
//!    freed on the transition from 1 → 0.
//! 4. `Static` form's pointer is `&'static`, never freed.
//! 5. `Inline` form has `len ≤ INLINE_CAP` and `data[len..]` is zero-
//!    padded.
//! 6. The 4-byte prefix at offset 4..8 always matches the first 4 bytes
//!    of the string content (zero-padded if the string is shorter).
//!
//! All `unsafe` blocks below cite the invariant they rely on.

#![allow(unsafe_code)]

use std::alloc::{Layout, alloc, dealloc, handle_alloc_error};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU32, Ordering};

/// Maximum number of UTF-8 bytes that fit in the inline variant.
pub(crate) const INLINE_CAP: usize = 12;

/// High-bit tag on the length field marking the **Static** variant.
const STATIC_TAG: u32 = 1 << 31;

/// Mask to extract the true length, regardless of variant.
const LEN_MASK: u32 = !STATIC_TAG;

#[repr(C)]
#[derive(Clone, Copy)]
struct InlineRepr {
    len: u32,
    data: [u8; INLINE_CAP],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PointerRepr {
    /// Length, with the [`STATIC_TAG`] high bit set when this is a
    /// Static-form pointer. For Heap form the high bit is clear.
    len_with_tag: u32,
    prefix: [u8; 4],
    ptr: *const u8,
}

#[repr(C)]
pub(crate) union Repr {
    inline: InlineRepr,
    pointer: PointerRepr,
}

/// Header at the start of a heap allocation. Followed by the string
/// bytes at `DATA_OFFSET` (computed via [`heap_layout`]).
#[repr(C)]
struct HeapHeader {
    refcount: AtomicU32,
}

fn heap_layout(len: usize) -> (Layout, usize) {
    let header = Layout::new::<HeapHeader>();
    let bytes = Layout::array::<u8>(len).expect("string length overflows Layout");
    let (combined, offset) = header
        .extend(bytes)
        .expect("combined heap layout overflows");
    (combined.pad_to_align(), offset)
}

/// Allocate a heap buffer for `s`, initialising the refcount to 1 and
/// copying the string bytes.
///
/// # Safety
///
/// The returned pointer is non-null, properly aligned, points to an
/// initialised `HeapHeader` followed by `s.len()` bytes copied from `s`,
/// and is owned by the caller (refcount = 1, must be released via
/// [`drop_heap`]).
fn alloc_heap(s: &str) -> NonNull<HeapHeader> {
    let len = s.len();
    let (layout, data_offset) = heap_layout(len);
    // Safety: `layout` is non-zero (header alone is 4 bytes).
    let raw = unsafe { alloc(layout) };
    let Some(raw) = NonNull::new(raw) else {
        handle_alloc_error(layout);
    };
    // Safety: `raw` is freshly allocated and points to space for a
    // HeapHeader. Initialise refcount=1 in place.
    unsafe {
        raw.cast::<HeapHeader>().as_ptr().write(HeapHeader {
            refcount: AtomicU32::new(1),
        });
    }
    // Safety: `raw + data_offset` is within the same allocation and
    // points to space for `len` u8 bytes; we copy from `s.as_ptr()`
    // which is valid for `len` bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(s.as_ptr(), raw.as_ptr().add(data_offset), len);
    }
    raw.cast::<HeapHeader>()
}

/// Increment the refcount on a heap pointer.
///
/// # Safety
///
/// `ptr` must be a live heap allocation produced by [`alloc_heap`]
/// (refcount > 0).
unsafe fn retain_heap(ptr: NonNull<HeapHeader>) {
    // Safety: invariant 2: heap pointers are valid until drop.
    let header = unsafe { ptr.as_ref() };
    // Relaxed is sound for refcount inc; we already hold a strong
    // reference, so there's no synchronisation required for the
    // increment itself. (Matches `Arc::clone`.)
    header.refcount.fetch_add(1, Ordering::Relaxed);
}

/// Drop a heap reference: decrement refcount, free on transition 1 → 0.
///
/// # Safety
///
/// `ptr` must be a live heap allocation produced by [`alloc_heap`]
/// with the caller holding one reference. After this call the caller
/// must not use `ptr` again.
unsafe fn drop_heap(ptr: NonNull<HeapHeader>, len: usize) {
    // Safety: invariant 2.
    let header = unsafe { ptr.as_ref() };
    // AcqRel mirrors `Arc::drop`: pairs with the producer's Release
    // ordering on its own decrement; the final dropper observes a
    // happens-before edge to all prior modifications.
    if header.refcount.fetch_sub(1, Ordering::AcqRel) == 1 {
        let (layout, _) = heap_layout(len);
        // Safety: refcount transition 1 → 0 means we're the last owner;
        // the allocation was made with this same layout in `alloc_heap`.
        unsafe {
            dealloc(ptr.as_ptr().cast::<u8>(), layout);
        }
    }
}

/// Read the bytes of a heap allocation as a `&str`.
///
/// # Safety
///
/// `ptr` must be a live heap allocation produced by [`alloc_heap`] with
/// `len` bytes of valid UTF-8 string content.
unsafe fn heap_bytes<'a>(ptr: NonNull<HeapHeader>, len: usize) -> &'a [u8] {
    let (_, data_offset) = heap_layout(len);
    // Safety: invariants 2 + 3; the bytes after the header are valid
    // for `len` for the lifetime of the allocation.
    unsafe { std::slice::from_raw_parts(ptr.as_ptr().cast::<u8>().add(data_offset), len) }
}

fn compute_prefix(bytes: &[u8]) -> [u8; 4] {
    let mut out = [0u8; 4];
    let n = bytes.len().min(4);
    out[..n].copy_from_slice(&bytes[..n]);
    out
}

impl Repr {
    /// Construct an empty (Inline, len=0) repr.
    pub(crate) const fn empty() -> Self {
        Self {
            inline: InlineRepr {
                len: 0,
                data: [0; INLINE_CAP],
            },
        }
    }

    /// Construct from a `&'static str` without allocating. `const fn`,
    /// preserves the const-evaluable API for module-level constants.
    pub(crate) const fn from_static(s: &'static str) -> Self {
        let bytes = s.as_bytes();
        let len = bytes.len();
        // Hand-rolled prefix: const fn slice indexing is supported but
        // `copy_from_slice` is not yet const-stable.
        let prefix = [
            if len > 0 { bytes[0] } else { 0 },
            if len > 1 { bytes[1] } else { 0 },
            if len > 2 { bytes[2] } else { 0 },
            if len > 3 { bytes[3] } else { 0 },
        ];
        Self {
            pointer: PointerRepr {
                len_with_tag: (len as u32) | STATIC_TAG,
                prefix,
                ptr: bytes.as_ptr(),
            },
        }
    }

    /// Construct from an arbitrary `&str`, allocating on the heap if
    /// the string does not fit inline.
    pub(crate) fn from_str(s: &str) -> Self {
        let bytes = s.as_bytes();
        let len = bytes.len();
        if len <= INLINE_CAP {
            let mut data = [0u8; INLINE_CAP];
            data[..len].copy_from_slice(bytes);
            Self {
                inline: InlineRepr {
                    len: len as u32,
                    data,
                },
            }
        } else {
            let prefix = compute_prefix(bytes);
            let ptr = alloc_heap(s);
            Self {
                pointer: PointerRepr {
                    len_with_tag: len as u32, // high bit clear ⇒ Heap
                    prefix,
                    ptr: ptr.as_ptr().cast::<u8>(),
                },
            }
        }
    }

    /// Length of the string content (independent of variant).
    #[inline]
    pub(crate) fn len(&self) -> usize {
        // Safety: invariant 1; the length field is at offset 0..4 of
        // every variant; reading it via `inline.len` and masking off
        // the static tag is sound regardless of which variant is
        // active.
        let raw = unsafe { self.inline.len };
        (raw & LEN_MASK) as usize
    }

    /// Four-byte prefix of the string, zero-padded if shorter.
    #[inline]
    pub(crate) fn prefix(&self) -> [u8; 4] {
        // Safety: invariant 6; the prefix bytes at offset 4..8 are
        // initialised to the first 4 bytes of the string content
        // regardless of variant. For Inline form the slot also holds
        // the first 4 bytes of `data`, which equals the prefix by
        // construction.
        unsafe {
            // Read inline.data[0..4]; this works for every variant
            // because that 4-byte window contains the prefix in all
            // three layouts.
            [
                self.inline.data[0],
                self.inline.data[1],
                self.inline.data[2],
                self.inline.data[3],
            ]
        }
    }

    /// Borrow the contents as `&str`. Lifetime tied to `&self`.
    #[inline]
    pub(crate) fn as_str(&self) -> &str {
        // Safety: invariant 1 + invariants 2/4/5 per variant.
        let bytes = unsafe {
            let raw_len = self.inline.len;
            if raw_len & STATIC_TAG != 0 {
                // Static: pointer is &'static, length is masked.
                let len = (raw_len & LEN_MASK) as usize;
                std::slice::from_raw_parts(self.pointer.ptr, len)
            } else if (raw_len as usize) <= INLINE_CAP {
                // Inline: bytes live in `data`.
                let len = raw_len as usize;
                &self.inline.data[..len]
            } else {
                // Heap: deref the pointer; bytes follow the header.
                let len = raw_len as usize;
                let header =
                    NonNull::new_unchecked(self.pointer.ptr.cast::<HeapHeader>().cast_mut());
                heap_bytes(header, len)
            }
        };
        // Safety: the string content was validated as UTF-8 at
        // construction (`from_str` / `from_static` both take `&str`).
        unsafe { std::str::from_utf8_unchecked(bytes) }
    }
}

impl Clone for Repr {
    fn clone(&self) -> Self {
        // Safety: invariant 1; read len-with-tag to discriminate; for
        // Heap variant, retain the refcount so the new instance owns
        // a strong reference. Inline and Static are trivially Copy.
        unsafe {
            let raw_len = self.inline.len;
            if raw_len & STATIC_TAG != 0 {
                Self {
                    pointer: self.pointer,
                }
            } else if (raw_len as usize) <= INLINE_CAP {
                Self {
                    inline: self.inline,
                }
            } else {
                let header =
                    NonNull::new_unchecked(self.pointer.ptr.cast::<HeapHeader>().cast_mut());
                retain_heap(header);
                Self {
                    pointer: self.pointer,
                }
            }
        }
    }
}

impl Drop for Repr {
    fn drop(&mut self) {
        // Safety: invariant 1; only Heap form needs cleanup; Inline
        // and Static are trivially droppable.
        unsafe {
            let raw_len = self.inline.len;
            if raw_len & STATIC_TAG == 0 && (raw_len as usize) > INLINE_CAP {
                let len = raw_len as usize;
                let header =
                    NonNull::new_unchecked(self.pointer.ptr.cast::<HeapHeader>().cast_mut());
                drop_heap(header, len);
            }
        }
    }
}

// Safety: the underlying data is thread-safe in every variant:
//   - Inline: stack bytes (Send + Sync trivially).
//   - Static: `&'static [u8]` (Send + Sync).
//   - Heap: refcount is `AtomicU32`; bytes are immutable after
//     construction. Matches `Arc<[u8]>` Send/Sync rules.
unsafe impl Send for Repr {}
unsafe impl Sync for Repr {}

#[cfg(test)]
mod repr_tests {
    use super::*;

    #[test]
    fn empty_is_inline() {
        let r = Repr::empty();
        assert_eq!(r.len(), 0);
        assert_eq!(r.as_str(), "");
        assert_eq!(r.prefix(), [0; 4]);
    }

    #[test]
    fn short_string_uses_inline() {
        let r = Repr::from_str("hi");
        assert_eq!(r.len(), 2);
        assert_eq!(r.as_str(), "hi");
        assert_eq!(r.prefix(), *b"hi\0\0");
    }

    #[test]
    fn boundary_string_inline_at_12_bytes() {
        let r = Repr::from_str("abcdefghijkl"); // exactly 12 bytes
        assert_eq!(r.len(), 12);
        assert_eq!(r.as_str(), "abcdefghijkl");
        assert_eq!(r.prefix(), *b"abcd");
    }

    #[test]
    fn heap_form_for_strings_over_12_bytes() {
        let r = Repr::from_str("auth.login_attempt.v2"); // 21 bytes
        assert_eq!(r.len(), 21);
        assert_eq!(r.as_str(), "auth.login_attempt.v2");
        assert_eq!(r.prefix(), *b"auth");
    }

    #[test]
    fn static_form_short_string() {
        let r = Repr::from_static("hi");
        assert_eq!(r.len(), 2);
        assert_eq!(r.as_str(), "hi");
        assert_eq!(r.prefix(), *b"hi\0\0");
    }

    #[test]
    fn static_form_long_string() {
        let r = Repr::from_static("auth.login_attempt.v2");
        assert_eq!(r.len(), 21);
        assert_eq!(r.as_str(), "auth.login_attempt.v2");
        assert_eq!(r.prefix(), *b"auth");
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
    fn struct_size_is_16_bytes() {
        // Sanity: the whole point of the Umbra layout is a 16-byte
        // stack representation.
        assert_eq!(std::mem::size_of::<Repr>(), 16);
    }

    #[test]
    fn long_heap_string_round_trips() {
        let s = "a".repeat(10_000);
        let r = Repr::from_str(&s);
        assert_eq!(r.len(), 10_000);
        assert_eq!(r.as_str(), s.as_str());
    }
}
