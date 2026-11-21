//! The buffer a bounded read collects a body into leaves no copy of the body
//! in memory it gives back: every block it frees, as it grows, when a body is
//! refused part of the way through, and when the bytes it handed out are
//! dropped, is wiped first. That holds for each reader: a success body read
//! whole, a refusal's body read for what it says, and either read by
//! status.
//!
//! The readers are handed a response built in this process, whose body
//! comes in chunks that point into this file's static data. The chunks are
//! the HTTP client's and are never freed; only what a reader collects them
//! into is.
//!
//! This test binary runs on an allocator of its own. It hands out zeroed
//! blocks, so that every byte of a block is initialised when it is read, and
//! while it is armed it looks in each block it is asked to free for a mark
//! every chunk of the body carries. A block freed with the mark in it is a
//! copy of the body left in freed memory: the property itself, whichever
//! call brought it about. `Vec` growth reaches the allocator as a
//! reallocation, which this allocator serves as a new block, a copy and a
//! free of the old one, so a buffer that grows in place is seen too.
//!
//! The allocator interface is `unsafe` to implement; this file is the one
//! place in the workspace that implements it, and the library crates hold no
//! `unsafe`.

#![cfg(feature = "http-body")]

use axess_factors::http_body::{
    BodyError, BoundedBody, ERROR_BODY_BYTES, ERROR_BODY_PARSE_BYTES, ErrorBody, TRUNCATED_SUFFIX,
    read_for_status, read_limited,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};

/// What every chunk of the body starts with, and nothing else in the
/// process holds outside this file's static data. It is UTF-8, so the text
/// a reader makes of a refusal's body (its lossy UTF-8) still carries it.
const MARK: &[u8] = "\u{2603}axess-body-wipe-probe\u{2603}".as_bytes();
const CHUNK_BYTES: usize = 1000;

const fn marked_chunk() -> [u8; CHUNK_BYTES] {
    let mut chunk = [b'.'; CHUNK_BYTES];
    let mut i = 0;
    while i < MARK.len() {
        chunk[i] = MARK[i];
        i += 1;
    }
    chunk
}

static CHUNK: [u8; CHUNK_BYTES] = marked_chunk();

static ARMED: AtomicBool = AtomicBool::new(false);
static FREED: AtomicUsize = AtomicUsize::new(0);
static FREED_MARKED: AtomicUsize = AtomicUsize::new(0);

struct Probe;

// SAFETY: every call is passed to the system allocator with the layout it
// came with; the probe only reads a block it is about to free.
unsafe impl GlobalAlloc for Probe {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's layout is passed on as it came.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(Ordering::SeqCst) {
            FREED.fetch_add(1, Ordering::SeqCst);
            // SAFETY: `ptr` is a live block of `layout.size()` bytes that
            // `alloc` zeroed, so every byte of it is initialised.
            let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            if block.windows(MARK.len()).any(|window| window == MARK) {
                FREED_MARKED.fetch_add(1, Ordering::SeqCst);
            }
        }
        // SAFETY: the block came from `alloc` with this layout.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Probe = Probe;

/// Run `f` with the probe armed: (blocks freed, blocks freed holding the mark).
fn watched(f: impl FnOnce()) -> (usize, usize) {
    FREED.store(0, Ordering::SeqCst);
    FREED_MARKED.store(0, Ordering::SeqCst);
    ARMED.store(true, Ordering::SeqCst);
    f();
    ARMED.store(false, Ordering::SeqCst);
    (
        FREED.load(Ordering::SeqCst),
        FREED_MARKED.load(Ordering::SeqCst),
    )
}

const MAX: usize = 64 * 1024;

/// A body of `left` chunks of `CHUNK`, each handed out as it is asked for.
struct Chunks {
    left: usize,
}

impl http_body_one::Body for Chunks {
    type Data = &'static [u8];
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body_one::Frame<Self::Data>, Self::Error>>> {
        if self.left == 0 {
            return Poll::Ready(None);
        }
        self.left -= 1;
        Poll::Ready(Some(Ok(http_body_one::Frame::data(CHUNK.as_slice()))))
    }
}

/// A response with `status` whose body is `chunks` chunks of `CHUNK` and
/// declares no length, so a reader grows its buffer as the chunks come.
fn response(status: u16, chunks: usize) -> reqwest::Response {
    let body = reqwest::Body::wrap(Chunks { left: chunks });
    reqwest::Response::from(
        http::Response::builder()
            .status(status)
            .body(body)
            .expect("a response"),
    )
}

/// Whether `bytes` are `n` bytes of the chunks, one after another.
fn is_body(bytes: &[u8], n: usize) -> bool {
    bytes.len() == n && bytes.chunks(CHUNK_BYTES).all(|c| c == &CHUNK[..c.len()])
}

// One test, so that no other test of this binary frees blocks while the
// probe is armed.
#[test]
fn a_bounded_body_wipes_every_block_it_frees() {
    // No declared length: the buffer grows from nothing, chunk by chunk.
    let (freed, marked) = watched(|| {
        let mut body = BoundedBody::new(None, MAX).expect("no length is declared");
        for _ in 0..40 {
            body.push(&CHUNK).expect("the body stays within the cap");
        }
        let bytes = body.into_bytes();
        assert_eq!(bytes.len(), 40 * CHUNK_BYTES);
        assert!(bytes.chunks(CHUNK_BYTES).all(|c| c == CHUNK.as_slice()));
    });
    assert!(freed > 0, "the probe saw no block freed");
    assert_eq!(
        marked, 0,
        "a grown body left {marked} unwiped copies in freed memory"
    );

    // Refused part of the way through: the bytes read so far go with it.
    let (_, marked) = watched(|| {
        let mut body =
            BoundedBody::new(None, 5 * CHUNK_BYTES + 500).expect("no length is declared");
        for _ in 0..5 {
            body.push(&CHUNK).expect("the body stays within the cap");
        }
        assert_eq!(
            body.push(&CHUNK),
            Err(BodyError::TooLarge {
                max: 5 * CHUNK_BYTES + 500
            })
        );
    });
    assert_eq!(
        marked, 0,
        "a refused body left {marked} unwiped copies in freed memory"
    );

    // A declared length sizes the buffer once, and the body never grows.
    let (_, marked) = watched(|| {
        let mut body = BoundedBody::new(Some(3 * CHUNK_BYTES as u64), MAX).expect("within the cap");
        for _ in 0..3 {
            body.push(&CHUNK).expect("the body stays within the cap");
        }
        assert_eq!(body.into_bytes().capacity(), 3 * CHUNK_BYTES);
    });
    assert_eq!(
        marked, 0,
        "a sized body left {marked} unwiped copies in freed memory"
    );

    // A declared length above the cap is refused before anything is held.
    assert_eq!(
        BoundedBody::new(Some(MAX as u64 + 1), MAX).err(),
        Some(BodyError::TooLarge { max: MAX })
    );
    assert_eq!(
        BoundedBody::new(Some(MAX as u64), MAX)
            .expect("at the cap")
            .into_bytes()
            .capacity(),
        MAX
    );

    the_readers_wipe_every_block_they_free();
}

/// One reading of a response, run while the probe is armed.
type Case<'a> = Box<dyn FnOnce() + 'a>;

/// Each reader of a response, across growth, a cut or refusal at its cap,
/// and the drop of what it returned.
fn the_readers_wipe_every_block_they_free() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a runtime");
    let rt = &runtime;
    let cases: Vec<(&str, Case<'_>)> = vec![
        // A success body read whole, growing chunk by chunk.
        (
            "read_limited, grown",
            Box::new(|| {
                let mut answer = response(200, 40);
                let bytes = rt
                    .block_on(read_limited(&mut answer, MAX))
                    .expect("within the cap");
                assert!(is_body(&bytes, 40 * CHUNK_BYTES));
            }),
        ),
        // A success body refused at its cap part of the way through.
        (
            "read_limited, refused",
            Box::new(|| {
                let mut answer = response(200, 10);
                let cap = 5 * CHUNK_BYTES + 500;
                assert_eq!(
                    rt.block_on(read_limited(&mut answer, cap)).err(),
                    Some(BodyError::TooLarge { max: cap })
                );
            }),
        ),
        // A refusal's body read for what it says, growing, then dropped.
        (
            "ErrorBody, grown",
            Box::new(|| {
                let mut answer = response(400, 40);
                let body = rt.block_on(ErrorBody::read(&mut answer));
                assert!(is_body(body.as_bytes(), 40 * CHUNK_BYTES));
            }),
        ),
        // A refusal's body longer than the reading bound, cut there.
        (
            "ErrorBody, cut",
            Box::new(|| {
                let mut answer = response(400, ERROR_BODY_PARSE_BYTES / CHUNK_BYTES + 5);
                let body = rt.block_on(ErrorBody::read(&mut answer));
                assert!(is_body(body.as_bytes(), ERROR_BODY_PARSE_BYTES));
            }),
        ),
        // Read by status: a refusal comes back as its snippet, cut and
        // marked.
        (
            "read_for_status, refusal",
            Box::new(|| {
                let mut answer = response(500, 3);
                let bytes = rt
                    .block_on(read_for_status(&mut answer, MAX))
                    .expect("never refused");
                assert!(bytes.starts_with(&CHUNK[..ERROR_BODY_BYTES.min(CHUNK_BYTES)]));
                assert!(bytes.ends_with(TRUNCATED_SUFFIX.as_bytes()));
            }),
        ),
        // Read by status: a success body, grown.
        (
            "read_for_status, success",
            Box::new(|| {
                let mut answer = response(200, 40);
                let bytes = rt
                    .block_on(read_for_status(&mut answer, MAX))
                    .expect("within the cap");
                assert!(is_body(&bytes, 40 * CHUNK_BYTES));
            }),
        ),
    ];

    for (name, case) in cases {
        let (freed, marked) = watched(case);
        assert!(freed > 0, "{name}: the probe saw no block freed");
        assert_eq!(
            marked, 0,
            "{name}: {marked} unwiped copies of the body in freed memory"
        );
    }
}
