//! Per-record subkeys: the seal that the random-nonce limit does not bound,
//! and the earlier layout that is still read.

use super::*;

const KEY: [u8; 32] = [5u8; 32];
const A: &[u8] = b"row-a";
const B: &[u8] = b"row-b";

/// An RNG that always answers the same bytes: the worst case for a scheme
/// that depends on a fresh draw per seal.
struct Stuck;

impl SecureRng for Stuck {
    fn fill_bytes(&self, dest: &mut [u8]) {
        dest.fill(0x42);
    }
}

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(x, y)| x ^ y).collect()
}

/// With a repeated draw, the direct layout reuses key and nonce, so two
/// ciphertexts XOR to the XOR of their plaintexts. A subkey is derived from
/// the row too, so rows keep distinct keystreams even then.
#[test]
fn a_repeated_random_draw_does_not_reuse_a_keystream_across_rows() {
    let crypto = SessionCrypto::new(KEY).with_rng(Arc::new(Stuck));
    let (p1, p2) = (b"AAAAAAAAAAAAAAAA", b"BBBBBBBBBBBBBBBB");

    let direct1 = crypto.encrypt_with_aad(&[], p1).unwrap();
    let direct2 = crypto.encrypt_with_aad(&[], p2).unwrap();
    assert_eq!(
        xor(
            &direct1[NONCE_LEN..NONCE_LEN + 16],
            &direct2[NONCE_LEN..NONCE_LEN + 16]
        ),
        xor(p1, p2),
        "the direct layout under a stuck RNG leaks the XOR of the plaintexts"
    );

    let bound1 = crypto.seal_bound(BoundFormat::SESSION, A, p1).unwrap();
    let bound2 = crypto.seal_bound(BoundFormat::SESSION, B, p2).unwrap();
    let skip = 4 + crate::subkey::SALT_LEN;
    assert_ne!(
        xor(&bound1[skip..skip + 16], &bound2[skip..skip + 16]),
        xor(p1, p2),
        "bound blobs of two rows must not share a keystream"
    );
}

#[test]
fn a_bound_blob_is_written_in_the_subkeyed_layout_and_is_not_stale() {
    let crypto = SessionCrypto::new(KEY);
    let sealed = crypto.seal_bound(BoundFormat::SESSION, A, b"data").unwrap();
    assert!(sealed.starts_with(&BoundFormat::SESSION.subkeyed_magic()));
    assert!(!sealed.starts_with(&BoundFormat::SESSION.magic));
    assert!(BoundFormat::SESSION.marks(&sealed));
    let opened = crypto
        .open_bound(BoundFormat::SESSION, A, &[], &sealed)
        .unwrap();
    assert_eq!(opened.plaintext, b"data");
    assert!(!opened.stale);
    // Two seals of one plaintext differ: the salt is fresh.
    let again = crypto.seal_bound(BoundFormat::SESSION, A, b"data").unwrap();
    assert_ne!(sealed, again);
}

#[test]
fn a_subkeyed_blob_opens_only_for_its_row_and_its_salt() {
    let crypto = SessionCrypto::new(KEY);
    let sealed = crypto.seal_bound(BoundFormat::SESSION, A, b"data").unwrap();
    assert!(
        crypto
            .open_bound(BoundFormat::SESSION, B, &[], &sealed)
            .is_err()
    );
    let mut salted = sealed.clone();
    salted[4] ^= 1;
    assert!(
        crypto
            .open_bound(BoundFormat::SESSION, A, &[], &salted)
            .is_err()
    );
    let mut flipped = sealed.clone();
    *flipped.last_mut().unwrap() ^= 1;
    assert!(
        crypto
            .open_bound(BoundFormat::SESSION, A, &[], &flipped)
            .is_err()
    );
    // A body that is too short for a salt and a tag is refused, not panicked on.
    let mut short = BoundFormat::SESSION.subkeyed_magic().to_vec();
    short.extend_from_slice(&[0u8; crate::subkey::SALT_LEN]);
    assert!(
        crypto
            .open_bound(BoundFormat::SESSION, A, &[], &short)
            .is_err()
    );
}

#[test]
fn the_earlier_direct_layout_of_the_current_format_is_read_and_stale() {
    let crypto = SessionCrypto::new(KEY);
    let body = crypto
        .encrypt_with_aad(&BoundFormat::SESSION.aad(A), b"old layout")
        .unwrap();
    let mut blob = BoundFormat::SESSION.magic.to_vec();
    blob.extend_from_slice(&body);
    assert!(BoundFormat::SESSION.marks(&blob));
    let opened = crypto
        .open_bound(BoundFormat::SESSION, A, &[], &blob)
        .unwrap();
    assert_eq!(opened.plaintext, b"old layout");
    assert!(
        opened.stale,
        "the caller re-seals it in the subkeyed layout"
    );
    assert!(
        crypto
            .open_bound(BoundFormat::SESSION, B, &[], &blob)
            .is_err()
    );
}

#[test]
fn a_subkeyed_blob_under_the_previous_key_is_stale() {
    let old = SessionCrypto::new([1u8; 32]);
    let sealed = old.seal_bound(BoundFormat::SESSION, A, b"rotated").unwrap();
    let rotated = SessionCrypto::new([2u8; 32]).with_previous_key([1u8; 32]);
    let opened = rotated
        .open_bound(BoundFormat::SESSION, A, &[], &sealed)
        .unwrap();
    assert_eq!(opened.plaintext, b"rotated");
    assert!(opened.stale);
    assert!(
        SessionCrypto::new([2u8; 32])
            .open_bound(BoundFormat::SESSION, A, &[], &sealed)
            .is_err()
    );
}

/// The meter counts the seals that spend the random-nonce budget, and only
/// those: a bound blob is under a subkey and is not one of them.
#[test]
fn the_seal_meter_counts_direct_seals_and_not_subkeyed_ones() {
    let crypto = SessionCrypto::new(KEY);
    let clone = crypto.clone();
    assert_eq!(crypto.seals(), 0);
    crypto.encrypt_with_aad(b"aad", b"x").unwrap();
    clone.encrypt_with_aad(b"aad", b"y").unwrap();
    assert_eq!(crypto.seals(), 2, "clones share one meter");
    crypto.seal_bound(BoundFormat::SESSION, A, b"z").unwrap();
    assert_eq!(crypto.seals(), 2);
}

/// Cost of a seal and an open, direct against subkeyed, for a 2 KiB payload.
/// Run by hand: `cargo test -p axess-core --all-features --lib
/// subkey_tests::seal_cost -- --ignored --nocapture`.
#[test]
#[ignore = "timing measurement, run by hand"]
fn seal_cost() {
    use std::time::Instant;
    let crypto = SessionCrypto::new(KEY);
    let payload = vec![7u8; 2048];
    let aad = BoundFormat::SESSION.aad(A);
    let n = 20_000u32;

    let t = Instant::now();
    let mut direct = Vec::new();
    for _ in 0..n {
        direct = crypto.encrypt_with_aad(&aad, &payload).unwrap();
    }
    let direct_seal = t.elapsed() / n;
    let t = Instant::now();
    for _ in 0..n {
        crypto.decrypt_with_aad(&aad, &direct).unwrap();
    }
    let direct_open = t.elapsed() / n;

    let t = Instant::now();
    let mut keyed = Vec::new();
    for _ in 0..n {
        keyed = crypto
            .seal_bound(BoundFormat::SESSION, A, &payload)
            .unwrap();
    }
    let keyed_seal = t.elapsed() / n;
    let t = Instant::now();
    for _ in 0..n {
        crypto
            .open_bound(BoundFormat::SESSION, A, &[], &keyed)
            .unwrap();
    }
    let keyed_open = t.elapsed() / n;

    println!(
        "2 KiB payload, {n} rounds: direct seal {direct_seal:?} open {direct_open:?}; \
         subkeyed seal {keyed_seal:?} open {keyed_open:?}; \
         overhead {} bytes",
        keyed.len() as i64 - direct.len() as i64
    );
}
