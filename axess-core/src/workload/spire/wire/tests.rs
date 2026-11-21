//! The wire reader and the frame decoder: what they read, what they
//! refuse, and that no input makes them panic or over-read.

use proptest::prelude::*;

use super::*;

fn varint(value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    put_varint(&mut out, value);
    out
}

#[test]
fn a_varint_reads_back_at_every_width() {
    for value in [
        0,
        1,
        127,
        128,
        300,
        16_383,
        16_384,
        u64::from(u32::MAX),
        u64::MAX,
    ] {
        // Field 1, wire type 0.
        let mut message = vec![0x08];
        message.extend(varint(value));
        let mut reader = Reader::new(&message);
        assert_eq!(reader.next_field(), Ok(Some((1, Field::Varint(value)))));
        assert_eq!(reader.next_field(), Ok(None));
    }
}

#[test]
fn an_eleven_byte_varint_is_refused() {
    let mut message = vec![0x08];
    message.extend([0xFF; 10]);
    message.push(0x01);
    assert_eq!(
        Reader::new(&message).next_field(),
        Err(WireError::VarintOverflow)
    );
}

#[test]
fn a_tenth_varint_byte_above_one_is_refused() {
    let mut message = vec![0x08];
    message.extend([0xFF; 9]);
    message.push(0x02);
    assert_eq!(
        Reader::new(&message).next_field(),
        Err(WireError::VarintOverflow)
    );
}

#[test]
fn a_varint_that_never_ends_is_truncated() {
    assert_eq!(
        Reader::new(&[0x08, 0x80, 0x80]).next_field(),
        Err(WireError::Truncated)
    );
}

#[test]
fn field_zero_is_refused() {
    assert_eq!(
        Reader::new(&[0x00, 0x00]).next_field(),
        Err(WireError::FieldNumber(0))
    );
}

#[test]
fn groups_are_refused() {
    // Field 1 with wire types 3 (start group) and 4 (end group).
    assert_eq!(
        Reader::new(&[0x0B]).next_field(),
        Err(WireError::WireType(3))
    );
    assert_eq!(
        Reader::new(&[0x0C]).next_field(),
        Err(WireError::WireType(4))
    );
}

#[test]
fn a_length_past_the_end_is_refused_before_it_is_sliced() {
    // Field 1, length-delimited, claiming 5 bytes with 2 present.
    assert_eq!(
        Reader::new(&[0x0A, 0x05, 0xAA, 0xBB]).next_field(),
        Err(WireError::Length {
            claimed: 5,
            left: 2
        })
    );
    // A length no machine holds.
    let mut message = vec![0x0A];
    message.extend(varint(u64::MAX));
    assert_eq!(
        Reader::new(&message).next_field(),
        Err(WireError::Length {
            claimed: u64::MAX,
            left: 0
        })
    );
}

#[test]
fn fixed_width_fields_read_little_endian() {
    let mut message = vec![0x09];
    message.extend(0x0102_0304_0506_0708u64.to_le_bytes());
    message.push(0x15);
    message.extend(0xDEAD_BEEFu32.to_le_bytes());
    let mut reader = Reader::new(&message);
    assert_eq!(
        reader.next_field(),
        Ok(Some((1, Field::Fixed64(0x0102_0304_0506_0708))))
    );
    assert_eq!(
        reader.next_field(),
        Ok(Some((2, Field::Fixed32(0xDEAD_BEEF))))
    );
    assert_eq!(reader.next_field(), Ok(None));
}

#[test]
fn a_truncated_fixed_field_is_refused() {
    assert_eq!(
        Reader::new(&[0x09, 1, 2, 3]).next_field(),
        Err(WireError::Truncated)
    );
}

#[test]
fn put_bytes_writes_what_the_reader_reads() {
    let mut message = Vec::new();
    put_bytes(&mut message, 3, b"spiffe://example.org/a");
    put_bytes(&mut message, 536_870_911, b"");
    let mut reader = Reader::new(&message);
    assert_eq!(
        reader.next_field(),
        Ok(Some((
            3,
            Field::Bytes(b"spiffe://example.org/a".as_slice())
        )))
    );
    assert_eq!(
        reader.next_field(),
        Ok(Some((536_870_911, Field::Bytes(b"".as_slice()))))
    );
    assert_eq!(reader.next_field(), Ok(None));
}

#[test]
fn a_frame_is_a_zero_flag_a_big_endian_length_and_the_message() {
    assert_eq!(frame(b"abc")[..], [0u8, 0, 0, 0, 3, b'a', b'b', b'c'][..]);
    assert_eq!(frame(b"")[..], [0u8, 0, 0, 0, 0][..]);
}

#[test]
fn the_decoder_waits_for_a_whole_frame() {
    let mut decoder = FrameDecoder::new(16);
    let whole = frame(b"hello");
    decoder.push(&whole[..3]);
    assert_eq!(decoder.next_message(), Ok(None));
    decoder.push(&whole[3..7]);
    assert_eq!(decoder.next_message(), Ok(None));
    assert!(!decoder.is_empty());
    decoder.push(&whole[7..]);
    assert_eq!(
        decoder.next_message(),
        Ok(Some(Zeroizing::new(b"hello".to_vec())))
    );
    assert!(decoder.is_empty());
    assert_eq!(decoder.next_message(), Ok(None));
}

#[test]
fn the_decoder_keeps_what_follows_a_message_when_its_buffer_is_replaced() {
    // Three frames in one chunk, then a fourth that makes the buffer grow:
    // each replacement of the buffer carries the unread bytes over.
    let mut decoder = FrameDecoder::new(4096);
    let mut body = Vec::new();
    for message in [b"one".as_slice(), b"two", b"three"] {
        body.extend_from_slice(&frame(message));
    }
    decoder.push(&body);
    let long = vec![7u8; 2000];
    let first = decoder.next_message().expect("a frame");
    let mut read = vec![first.expect("a message").to_vec()];
    decoder.push(&frame(&long));
    while let Some(message) = decoder.next_message().expect("a frame") {
        read.push(message.to_vec());
    }
    assert_eq!(
        read,
        [b"one".to_vec(), b"two".to_vec(), b"three".to_vec(), long]
    );
    assert!(decoder.is_empty());
}

#[test]
fn the_decoder_refuses_a_frame_over_the_limit_from_its_prefix_alone() {
    let mut decoder = FrameDecoder::new(4);
    // Only the prefix has arrived, claiming 5 bytes.
    decoder.push(&[0, 0, 0, 0, 5]);
    assert_eq!(
        decoder.next_message(),
        Err(WireError::MessageTooLarge { len: 5, max: 4 })
    );
}

#[test]
fn the_decoder_refuses_a_compressed_frame_and_an_unknown_flag() {
    let mut compressed = FrameDecoder::new(16);
    compressed.push(&[1, 0, 0, 0, 0]);
    assert_eq!(compressed.next_message(), Err(WireError::Compressed));
    let mut unknown = FrameDecoder::new(16);
    unknown.push(&[7, 0, 0, 0, 0]);
    assert_eq!(unknown.next_message(), Err(WireError::FrameFlag(7)));
}

proptest! {
    /// Any `u64` survives the varint encoding.
    #[test]
    fn varints_round_trip(value in any::<u64>()) {
        let mut message = vec![0x08];
        message.extend(varint(value));
        let mut reader = Reader::new(&message);
        prop_assert_eq!(reader.next_field(), Ok(Some((1, Field::Varint(value)))));
        prop_assert_eq!(reader.next_field(), Ok(None));
    }

    /// Fields written by `put_bytes` read back in order, whatever they hold.
    #[test]
    fn delimited_fields_round_trip(
        fields in proptest::collection::vec(
            (1u32..=536_870_911, proptest::collection::vec(any::<u8>(), 0..64)),
            0..8,
        ),
    ) {
        let mut message = Vec::new();
        for (number, value) in &fields {
            put_bytes(&mut message, *number, value);
        }
        let mut reader = Reader::new(&message);
        for (number, value) in &fields {
            prop_assert_eq!(
                reader.next_field(),
                Ok(Some((*number, Field::Bytes(value.as_slice()))))
            );
        }
        prop_assert_eq!(reader.next_field(), Ok(None));
    }

    /// No bytes make the reader panic, loop, or hand out a slice from
    /// outside the message: it ends in `None` or in an error, having
    /// consumed at most the message.
    #[test]
    fn the_reader_ends_on_any_input(message in proptest::collection::vec(any::<u8>(), 0..256)) {
        let mut reader = Reader::new(&message);
        let mut read = 0usize;
        while let Ok(Some((number, field))) = reader.next_field() {
            prop_assert!(number >= 1);
            if let Field::Bytes(value) = field {
                read += value.len();
            }
            prop_assert!(read <= message.len());
        }
    }

    /// However the body is cut into chunks, the decoder gives the same
    /// messages.
    #[test]
    fn the_decoder_does_not_depend_on_the_chunking(
        messages in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..40), 0..6),
        cut in 1usize..17,
    ) {
        let mut body = Vec::new();
        for message in &messages {
            body.extend_from_slice(&frame(message));
        }
        let mut decoder = FrameDecoder::new(64);
        let mut decoded = Vec::new();
        for chunk in body.chunks(cut) {
            decoder.push(chunk);
            while let Some(message) = decoder.next_message().expect("well-formed frames") {
                decoded.push(message.to_vec());
            }
        }
        prop_assert!(decoder.is_empty());
        prop_assert_eq!(decoded, messages);
    }

    /// No bytes make the decoder panic or give a message over its limit.
    #[test]
    fn the_decoder_holds_its_limit_on_any_input(body in proptest::collection::vec(any::<u8>(), 0..128)) {
        let mut decoder = FrameDecoder::new(16);
        decoder.push(&body);
        while let Ok(Some(message)) = decoder.next_message() {
            prop_assert!(message.len() <= 16);
        }
    }
}
