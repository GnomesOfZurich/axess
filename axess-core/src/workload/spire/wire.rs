//! The protobuf wire format and the gRPC message framing, as much of each as
//! the Workload API uses.
//!
//! A Workload API message is a handful of strings, byte strings and maps, so
//! the reader here knows the four wire types protobuf still emits (varint,
//! 64-bit, length-delimited, 32-bit) and refuses the two it retired (groups).
//! Every length is checked against the bytes that are left before anything is
//! sliced, and nothing is allocated from a length the peer chose.

use axum::body::Bytes;
use zeroize::Zeroizing;

/// The most bytes a varint occupies: ten groups of seven bits cover 64.
const MAX_VARINT_BYTES: usize = 10;

/// The highest field number protobuf allows (2^29 - 1).
const MAX_FIELD_NUMBER: u64 = 0x1FFF_FFFF;

/// The length of a gRPC message prefix: one flag byte and a big-endian
/// 32-bit length.
pub(crate) const FRAME_PREFIX_BYTES: usize = 5;

/// Why bytes could not be read as a message or as a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum WireError {
    /// The bytes end inside a tag, a varint or a fixed-width value.
    #[error("the message ends inside a field")]
    Truncated,
    /// A varint carries more than 64 bits.
    #[error("a varint is longer than 64 bits")]
    VarintOverflow,
    /// A tag names field zero or a field above the protobuf limit.
    #[error("field number {0} is outside the protobuf range")]
    FieldNumber(u64),
    /// A tag carries a wire type this reader does not accept.
    #[error("wire type {0} is not supported")]
    WireType(u8),
    /// A length-delimited field claims more bytes than the message holds.
    #[error("a field claims {claimed} bytes where {left} are left")]
    Length {
        /// The length the field states.
        claimed: u64,
        /// The bytes left in the message.
        left: usize,
    },
    /// A gRPC frame is marked compressed; the client asks for none.
    #[error("the message is compressed, which this client does not accept")]
    Compressed,
    /// A gRPC frame's flag byte is neither 0 nor 1.
    #[error("the frame flag {0} is not a gRPC flag")]
    FrameFlag(u8),
    /// A gRPC frame states a message longer than the configured limit.
    #[error("a message of {len} bytes is over the limit of {max}")]
    MessageTooLarge {
        /// The length the frame states.
        len: usize,
        /// The configured limit.
        max: usize,
    },
}

/// One field's value, borrowed from the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Field<'a> {
    /// Wire type 0.
    Varint(u64),
    /// Wire type 1, little-endian.
    Fixed64(u64),
    /// Wire type 2: a string, a byte string, a nested message or a map entry.
    Bytes(&'a [u8]),
    /// Wire type 5, little-endian.
    Fixed32(u32),
}

/// Reads the fields of one message in the order they were written.
#[derive(Debug, Clone)]
pub(crate) struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    /// A reader over one whole message.
    pub(crate) fn new(message: &'a [u8]) -> Self {
        Self { rest: message }
    }

    /// The next field as `(number, value)`, or `None` at the end of the
    /// message.
    pub(crate) fn next_field(&mut self) -> Result<Option<(u32, Field<'a>)>, WireError> {
        if self.rest.is_empty() {
            return Ok(None);
        }
        let tag = self.varint()?;
        let number = tag >> 3;
        if number == 0 || number > MAX_FIELD_NUMBER {
            return Err(WireError::FieldNumber(number));
        }
        let field = match (tag & 0b111) as u8 {
            0 => Field::Varint(self.varint()?),
            1 => Field::Fixed64(u64::from_le_bytes(self.fixed()?)),
            2 => Field::Bytes(self.delimited()?),
            5 => Field::Fixed32(u32::from_le_bytes(self.fixed()?)),
            other => return Err(WireError::WireType(other)),
        };
        // `number` is at most 2^29 - 1, checked above.
        Ok(Some((number as u32, field)))
    }

    fn varint(&mut self) -> Result<u64, WireError> {
        let mut value = 0u64;
        for (index, byte) in self.rest.iter().copied().enumerate() {
            if index == MAX_VARINT_BYTES {
                return Err(WireError::VarintOverflow);
            }
            let bits = u64::from(byte & 0x7F);
            // The tenth group has room for one bit of a 64-bit value.
            if index == MAX_VARINT_BYTES - 1 && bits > 1 {
                return Err(WireError::VarintOverflow);
            }
            value |= bits << (7 * index);
            if byte & 0x80 == 0 {
                self.rest = &self.rest[index + 1..];
                return Ok(value);
            }
        }
        Err(WireError::Truncated)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        let (head, tail) = self
            .rest
            .split_first_chunk::<N>()
            .ok_or(WireError::Truncated)?;
        self.rest = tail;
        Ok(*head)
    }

    fn delimited(&mut self) -> Result<&'a [u8], WireError> {
        let claimed = self.varint()?;
        let left = self.rest.len();
        let len = usize::try_from(claimed)
            .ok()
            .filter(|len| *len <= left)
            .ok_or(WireError::Length { claimed, left })?;
        let (head, tail) = self.rest.split_at(len);
        self.rest = tail;
        Ok(head)
    }
}

/// Append `value` as a varint.
pub(crate) fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8 & 0x7F) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

/// Append field `number` as a length-delimited value: a string, a byte
/// string or a nested message.
pub(crate) fn put_bytes(out: &mut Vec<u8>, number: u32, value: &[u8]) {
    put_varint(out, (u64::from(number) << 3) | 2);
    put_varint(out, value.len() as u64);
    out.extend_from_slice(value);
}

/// One message as a gRPC frame: the flag byte for "not compressed", the
/// length, then the message.
pub(crate) fn frame(message: &[u8]) -> Bytes {
    let mut out = Vec::with_capacity(FRAME_PREFIX_BYTES + message.len());
    out.push(0);
    // A request this client writes is a few hundred bytes; a message over
    // 4 GiB cannot be framed at all and is cut here rather than wrapped.
    let len = u32::try_from(message.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&message[..len as usize]);
    Bytes::from(out)
}

/// Reassembles gRPC frames from the chunks HTTP/2 delivers, refusing a frame
/// longer than the limit before any of its body is kept.
///
/// A message may carry a private key or a bearer token, so the decoder wipes
/// what it held of one: its buffer is wiped when it is replaced and when the
/// decoder is dropped, and a message is handed out in memory that wipes
/// itself. The chunks the HTTP/2 layer delivered are that layer's and are
/// not within reach.
pub(crate) struct FrameDecoder {
    buffer: Zeroizing<Vec<u8>>,
    max_message_bytes: usize,
}

impl FrameDecoder {
    /// A decoder that refuses a message longer than `max_message_bytes`.
    pub(crate) fn new(max_message_bytes: usize) -> Self {
        Self {
            buffer: Zeroizing::new(Vec::new()),
            max_message_bytes,
        }
    }

    /// Add a chunk of the response body.
    pub(crate) fn push(&mut self, chunk: &[u8]) {
        let needed = self.buffer.len().saturating_add(chunk.len());
        if needed > self.buffer.capacity() {
            // A `Vec` that grows in place frees its old bytes as they are.
            // Growing into a new buffer lets the old one be wiped.
            let room = needed.max(self.buffer.capacity().saturating_mul(2));
            let mut grown = Zeroizing::new(Vec::with_capacity(room));
            grown.extend_from_slice(&self.buffer);
            self.buffer = grown;
        }
        self.buffer.extend_from_slice(chunk);
    }

    /// Whether no partial frame is waiting for more bytes.
    pub(crate) fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// The next whole message, `None` when more bytes are needed.
    pub(crate) fn next_message(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>, WireError> {
        let Some((prefix, body)) = self.buffer.split_first_chunk::<FRAME_PREFIX_BYTES>() else {
            return Ok(None);
        };
        match prefix[0] {
            0 => {}
            1 => return Err(WireError::Compressed),
            other => return Err(WireError::FrameFlag(other)),
        }
        let len = u32::from_be_bytes([prefix[1], prefix[2], prefix[3], prefix[4]]) as usize;
        if len > self.max_message_bytes {
            return Err(WireError::MessageTooLarge {
                len,
                max: self.max_message_bytes,
            });
        }
        if body.len() < len {
            return Ok(None);
        }
        let message = Zeroizing::new(body[..len].to_vec());
        // What follows the frame moves to a buffer of its own, and the one
        // that held the message is wiped as it is dropped.
        let rest = Zeroizing::new(body[len..].to_vec());
        self.buffer = rest;
        Ok(Some(message))
    }
}

#[cfg(test)]
mod tests;
