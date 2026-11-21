//! The key a session is stored, registered, recorded and logged under.
//!
//! A session id is what a cookie carries: whoever holds it holds the
//! session. A [`SessionKey`] is the SHA-256 of a fixed tag and that id, so
//! a store, a registry, an audit record or a log line can name the session
//! without holding a value a cookie could carry.
//!
//! There are two ways from a session id to a key, and only two, each a
//! name a reader can search for: [`SessionKey::of`], and
//! [`SessionKey::from_recorded`] for a record an earlier release wrote.
//! The type has no `From` conversion from an id, a UUID, bytes or text, no
//! default and no view as a string. [`SessionKey::try_from_hex`] cannot
//! read a session id by accident either: it checks the length first, a key
//! is 64 characters, the four text forms of an id are 36, 32, 38 and 45
//! characters, and a cookie value holds a dot.

use std::fmt::{self, Write as _};
use std::str::FromStr;

use sha2::{Digest, Sha256};

use crate::{SessionId, Uuid};

/// The 21 bytes hashed before a session id: the ASCII text
/// `axess.session-key.v1` and one zero byte.
pub const SESSION_KEY_DOMAIN: [u8; 21] = *b"axess.session-key.v1\0";

/// The lowercase hexadecimal digits, by value.
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// The name a session is stored, registered, recorded and logged under:
/// SHA-256 over [`SESSION_KEY_DOMAIN`] and the 16 bytes of the session id.
///
/// The text form ([`Display`](fmt::Display), serde, a SQL column) is 64
/// lowercase hexadecimal characters. `Debug` prints the log form, eight
/// characters, so a derived `Debug` of a type that holds a key does not
/// print the whole of it.
///
/// ```
/// use axess_identity::{SessionId, SessionKey};
///
/// let id = SessionId::from_bytes([7; 16]);
/// let key = SessionKey::of(&id);
/// assert_eq!(
///     key.to_string(),
///     "010680961e7389e91169c898e25ec530a925e360b5b40f08b82f44d4f25e796d",
/// );
/// assert_eq!(key.prefix().to_string(), "01068096...");
/// assert_eq!(key.to_string().parse::<SessionKey>(), Ok(key));
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct SessionKey([u8; 32]);

impl SessionKey {
    /// The length of the text form.
    pub const HEX_LEN: usize = 64;

    /// The key of a session id. The one way from a session id to a key.
    pub fn of(id: &SessionId) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(SESSION_KEY_DOMAIN);
        hasher.update(id.as_bytes());
        Self(hasher.finalize().into())
    }

    /// A key from its 32 bytes: one read back from a binary column, or the
    /// name of a registry entry that is not a session.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// A key from its text form: exactly 64 characters, each of `0-9a-f`.
    ///
    /// The length is checked before any character is read, so no text form
    /// of a session id and no cookie value is ever parsed. An uppercase
    /// digit is refused: one key has one text.
    pub fn try_from_hex(text: &str) -> Result<Self, SessionKeyError> {
        let digits = text.as_bytes();
        if digits.len() != Self::HEX_LEN {
            return Err(SessionKeyError);
        }
        // 64 bytes are 32 pairs with nothing left over.
        let (pairs, _) = digits.as_chunks::<2>();
        let mut bytes = [0u8; 32];
        for (byte, [high, low]) in bytes.iter_mut().zip(pairs) {
            let (Some(high), Some(low)) = (hex_value(*high), hex_value(*low)) else {
                return Err(SessionKeyError);
            };
            *byte = (high << 4) | low;
        }
        Ok(Self(bytes))
    }

    /// A key from the text a record holds in a field that names a session:
    /// the 64 characters of a key, or a session id in any text form, which
    /// an earlier release wrote there and which reads as the key of that id.
    ///
    /// A text of 64 characters is read as a key and as nothing else (it is
    /// not lenient there: 64 characters that are not lowercase hexadecimal
    /// fail). Any other text is read as a UUID, in the hyphenated, simple,
    /// braced or URN form and in either case, and gives [`SessionKey::of`]
    /// that id, so a record of an earlier release and a record of this one
    /// name the same session by the same key.
    pub fn from_recorded(text: &str) -> Result<Self, SessionKeyError> {
        if text.len() == Self::HEX_LEN {
            return Self::try_from_hex(text);
        }
        Uuid::parse_str(text)
            .map(|uuid| Self::of(&SessionId::from_uuid(uuid)))
            .map_err(|_| SessionKeyError)
    }

    /// The 32 bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The form a log line prints: the first eight characters of the text
    /// form, then three dots.
    pub fn prefix(&self) -> SessionKeyPrefix {
        SessionKeyPrefix([self.0[0], self.0[1], self.0[2], self.0[3]])
    }
}

/// The value of one lowercase hexadecimal digit.
fn hex_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

/// Write `bytes` as lowercase hexadecimal, two characters a byte.
fn write_hex(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for byte in bytes {
        f.write_char(char::from(HEX_DIGITS[usize::from(byte >> 4)]))?;
        f.write_char(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]))?;
    }
    Ok(())
}

impl fmt::Display for SessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.0)
    }
}

impl fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SessionKey({})", self.prefix())
    }
}

impl FromStr for SessionKey {
    type Err = SessionKeyError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::try_from_hex(text)
    }
}

/// The log form of a [`SessionKey`]: its first eight hexadecimal
/// characters and three dots. Enough to follow one session through a
/// trace, and not enough to look its row up.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SessionKeyPrefix([u8; 4]);

impl fmt::Display for SessionKeyPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.0)?;
        f.write_str("...")
    }
}

impl fmt::Debug for SessionKeyPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// A text that is not a session key. It does not carry the text: what was
/// refused may be a session id, and an error is logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a session key is 64 lowercase hexadecimal characters")]
pub struct SessionKeyError;

/// Reads a key from a string through `read`, for the serde readers.
#[cfg(feature = "serde")]
struct KeyText(fn(&str) -> Result<SessionKey, SessionKeyError>);

#[cfg(feature = "serde")]
impl serde::de::Visitor<'_> for KeyText {
    type Value = SessionKey;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a session key")
    }

    // The error is the type's own, which holds no text. The error serde
    // builds for an unexpected value quotes that value, and the refused
    // text may be a session id.
    fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<SessionKey, E> {
        (self.0)(text).map_err(E::custom)
    }
}

/// Reads an optional key from a string, or from nothing, for
/// [`SessionKey::deserialize_recorded_option`].
#[cfg(feature = "serde")]
struct RecordedOption;

#[cfg(feature = "serde")]
impl<'de> serde::de::Visitor<'de> for RecordedOption {
    type Value = Option<SessionKey>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a session key, a session id, or nothing")
    }

    fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_some<D: serde::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        SessionKey::deserialize_recorded(d).map(Some)
    }
}

/// The text form. A human-readable format and a binary one write the same
/// 64 characters, so a record reads the same whichever wrote it.
#[cfg(feature = "serde")]
impl serde::Serialize for SessionKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// The strict reader: [`SessionKey::try_from_hex`]. A session id is
/// refused; a field an earlier release wrote names
/// [`SessionKey::deserialize_recorded`] instead.
#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for SessionKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_str(KeyText(SessionKey::try_from_hex))
    }
}

#[cfg(feature = "serde")]
impl SessionKey {
    /// Serde reader for a record field that names a session and may have
    /// been written by a release that stored the session id there
    /// (`#[serde(deserialize_with = "SessionKey::deserialize_recorded")]`).
    /// It reads what [`SessionKey::from_recorded`] reads.
    pub fn deserialize_recorded<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_str(KeyText(SessionKey::from_recorded))
    }

    /// The same for an optional field, beside `#[serde(default)]`.
    pub fn deserialize_recorded_option<'de, D: serde::Deserializer<'de>>(
        d: D,
    ) -> Result<Option<Self>, D::Error> {
        d.deserialize_option(RecordedOption)
    }
}

// sqlx integration, through `String` as the typed ids do it: the column
// holds the 64 characters of the text form, and a value read back that is
// not such a text is a decode error.
#[cfg(feature = "sqlx")]
impl<DB> sqlx::Type<DB> for SessionKey
where
    DB: sqlx::Database,
    String: sqlx::Type<DB>,
{
    fn type_info() -> <DB as sqlx::Database>::TypeInfo {
        <String as sqlx::Type<DB>>::type_info()
    }

    fn compatible(ty: &<DB as sqlx::Database>::TypeInfo) -> bool {
        <String as sqlx::Type<DB>>::compatible(ty)
    }
}

#[cfg(feature = "sqlx")]
impl<'q, DB> sqlx::Encode<'q, DB> for SessionKey
where
    DB: sqlx::Database,
    String: sqlx::Encode<'q, DB>,
{
    fn encode_by_ref(
        &self,
        buf: &mut <DB as sqlx::Database>::ArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        <String as sqlx::Encode<'q, DB>>::encode_by_ref(&self.to_string(), buf)
    }
}

#[cfg(feature = "sqlx")]
impl<'r, DB> sqlx::Decode<'r, DB> for SessionKey
where
    DB: sqlx::Database,
    String: sqlx::Decode<'r, DB>,
{
    fn decode(
        value: <DB as sqlx::Database>::ValueRef<'r>,
    ) -> Result<Self, sqlx::error::BoxDynError> {
        let text = <String as sqlx::Decode<'r, DB>>::decode(value)?;
        Self::try_from_hex(&text).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests;
