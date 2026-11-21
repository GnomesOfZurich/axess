//! serde for the time types, under the `serde` feature.
//!
//! Each type is written as its text and read through its reader, so a field
//! of one of these types, or of an `Option` of one, needs no helper module.

use crate::date::UtcDate;
use crate::timestamp::Timestamp;
use crate::until::Until;
use serde::de::{Deserialize, Deserializer, Error, Visitor};
use serde::ser::{Serialize, Serializer};
use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;

/// Reads a string through the `FromStr` of `T`.
struct TextVisitor<T> {
    expecting: &'static str,
    read: PhantomData<T>,
}

impl<T> Visitor<'_> for TextVisitor<T>
where
    T: FromStr,
    T::Err: fmt::Display,
{
    type Value = T;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.expecting)
    }

    fn visit_str<E: Error>(self, text: &str) -> Result<T, E> {
        text.parse().map_err(E::custom)
    }
}

/// Written as the text of [`Timestamp::to_rfc3339`]: UTC with a `Z` and the
/// fewest of 0, 3, 6 or 9 fraction digits that hold the value.
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// Read from a string through [`Timestamp::parse_rfc3339`], so every form an
/// earlier release stored still reads. A number is refused.
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Timestamp, D::Error> {
        deserializer.deserialize_str(TextVisitor {
            expecting: "an RFC 3339 formatted date and time string",
            read: PhantomData,
        })
    }
}

/// Written as the text of [`Until::to_timestamp`]: `Forever` is the text of
/// [`Until::LEGACY_FOREVER`], the value earlier releases stored for it.
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl Serialize for Until {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_timestamp().serialize(serializer)
    }
}

/// Read as a [`Timestamp`], then through [`Until::from_timestamp`]: exactly
/// [`Until::LEGACY_FOREVER`] reads as `Forever`.
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl<'de> Deserialize<'de> for Until {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Until, D::Error> {
        Timestamp::deserialize(deserializer).map(Until::from_timestamp)
    }
}

/// Written as `YYYY-MM-DD`, with a signed year outside 0 to 9999.
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl Serialize for UtcDate {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// Read from a string of exactly the written form.
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl<'de> Deserialize<'de> for UtcDate {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<UtcDate, D::Error> {
        deserializer.deserialize_str(TextVisitor {
            expecting: "a date written as YYYY-MM-DD",
            read: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests;
