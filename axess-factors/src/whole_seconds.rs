//! Spans a stored configuration keeps as a whole count of seconds.
//!
//! The field is a `std::time::Duration` in the API and is written and read as
//! the integer it was stored as before, under the name it had, so a stored
//! row keeps its bytes. A span with a fraction of a second, or one too large
//! for the integer, is refused when written, never rounded: the setting that
//! holds it is refused by name where it is configured, and this is the last
//! line behind that.

use std::time::Duration;

/// The whole seconds of `span`, or `None` when it has a fraction of a second.
fn whole(span: &Duration) -> Option<u64> {
    (span.subsec_nanos() == 0).then_some(span.as_secs())
}

/// The refusal of a span the stored form cannot hold.
fn unstorable<E: serde::ser::Error>(span: &Duration, form: &str) -> E {
    E::custom(format!(
        "a span of {span:?} cannot be stored: it is kept as a whole count of seconds in a {form}"
    ))
}

/// A `Duration` stored as a `u32` of seconds.
#[cfg(any(feature = "totp", feature = "email_otp"))]
pub(crate) mod u32_seconds {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub(crate) fn serialize<S: Serializer>(span: &Duration, out: S) -> Result<S::Ok, S::Error> {
        let secs = super::whole(span)
            .and_then(|secs| u32::try_from(secs).ok())
            .ok_or_else(|| super::unstorable(span, "u32"))?;
        out.serialize_u32(secs)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(input: D) -> Result<Duration, D::Error> {
        u32::deserialize(input).map(|secs| Duration::from_secs(u64::from(secs)))
    }
}

/// An optional `Duration` stored as an optional `u64` of seconds.
#[cfg(any(feature = "oauth", feature = "outbound-oauth"))]
pub(crate) mod option_u64_seconds {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub(crate) fn serialize<S: Serializer>(
        span: &Option<Duration>,
        out: S,
    ) -> Result<S::Ok, S::Error> {
        match span {
            None => out.serialize_none(),
            Some(span) => {
                let secs = super::whole(span).ok_or_else(|| super::unstorable(span, "u64"))?;
                out.serialize_some(&secs)
            }
        }
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        input: D,
    ) -> Result<Option<Duration>, D::Error> {
        Option::<u64>::deserialize(input).map(|secs| secs.map(Duration::from_secs))
    }
}

#[cfg(test)]
mod tests;
