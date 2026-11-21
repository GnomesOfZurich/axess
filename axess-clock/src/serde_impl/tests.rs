use crate::date::UtcDate;
use crate::timestamp::Timestamp;
use crate::until::Until;
use serde::de::value::{Error, I64Deserializer, StrDeserializer, UnitDeserializer};
use serde::de::{Deserialize, IntoDeserializer};
use serde::ser::{Impossible, Serialize, Serializer};

/// A serializer that takes a string and nothing else, and hands it back.
struct Text;

/// The methods of [`Serializer`] that take one value that is not a string.
macro_rules! refuse {
    ($($method:ident($($argument:ty),*);)*) => {
        $(
            fn $method(self, $(_: $argument),*) -> Result<String, Error> {
                Err(serde::ser::Error::custom("not a string"))
            }
        )*
    };
}

/// The methods of [`Serializer`] that open a sequence, a map or a struct.
macro_rules! refuse_compound {
    ($($method:ident($($argument:ty),*) -> $compound:ident;)*) => {
        $(
            fn $method(self, $(_: $argument),*) -> Result<Self::$compound, Error> {
                Err(serde::ser::Error::custom("not a string"))
            }
        )*
    };
}

impl Serializer for Text {
    type Ok = String;
    type Error = Error;
    type SerializeSeq = Impossible<String, Error>;
    type SerializeTuple = Impossible<String, Error>;
    type SerializeTupleStruct = Impossible<String, Error>;
    type SerializeTupleVariant = Impossible<String, Error>;
    type SerializeMap = Impossible<String, Error>;
    type SerializeStruct = Impossible<String, Error>;
    type SerializeStructVariant = Impossible<String, Error>;

    fn serialize_str(self, text: &str) -> Result<String, Error> {
        Ok(text.to_owned())
    }

    refuse! {
        serialize_bool(bool);
        serialize_i8(i8);
        serialize_i16(i16);
        serialize_i32(i32);
        serialize_i64(i64);
        serialize_u8(u8);
        serialize_u16(u16);
        serialize_u32(u32);
        serialize_u64(u64);
        serialize_f32(f32);
        serialize_f64(f64);
        serialize_char(char);
        serialize_bytes(&[u8]);
        serialize_none();
        serialize_unit();
        serialize_unit_struct(&'static str);
        serialize_unit_variant(&'static str, u32, &'static str);
    }

    refuse_compound! {
        serialize_seq(Option<usize>) -> SerializeSeq;
        serialize_tuple(usize) -> SerializeTuple;
        serialize_tuple_struct(&'static str, usize) -> SerializeTupleStruct;
        serialize_tuple_variant(&'static str, u32, &'static str, usize) -> SerializeTupleVariant;
        serialize_map(Option<usize>) -> SerializeMap;
        serialize_struct(&'static str, usize) -> SerializeStruct;
        serialize_struct_variant(&'static str, u32, &'static str, usize) -> SerializeStructVariant;
    }

    fn serialize_some<T: Serialize + ?Sized>(self, _: &T) -> Result<String, Error> {
        Err(serde::ser::Error::custom("not a string"))
    }

    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _: &'static str,
        _: &T,
    ) -> Result<String, Error> {
        Err(serde::ser::Error::custom("not a string"))
    }

    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: &T,
    ) -> Result<String, Error> {
        Err(serde::ser::Error::custom("not a string"))
    }
}

fn written<T: Serialize>(value: &T) -> String {
    value.serialize(Text).expect("written as a string")
}

fn read<'de, T: Deserialize<'de>>(text: &'de str) -> Result<T, String> {
    let text: StrDeserializer<'de, Error> = text.into_deserializer();
    T::deserialize(text).map_err(|error| error.to_string())
}

fn at(secs: i64, nanos: u32) -> Timestamp {
    Timestamp::new(secs, nanos).expect("a reading inside the range")
}

/// 2026-01-01T00:00:00Z as Unix seconds.
const R: i64 = 1_767_225_600;

#[test]
fn a_reading_is_written_as_its_z_text_and_read_back() {
    let cases = [
        (at(R, 0), "2026-01-01T00:00:00Z"),
        (at(R, 500_000_000), "2026-01-01T00:00:00.500Z"),
        (at(R, 123_456_000), "2026-01-01T00:00:00.123456Z"),
        (at(R, 100_000_001), "2026-01-01T00:00:00.100000001Z"),
        (at(-1, 999_999_999), "1969-12-31T23:59:59.999999999Z"),
        (at(253_402_300_800, 0), "+10000-01-01T00:00:00Z"),
        (at(-62_167_219_201, 0), "-0001-12-31T23:59:59Z"),
        (Timestamp::MAX, "+262142-12-31T23:59:59.999999999Z"),
        (Timestamp::MIN, "-262143-01-01T00:00:00Z"),
    ];
    for (reading, text) in cases {
        assert_eq!(written(&reading), text);
        assert_eq!(read::<Timestamp>(text), Ok(reading), "{text}");
    }
}

#[test]
fn the_other_stored_forms_of_a_reading_read() {
    for text in [
        "2026-01-01T00:00:00+00:00",
        "2026-01-01T01:00:00+01:00",
        "2025-12-31T19:30:00-04:30",
        "2026-01-01t00:00:00z",
        "2026-01-01 00:00:00Z",
        "2026-01-01T00:00:00.000Z",
        "2026-01-01T00:00:00.000000000000Z",
        "2026-01-01T00:00:00+0000",
        "2026-01-01T00:00:00 UTC",
        "2026-01-01T00:00:00 +00:00",
    ] {
        assert_eq!(read::<Timestamp>(text), Ok(at(R, 0)), "{text}");
    }
    assert_eq!(
        read::<Timestamp>("2026-01-01T00:00:00.1234567899Z"),
        Ok(at(R, 123_456_789))
    );
}

#[test]
fn a_text_that_is_no_reading_is_refused_with_the_reason() {
    let cases = [
        ("", "the text ends before the value is complete"),
        ("2026-01-01", "the text ends before the value is complete"),
        (
            "2026-01-01T00:00:00",
            "the text ends before the value is complete",
        ),
        (
            "2026-13-01T00:00:00Z",
            "the value is outside the range the type holds",
        ),
        (
            "2026-02-30T00:00:00Z",
            "the value is outside the range the type holds",
        ),
        (
            "2026-01-01T24:00:00Z",
            "the value is outside the range the type holds",
        ),
        (
            "2026-01-01T00:00:00+24:00",
            "the value is outside the range the type holds",
        ),
        (
            "2026-01-01T00:00:00Zjunk",
            "the text continues after the value",
        ),
        (
            "1767225600",
            "the text holds a character the format has no place for",
        ),
    ];
    for (text, reason) in cases {
        assert_eq!(read::<Timestamp>(text), Err(reason.to_owned()), "{text:?}");
        assert_eq!(read::<Until>(text), Err(reason.to_owned()), "{text:?}");
    }
}

#[test]
fn a_number_is_not_a_reading() {
    let number: I64Deserializer<Error> = 1_767_225_600_i64.into_deserializer();
    assert_eq!(
        Timestamp::deserialize(number).map_err(|error| error.to_string()),
        Err(
            "invalid type: integer `1767225600`, expected an RFC 3339 formatted date and time \
             string"
                .to_owned()
        )
    );
    let number: I64Deserializer<Error> = 20_454_i64.into_deserializer();
    assert_eq!(
        UtcDate::deserialize(number).map_err(|error| error.to_string()),
        Err("invalid type: integer `20454`, expected a date written as YYYY-MM-DD".to_owned())
    );
}

#[test]
fn an_optional_reading_needs_no_helper() {
    let absent: UnitDeserializer<Error> = ().into_deserializer();
    assert_eq!(Option::<Timestamp>::deserialize(absent), Ok(None));
    let absent: UnitDeserializer<Error> = ().into_deserializer();
    assert_eq!(Option::<Until>::deserialize(absent), Ok(None));
}

#[test]
fn forever_is_written_as_the_stored_value_and_read_back_as_forever() {
    let stored = "+262142-12-31T23:59:59.999999999Z";
    assert_eq!(written(&Until::Forever), stored);
    assert_eq!(read::<Until>(stored), Ok(Until::Forever));
    // An end at the stored value itself is the same text.
    assert_eq!(written(&Until::At(Timestamp::MAX)), stored);

    let near = "+262142-12-31T23:59:59.999999998Z";
    let end = Until::At(at(8_210_266_876_799, 999_999_998));
    assert_eq!(written(&end), near);
    assert_eq!(read::<Until>(near), Ok(end));

    let end = Until::At(at(R + 900, 250_000_000));
    assert_eq!(written(&end), "2026-01-01T00:15:00.250Z");
    assert_eq!(read::<Until>("2026-01-01T00:15:00.250Z"), Ok(end));
    assert_eq!(read::<Until>("2026-01-01T01:15:00.250+01:00"), Ok(end));
}

#[test]
fn a_date_is_written_as_year_month_day_and_read_back() {
    let cases = [
        ((2026, 2, 28), "2026-02-28"),
        ((1, 1, 1), "0001-01-01"),
        ((10_000, 1, 1), "+10000-01-01"),
        ((-1, 12, 31), "-0001-12-31"),
        ((262_142, 12, 31), "+262142-12-31"),
        ((-262_143, 1, 1), "-262143-01-01"),
    ];
    for ((year, month, day), text) in cases {
        let date = UtcDate::new(year, month, day).expect("a day of the calendar");
        assert_eq!(written(&date), text);
        assert_eq!(read::<UtcDate>(text), Ok(date), "{text}");
    }
    assert_eq!(
        read::<UtcDate>("2026-02-30"),
        Err("the value is outside the range the type holds".to_owned())
    );
    assert_eq!(
        read::<UtcDate>("2026-2-28"),
        Err("the text holds a character the format has no place for".to_owned())
    );
    assert_eq!(
        read::<UtcDate>("2026-02-28T00:00:00Z"),
        Err("the text holds a character the format has no place for".to_owned())
    );
}
