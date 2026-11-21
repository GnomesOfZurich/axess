//! `tests`: the unit tests of `session_key.rs`.

use super::*;

/// The three recorded vectors: a session id, its key and its log form.
/// The keys were computed outside this crate (SHA-256 of the 21 tag bytes
/// and the 16 id bytes).
const VECTORS: [([u8; 16], &str, &str); 3] = [
    (
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ],
        "4be3d46ff665b81b0ec659ea7440156ff7d1c34920b374d5f1c17a56d7fd94c8",
        "4be3d46f...",
    ),
    (
        [0; 16],
        "0421f24466fc2c4540f0e6538f36180ccadbe875058956bbd653b54888b20c5f",
        "0421f244...",
    ),
    (
        [7; 16],
        "010680961e7389e91169c898e25ec530a925e360b5b40f08b82f44d4f25e796d",
        "01068096...",
    ),
];

/// The id of the first vector, in the four text forms a UUID has.
const ID_FORMS: [&str; 4] = [
    "00112233-4455-6677-8899-aabbccddeeff",
    "00112233445566778899aabbccddeeff",
    "{00112233-4455-6677-8899-aabbccddeeff}",
    "urn:uuid:00112233-4455-6677-8899-aabbccddeeff",
];

fn first_id() -> SessionId {
    SessionId::from_bytes(VECTORS[0].0)
}

#[test]
fn the_domain_tag_is_its_recorded_bytes() {
    assert_eq!(
        SESSION_KEY_DOMAIN,
        [
            0x61, 0x78, 0x65, 0x73, 0x73, 0x2e, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x2d,
            0x6b, 0x65, 0x79, 0x2e, 0x76, 0x31, 0x00,
        ]
    );
}

#[test]
fn the_key_of_an_id_is_its_recorded_vector() {
    for (bytes, key, log_form) in VECTORS {
        let computed = SessionKey::of(&SessionId::from_bytes(bytes));
        assert_eq!(computed.to_string(), key);
        assert_eq!(computed.prefix().to_string(), log_form);
        assert_eq!(format!("{:?}", computed.prefix()), log_form);
    }
}

#[test]
fn the_text_form_reads_back_as_the_same_key() {
    for (bytes, text, _) in VECTORS {
        let key = SessionKey::of(&SessionId::from_bytes(bytes));
        assert_eq!(key.to_string().len(), SessionKey::HEX_LEN);
        assert_eq!(key.to_string().parse::<SessionKey>(), Ok(key));
        assert_eq!(SessionKey::try_from_hex(text), Ok(key));
        assert_eq!(SessionKey::from_bytes(*key.as_bytes()), key);
    }
}

#[test]
fn two_ids_have_two_keys() {
    let one = SessionKey::of(&SessionId::from_bytes([1; 16]));
    let mut other_bytes = [1; 16];
    other_bytes[15] = 0;
    let other = SessionKey::of(&SessionId::from_bytes(other_bytes));
    assert_ne!(one, other);
    assert_ne!(one.to_string(), other.to_string());
}

#[test]
fn a_text_of_another_length_is_not_a_key() {
    let text = VECTORS[0].1;
    assert_eq!(SessionKey::try_from_hex(&text[..63]), Err(SessionKeyError));
    assert_eq!(
        SessionKey::try_from_hex(&format!("{text}0")),
        Err(SessionKeyError)
    );
    assert_eq!(SessionKey::try_from_hex(""), Err(SessionKeyError));
}

#[test]
fn an_uppercase_or_foreign_digit_is_not_a_key() {
    let text = VECTORS[0].1;
    // One digit in upper case: near the start and in the middle of the
    // first vector, and at the first and the last place of the third.
    for (text, at) in [(text, 1), (text, 31), (VECTORS[2].1, 63), ("f0", 0)] {
        let mut upper = format!("{text:0<64}");
        let digit = upper[at..=at].to_ascii_uppercase();
        assert_ne!(digit, &upper[at..=at], "the digit at {at} is a letter");
        assert!(SessionKey::try_from_hex(&upper).is_ok());
        upper.replace_range(at..=at, &digit);
        assert_eq!(SessionKey::try_from_hex(&upper), Err(SessionKeyError));
    }
    assert_eq!(
        SessionKey::try_from_hex(&text.to_ascii_uppercase()),
        Err(SessionKeyError)
    );
    for foreign in ["g", " ", "-", "+", "\u{0}"] {
        let mut other = text.to_string();
        other.replace_range(10..=10, foreign);
        assert_eq!(other.len(), 64);
        assert_eq!(SessionKey::try_from_hex(&other), Err(SessionKeyError));
    }
    // 64 bytes that are fewer characters.
    let wide = format!("{}\u{e9}", &text[..62]);
    assert_eq!(wide.len(), 64);
    assert_eq!(SessionKey::try_from_hex(&wide), Err(SessionKeyError));
}

#[test]
fn no_form_of_a_session_id_parses_as_a_key() {
    let id = first_id();
    let uuid = id.as_uuid();
    let forms = [
        id.to_string(),
        uuid.simple().to_string(),
        uuid.braced().to_string(),
        uuid.urn().to_string(),
    ];
    assert_eq!(forms.map(|form| form.len()), [36, 32, 38, 45]);
    for form in ID_FORMS {
        assert_eq!(SessionKey::try_from_hex(form), Err(SessionKeyError));
        assert_eq!(form.parse::<SessionKey>(), Err(SessionKeyError));
        assert_eq!(
            SessionKey::try_from_hex(&form.to_ascii_uppercase()),
            Err(SessionKeyError)
        );
    }
    // A signed cookie value: 22 characters of the id, a dot, 43 of the tag.
    let cookie = format!("{}.{}", "A".repeat(22), "B".repeat(43));
    assert_eq!(SessionKey::try_from_hex(&cookie), Err(SessionKeyError));
    // The same shape cut to a key's length still holds the dot.
    assert_eq!(
        SessionKey::try_from_hex(&cookie[..64]),
        Err(SessionKeyError)
    );
}

#[test]
fn debug_prints_eight_characters_of_a_key() {
    // A struct of the adopter's that holds a key and derives `Debug`.
    #[derive(Debug)]
    struct Holder {
        key: SessionKey,
    }

    let (bytes, text, _) = VECTORS[0];
    let key = SessionKey::of(&SessionId::from_bytes(bytes));
    assert_eq!(format!("{key:?}"), "SessionKey(4be3d46f...)");
    let holder = Holder { key };
    assert_eq!(holder.key, key);
    let held = format!("{holder:?}");
    assert_eq!(held, "Holder { key: SessionKey(4be3d46f...) }");
    for printed in [format!("{key:?}"), held, format!("{holder:#?}")] {
        assert!(printed.contains(&text[..8]));
        assert!(
            !printed.contains(&text[..9]),
            "the ninth character: {printed}"
        );
    }
}

#[test]
fn the_error_does_not_hold_the_refused_text() {
    let refused = first_id().to_string();
    let error = SessionKey::try_from_hex(&refused).unwrap_err();
    for printed in [error.to_string(), format!("{error:?}")] {
        assert!(!printed.contains(&refused));
        assert!(!printed.contains(&refused[..8]));
    }
    assert_eq!(
        error.to_string(),
        "a session key is 64 lowercase hexadecimal characters"
    );
}

#[test]
fn a_recorded_key_reads_as_that_key() {
    for (bytes, text, _) in VECTORS {
        assert_eq!(
            SessionKey::from_recorded(text),
            Ok(SessionKey::of(&SessionId::from_bytes(bytes)))
        );
    }
}

#[test]
fn a_recorded_session_id_reads_as_the_key_of_that_id() {
    let key = SessionKey::of(&first_id());
    assert_eq!(key.to_string(), VECTORS[0].1);
    for form in ID_FORMS {
        assert_eq!(SessionKey::from_recorded(form), Ok(key), "{form}");
        assert_eq!(
            SessionKey::from_recorded(&form.to_ascii_uppercase().replace("URN:UUID:", "urn:uuid:")),
            Ok(key),
            "{form} in upper case"
        );
    }
    // The key of the id, never the id's bytes with zeroes after them.
    let mut padded = [0u8; 32];
    padded[..16].copy_from_slice(first_id().as_bytes());
    assert_ne!(
        SessionKey::from_recorded(ID_FORMS[0]),
        Ok(SessionKey::from_bytes(padded))
    );
}

#[test]
fn a_recorded_text_that_is_neither_is_refused() {
    let text = VECTORS[0].1;
    for refused in [
        text.to_ascii_uppercase(),
        text[..63].to_string(),
        format!("{text}0"),
        String::new(),
        "a session".to_string(),
        "00112233-4455-6677-8899-aabbccddeef".to_string(),
        // 64 characters that hold a UUID are a key's length, so they are
        // read as a key and fail as one.
        format!("{:<64}", ID_FORMS[0]),
    ] {
        assert_eq!(
            SessionKey::from_recorded(&refused),
            Err(SessionKeyError),
            "{refused:?}"
        );
    }
}

#[cfg(feature = "serde")]
mod serde_form {
    use super::*;

    #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    struct Record {
        #[serde(deserialize_with = "SessionKey::deserialize_recorded")]
        session: SessionKey,
        #[serde(default, deserialize_with = "SessionKey::deserialize_recorded_option")]
        former: Option<SessionKey>,
    }

    #[test]
    fn serde_writes_the_text_form() {
        let key = SessionKey::of(&first_id());
        let written = serde_json::to_string(&key).unwrap();
        assert_eq!(written, format!("\"{}\"", VECTORS[0].1));
        assert_eq!(serde_json::from_str::<SessionKey>(&written).unwrap(), key);
    }

    #[cfg_attr(
        miri,
        ignore = "serde_json reports an error's position through memchr's aligned SSE2 load, which the symbolic alignment check reports as a false positive; the cases that read a key back still run under Miri"
    )]
    #[test]
    fn the_strict_reader_refuses_an_uppercase_key_and_a_session_id() {
        let upper = format!("\"{}\"", VECTORS[0].1.to_ascii_uppercase());
        assert!(serde_json::from_str::<SessionKey>(&upper).is_err());
        for form in ID_FORMS {
            let error = serde_json::from_str::<SessionKey>(&format!("\"{form}\"")).unwrap_err();
            assert!(
                !error.to_string().contains(&form[..8]),
                "the error quotes the refused text: {error}"
            );
        }
        assert!(serde_json::from_str::<SessionKey>("17").is_err());
    }

    #[test]
    fn a_record_of_an_earlier_release_reads_as_the_key_of_its_id() {
        let key = SessionKey::of(&first_id());
        for form in ID_FORMS {
            let record: Record =
                serde_json::from_str(&format!(r#"{{"session":"{form}","former":"{form}"}}"#))
                    .unwrap();
            assert_eq!(
                record,
                Record {
                    session: key,
                    former: Some(key)
                }
            );
        }
    }

    #[test]
    fn a_record_of_this_release_reads_back() {
        let record = Record {
            session: SessionKey::of(&first_id()),
            former: Some(SessionKey::of(&SessionId::from_bytes([7; 16]))),
        };
        let written = serde_json::to_string(&record).unwrap();
        assert!(written.contains(VECTORS[0].1));
        assert!(written.contains(VECTORS[2].1));
        assert_eq!(serde_json::from_str::<Record>(&written).unwrap(), record);
    }

    #[test]
    fn an_optional_recorded_field_may_be_absent_or_null() {
        let text = VECTORS[0].1;
        for written in [
            format!(r#"{{"session":"{text}"}}"#),
            format!(r#"{{"session":"{text}","former":null}}"#),
        ] {
            let record: Record = serde_json::from_str(&written).unwrap();
            assert_eq!(record.former, None);
        }
    }

    #[cfg_attr(
        miri,
        ignore = "serde_json reports an error's position through memchr's aligned SSE2 load, which the symbolic alignment check reports as a false positive; the cases that read a Record still run under Miri"
    )]
    #[test]
    fn a_recorded_field_refuses_what_is_neither_a_key_nor_an_id() {
        let upper = VECTORS[0].1.to_ascii_uppercase();
        for written in [
            format!(r#"{{"session":"{upper}"}}"#),
            r#"{"session":"a session"}"#.to_string(),
            format!(r#"{{"session":"{}","former":"{upper}"}}"#, VECTORS[0].1),
            format!(r#"{{"session":"{}","former":7}}"#, VECTORS[0].1),
        ] {
            assert!(
                serde_json::from_str::<Record>(&written).is_err(),
                "{written}"
            );
        }
    }
}

/// The archive of a key is its 32 bytes, as the archive of an id is its 16.
#[cfg(feature = "rkyv")]
#[test]
fn rkyv_archives_the_32_bytes() {
    let key = SessionKey::of(&first_id());
    let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&key).unwrap();
    assert_eq!(&bytes[..], key.as_bytes());
    let back: SessionKey = rkyv::from_bytes::<SessionKey, rkyv::rancor::Error>(&bytes).unwrap();
    assert_eq!(back, key);
}

/// A key bound into a TEXT column is its 64 characters, and reads back.
#[cfg(feature = "sqlx")]
#[cfg_attr(
    miri,
    ignore = "the tokio runtime starts an I/O driver, which Miri does not support"
)]
#[tokio::test]
async fn sqlx_binds_and_reads_the_text_form() {
    use sqlx::sqlite::SqlitePoolOptions;

    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::query("CREATE TABLE names (name TEXT NOT NULL PRIMARY KEY)")
        .execute(&pool)
        .await
        .unwrap();

    let key = SessionKey::of(&first_id());
    sqlx::query("INSERT INTO names (name) VALUES (?1)")
        .bind(key)
        .execute(&pool)
        .await
        .unwrap();

    let text: (String,) = sqlx::query_as("SELECT name FROM names")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(text.0, VECTORS[0].1);
    let read: (SessionKey,) = sqlx::query_as("SELECT name FROM names")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(read.0, key);

    // A column that holds a session id's text is not a key.
    sqlx::query("UPDATE names SET name = ?1")
        .bind(first_id().to_string())
        .execute(&pool)
        .await
        .unwrap();
    let refused: Result<(SessionKey,), _> = sqlx::query_as("SELECT name FROM names")
        .fetch_one(&pool)
        .await;
    assert!(refused.is_err());
}
