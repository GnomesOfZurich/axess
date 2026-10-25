//! Hashes written by 0.10.0 (`password_auth::generate_hash`, random salt)
//! captured as literals, so verification is checked against bytes this crate
//! did not produce.

use super::*;

const LONG: &str = concat!(
    "long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-",
    "long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-",
    "long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-",
    "long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-",
    "long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-",
);

fn fixtures() -> [(String, &'static str); 5] {
    [
        (
            "Gnomes2+".into(),
            "$argon2id$v=19$m=19456,t=2,p=1$YT0eBJkc+fGx9d4XXuZw1Q$gQu/cRWKR8AUZnd2leNgYrLDl+P77Ytb6YNMWnNoRgM",
        ),
        (
            "correct horse battery staple".into(),
            "$argon2id$v=19$m=19456,t=2,p=1$lSxZamf8cX+C/JeSUOkj+Q$c6fRxnDxkbuhe/Cl53q5pNfxyPKPOn3AfrODMuz/nw8",
        ),
        (
            "pässwörd-Ωmega-日本語-🔑".into(),
            "$argon2id$v=19$m=19456,t=2,p=1$eqipBo7xJhY0IqQeu2pi4Q$fh+W9JvbsBqFFtwq/8rNivnNGJxEeuN2vDV8YrYOm7A",
        ),
        (
            LONG.into(),
            "$argon2id$v=19$m=19456,t=2,p=1$q7/0H+zbFgbzmplCgSz3gA$49f79xDu6AMRT6SK2wM5qVAVDhgNi4XYIeeJ7JfFvaU",
        ),
        (
            String::new(),
            "$argon2id$v=19$m=19456,t=2,p=1$+hUlOPOOwrmwPZUAcNQPzA$/fjtMpi1UWbmVXBRU0gKuuQ9oxo4PXhLCFLIiQpiJAs",
        ),
    ]
}

#[test]
fn hashes_written_by_the_previous_release_verify() {
    for (password, hash) in fixtures() {
        assert!(
            verify_password(&password, hash).is_ok(),
            "legacy hash for {:?} did not verify",
            password.chars().take(12).collect::<String>()
        );
    }
}

#[test]
fn a_legacy_hash_rejects_every_other_fixture_password() {
    let all = fixtures();
    for (i, (_, hash)) in all.iter().enumerate() {
        for (j, (other, _)) in all.iter().enumerate() {
            if i != j {
                assert!(verify_password(other, hash).is_err());
            }
        }
    }
}

#[test]
fn the_legacy_recovery_code_row_verifies() {
    // `password_auth::generate_hash("ABCDEFGHJK")`, as stored with no tag.
    let hash = "$argon2id$v=19$m=19456,t=2,p=1$voiY5VTMAUcmoARp7sKOIQ$v3MaMmC3cYh7wPtRTiwfdnF134601LMEYmj4+4JJwDg";
    assert!(verify_password("ABCDEFGHJK", hash).is_ok());
    assert!(verify_password("ABCDEFGHJL", hash).is_err());
}

#[test]
fn a_hash_made_now_has_the_legacy_parameter_block() {
    let (_, legacy) = fixtures()[0].clone();
    let fresh = generate_password_hash("Gnomes2+");
    let block = |h: &str| h.split('$').take(4).collect::<Vec<_>>().join("$");
    assert_eq!(block(&fresh), block(legacy));
    let fields = |h: &str| h.split('$').count();
    assert_eq!(fields(&fresh), fields(legacy), "same PHC field layout");
    let tag_len = |h: &str| h.rsplit('$').next().map(str::len);
    assert_eq!(tag_len(&fresh), tag_len(legacy), "same 32-byte output");
}

#[test]
fn the_error_says_whether_the_hash_or_the_password_was_wrong() {
    let (_, hash) = fixtures()[0].clone();
    assert_eq!(
        verify_password("nope", hash),
        Err(PasswordVerifyError::Mismatch)
    );
    for junk in ["", "not a hash", "$argon2id$v=19$m=19456,t=2,p=1$"] {
        assert_eq!(
            verify_password("Gnomes2+", junk),
            Err(PasswordVerifyError::Malformed),
            "{junk:?}"
        );
    }
}
