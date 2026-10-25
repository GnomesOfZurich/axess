use super::*;

/// Fills every byte with one value: deterministic shape assertions.
struct FixedRng(u8);
impl SecureRng for FixedRng {
    fn fill_bytes(&self, dest: &mut [u8]) {
        dest.fill(self.0);
    }
}

/// Fills bytes from a counter: distinct codes in one set.
struct CountingRng(std::sync::atomic::AtomicU8);
impl SecureRng for CountingRng {
    fn fill_bytes(&self, dest: &mut [u8]) {
        for b in dest {
            *b = self.0.fetch_add(7, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

fn at(secs: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(secs, 0).unwrap()
}

#[test]
fn a_code_shows_as_two_groups_of_five() {
    let set = generate_recovery_codes(&FixedRng(0), 1);
    let shown: &str = set.display[0].as_ref();
    assert_eq!(shown.len(), RECOVERY_CODE_LENGTH + 1);
    assert_eq!(&shown[5..6], "-");
}

#[test]
fn the_alphabet_is_32_symbols_without_easily_confused_ones() {
    // 32 is what makes `byte % len` uniform over a u8; a different length
    // reintroduces modulo bias.
    assert_eq!(RECOVERY_CODE_ALPHABET.len(), 32);
    for excluded in b"0O1I" {
        assert!(!RECOVERY_CODE_ALPHABET.contains(excluded));
    }
}

#[test]
fn normalizing_undoes_display_formatting_and_case() {
    let expected = normalize_recovery_code("ABCDE-FGHJK");
    assert_eq!(&*expected, "ABCDEFGHJK");
    let lower = normalize_recovery_code(" abcde fghjk ");
    assert_eq!(&*lower, "ABCDEFGHJK");
}

#[test]
fn a_set_holds_only_hashes_and_verifies_each_code_once() {
    let rng = CountingRng(std::sync::atomic::AtomicU8::new(1));
    let set = generate_recovery_codes(&rng, 3);
    assert_eq!(set.config.remaining(), 3);
    for (shown, stored) in set.display.iter().zip(&set.config.codes) {
        let shown: &str = shown.as_ref();
        assert!(
            !stored.hash.contains(&shown.replace('-', "")),
            "no plaintext stored"
        );
    }

    let first: &str = set.display[0].as_ref();
    let after = verify_recovery_code(&set.config, &first.to_lowercase(), at(100), None)
        .expect("the code verifies, typed in lower case");
    assert_eq!(after.remaining(), 2);
    assert_eq!(after.codes[0].used_at, Some(at(100)));
    assert!(
        verify_recovery_code(&after, first, at(200), None).is_none(),
        "a spent code does not verify again"
    );
    let second: &str = set.display[1].as_ref();
    assert!(verify_recovery_code(&after, second, at(300), None).is_some());
}

#[test]
fn malformed_or_unknown_codes_do_not_verify() {
    let set = generate_recovery_codes(&FixedRng(3), 1);
    assert!(verify_recovery_code(&set.config, "", at(1), None).is_none());
    assert!(
        verify_recovery_code(&set.config, "ABCDE", at(1), None).is_none(),
        "too short"
    );
    assert!(
        verify_recovery_code(&set.config, "00000-00000", at(1), None).is_none(),
        "outside the alphabet"
    );
    assert!(
        verify_recovery_code(&set.config, "ZZZZZ-ZZZZZ", at(1), None).is_none(),
        "not in the set"
    );
}

fn pepper() -> RecoveryCodePepper {
    RecoveryCodePepper::new(vec![0x5Au8; 32]).unwrap()
}

#[test]
fn a_short_pepper_is_refused() {
    let err = RecoveryCodePepper::new(vec![1u8; 31]).unwrap_err();
    assert_eq!(err, PepperTooShort { got: 31 });
    assert!(RecoveryCodePepper::new(vec![1u8; 32]).is_ok());
}

#[test]
fn the_pepper_debug_prints_no_bytes() {
    assert_eq!(format!("{:?}", pepper()), "RecoveryCodePepper(***)");
}

#[test]
fn a_peppered_set_stores_the_tagged_mac_and_verifies_once() {
    let rng = CountingRng(std::sync::atomic::AtomicU8::new(1));
    let set = generate_recovery_codes_peppered(&rng, 3, &pepper());
    for (shown, stored) in set.display.iter().zip(&set.config.codes) {
        let plain: &str = &shown.replace('-', "");
        assert!(stored.hash.starts_with(KEYED_CODE_PREFIX));
        assert_eq!(stored.hash.len(), KEYED_CODE_PREFIX.len() + 64);
        assert!(!stored.hash.contains(plain), "no plaintext stored");
    }
    assert!(!set.config.needs_slow_verification());

    let p = pepper();
    let first: &str = set.display[0].as_ref();
    let after = verify_recovery_code(&set.config, &first.to_lowercase(), at(100), Some(&p))
        .expect("the keyed code verifies, typed in lower case");
    assert_eq!(after.remaining(), 2);
    assert_eq!(after.codes[0].used_at, Some(at(100)));
    assert!(verify_recovery_code(&after, first, at(200), Some(&p)).is_none());
    let third: &str = set.display[2].as_ref();
    let after = verify_recovery_code(&after, third, at(300), Some(&p)).unwrap();
    assert_eq!(after.codes[2].used_at, Some(at(300)));
}

#[test]
fn the_stored_mac_is_the_hmac_of_the_domain_and_the_canonical_code() {
    // Pins the construction so a stored row stays verifiable across releases.
    let set = generate_recovery_codes_peppered(&FixedRng(0), 1, &pepper());
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&[0x5Au8; 32]).unwrap();
    mac.update(b"axess/recovery-code/v1\0");
    mac.update(b"AAAAAAAAAA");
    let expected = format!("hmac-sha256:{}", hex::encode(mac.finalize().into_bytes()));
    assert_eq!(set.config.codes[0].hash, expected);
}

#[test]
fn a_keyed_row_never_verifies_without_the_pepper_or_under_another() {
    let set = generate_recovery_codes_peppered(&FixedRng(2), 2, &pepper());
    let shown: &str = set.display[0].as_ref();
    assert!(verify_recovery_code(&set.config, shown, at(1), None).is_none());
    let other = RecoveryCodePepper::new(vec![0x11u8; 32]).unwrap();
    assert!(verify_recovery_code(&set.config, shown, at(1), Some(&other)).is_none());
}

#[test]
fn rows_stored_by_the_previous_release_still_verify() {
    // The previous release wrote `password_auth::generate_hash(canonical)`
    // with no tag; this literal is one such row, captured from that release.
    let legacy = StoredRecoveryCode {
        hash: "$argon2id$v=19$m=19456,t=2,p=1$voiY5VTMAUcmoARp7sKOIQ$v3MaMmC3cYh7wPtRTiwfdnF134601LMEYmj4+4JJwDg".to_owned(),
        used_at: None,
    };
    assert!(legacy.hash.starts_with("$argon2id$"));
    let config = RecoveryCodesConfig {
        codes: vec![legacy],
    };
    assert!(config.needs_slow_verification());
    let after = verify_recovery_code(&config, "abcde-fghjk", at(5), None)
        .expect("an untagged row takes the Argon2id path");
    assert_eq!(after.codes[0].used_at, Some(at(5)));
    assert!(
        verify_recovery_code(&config, "ZZZZZ-ZZZZZ", at(5), Some(&pepper())).is_none(),
        "a pepper does not disturb the Argon2id path"
    );
}

#[test]
fn a_mixed_set_verifies_both_forms() {
    let p = pepper();
    let keyed =
        generate_recovery_codes_peppered(&CountingRng(std::sync::atomic::AtomicU8::new(1)), 1, &p);
    let argon = generate_recovery_codes(&CountingRng(std::sync::atomic::AtomicU8::new(100)), 1);
    let config = RecoveryCodesConfig {
        codes: vec![keyed.config.codes[0].clone(), argon.config.codes[0].clone()],
    };
    let k: &str = keyed.display[0].as_ref();
    let a: &str = argon.display[0].as_ref();
    let after = verify_recovery_code(&config, a, at(1), Some(&p)).unwrap();
    assert_eq!(after.codes[1].used_at, Some(at(1)));
    assert!(after.codes[0].used_at.is_none());
    let after = verify_recovery_code(&config, k, at(2), Some(&p)).unwrap();
    assert_eq!(after.codes[0].used_at, Some(at(2)));
}

#[test]
fn a_spent_argon2_row_makes_the_set_cheap() {
    let mut set = generate_recovery_codes(&FixedRng(4), 1);
    set.config.codes[0].used_at = Some(at(1));
    assert!(!set.config.needs_slow_verification());
}

#[test]
fn every_row_is_examined_wherever_the_match_sits() {
    let p = pepper();
    let rng = CountingRng(std::sync::atomic::AtomicU8::new(9));
    let set = generate_recovery_codes_peppered(&rng, 10, &p);
    for hit in [0usize, 4, 9] {
        let canonical = set.display[hit].replace('-', "");
        let mac = p.mac(&canonical);
        let (found, examined) = find_match(&set.config, &canonical, Some(&mac));
        assert_eq!(found, Some(hit));
        assert_eq!(examined, 10, "no early exit for a match at {hit}");
    }
    let miss = p.mac("AAAAAAAAAA");
    let (found, examined) = find_match(&set.config, "AAAAAAAAAA", Some(&miss));
    assert_eq!((found, examined), (None, 10));
}

#[test]
fn a_spent_keyed_row_does_not_match_and_a_malformed_one_is_inert() {
    let p = pepper();
    let mut set = generate_recovery_codes_peppered(&FixedRng(6), 3, &p);
    set.config.codes[0].used_at = Some(at(1));
    set.config.codes[1].hash = format!("{KEYED_CODE_PREFIX}not-hex");
    let canonical = set.display[0].replace('-', "");
    let mac = p.mac(&canonical);
    // FixedRng makes all three codes identical; row 0 is spent and row 1 is
    // corrupt, so only row 2 can match, and it is the one chosen.
    let (found, examined) = find_match(&set.config, &canonical, Some(&mac));
    assert_eq!((found, examined), (Some(2), 3));
}
