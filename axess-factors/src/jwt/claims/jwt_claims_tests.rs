use super::*;

#[test]
fn an_extreme_iat_is_out_of_range_not_an_overflow() {
    for iat in [i64::MIN, i64::MAX] {
        let payload = serde_json::json!({ "iat": iat });
        assert!(
            matches!(
                check_iat(&payload, 1_700_000_000),
                IatCheck::OutOfRange { .. }
            ),
            "iat {iat} must be out of range"
        );
    }
}

/// `MAX_JWT_BYTES` is exactly 8192 (8 KiB). Pins
/// the `8 * 1024` expression against `+` (1032) and `/` (0)
/// mutations; both would silently change the size cap.
#[test]
fn max_jwt_bytes_is_eight_kib() {
    assert_eq!(MAX_JWT_BYTES, 8192, "MAX_JWT_BYTES must be 8 * 1024 = 8192");
}

/// `decode_jwt_payload` rejects with size error only when
/// strictly above 8192 bytes. At exactly 8192 the size check passes
/// (we then fail downstream on parts-split). Pins the `>` operator
/// against `==`/`>=` mutations. Uses a hardcoded literal
/// rather than `MAX_JWT_BYTES` so the test discriminates
/// even when the constant is mutated.
#[test]
fn decode_jwt_payload_size_boundary_is_strict_greater_than() {
    // Exactly at the cap; must NOT be rejected as oversized.
    let at_cap = "x".repeat(8192);
    let err = decode_jwt_payload(&at_cap).expect_err("non-JWT payload still fails downstream");
    assert!(
        !err.contains("too large"),
        "at exactly 8192 bytes the size guard must pass (got: {err})"
    );

    // One byte over; must be rejected as oversized.
    let over_cap = "x".repeat(8193);
    let err = decode_jwt_payload(&over_cap).expect_err("oversized must reject");
    assert!(
        err.contains("too large"),
        "8193 bytes must trigger the size guard (got: {err})"
    );
}

/// `aud_contains` accepts an array `aud` whose elements
/// contain the client_id. Pins both `delete match arm Array(arr)`
/// and `== → !=` mutations. Without an array-aud
/// positive test, the array branch could be removed entirely
/// without breaking any test.
#[test]
fn aud_contains_accepts_array_with_matching_client_id() {
    let payload = serde_json::json!({
        "aud": ["other-rp", "this-client", "yet-another-rp"]
    });
    assert!(
        aud_contains(&payload, "this-client"),
        "array aud containing client_id must match"
    );
    assert!(
        !aud_contains(&payload, "not-listed"),
        "array aud not containing client_id must reject"
    );
}

/// `azp_satisfied` skips the `azp` requirement when `aud`
/// is a single-element array (OIDC §2 only mandates `azp` when
/// `aud` has multiple values). Pins the match guard `arr.len() > 1`
/// against `true`/`==`/`>=` mutations.
#[test]
fn azp_satisfied_skips_azp_for_single_element_array_aud() {
    let payload = serde_json::json!({
        "aud": ["this-client"],
    });
    assert!(
        azp_satisfied(&payload, "this-client"),
        "single-element array aud must not require azp"
    );
}

/// `azp_satisfied` returns `true` when `aud` is a multi-
/// element array AND `azp` matches the relying party's client_id.
#[test]
fn azp_satisfied_accepts_multi_element_aud_when_azp_matches() {
    let payload = serde_json::json!({
        "aud": ["this-client", "other-rp"],
        "azp": "this-client",
    });
    assert!(
        azp_satisfied(&payload, "this-client"),
        "multi-element aud with matching azp must be accepted"
    );
}

/// `aud_contains` matches when `aud` is a single JSON String
/// (the other RFC 7519 form). Pins `delete match arm
/// Some(serde_json::Value::String(s))` and `s == client_id → !=`
/// without a positive String-aud test, both mutations slip
/// through (the Array branch keeps the test suite green).
#[test]
fn aud_contains_accepts_single_string_with_matching_client_id() {
    let payload = serde_json::json!({ "aud": "this-client" });
    assert!(
        aud_contains(&payload, "this-client"),
        "single-string aud equal to client_id must match"
    );
    assert!(
        !aud_contains(&payload, "other-client"),
        "single-string aud different from client_id must reject \
         (kills `== → !=` on line 46)"
    );
}

/// `check_iat` pins the `age = now - iat` subtraction and the
/// `(-60..=MAX_IAT_AGE_SECS).contains(&age)` range. Discriminates
/// `- → +`, `- → /`, and `delete -` mutations:
///
/// - `iat = now`: age = 0 → in range → Ok. Under `+`, age =
///   `2 * now` ≈ 4e9 → out of range. Under `/`, age = 1 → still
///   Ok (no kill). Under `delete -`, age is unspecified; hits
///   subtraction shape.
/// - `iat = now - 600`: age = 600 → out of range → OutOfRange.
///   Under `+`, age = `2*now - 600` → still out of range; under
///   `/`, age = `now / iat` ≈ 1 → Ok (kill).
/// - `iat = now + 30`: age = -30 → in range → Ok. Under `+`,
///   age = `2*now + 30` → out of range (kill).
///
/// Together the three fixtures kill all three mutants. The "now"
/// constant is large enough that division collapses to a
/// near-constant (~1), and subtraction with a small offset stays
/// inside the range only for the strictly-subtracted form.
#[test]
fn check_iat_pins_subtraction_against_plus_div_and_delete() {
    // Use an absolute timestamp far from zero so the relational
    // tests are unambiguous.
    let now: i64 = 1_700_000_000;

    // iat == now → Ok.
    let p = serde_json::json!({ "iat": now });
    assert!(matches!(check_iat(&p, now), IatCheck::Ok));

    // iat = now - 600 → age 600s, out of MAX_IAT_AGE_SECS=300 → OutOfRange.
    let p = serde_json::json!({ "iat": now - 600 });
    assert!(
        matches!(check_iat(&p, now), IatCheck::OutOfRange { .. }),
        "iat older than 300s must reject (kills `- → /` which would yield ~1)"
    );

    // iat = now + 30 → age -30s, within the [-60..=300] window → Ok.
    let p = serde_json::json!({ "iat": now + 30 });
    assert!(
        matches!(check_iat(&p, now), IatCheck::Ok),
        "iat 30s in the future must be accepted within 60s skew \
         (kills `- → +` which would explode age to ~2e9)"
    );

    // iat = now + 120 (skew larger than 60s) → age -120s → out of range.
    let p = serde_json::json!({ "iat": now + 120 });
    assert!(
        matches!(check_iat(&p, now), IatCheck::OutOfRange { .. }),
        "iat 120s in the future exceeds 60s skew window"
    );

    // Missing iat → Missing.
    let p = serde_json::json!({ "sub": "x" });
    assert!(matches!(check_iat(&p, now), IatCheck::Missing));
}

/// `azp_satisfied` returns `false` when `aud` is a multi-
/// element array and `azp` is absent or mismatched.
#[test]
fn azp_satisfied_rejects_multi_element_aud_without_matching_azp() {
    // Missing azp.
    let missing = serde_json::json!({
        "aud": ["this-client", "other-rp"],
    });
    assert!(
        !azp_satisfied(&missing, "this-client"),
        "multi-element aud without azp must reject"
    );

    // Mismatched azp.
    let mismatched = serde_json::json!({
        "aud": ["this-client", "other-rp"],
        "azp": "other-rp",
    });
    assert!(
        !azp_satisfied(&mismatched, "this-client"),
        "multi-element aud with non-matching azp must reject"
    );
}

/// A foreign `azp` is refused even when `aud` holds only us.
#[test]
fn azp_satisfied_rejects_foreign_azp_with_single_aud() {
    for aud in [
        serde_json::json!("this-client"),
        serde_json::json!(["this-client"]),
    ] {
        let payload = serde_json::json!({ "aud": aud, "azp": "other-rp" });
        assert!(!azp_satisfied(&payload, "this-client"));
    }
    let non_string = serde_json::json!({ "aud": "this-client", "azp": 7 });
    assert!(!azp_satisfied(&non_string, "this-client"));
}
