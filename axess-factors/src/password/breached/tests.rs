use super::*;
use crate::password::{
    NewPasswordError, PasswordRules, hash_new_password_checked, verify_password,
};
use sha1::Digest as _;

/// SHA-1 of `password`, upper-case hex, computed here so the vector below
/// is checked against the hash and not only against itself.
fn sha1_upper(password: &str) -> String {
    sha1::Sha1::digest(password.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect()
}

#[test]
fn the_range_prefix_splits_the_upper_case_sha1_at_five() {
    // The published vector: SHA-1("password").
    let (prefix, suffix) = range_prefix("password");
    assert_eq!(prefix, "5BAA6");
    assert_eq!(suffix, "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
    assert_eq!(format!("{prefix}{suffix}"), sha1_upper("password"));

    let (prefix, suffix) = range_prefix("");
    assert_eq!(prefix.len(), 5);
    assert_eq!(suffix.len(), 35);
    assert_eq!(format!("{prefix}{suffix}"), sha1_upper(""));
    assert_eq!(
        format!("{prefix}{suffix}"),
        "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
    );
}

#[test]
fn a_suffix_in_the_range_body_is_counted() {
    let body = "1E2AAA439972480CEC7F16C795BBB429372:1\r\n\
                1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\r\n\
                1E7BF3EA6FDB3D8B5B9A6E2D9F6B1C6E0D5:7\r\n";
    assert_eq!(
        count_in_range(body, "1E4C9B93F3F0682250B6CF8331B7EE68FD8"),
        Some(3_861_493)
    );
    assert_eq!(
        count_in_range(body, "1E2AAA439972480CEC7F16C795BBB429372"),
        Some(1)
    );
}

#[test]
fn a_suffix_absent_from_the_range_body_is_none() {
    let body = "1E2AAA439972480CEC7F16C795BBB429372:1\n";
    assert_eq!(
        count_in_range(body, "1E4C9B93F3F0682250B6CF8331B7EE68FD8"),
        None
    );
    assert_eq!(
        count_in_range("", "1E4C9B93F3F0682250B6CF8331B7EE68FD8"),
        None
    );
}

#[test]
fn a_padded_zero_count_and_a_lower_case_body_are_read() {
    // Padded answers carry `SUFFIX:0` rows; a lower-case body matches too.
    let body = "1e4c9b93f3f0682250b6cf8331b7ee68fd8:0\n";
    assert_eq!(
        count_in_range(body, "1E4C9B93F3F0682250B6CF8331B7EE68FD8"),
        Some(0)
    );
}

#[test]
fn a_malformed_count_or_line_is_skipped() {
    let body = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:many\nno colon here\n:5\n";
    assert_eq!(
        count_in_range(body, "1E4C9B93F3F0682250B6CF8331B7EE68FD8"),
        None
    );
}

#[tokio::test]
async fn the_list_answers_membership_and_the_outage_answers_an_error() {
    let list = BreachedPasswordList::new(["Password123!"]);
    assert_eq!(list.is_breached("Password123!").await, Ok(true));
    assert_eq!(list.is_breached("Gnomes2+andmore").await, Ok(false));

    let outage = BreachCheckOutage::new("range service timed out");
    let err = outage.is_breached("anything").await.unwrap_err();
    assert_eq!(err.to_string(), "range service timed out");
}

#[tokio::test]
async fn no_check_configured_means_no_screening() {
    let rules = PasswordRules::default();
    assert_eq!(
        check_password_breached("Password123!", &rules, None, BreachCheckUnavailable::Refuse).await,
        Ok(())
    );
}

#[tokio::test]
async fn a_breached_password_is_refused_by_name() {
    let list = BreachedPasswordList::new(["Password123!"]);
    let rules = PasswordRules::default();
    assert_eq!(
        check_password_breached(
            "Password123!",
            &rules,
            Some(&list),
            BreachCheckUnavailable::Refuse
        )
        .await,
        Err(NewPasswordError::Breached)
    );
    assert_eq!(
        check_password_breached(
            "Gnomes2+andmore",
            &rules,
            Some(&list),
            BreachCheckUnavailable::Refuse
        )
        .await,
        Ok(())
    );
}

#[tokio::test]
async fn an_exempt_tenant_skips_the_check() {
    let list = BreachedPasswordList::new(["Password123!"]);
    let rules = PasswordRules {
        breached_check: false,
        ..PasswordRules::default()
    };
    assert_eq!(
        check_password_breached(
            "Password123!",
            &rules,
            Some(&list),
            BreachCheckUnavailable::Refuse
        )
        .await,
        Ok(())
    );
}

#[tokio::test]
async fn an_unavailable_check_refuses_unless_the_policy_allows() {
    let outage = BreachCheckOutage::new("range service timed out");
    let rules = PasswordRules::default();
    assert_eq!(
        check_password_breached(
            "Gnomes2+andmore",
            &rules,
            Some(&outage),
            BreachCheckUnavailable::Refuse
        )
        .await,
        Err(NewPasswordError::BreachCheckUnavailable)
    );
    assert_eq!(
        check_password_breached(
            "Gnomes2+andmore",
            &rules,
            Some(&outage),
            BreachCheckUnavailable::Allow
        )
        .await,
        Ok(())
    );
}

#[test]
fn the_policy_defaults_to_refuse() {
    assert_eq!(
        BreachCheckUnavailable::default(),
        BreachCheckUnavailable::Refuse
    );
}

#[tokio::test]
async fn the_checked_hash_refuses_rules_then_breach_then_hashes() {
    let list = BreachedPasswordList::new(["Password123!"]);
    let rules = PasswordRules::default();
    let policy = BreachCheckUnavailable::Refuse;
    assert_eq!(
        hash_new_password_checked("short1A", &rules, Some(&list), policy).await,
        Err(NewPasswordError::RulesNotMet)
    );
    assert_eq!(
        hash_new_password_checked("Password123!", &rules, Some(&list), policy).await,
        Err(NewPasswordError::Breached)
    );
    let long = format!("Aa1{}", "x".repeat(super::super::MAX_PASSWORD_BYTES - 2));
    assert_eq!(
        hash_new_password_checked(&long, &rules, Some(&list), policy).await,
        Err(NewPasswordError::TooLong)
    );
    let hash = hash_new_password_checked("Gnomes2+andmore", &rules, Some(&list), policy)
        .await
        .unwrap();
    assert!(verify_password("Gnomes2+andmore", &hash).is_ok());
}

#[tokio::test]
async fn the_checked_hash_refuses_an_outage_by_default_and_allows_on_opt_out() {
    let outage = BreachCheckOutage::new("range service timed out");
    let rules = PasswordRules::default();
    assert_eq!(
        hash_new_password_checked(
            "Gnomes2+andmore",
            &rules,
            Some(&outage),
            BreachCheckUnavailable::Refuse
        )
        .await,
        Err(NewPasswordError::BreachCheckUnavailable)
    );
    assert!(
        hash_new_password_checked(
            "Gnomes2+andmore",
            &rules,
            Some(&outage),
            BreachCheckUnavailable::Allow
        )
        .await
        .is_ok()
    );
}

#[test]
fn the_new_refusals_have_their_own_sentences() {
    assert_eq!(
        NewPasswordError::Breached.to_string(),
        "password is known from a data breach; choose another"
    );
    assert_eq!(
        NewPasswordError::BreachCheckUnavailable.to_string(),
        "the breached-password check is unavailable; try again later"
    );
}

#[test]
fn password_rules_screen_for_breaches_by_default_and_when_the_field_is_absent() {
    assert!(PasswordRules::default().breached_check);
    let stored: PasswordRules = serde_json::from_str(
        r#"{"min_length":12,"require_uppercase":true,"require_lowercase":true,"require_digit":true,"require_special":false}"#,
    )
    .unwrap();
    assert!(
        stored.breached_check,
        "a row written before the field screens"
    );
}
