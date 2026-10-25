//! The facade reaches the validation helpers without a direct axess-core
//! dependency.

#[test]
fn password_validation_is_reachable_from_the_facade() {
    assert!(axess::validation::is_valid_password(
        "Correct-horse-9",
        12,
        true,
        true,
        true,
        false
    ));
    assert!(!axess::validation::is_valid_password(
        "short", 12, true, true, true, false
    ));
}
