//! The date after which plain-text TOTP secrets are refused is a fixed one:
//! it does not depend on when the process started.

use axess_example_sqlite::web::app::plain_secret_cutoff;

#[test]
fn the_plain_secret_cutoff_is_a_fixed_date() {
    let cutoff = plain_secret_cutoff();
    assert_eq!(cutoff.to_rfc3339(), "2027-01-31T00:00:00+00:00");
    assert_eq!(cutoff, plain_secret_cutoff());
}
