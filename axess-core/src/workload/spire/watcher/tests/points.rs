//! The instant a validity is due at.

use axess_clock::Timestamp;
use proptest::prelude::*;

use super::super::refresh_point;
use crate::workload::spire::test_support::REFERENCE;

fn at(seconds: i64) -> Timestamp {
    Timestamp::from_unix_seconds(REFERENCE + seconds).expect("in range")
}

#[test]
fn the_refresh_point_is_a_share_of_the_lifetime() {
    assert_eq!(refresh_point(at(0), at(3600), 50), at(1800));
    assert_eq!(refresh_point(at(0), at(3600), 75), at(2700));
    assert_eq!(refresh_point(at(0), at(3600), 1), at(36));
    assert_eq!(refresh_point(at(0), at(3600), 99), at(3564));
    assert_eq!(refresh_point(at(100), at(400), 50), at(250));
    // The widest validity a certificate can state does not overflow.
    let widest = refresh_point(Timestamp::MIN, Timestamp::MAX, 99);
    assert!(widest <= Timestamp::MAX);
}

#[test]
fn a_validity_that_does_not_run_forwards_is_due_at_its_end() {
    // Nothing waits for a point that lies after the expiry.
    assert_eq!(refresh_point(at(3600), at(0), 50), at(0));
    assert_eq!(refresh_point(at(3600), at(0), 99), at(0));
    assert_eq!(refresh_point(at(100), at(100), 50), at(100));
}

proptest! {
    /// The refresh point of a validity that runs forwards lies inside it.
    #[test]
    fn the_refresh_point_lies_inside_the_validity(
        from in -10_000_000_000i64..10_000_000_000,
        lifetime in 0i64..10_000_000_000,
        percent in 1u8..=99,
    ) {
        let start = Timestamp::from_unix_seconds(from).expect("in range");
        let end = Timestamp::from_unix_seconds(from + lifetime).expect("in range");
        let point = refresh_point(start, end, percent);
        prop_assert!(start <= point && point <= end);
    }

    /// Whichever way a validity runs, its refresh point is never after its
    /// end.
    #[test]
    fn the_refresh_point_is_never_after_the_end(
        from in -10_000_000_000i64..10_000_000_000,
        until in -10_000_000_000i64..10_000_000_000,
        percent in 1u8..=99,
    ) {
        let start = Timestamp::from_unix_seconds(from).expect("in range");
        let end = Timestamp::from_unix_seconds(until).expect("in range");
        prop_assert!(refresh_point(start, end, percent) <= end);
    }
}
