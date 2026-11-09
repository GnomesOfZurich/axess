use super::*;
use crate::authn::ids::{TenantId, UserId};
use chrono::{DateTime, TimeZone, Utc};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

fn at(secs: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(1_700_000_000 + secs, 0).unwrap()
}

fn state(failures: u32, last_secs: i64) -> ThrottleState {
    ThrottleState {
        failures,
        last_failure_at: at(last_secs),
    }
}

fn addr(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(203, 0, 113, last))
}

#[test]
fn the_default_is_one_second_doubling_to_sixty_four_keyed_on_account_and_address() {
    let throttle = Throttle::default();
    assert_eq!(throttle.first_delay, Duration::from_secs(1));
    assert_eq!(throttle.max_delay, Duration::from_secs(64));
    assert_eq!(throttle.key, ThrottleKey::AccountAndAddress);
}

#[test]
fn the_delay_doubles_per_consecutive_failure_and_caps_at_max_delay() {
    let throttle = Throttle::default();
    let expected = [0, 1, 2, 4, 8, 16, 32, 64, 64, 64];
    for (failures, secs) in expected.into_iter().enumerate() {
        assert_eq!(
            throttle.delay_after(failures as u32),
            Duration::from_secs(secs),
            "after {failures} failures"
        );
    }
    assert_eq!(
        throttle.delay_after(u32::MAX),
        Duration::from_secs(64),
        "a count past the shift width is capped, not wrapped"
    );
}

#[test]
fn a_guess_before_the_delay_has_run_is_refused_with_the_time_left() {
    let throttle = Throttle::default();
    // Three failures, the last at t=10: the fourth guess waits 4 s, to t=14.
    let state = state(3, 10);
    assert_eq!(
        throttle.retry_after(Some(&state), at(10)),
        Some(Duration::from_secs(4))
    );
    assert_eq!(
        throttle.retry_after(Some(&state), at(13)),
        Some(Duration::from_secs(1))
    );
    assert_eq!(
        throttle.retry_after(Some(&state), at(14)),
        None,
        "at the retry time the guess is allowed"
    );
    assert_eq!(throttle.retry_after(None, at(10)), None);
}

#[test]
fn a_fraction_of_a_second_left_is_a_whole_second_to_wait() {
    let throttle = Throttle::default();
    let state = ThrottleState {
        failures: 1,
        last_failure_at: at(10) + chrono::Duration::milliseconds(400),
    };
    assert_eq!(
        throttle.retry_after(Some(&state), at(11)),
        Some(Duration::from_millis(400)),
        "the duration carries the exact remainder; rounding is the HTTP mapping's"
    );
}

#[test]
fn a_key_older_than_twice_max_delay_is_as_good_as_absent() {
    let throttle = Throttle::default();
    assert_eq!(throttle.forget_after(), Duration::from_secs(128));
    let state = state(7, 0);
    assert!(!throttle.is_stale(&state, at(128)));
    assert!(throttle.is_stale(&state, at(129)));
    assert_eq!(
        throttle.retry_after(Some(&state), at(129)),
        None,
        "a stale entry throttles nothing"
    );
}

#[test]
fn a_zero_first_delay_throttles_nothing() {
    let throttle = Throttle {
        first_delay: Duration::ZERO,
        ..Throttle::default()
    };
    assert_eq!(throttle.retry_after(Some(&state(5, 10)), at(10)), None);
}

#[test]
fn the_subject_carries_the_address_only_under_account_and_address() {
    let tenant = TenantId::system();
    let user = UserId::system();
    let both = Throttle::default().subject(&tenant, &user, Some(addr(1)));
    assert_eq!(both.address, Some(addr(1)));
    let account = Throttle {
        key: ThrottleKey::Account,
        ..Throttle::default()
    }
    .subject(&tenant, &user, Some(addr(1)));
    assert_eq!(account.address, None);
    assert_eq!(account.tenant_id, tenant);
    assert_eq!(account.user_id, user);
    assert_ne!(
        both,
        Throttle::default().subject(&tenant, &user, Some(addr(2))),
        "two addresses are two subjects"
    );
}

#[test]
fn the_lockout_policy_throttles_by_default_and_without_throttle_is_the_named_opt_out() {
    let policy = crate::authn::types::LockoutPolicy::default();
    assert_eq!(policy.throttle, Some(Throttle::default()));
    let off = crate::authn::types::LockoutPolicy::default().without_throttle();
    assert_eq!(off.throttle, None);
    assert_eq!(
        off.max_attempts, policy.max_attempts,
        "the lock is untouched by the opt-out"
    );
}

fn addr6(text: &str) -> IpAddr {
    text.parse().expect("an IPv6 literal")
}

fn subject_of(throttle: &Throttle, address: IpAddr) -> ThrottleSubject {
    throttle.subject(&TenantId::system(), &UserId::system(), Some(address))
}

#[test]
fn an_ipv6_subject_is_keyed_on_its_64_prefix() {
    use axess_testing::ipv6_forms::IPV6_FORMS;
    let throttle = Throttle::default();
    let form = |name: &str| {
        let found = IPV6_FORMS.iter().find(|f| f.name == name).expect("a row");
        addr6(found.address)
    };
    let (first, second, next) = (
        form("same /64, first"),
        form("same /64, second"),
        form("next /64"),
    );
    assert_eq!(
        subject_of(&throttle, first),
        subject_of(&throttle, second),
        "failures inside one /64 must build up under one key"
    );
    assert_ne!(
        subject_of(&throttle, first),
        subject_of(&throttle, next),
        "another /64 is another guesser"
    );
    assert_eq!(
        subject_of(&throttle, addr(7)).address,
        Some(addr(7)),
        "an IPv4 address is kept as it is"
    );
}

#[test]
fn an_ipv4_mapped_address_is_the_ipv4_address_it_carries() {
    use axess_testing::ipv6_forms::IPV6_FORMS;
    let throttle = Throttle::default();
    for form in IPV6_FORMS.iter().filter(|f| f.embedded_v4.is_some()) {
        let carried: IpAddr = form.embedded_v4.expect("filtered").parse().expect("IPv4");
        assert_eq!(
            subject_of(&throttle, addr6(form.address)),
            subject_of(&throttle, carried),
            "{}",
            form.name
        );
    }
}

#[test]
fn a_huge_max_delay_refuses_the_guess_and_never_waits_less_as_failures_grow() {
    let table = axess_testing::durations::extreme_durations();
    for first in &table {
        for max in &table {
            let throttle = Throttle {
                first_delay: first.value,
                max_delay: max.value,
                ..Throttle::default()
            };
            let mut previous = Duration::ZERO;
            for failures in [1, 2, 3, 40, 100, u32::MAX] {
                let delay = throttle.delay_after(failures);
                assert!(delay <= max.value, "{} / {}", first.name, max.name);
                assert!(delay >= previous, "{} / {}", first.name, max.name);
                previous = delay;
                let waiting = throttle.retry_after(Some(&state(failures, 0)), at(0));
                if !first.value.is_zero() && !max.value.is_zero() {
                    assert!(
                        matches!(waiting, Some(wait) if !wait.is_zero()),
                        "throttle fails open: first {} / max {} at {failures} failures gave {waiting:?}",
                        first.name,
                        max.name
                    );
                }
            }
        }
    }
}

#[test]
fn a_zero_first_delay_stays_zero_past_the_doubling_width() {
    let throttle = Throttle {
        first_delay: Duration::ZERO,
        ..Throttle::default()
    };
    assert_eq!(throttle.delay_after(40), Duration::ZERO);
    assert_eq!(throttle.retry_after(Some(&state(40, 0)), at(0)), None);
}
