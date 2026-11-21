//! The conformance check of [`FactorStore::compare_and_save_factor`], the
//! swap that makes a TOTP step, an HOTP counter and a recovery code
//! single-use.
//!
//! The service verifies a code against the factor it loaded and then asks
//! the store to replace that very value. Two requests carrying one code both
//! verify; the swap is what lets one of them through. A store that reads and
//! then writes lets both through, and a store that answers the loser with an
//! error (a lock it could not take, a busy database) fails a login that the
//! contract says was merely a replay.

use std::sync::Arc;

use axess_clock::Timestamp;

use crate::authn::factor::{
    FactorConfig, FactorKind, FactorSecret, HotpConfig, RecoveryCodesConfig, StoredRecoveryCode,
    TotpConfig, ZeroizedString,
};
use crate::authn::ids::{TenantId, UserId};
use crate::authn::store::FactorStore;
use crate::authn::types::AuthnScope;

/// How many swaps race one stored value in each round of
/// [`assert_compare_and_save_factor_contract`].
pub const RACING_SWAPS: usize = 16;

/// How many rounds of the race each kind of factor gets. Each round starts
/// from what the round before left in the store.
const RACE_ROUNDS: usize = 4;

/// The part of a stored factor the service spends through the swap, which
/// is what the check reads back to say what a store holds.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Spent {
    /// The last TOTP step accepted.
    TotpStep(Option<u64>),
    /// The HOTP counter, and the count of wrong codes against it.
    HotpCounter {
        /// The next counter value a code is checked from.
        counter: u64,
        /// Wrong codes since the last right one.
        attempt_count: u8,
    },
    /// When each recovery code of the set was spent, in the set's order.
    RecoveryCodes(Vec<Option<Timestamp>>),
}

impl Spent {
    /// What `config` has spent.
    ///
    /// # Panics
    ///
    /// On a kind the check does not store, which a store can only hand back
    /// by answering a load with another row.
    fn of(config: &FactorConfig) -> Self {
        match config {
            FactorConfig::Totp(totp) => Self::TotpStep(totp.last_step),
            FactorConfig::Hotp(hotp) => Self::HotpCounter {
                counter: hotp.counter,
                attempt_count: hotp.attempt_count,
            },
            FactorConfig::RecoveryCodes(set) => {
                Self::RecoveryCodes(set.codes.iter().map(|code| code.used_at).collect())
            }
            other => panic!(
                "the store answered a load with a factor of another kind: {:?}",
                other.kind()
            ),
        }
    }
}

/// One of the three things the service spends, with the value the check
/// starts from and the ways it moves that value on.
struct Subject {
    /// The words of this subject in a failure message.
    name: &'static str,
    kind: FactorKind,
    start: FactorConfig,
    /// The update request number `n` would write over `from`, as the service
    /// builds it: a clone of what was loaded with the spent part moved on.
    /// Two requests differ in what they write wherever the kind allows.
    advance: fn(&FactorConfig, u64) -> FactorConfig,
}

/// The instant the check's recovery codes are spent from.
fn spending_instant(n: u64) -> Timestamp {
    Timestamp::from_unix_seconds(1_800_000_000 + i64::try_from(n).unwrap_or(0))
        .expect("a valid instant")
}

/// A later step than the stored one, a different one per request: two codes
/// of one window, each accepted against the same stored step.
fn advance_totp(from: &FactorConfig, n: u64) -> FactorConfig {
    let FactorConfig::Totp(mut totp) = from.clone() else {
        panic!("the store answered a TOTP load with another kind");
    };
    totp.last_step = Some(totp.last_step.unwrap_or(0) + 1 + n);
    FactorConfig::Totp(totp)
}

/// An even request carries a right code: the counter moves past it and the
/// attempt count starts over. An odd request carries a wrong one: the
/// counter stays and the attempt count goes up, so a store that compares the
/// counter alone would let a stale failure count through.
fn advance_hotp(from: &FactorConfig, n: u64) -> FactorConfig {
    let FactorConfig::Hotp(mut hotp) = from.clone() else {
        panic!("the store answered an HOTP load with another kind");
    };
    if n.is_multiple_of(2) {
        hotp.counter += 1 + n;
        hotp.attempt_count = 0;
    } else {
        hotp.attempt_count = hotp.attempt_count.saturating_add(1);
    }
    FactorConfig::Hotp(hotp)
}

/// Spends one of the codes still unspent, a different one per request while
/// there are several, at an instant of the request's own.
fn advance_recovery_codes(from: &FactorConfig, n: u64) -> FactorConfig {
    let FactorConfig::RecoveryCodes(mut set) = from.clone() else {
        panic!("the store answered a recovery-code load with another kind");
    };
    let unspent: Vec<usize> = set
        .codes
        .iter()
        .enumerate()
        .filter(|(_, code)| code.used_at.is_none())
        .map(|(at, _)| at)
        .collect();
    assert!(
        !unspent.is_empty(),
        "the check ran out of unspent recovery codes, which is its own fault"
    );
    let pick = unspent[usize::try_from(n).unwrap_or(0) % unspent.len()];
    set.codes[pick].used_at = Some(spending_instant(n));
    FactorConfig::RecoveryCodes(set)
}

/// The three subjects, each from a value no earlier run can have left.
fn subjects() -> [Subject; 3] {
    let secret = || FactorSecret::Plain(ZeroizedString::new("JBSWY3DPEHPK3PXP"));
    // More codes than the check ever spends: two in the sequential part and
    // one per round of the race.
    let codes = (0..32)
        .map(|n| StoredRecoveryCode {
            hash: format!("hmac-sha256:{n:064x}"),
            used_at: None,
        })
        .collect();
    [
        Subject {
            name: "a TOTP step",
            kind: FactorKind::Totp,
            start: FactorConfig::Totp(TotpConfig {
                secret: secret(),
                last_step: Some(59_000_000),
                ..TotpConfig::default()
            }),
            advance: advance_totp,
        },
        Subject {
            name: "an HOTP counter with its attempt count",
            kind: FactorKind::Hotp,
            start: FactorConfig::Hotp(HotpConfig {
                secret: secret(),
                counter: 7,
                attempt_count: 2,
                ..HotpConfig::default()
            }),
            advance: advance_hotp,
        },
        Subject {
            name: "a recovery code's spent mark",
            kind: FactorKind::RecoveryCode,
            start: FactorConfig::RecoveryCodes(RecoveryCodesConfig {
                codes,
                under_previous_pepper: false,
            }),
            advance: advance_recovery_codes,
        },
    ]
}

/// Exercise the compare-and-swap of a factor store and panic with a message
/// naming the broken rule. `user` is a user of `tenant` that the store
/// takes factor rows for. The check overwrites that user's TOTP, HOTP and
/// recovery-code rows and leaves its own there, so give it a user made for
/// the test.
///
/// For each of the three things the service spends through the swap (a
/// TOTP step, an HOTP counter with its attempt count, a recovery code's
/// spent mark):
///
/// - a swap whose prior was never stored answers `false` and writes
///   nothing, and so does a swap for a user who has no row, which must not
///   create one;
/// - a swap whose prior is the stored value answers `true` and stores the
///   update;
/// - the same swap made again, and any other swap that still holds the
///   replaced prior, answers `false` and writes nothing;
/// - a swap from the value now stored answers `true`, and its prior is
///   stale in turn;
/// - of [`RACING_SWAPS`] swaps racing one stored value on separate tasks,
///   exactly one answers `true`, every other answers `false`, none answers
///   an error, and the store holds what the one winner wrote.
///
/// The last rule is the reason for the method. An error from a swap that
/// lost a race is a broken contract and not a stricter one: the service
/// reads `false` as a replay and an error as a failed login. A store that
/// reads the row and then writes it inside a transaction that takes its
/// write lock late answers exactly that error under load.
///
/// The race needs real parallelism, so the check must run on a multi-thread
/// runtime with at least two workers
/// (`#[tokio::test(flavor = "multi_thread", worker_threads = 4)]`), and the
/// store is taken by `Arc` so that each racing task holds it. Run it
/// against the store as production opens it: a pool of one connection
/// cannot race itself and passes whatever the statement.
///
/// # Panics
///
/// On the first rule the store breaks, on a store error, and on a runtime
/// that cannot run the race.
pub async fn assert_compare_and_save_factor_contract<S: FactorStore>(
    store: Arc<S>,
    tenant: &TenantId,
    user: &UserId,
) {
    assert_runtime_can_race();
    let scope = AuthnScope::User {
        tenant_id: *tenant,
        user_id: *user,
    };
    // A user no row was ever written for.
    let nobody = AuthnScope::User {
        tenant_id: *tenant,
        user_id: UserId::new(&axess_rng::SystemRng),
    };
    for subject in subjects() {
        assert_sequential_rules(store.as_ref(), &scope, &nobody, &subject).await;
        for round in 0..RACE_ROUNDS {
            assert_one_winner(&store, &scope, &subject, round).await;
        }
    }
}

/// Refuse a runtime on which the racing tasks would take turns on one
/// thread: such a run passes a store whose swap is two steps with no
/// suspension point between them.
fn assert_runtime_can_race() {
    let handle = tokio::runtime::Handle::current();
    let one_thread = matches!(
        handle.runtime_flavor(),
        tokio::runtime::RuntimeFlavor::CurrentThread
    );
    assert!(
        !one_thread && handle.metrics().num_workers() >= 2,
        "the compare-and-save check races its swaps on separate threads and needs a \
         multi-thread runtime with at least two workers: \
         #[tokio::test(flavor = \"multi_thread\", worker_threads = 4)]"
    );
}

async fn load<S: FactorStore>(store: &S, scope: &AuthnScope, subject: &Subject) -> FactorConfig {
    store
        .load_factor(scope, subject.kind.clone())
        .await
        .expect("load_factor errored")
        .unwrap_or_else(|| panic!("{}: a saved factor must load", subject.name))
}

async fn swap<S: FactorStore>(
    store: &S,
    scope: &AuthnScope,
    prior: &FactorConfig,
    updated: FactorConfig,
) -> bool {
    store
        .compare_and_save_factor(scope, prior, updated)
        .await
        .expect("compare_and_save_factor errored with no other writer")
}

/// The rules one request after another can show.
async fn assert_sequential_rules<S: FactorStore>(
    store: &S,
    scope: &AuthnScope,
    nobody: &AuthnScope,
    subject: &Subject,
) {
    let name = subject.name;
    let advance = subject.advance;
    store
        .save_factor(scope, subject.start.clone())
        .await
        .expect("save_factor errored");
    // Every prior below is a value the store handed back, and every update
    // a clone of one with the spent part moved on, as the service makes
    // them: a store may compare by a form only its own rows carry.
    let first = load(store, scope, subject).await;
    assert_eq!(
        Spent::of(&first),
        Spent::of(&subject.start),
        "{name}: a saved factor must load as it was saved"
    );

    let never_stored = advance(&first, 40);
    assert!(
        !swap(store, scope, &never_stored, advance(&first, 42)).await,
        "{name}: a swap whose prior was never stored must answer false"
    );
    assert_eq!(
        Spent::of(&load(store, scope, subject).await),
        Spent::of(&first),
        "{name}: a swap whose prior was never stored must write nothing"
    );

    let next = advance(&first, 0);
    assert!(
        !swap(store, nobody, &first, next.clone()).await,
        "{name}: a swap for a user who has no row must answer false"
    );
    assert!(
        store
            .load_factor(nobody, subject.kind.clone())
            .await
            .expect("load_factor errored")
            .is_none(),
        "{name}: a swap for a user who has no row must not create one"
    );

    assert!(
        swap(store, scope, &first, next.clone()).await,
        "{name}: a swap whose prior is the stored value must answer true"
    );
    assert_eq!(
        Spent::of(&load(store, scope, subject).await),
        Spent::of(&next),
        "{name}: a swap that answered true must store the update"
    );

    assert!(
        !swap(store, scope, &first, next.clone()).await,
        "{name}: the same swap made again must answer false: the second request is a replay"
    );
    assert!(
        !swap(store, scope, &first, advance(&first, 2)).await,
        "{name}: a second swap holding the replaced prior must answer false"
    );
    assert_eq!(
        Spent::of(&load(store, scope, subject).await),
        Spent::of(&next),
        "{name}: a swap that answered false must write nothing"
    );

    // An odd request: for HOTP the one that moves the attempt count alone.
    let second = load(store, scope, subject).await;
    let after = advance(&second, 1);
    assert!(
        swap(store, scope, &second, after.clone()).await,
        "{name}: a swap from the value now stored must answer true"
    );
    assert!(
        !swap(store, scope, &second, advance(&second, 3)).await,
        "{name}: the prior of the swap before must be stale once that swap is stored"
    );
    assert_eq!(
        Spent::of(&load(store, scope, subject).await),
        Spent::of(&after),
        "{name}: a swap that answered false must write nothing"
    );
}

/// One round of the race: [`RACING_SWAPS`] tasks hold one prior, wait at a
/// barrier and swap at once.
async fn assert_one_winner<S: FactorStore>(
    store: &Arc<S>,
    scope: &AuthnScope,
    subject: &Subject,
    round: usize,
) {
    let name = subject.name;
    let prior = load(store.as_ref(), scope, subject).await;
    let barrier = Arc::new(tokio::sync::Barrier::new(RACING_SWAPS));
    let racers: Vec<_> = (0..RACING_SWAPS)
        .map(|n| {
            let update = (subject.advance)(&prior, n as u64);
            let wrote = Spent::of(&update);
            let (store, scope, prior, barrier) = (
                Arc::clone(store),
                scope.clone(),
                prior.clone(),
                Arc::clone(&barrier),
            );
            tokio::spawn(async move {
                barrier.wait().await;
                let answer = store
                    .compare_and_save_factor(&scope, &prior, update)
                    .await
                    .map_err(|error| error.to_string());
                (wrote, answer)
            })
        })
        .collect();

    let mut winners = Vec::new();
    let mut errors = Vec::new();
    for racer in racers {
        match racer.await.expect("a racing swap panicked") {
            (wrote, Ok(true)) => winners.push(wrote),
            (_, Ok(false)) => {}
            (_, Err(error)) => errors.push(error),
        }
    }

    if let Some(first) = errors.first() {
        panic!(
            "{name}: a swap that loses a race must answer false, never an error, because \
             the service turns a store error into a failed login: {} of {RACING_SWAPS} \
             racing swaps errored in round {round}, the first with: {first}",
            errors.len()
        );
    }
    if winners.len() != 1 {
        panic!(
            "{name}: of {RACING_SWAPS} racing swaps exactly one must answer true: {} did \
             in round {round}",
            winners.len()
        );
    }
    assert_eq!(
        Spent::of(&load(store.as_ref(), scope, subject).await),
        winners[0],
        "{name}: after a race the store must hold what the one winning swap wrote"
    );
}

#[cfg(test)]
mod tests;
