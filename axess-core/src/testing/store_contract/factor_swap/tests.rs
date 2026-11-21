//! The compare-and-save check, held against the stores this crate ships and
//! against stores whose swap is broken in the ways the check exists for:
//! each fault is caught by name.

use super::*;
use crate::authn::store::{AuthMethod, Fido2CredentialClaim, ResolvedFactor};
use crate::session::storage::in_memory_backend::InMemoryBackend;
use crate::testing::mock_authn::{MockFactorStore, MockStoreError};
use std::time::Duration;

/// How long a faulty store stays between its two steps. Every racing task
/// reaches its first step well inside it, so the fault shows in every round.
const GAP: Duration = Duration::from_millis(50);

/// How a faulty store breaks the swap.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    /// None: the store under it, as it is.
    Sound,
    /// Reads the row, then writes it, with nothing holding the two together.
    /// Right for one request at a time.
    ReadsThenWrites,
    /// Swaps in one step but refuses to wait for another writer: a request
    /// that finds the row busy is answered an error.
    ErrorsWhenBusy,
    /// Swaps in one step, and lets one more request through on the prior a
    /// swap still in flight just replaced.
    LetsTwoSwapsWin,
    /// Writes the update whatever the prior.
    IgnoresThePrior,
    /// Writes the update for a user who has no row.
    CreatesTheRow,
}

/// A mock store behind a fault.
struct Faulty {
    inner: MockFactorStore,
    fault: Fault,
    /// Held by a swap of the store that errors when busy.
    busy: tokio::sync::Mutex<()>,
    /// The prior of the swap in flight in the store that lets two win.
    in_flight: tokio::sync::Mutex<Option<serde_json::Value>>,
}

impl Faulty {
    fn with(fault: Fault) -> Arc<Self> {
        Arc::new(Self {
            inner: MockFactorStore::new(),
            fault,
            busy: tokio::sync::Mutex::default(),
            in_flight: tokio::sync::Mutex::default(),
        })
    }
}

/// The form two configurations are compared in: they carry no equality of
/// their own.
fn form(config: &FactorConfig) -> serde_json::Value {
    serde_json::to_value(config).expect("a factor configuration serialises")
}

impl FactorStore for Faulty {
    type Error = MockStoreError;

    async fn resolve_factor(
        &self,
        scope: &AuthnScope,
        kind: FactorKind,
    ) -> Result<Option<ResolvedFactor>, Self::Error> {
        self.inner.resolve_factor(scope, kind).await
    }

    async fn load_factor(
        &self,
        scope: &AuthnScope,
        kind: FactorKind,
    ) -> Result<Option<FactorConfig>, Self::Error> {
        self.inner.load_factor(scope, kind).await
    }

    async fn save_factor(
        &self,
        scope: &AuthnScope,
        config: FactorConfig,
    ) -> Result<(), Self::Error> {
        self.inner.save_factor(scope, config).await
    }

    async fn compare_and_save_factor(
        &self,
        scope: &AuthnScope,
        prior: &FactorConfig,
        updated: FactorConfig,
    ) -> Result<bool, Self::Error> {
        match self.fault {
            Fault::Sound => {
                self.inner
                    .compare_and_save_factor(scope, prior, updated)
                    .await
            }
            Fault::ReadsThenWrites => {
                let stored = self.inner.load_factor(scope, prior.kind()).await?;
                tokio::time::sleep(GAP).await;
                match stored {
                    Some(stored) if form(&stored) == form(prior) => {
                        self.inner.save_factor(scope, updated).await?;
                        Ok(true)
                    }
                    _ => Ok(false),
                }
            }
            Fault::ErrorsWhenBusy => {
                let Ok(held) = self.busy.try_lock() else {
                    return Err(MockStoreError::Unavailable);
                };
                let swapped = self
                    .inner
                    .compare_and_save_factor(scope, prior, updated)
                    .await?;
                tokio::time::sleep(GAP).await;
                drop(held);
                Ok(swapped)
            }
            Fault::LetsTwoSwapsWin => {
                let mut in_flight = self.in_flight.lock().await;
                let swapped = self
                    .inner
                    .compare_and_save_factor(scope, prior, updated.clone())
                    .await?;
                if swapped {
                    *in_flight = Some(form(prior));
                    drop(in_flight);
                    tokio::time::sleep(GAP).await;
                    *self.in_flight.lock().await = None;
                    return Ok(true);
                }
                if in_flight.as_ref() == Some(&form(prior)) {
                    *in_flight = None;
                    self.inner.save_factor(scope, updated).await?;
                    return Ok(true);
                }
                Ok(false)
            }
            Fault::IgnoresThePrior => {
                if self.inner.load_factor(scope, prior.kind()).await?.is_none() {
                    return Ok(false);
                }
                self.inner.save_factor(scope, updated).await?;
                Ok(true)
            }
            Fault::CreatesTheRow => {
                if self.inner.load_factor(scope, prior.kind()).await?.is_none() {
                    self.inner.save_factor(scope, updated).await?;
                    return Ok(false);
                }
                self.inner
                    .compare_and_save_factor(scope, prior, updated)
                    .await
            }
        }
    }

    async fn insert_factor_if_absent(
        &self,
        scope: &AuthnScope,
        config: FactorConfig,
    ) -> Result<bool, Self::Error> {
        self.inner.insert_factor_if_absent(scope, config).await
    }

    async fn available_methods(
        &self,
        user_id: &UserId,
        tenant_id: &TenantId,
    ) -> Result<Vec<AuthMethod>, Self::Error> {
        self.inner.available_methods(user_id, tenant_id).await
    }

    async fn save_method(&self, scope: &AuthnScope, method: AuthMethod) -> Result<(), Self::Error> {
        self.inner.save_method(scope, method).await
    }

    async fn remove_method(&self, scope: &AuthnScope, name: &str) -> Result<(), Self::Error> {
        self.inner.remove_method(scope, name).await
    }

    async fn set_method_enabled(
        &self,
        scope: &AuthnScope,
        name: &str,
        enabled: bool,
    ) -> Result<bool, Self::Error> {
        self.inner.set_method_enabled(scope, name, enabled).await
    }

    async fn claim_fido2_credential(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        credential_id: &[u8],
    ) -> Result<Fido2CredentialClaim, Self::Error> {
        self.inner
            .claim_fido2_credential(tenant_id, user_id, credential_id)
            .await
    }

    async fn release_fido2_credential(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        credential_id: &[u8],
    ) -> Result<(), Self::Error> {
        self.inner
            .release_fido2_credential(tenant_id, user_id, credential_id)
            .await
    }
}

fn tenant() -> TenantId {
    "00000000-0000-4000-8000-0000000000a1"
        .parse()
        .expect("a tenant id")
}

fn user() -> UserId {
    "00000000-0000-4000-8000-0000000000b1"
        .parse()
        .expect("a user id")
}

async fn check<S: FactorStore>(store: Arc<S>) {
    assert_compare_and_save_factor_contract(store, &tenant(), &user()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_mock_factor_store_meets_the_contract() {
    check(Arc::new(MockFactorStore::new())).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_in_memory_backend_meets_the_contract() {
    check(Arc::new(InMemoryBackend::new())).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_store_that_swaps_in_one_step_passes() {
    check(Faulty::with(Fault::Sound)).await;
}

/// The check can run again on a store that kept the rows of an earlier run:
/// it starts each kind from its own value.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_check_runs_again_on_the_rows_it_left() {
    let store = Arc::new(MockFactorStore::new());
    check(Arc::clone(&store)).await;
    check(store).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[should_panic(expected = "a TOTP step: of 16 racing swaps exactly one must answer true")]
async fn a_store_that_reads_and_then_writes_is_caught() {
    check(Faulty::with(Fault::ReadsThenWrites)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[should_panic(
    expected = "a TOTP step: a swap that loses a race must answer false, never an error"
)]
async fn a_store_that_answers_an_error_under_the_race_is_caught() {
    check(Faulty::with(Fault::ErrorsWhenBusy)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[should_panic(
    expected = "a TOTP step: of 16 racing swaps exactly one must answer true: 2 did in round 0"
)]
async fn a_store_that_lets_two_swaps_win_is_caught() {
    check(Faulty::with(Fault::LetsTwoSwapsWin)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[should_panic(expected = "a TOTP step: a swap whose prior was never stored must answer false")]
async fn a_store_that_ignores_the_prior_is_caught() {
    check(Faulty::with(Fault::IgnoresThePrior)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[should_panic(expected = "a TOTP step: a swap for a user who has no row must not create one")]
async fn a_store_that_creates_the_row_is_caught() {
    check(Faulty::with(Fault::CreatesTheRow)).await;
}

/// On one thread the racing tasks take turns, and a swap made of two steps
/// with no suspension point between them would pass. The check says so
/// instead of passing.
#[tokio::test]
#[should_panic(expected = "needs a multi-thread runtime with at least two workers")]
async fn the_check_refuses_a_runtime_of_one_thread() {
    check(Arc::new(MockFactorStore::new())).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[should_panic(expected = "needs a multi-thread runtime with at least two workers")]
async fn the_check_refuses_a_multi_thread_runtime_of_one_worker() {
    check(Arc::new(MockFactorStore::new())).await;
}

/// The three subjects are what the service spends, and each request of a
/// race writes something of its own wherever the kind allows.
#[test]
fn the_subjects_move_what_the_service_spends() {
    let [totp, hotp, codes] = subjects();

    assert_eq!(Spent::of(&totp.start), Spent::TotpStep(Some(59_000_000)));
    assert_eq!(
        Spent::of(&(totp.advance)(&totp.start, 0)),
        Spent::TotpStep(Some(59_000_001))
    );
    assert_eq!(
        Spent::of(&(totp.advance)(&totp.start, 3)),
        Spent::TotpStep(Some(59_000_004))
    );

    // A right code moves the counter and starts the attempt count over; a
    // wrong one counts and leaves the counter.
    assert_eq!(
        Spent::of(&(hotp.advance)(&hotp.start, 0)),
        Spent::HotpCounter {
            counter: 8,
            attempt_count: 0
        }
    );
    assert_eq!(
        Spent::of(&(hotp.advance)(&hotp.start, 1)),
        Spent::HotpCounter {
            counter: 7,
            attempt_count: 3
        }
    );

    let spent_marks = |config: &FactorConfig| match Spent::of(config) {
        Spent::RecoveryCodes(marks) => marks,
        other => panic!("not a recovery-code set: {other:?}"),
    };
    assert!(spent_marks(&codes.start).iter().all(Option::is_none));
    let one = (codes.advance)(&codes.start, 0);
    let other = (codes.advance)(&codes.start, 1);
    assert_eq!(spent_marks(&one).iter().flatten().count(), 1);
    assert_eq!(spent_marks(&other).iter().flatten().count(), 1);
    assert_ne!(spent_marks(&one), spent_marks(&other));
    // A spent code stays spent when the next one goes.
    let two = (codes.advance)(&one, 0);
    assert_eq!(spent_marks(&two).iter().flatten().count(), 2);
}
