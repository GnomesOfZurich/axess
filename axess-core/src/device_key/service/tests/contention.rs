//! The key service against a store whose compare-and-swap is lost, or whose
//! row moves between the read and the write: the retries, the exhaustion,
//! and the three races the design names.

use super::*;
use crate::device::store::{OwnerClaim, SweepCounts, TrustTransition};
use crate::device::types::FingerprintHash;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};

/// What a test does to the row between a service's read and its write.
type Rival = Box<dyn FnOnce(MemoryDeviceStore) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send>;

/// A store whose next `conflicts` compare-and-swaps are lost, which lets a
/// rival at the row once, right before a swap, and which counts how often a
/// row is read, through `load` (a cache may answer it) and fresh.
#[derive(Clone, Default)]
struct Contending {
    inner: MemoryDeviceStore,
    conflicts: Arc<AtomicUsize>,
    rival: Arc<Mutex<Option<Rival>>>,
    loads: Arc<AtomicUsize>,
    fresh_loads: Arc<AtomicUsize>,
}

impl Contending {
    fn lose(&self, swaps: usize) {
        self.conflicts.store(swaps, Ordering::SeqCst);
    }

    fn before_the_next_swap(&self, rival: Rival) {
        *self.rival.lock().unwrap() = Some(rival);
    }

    /// The reads made since the last call, as `(load, load_fresh)`.
    fn reads(&self) -> (usize, usize) {
        (
            self.loads.swap(0, Ordering::SeqCst),
            self.fresh_loads.swap(0, Ordering::SeqCst),
        )
    }
}

impl DeviceStore for Contending {
    type Error = <MemoryDeviceStore as DeviceStore>::Error;

    async fn replace_bindings(
        &self,
        t: &TenantId,
        id: &DeviceId,
        expected: &[DeviceBinding],
        bindings: &[DeviceBinding],
        now: Timestamp,
    ) -> Result<BindingsUpdate, Self::Error> {
        let rival = self.rival.lock().unwrap().take();
        if let Some(rival) = rival {
            rival(self.inner.clone()).await;
        }
        if self.conflicts.load(Ordering::SeqCst) > 0 {
            self.conflicts.fetch_sub(1, Ordering::SeqCst);
            return Ok(BindingsUpdate::Conflict);
        }
        self.inner
            .replace_bindings(t, id, expected, bindings, now)
            .await
    }
    fn set_trust_level_if(
        &self,
        t: &TenantId,
        id: &DeviceId,
        expected: DeviceTrustLevel,
        level: DeviceTrustLevel,
        now: Timestamp,
    ) -> impl Future<Output = Result<TrustTransition, Self::Error>> + Send {
        self.inner.set_trust_level_if(t, id, expected, level, now)
    }
    fn claim_owner(
        &self,
        t: &TenantId,
        id: &DeviceId,
        user: &UserId,
        now: Timestamp,
    ) -> impl Future<Output = Result<OwnerClaim, Self::Error>> + Send {
        self.inner.claim_owner(t, id, user, now)
    }
    fn load_fresh(
        &self,
        t: &TenantId,
        id: &DeviceId,
    ) -> impl Future<Output = Result<Option<Device>, Self::Error>> + Send {
        self.fresh_loads.fetch_add(1, Ordering::SeqCst);
        self.inner.load_fresh(t, id)
    }
    fn load(
        &self,
        t: &TenantId,
        id: &DeviceId,
    ) -> impl Future<Output = Result<Option<Device>, Self::Error>> + Send {
        self.loads.fetch_add(1, Ordering::SeqCst);
        self.inner.load(t, id)
    }
    fn find_by_fingerprint(
        &self,
        t: &TenantId,
        h: &FingerprintHash,
    ) -> impl Future<Output = Result<Option<Device>, Self::Error>> + Send {
        self.inner.find_by_fingerprint(t, h)
    }
    fn find_for_user(
        &self,
        t: &TenantId,
        u: &UserId,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<Device>, Self::Error>> + Send {
        self.inner.find_for_user(t, u, limit)
    }
    fn find_by_refresh_family(
        &self,
        t: &TenantId,
        f: &str,
    ) -> impl Future<Output = Result<Vec<Device>, Self::Error>> + Send {
        self.inner.find_by_refresh_family(t, f)
    }
    fn save(
        &self,
        d: &Device,
        now: Timestamp,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        self.inner.save(d, now)
    }
    fn create_or_find(
        &self,
        d: &Device,
        now: Timestamp,
    ) -> impl Future<Output = Result<Device, Self::Error>> + Send {
        self.inner.create_or_find(d, now)
    }
    fn record_sighting(
        &self,
        t: &TenantId,
        id: &DeviceId,
        now: Timestamp,
    ) -> impl Future<Output = Result<DeviceTrustLevel, Self::Error>> + Send {
        self.inner.record_sighting(t, id, now)
    }
    fn set_trust_level(
        &self,
        t: &TenantId,
        id: &DeviceId,
        level: DeviceTrustLevel,
        now: Timestamp,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        self.inner.set_trust_level(t, id, level, now)
    }
    fn delete(
        &self,
        t: &TenantId,
        id: &DeviceId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        self.inner.delete(t, id)
    }
    fn sweep(
        &self,
        t: &TenantId,
        now: Timestamp,
    ) -> impl Future<Output = Result<SweepCounts, Self::Error>> + Send {
        self.inner.sweep(t, now)
    }
}

/// A service over a contending store that holds the test user's device.
async fn contending() -> (DeviceKeyService<Contending>, Contending) {
    let store = Contending::default();
    store
        .inner
        .save(&device("laptop", 1, DeviceTrustLevel::Seen, at(0)), at(0))
        .await
        .unwrap();
    let service = DeviceKeyService::new(store.clone(), DeviceKeyConfig::new(ORIGIN))
        .unwrap()
        .with_rng(MockRng::new(21));
    (service, store)
}

/// A second node's service over the same rows.
fn rival_service(store: MemoryDeviceStore) -> Service {
    DeviceKeyService::new(store, DeviceKeyConfig::new(ORIGIN))
        .unwrap()
        .with_rng(MockRng::new(77))
}

type Contended = DeviceKeyError<<Contending as DeviceStore>::Error>;

async fn register_on<S: DeviceStore>(
    service: &DeviceKeyService<S>,
    signer: &SoftwareKey,
) -> Result<RegisteredKey, DeviceKeyError<S::Error>> {
    let url = service.config().registration_url(ORIGIN);
    let jws = signed(signer, KeyProofShape::Browser, &url, OFFER, true);
    service
        .register_device_key(
            &tenant(),
            &dev_id("laptop"),
            &user(),
            proof(&jws, KeyProofShape::Browser, &url),
            OFFER,
            at(10),
        )
        .await
}

/// The refresh proof of the test key over `challenge`.
fn refresh_proof(challenge: &KeyChallenge) -> String {
    let url = DeviceKeyConfig::new(ORIGIN).refresh_url(ORIGIN);
    signed(
        &key(),
        KeyProofShape::Browser,
        &url,
        &challenge.to_text(),
        false,
    )
}

async fn prove_on<S: DeviceStore>(
    service: &DeviceKeyService<S>,
    jws: &str,
    secs: i64,
) -> Result<ProvedKey, DeviceKeyError<S::Error>> {
    let url = service.config().refresh_url(ORIGIN);
    service
        .prove_device_key(
            &tenant(),
            &dev_id("laptop"),
            proof(jws, KeyProofShape::Browser, &url),
            at(secs),
        )
        .await
}

/// A swap that is lost once is made again on the row as it is then, for a
/// registration, a proof and a forgotten key alike.
#[tokio::test]
async fn a_lost_swap_is_made_again_on_the_fresh_row() {
    let (service, store) = contending().await;
    store.lose(1);
    let registered = register_on(&service, &key()).await.unwrap();
    store.lose(1);
    let proved = prove_on(&service, &refresh_proof(&registered.challenge), 20)
        .await
        .unwrap();
    assert_ne!(proved.next_challenge, registered.challenge);
    store.lose(1);
    assert!(
        service
            .forget_device_key(&tenant(), &dev_id("laptop"), at(30))
            .await
            .unwrap()
    );
    assert_eq!(store.conflicts.load(Ordering::SeqCst), 0);
}

/// A row that changes under every attempt is given up on by name, and
/// nothing is half written: no key after the registration, the same
/// challenge after the proof, the key still there after the forgetting.
#[tokio::test]
async fn a_row_that_keeps_changing_is_contended() {
    let (service, store) = contending().await;
    let (t, d) = (tenant(), dev_id("laptop"));
    store.lose(usize::MAX);
    assert!(matches!(
        register_on(&service, &key()).await,
        Err(Contended::Contended)
    ));
    store.lose(0);
    assert_eq!(service.key_thumbprint(&t, &d).await.unwrap(), None);
    let registered = register_on(&service, &key()).await.unwrap();

    store.lose(usize::MAX);
    assert!(matches!(
        prove_on(&service, &refresh_proof(&registered.challenge), 20).await,
        Err(Contended::Contended)
    ));
    let expired = 10 + DeviceKeyConfig::new(ORIGIN).challenge_ttl().as_secs() as i64;
    assert!(matches!(
        service.current_key_challenge(&t, &d, at(expired)).await,
        Err(Contended::Contended)
    ));
    assert!(matches!(
        service.forget_device_key(&t, &d, at(21)).await,
        Err(Contended::Contended)
    ));
    store.lose(0);
    assert_eq!(
        service.current_key_challenge(&t, &d, at(22)).await.unwrap(),
        registered.challenge
    );
    assert!(service.key_thumbprint(&t, &d).await.unwrap().is_some());
}

/// Two registrations for one device: the one whose swap comes second finds
/// the row changed, reads it again, and is refused; one key is left.
#[tokio::test]
async fn of_two_registrations_one_key_is_left() {
    let (service, store) = contending().await;
    store.before_the_next_swap(Box::new(|rows| {
        Box::pin(async move {
            register_on(&rival_service(rows), &other_key())
                .await
                .expect("the rival registers first");
        })
    }));
    assert!(matches!(
        register_on(&service, &key()).await,
        Err(Contended::Registered)
    ));
    assert_eq!(
        service
            .key_thumbprint(&tenant(), &dev_id("laptop"))
            .await
            .unwrap(),
        Some(KeyThumbprint::from_bytes(other_key().public().thumbprint()))
    );
}

/// Two refreshes with one proof: the second to swap finds the challenge
/// replaced and is asked for the new one. One proof, one acceptance.
#[tokio::test]
async fn of_two_refreshes_with_one_proof_one_is_accepted() {
    let (service, store) = contending().await;
    let registered = register_on(&service, &key()).await.unwrap();
    let jws = refresh_proof(&registered.challenge);
    let rivals = jws.clone();
    let accepted = Arc::new(Mutex::new(None));
    let seen = accepted.clone();
    store.before_the_next_swap(Box::new(move |rows| {
        Box::pin(async move {
            let proved = prove_on(&rival_service(rows), &rivals, 20)
                .await
                .expect("the rival's refresh is accepted");
            *seen.lock().unwrap() = Some(proved.next_challenge);
        })
    }));
    let Err(Contended::Stale { current }) = prove_on(&service, &jws, 20).await else {
        panic!("the same proof is accepted once");
    };
    assert_eq!(Some(current), accepted.lock().unwrap().clone());
}

/// A refresh whose device is revoked between its read and its write proves
/// nothing: the swap finds the row revoked.
#[tokio::test]
async fn a_refresh_that_races_a_revocation_proves_nothing() {
    let (service, store) = contending().await;
    let registered = register_on(&service, &key()).await.unwrap();
    store.before_the_next_swap(Box::new(|rows| {
        Box::pin(async move {
            rows.set_trust_level(
                &tenant(),
                &dev_id("laptop"),
                DeviceTrustLevel::Revoked,
                at(19),
            )
            .await
            .unwrap();
        })
    }));
    assert!(matches!(
        prove_on(&service, &refresh_proof(&registered.challenge), 20).await,
        Err(Contended::Ended)
    ));
}

/// No store is read for a request that has shown no secret and no valid
/// signature. A value that is no proof, a proof whose signature does not
/// hold under the key it carries, one for another request and one outside
/// its time are refused before any row is read and before the replay store
/// is asked. A proof that does verify under a stranger's own key, naming
/// someone else's device, costs one read, through the cache when the
/// request holds no bound session and fresh when it does, records no `jti`
/// and proves nothing.
#[tokio::test]
async fn a_request_proof_reads_no_row_before_its_signature_holds() {
    let (plain, store) = contending().await;
    let jtis = Jtis::default();
    let recorded = || jtis.seen.lock().unwrap().len();
    let service = plain
        .with_request_proofs(jtis.clone(), Duration::from_secs(60))
        .unwrap();
    register_on(&service, &key()).await.unwrap();
    store.reads();
    let target = ProofTarget {
        method: "GET",
        url: "https://app.example/dashboard",
    };
    let now = at(20).unix_seconds();
    let ask = |sender: RequestProofSender, jws: String| {
        let service = service.clone();
        async move {
            let proof = RequestProof {
                jws: &jws,
                method: "GET",
                url: "https://app.example/dashboard",
            };
            service
                .prove_request(&tenant(), &dev_id("laptop"), sender, proof, at(20))
                .await
        }
    };
    let sound = key().sign_request(target, now, "j");
    let (head_and_claims, _) = sound.rsplit_once('.').unwrap();
    let forged = format!("{head_and_claims}.{}", "A".repeat(86));
    let elsewhere = ProofTarget {
        method: "GET",
        url: "https://app.example/elsewhere",
    };
    let unread = [
        "garbage".to_string(),
        forged,
        key().sign_request(elsewhere, now, "j"),
        key().sign_request(target, now - 600, "j"),
    ];
    for sender in [
        RequestProofSender::Unbound,
        RequestProofSender::BoundSession,
    ] {
        for jws in &unread {
            assert!(
                matches!(
                    ask(sender, jws.clone()).await,
                    Err(DeviceKeyError::Proof(_))
                ),
                "{sender:?}"
            );
            assert_eq!(store.reads(), (0, 0), "{sender:?}: no read");
        }
    }
    assert_eq!(recorded(), 0, "no jti was offered");

    // A stranger's own key, sound, naming this device.
    let strangers = || other_key().sign_request(target, now, "s");
    assert!(matches!(
        ask(RequestProofSender::Unbound, strangers()).await,
        Err(DeviceKeyError::Proof(KeyProofError::Signature))
    ));
    assert_eq!(store.reads(), (1, 0), "one read, which a cache may answer");
    assert!(matches!(
        ask(RequestProofSender::BoundSession, strangers()).await,
        Err(DeviceKeyError::Proof(KeyProofError::Signature))
    ));
    assert_eq!(store.reads(), (0, 1), "a bound session's row is read fresh");
    assert_eq!(recorded(), 0, "and no jti is recorded");

    // The device's own key: one read each way, and the jti is recorded.
    assert!(ask(RequestProofSender::Unbound, sound).await.is_ok());
    assert_eq!(store.reads(), (1, 0));
    assert_eq!(recorded(), 1);
}
