use super::*;
use crate::device::store::MemoryDeviceStore;
use crate::device::store::consistency::{at, dev_id, device, tenant, user};
use crate::testing::mock_random::MockRng;
use axess_factors::key_proof::testing::SoftwareKey;
use std::sync::Mutex;
use std::time::Duration;

mod contention;

const ORIGIN: &str = "https://app.example";
const OFFER: &str = "v1.offer";

type Service = DeviceKeyService<MemoryDeviceStore>;
type Refusal = DeviceKeyError<<MemoryDeviceStore as DeviceStore>::Error>;

#[derive(Default)]
struct Captured(Mutex<Vec<crate::authn::event::AuthEvent>>);

impl DeviceEventSink for Arc<Captured> {
    fn emit<'a>(
        &'a self,
        event: crate::authn::event::AuthEvent,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            self.0.lock().unwrap().push(event);
        })
    }
}

impl Captured {
    fn count(&self, kind: AuthEventType, status: AuthEventStatus) -> usize {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.event_type == kind && e.event_status == status)
            .count()
    }
}

fn key() -> SoftwareKey {
    SoftwareKey::from_seed([7; 32])
}

fn other_key() -> SoftwareKey {
    SoftwareKey::from_seed([8; 32])
}

/// A service over a store that holds one `Seen` device of the test user,
/// and the sink its audit rows land in.
async fn service() -> (Service, Arc<Captured>) {
    let store = MemoryDeviceStore::new();
    store
        .save(&device("laptop", 1, DeviceTrustLevel::Seen, at(0)), at(0))
        .await
        .unwrap();
    let sink = Arc::new(Captured::default());
    let service = DeviceKeyService::new(store, DeviceKeyConfig::new(ORIGIN))
        .unwrap()
        .with_rng(MockRng::new(21))
        .with_event_sink(sink.clone());
    (service, sink)
}

fn shape_of(shape: KeyProofShape) -> axess_factors::key_proof::KeyProofShape {
    match shape {
        KeyProofShape::Browser => axess_factors::key_proof::KeyProofShape::Browser,
        KeyProofShape::App => axess_factors::key_proof::KeyProofShape::App,
    }
}

/// A proof by `signer` in `shape` for `url` over `challenge`.
fn signed(
    signer: &SoftwareKey,
    shape: KeyProofShape,
    url: &str,
    challenge: &str,
    with_key: bool,
) -> String {
    let target = ProofTarget {
        method: "POST",
        url,
    };
    signer.sign(shape_of(shape), target, challenge, with_key)
}

fn proof<'a>(jws: &'a str, shape: KeyProofShape, url: &'a str) -> KeyProof<'a> {
    KeyProof {
        jws,
        shape,
        method: "POST",
        url,
    }
}

async fn register(service: &Service, shape: KeyProofShape) -> Result<RegisteredKey, Refusal> {
    let url = service.config().registration_url(ORIGIN);
    let jws = signed(&key(), shape, &url, OFFER, true);
    service
        .register_device_key(
            &tenant(),
            &dev_id("laptop"),
            &user(),
            proof(&jws, shape, &url),
            OFFER,
            at(10),
        )
        .await
}

/// A refresh proof by `signer` over `challenge`, presented at `secs`.
async fn prove(
    service: &Service,
    signer: &SoftwareKey,
    challenge: &KeyChallenge,
    secs: i64,
) -> Result<ProvedKey, Refusal> {
    let url = service.config().refresh_url(ORIGIN);
    let jws = signed(
        signer,
        KeyProofShape::Browser,
        &url,
        &challenge.to_text(),
        false,
    );
    service
        .prove_device_key(
            &tenant(),
            &dev_id("laptop"),
            proof(&jws, KeyProofShape::Browser, &url),
            at(secs),
        )
        .await
}

#[tokio::test]
async fn a_registration_adds_the_key_and_hands_out_the_first_challenge() {
    for shape in [KeyProofShape::Browser, KeyProofShape::App] {
        let (service, sink) = service().await;
        let registered = register(&service, shape).await.unwrap();
        assert_eq!(
            registered.thumbprint,
            KeyThumbprint::from_bytes(key().public().thumbprint())
        );
        let row = service
            .store()
            .load_fresh(&tenant(), &dev_id("laptop"))
            .await
            .unwrap()
            .unwrap();
        let stored = key_of(&row.bindings).expect("the key is on the row");
        assert_eq!(stored.thumbprint, registered.thumbprint);
        assert_eq!(stored.challenge, &registered.challenge);
        assert_eq!(stored.challenge_issued_at, at(10));
        assert_eq!(stored.public_key.x, key().public().x);
        assert_eq!(
            service
                .key_thumbprint(&tenant(), &dev_id("laptop"))
                .await
                .unwrap(),
            Some(registered.thumbprint)
        );
        assert_eq!(
            sink.count(AuthEventType::DeviceKeyRegistered, AuthEventStatus::Success),
            1
        );
    }
}

#[tokio::test]
async fn a_registration_is_refused_for_a_wrong_offer_a_second_key_or_another_owner() {
    let (service, sink) = service().await;
    let url = service.config().registration_url(ORIGIN);
    let (t, d) = (tenant(), dev_id("laptop"));
    let jws = signed(
        &key(),
        KeyProofShape::Browser,
        &url,
        "v1.another-offer",
        true,
    );

    // A proof over another offer.
    let refused = service
        .register_device_key(
            &t,
            &d,
            &user(),
            proof(&jws, KeyProofShape::Browser, &url),
            OFFER,
            at(10),
        )
        .await;
    assert!(matches!(
        refused,
        Err(DeviceKeyError::Proof(KeyProofError::Challenge))
    ));
    // A proof with no key of its own.
    let keyless = signed(&key(), KeyProofShape::Browser, &url, OFFER, false);
    let refused = service
        .register_device_key(
            &t,
            &d,
            &user(),
            proof(&keyless, KeyProofShape::Browser, &url),
            OFFER,
            at(10),
        )
        .await;
    assert!(matches!(
        refused,
        Err(DeviceKeyError::Proof(KeyProofError::Key))
    ));
    // Another user's device.
    let good = signed(&key(), KeyProofShape::Browser, &url, OFFER, true);
    let stranger = crate::authn::ids::testing::user("stranger");
    let refused = service
        .register_device_key(
            &t,
            &d,
            &stranger,
            proof(&good, KeyProofShape::Browser, &url),
            OFFER,
            at(10),
        )
        .await;
    assert!(matches!(refused, Err(DeviceKeyError::NotOwner)));
    assert_eq!(service.key_thumbprint(&t, &d).await.unwrap(), None);

    // The owner registers; a second key is then refused, whoever signs it.
    register(&service, KeyProofShape::Browser).await.unwrap();
    let second = signed(&other_key(), KeyProofShape::Browser, &url, OFFER, true);
    let refused = service
        .register_device_key(
            &t,
            &d,
            &user(),
            proof(&second, KeyProofShape::Browser, &url),
            OFFER,
            at(11),
        )
        .await;
    assert!(matches!(refused, Err(DeviceKeyError::Registered)));
    assert_eq!(
        service.key_thumbprint(&t, &d).await.unwrap(),
        Some(KeyThumbprint::from_bytes(key().public().thumbprint()))
    );
    assert_eq!(
        sink.count(AuthEventType::DeviceKeyRegistered, AuthEventStatus::Failure),
        4
    );
}

#[tokio::test]
async fn a_revoked_or_missing_device_registers_and_proves_nothing() {
    let (service, _) = service().await;
    let registered = register(&service, KeyProofShape::Browser).await.unwrap();
    service
        .store()
        .set_trust_level(
            &tenant(),
            &dev_id("laptop"),
            DeviceTrustLevel::Revoked,
            at(11),
        )
        .await
        .unwrap();
    assert!(matches!(
        prove(&service, &key(), &registered.challenge, 12).await,
        Err(DeviceKeyError::Ended)
    ));
    assert!(matches!(
        service
            .current_key_challenge(&tenant(), &dev_id("laptop"), at(12))
            .await,
        Err(DeviceKeyError::Ended)
    ));
    assert!(matches!(
        service
            .current_key_challenge(&tenant(), &dev_id("nowhere"), at(12))
            .await,
        Err(DeviceKeyError::Ended)
    ));
    // A second key on the revoked device, and a first on one that is gone.
    assert!(matches!(
        register(&service, KeyProofShape::Browser).await,
        Err(DeviceKeyError::Ended)
    ));
    let url = service.config().registration_url(ORIGIN);
    let jws = signed(&key(), KeyProofShape::Browser, &url, OFFER, true);
    assert!(matches!(
        service
            .register_device_key(
                &tenant(),
                &dev_id("nowhere"),
                &user(),
                proof(&jws, KeyProofShape::Browser, &url),
                OFFER,
                at(13),
            )
            .await,
        Err(DeviceKeyError::Ended)
    ));
    // A proof for a device that is gone, and a secret holder's.
    let refresh = service.config().refresh_url(ORIGIN);
    let jws = signed(
        &key(),
        KeyProofShape::Browser,
        &refresh,
        &registered.challenge.to_text(),
        false,
    );
    assert!(matches!(
        service
            .prove_device_key(
                &tenant(),
                &dev_id("nowhere"),
                proof(&jws, KeyProofShape::Browser, &refresh),
                at(13),
            )
            .await,
        Err(DeviceKeyError::Ended)
    ));
    for device in ["laptop", "nowhere"] {
        assert!(
            matches!(
                service
                    .prove_key_of_secret_holder(&tenant(), &dev_id(device), None, at(13))
                    .await,
                Err(DeviceKeyError::Ended)
            ),
            "{device}"
        );
    }
}

/// Invariant 3: a challenge is accepted once. The proof that was accepted is
/// refused when it comes back, and the answer is the challenge to sign now.
#[tokio::test]
async fn a_proof_rotates_the_challenge_and_is_not_accepted_twice() {
    let (service, sink) = service().await;
    let first = register(&service, KeyProofShape::Browser)
        .await
        .unwrap()
        .challenge;

    let proved = prove(&service, &key(), &first, 20).await.unwrap();
    assert_ne!(proved.next_challenge, first);
    assert_eq!(
        service
            .current_key_challenge(&tenant(), &dev_id("laptop"), at(21))
            .await
            .unwrap(),
        proved.next_challenge
    );

    match prove(&service, &key(), &first, 22).await {
        Err(DeviceKeyError::Stale { current }) => assert_eq!(current, proved.next_challenge),
        other => panic!("a replayed proof must be stale, got {other:?}"),
    }
    // The next one is accepted in its turn.
    let again = prove(&service, &key(), &proved.next_challenge, 23)
        .await
        .unwrap();
    assert_ne!(again.next_challenge, proved.next_challenge);
    // A stale challenge is nobody's fault and leaves no row.
    assert_eq!(
        sink.count(
            AuthEventType::DeviceKeyProofRefused,
            AuthEventStatus::Suspicious
        ),
        0
    );
}

/// The current challenge signed by another key is the theft signal: refused,
/// recorded as suspicious, and nothing changes, so the owner's own proof
/// still stands.
#[tokio::test]
async fn the_current_challenge_signed_by_another_key_is_refused_and_recorded() {
    let (service, sink) = service().await;
    let challenge = register(&service, KeyProofShape::Browser)
        .await
        .unwrap()
        .challenge;

    assert!(matches!(
        prove(&service, &other_key(), &challenge, 20).await,
        Err(DeviceKeyError::Proof(KeyProofError::Signature))
    ));
    assert_eq!(
        sink.count(
            AuthEventType::DeviceKeyProofRefused,
            AuthEventStatus::Suspicious
        ),
        1
    );
    assert_eq!(
        service
            .current_key_challenge(&tenant(), &dev_id("laptop"), at(21))
            .await
            .unwrap(),
        challenge,
        "a refused proof consumes nothing"
    );
    assert!(prove(&service, &key(), &challenge, 22).await.is_ok());

    // Bytes that are no proof at all read no row and record nothing.
    let url = service.config().refresh_url(ORIGIN);
    let garbage = service
        .prove_device_key(
            &tenant(),
            &dev_id("laptop"),
            proof("not-a-proof", KeyProofShape::Browser, &url),
            at(23),
        )
        .await;
    assert!(matches!(
        garbage,
        Err(DeviceKeyError::Proof(KeyProofError::Malformed))
    ));
    assert_eq!(
        sink.count(
            AuthEventType::DeviceKeyProofRefused,
            AuthEventStatus::Suspicious
        ),
        1
    );
}

/// A challenge is good for its lifetime and not at its end: one second
/// before, the proof is accepted; at the end it is stale and another
/// challenge has been issued.
#[tokio::test]
async fn a_challenge_ends_exactly_at_its_lifetime() {
    let ttl = DeviceKeyConfig::new(ORIGIN).challenge_ttl().as_secs() as i64;

    let (service, _) = service().await;
    let challenge = register(&service, KeyProofShape::Browser)
        .await
        .unwrap()
        .challenge;
    assert!(
        prove(&service, &key(), &challenge, 10 + ttl - 1)
            .await
            .is_ok()
    );

    let (service, _) = self::service().await;
    let challenge = register(&service, KeyProofShape::Browser)
        .await
        .unwrap()
        .challenge;
    let fresh = match prove(&service, &key(), &challenge, 10 + ttl).await {
        Err(DeviceKeyError::Stale { current }) => current,
        other => panic!("a challenge at its end must be stale, got {other:?}"),
    };
    assert_ne!(fresh, challenge);
    // The replacement is the one stored, and a proof over it is accepted.
    assert!(prove(&service, &key(), &fresh, 10 + ttl + 1).await.is_ok());
}

/// For a caller that presented a secret, the signature is judged first: a
/// sound signature over a stale challenge changes nothing, and a missing or
/// foreign signature is the refusal the caller acts on.
#[tokio::test]
async fn a_secret_holder_is_judged_by_signature_before_challenge() {
    let (service, sink) = service().await;
    let challenge = register(&service, KeyProofShape::App)
        .await
        .unwrap()
        .challenge;
    let url = "https://app.example/token";
    let (t, d) = (tenant(), dev_id("laptop"));

    let stale = signed(&key(), KeyProofShape::App, url, "an-old-challenge", false);
    match service
        .prove_key_of_secret_holder(&t, &d, Some(proof(&stale, KeyProofShape::App, url)), at(20))
        .await
    {
        Err(DeviceKeyError::Stale { current }) => assert_eq!(current, challenge),
        other => panic!("a sound signature over a stale challenge is stale, got {other:?}"),
    }
    assert_eq!(
        sink.count(
            AuthEventType::DeviceKeyProofRefused,
            AuthEventStatus::Suspicious
        ),
        0
    );

    let foreign = signed(
        &other_key(),
        KeyProofShape::App,
        url,
        "an-old-challenge",
        false,
    );
    assert!(matches!(
        service
            .prove_key_of_secret_holder(
                &t,
                &d,
                Some(proof(&foreign, KeyProofShape::App, url)),
                at(21)
            )
            .await,
        Err(DeviceKeyError::Proof(KeyProofError::Signature))
    ));
    assert!(matches!(
        service
            .prove_key_of_secret_holder(&t, &d, None, at(22))
            .await,
        Err(DeviceKeyError::Proof(_))
    ));
    assert_eq!(
        sink.count(
            AuthEventType::DeviceKeyProofRefused,
            AuthEventStatus::Suspicious
        ),
        2
    );

    let good = signed(&key(), KeyProofShape::App, url, &challenge.to_text(), false);
    assert!(
        service
            .prove_key_of_secret_holder(&t, &d, Some(proof(&good, KeyProofShape::App, url)), at(23))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn a_device_without_a_key_is_keyless_and_forgetting_a_key_makes_it_so() {
    let (service, _) = service().await;
    let (t, d) = (tenant(), dev_id("laptop"));
    assert!(matches!(
        service
            .prove_key_of_secret_holder(&t, &d, None, at(5))
            .await,
        Err(DeviceKeyError::Keyless)
    ));
    assert!(!service.forget_device_key(&t, &d, at(5)).await.unwrap());

    let challenge = register(&service, KeyProofShape::Browser)
        .await
        .unwrap()
        .challenge;
    assert!(service.forget_device_key(&t, &d, at(11)).await.unwrap());
    assert_eq!(service.key_thumbprint(&t, &d).await.unwrap(), None);
    assert!(matches!(
        prove(&service, &key(), &challenge, 12).await,
        Err(DeviceKeyError::Keyless)
    ));
    // The other bindings and the trust level are as they were.
    let row = service.store().load_fresh(&t, &d).await.unwrap().unwrap();
    assert_eq!(row.trust_level, DeviceTrustLevel::Seen);
}

#[tokio::test]
async fn a_refused_configuration_builds_no_service() {
    let refused = DeviceKeyService::new(
        MemoryDeviceStore::new(),
        DeviceKeyConfig::new(ORIGIN).with_proof_ttl(Duration::from_secs(1)),
    );
    assert_eq!(refused.err().map(|e| e.setting), Some("proof_ttl"));
}

/// Every outcome of a registration and a proof reaches the device-key
/// concern once.
#[tokio::test]
async fn the_service_reports_to_the_device_key_concern() {
    let recorder = Arc::new(crate::testing::RecordingMetrics::default());
    let (service, _) = service().await;
    let service = service
        .with_metrics(crate::metrics::MetricSinks::noop().with_device_keys(recorder.clone()));

    let first = register(&service, KeyProofShape::Browser)
        .await
        .unwrap()
        .challenge;
    assert_eq!(recorder.count("key_registered"), 1);
    assert!(register(&service, KeyProofShape::Browser).await.is_err());
    assert_eq!(recorder.count("key_registration_refused"), 1);

    assert!(prove(&service, &other_key(), &first, 20).await.is_err());
    assert_eq!(recorder.count("key_proof_refused"), 1);
    assert!(prove(&service, &key(), &first, 21).await.is_ok());
    assert_eq!(recorder.count("key_proof_accepted"), 1);
    assert!(prove(&service, &key(), &first, 22).await.is_err());
    assert_eq!(recorder.count("key_proof_challenged"), 1);
    assert_eq!(recorder.calls().len(), 5, "{:?}", recorder.calls());
}

/// A replay store of the tests' own: each `jti` once, with the window it was
/// asked to keep it for, or, when down, no answer at all.
#[derive(Clone, Default)]
struct Jtis {
    seen: Arc<Mutex<Vec<(String, Duration)>>>,
    down: bool,
}

impl axess_factors::jwt::verifier::JtiReplayStore for Jtis {
    async fn check_and_record(
        &self,
        jti: &str,
        ttl: Duration,
    ) -> Result<(), axess_factors::jwt::verifier::JtiReplayError> {
        use axess_factors::jwt::verifier::JtiReplayError;
        if self.down {
            return Err(JtiReplayError::Backend("down".to_string()));
        }
        let mut seen = self.seen.lock().unwrap();
        if seen.iter().any(|(held, _)| held == jti) {
            return Err(JtiReplayError::already_used(jti));
        }
        seen.push((jti.to_string(), ttl));
        Ok(())
    }
}

/// A replay store that cannot answer and says so by quoting the key it was
/// handed (the namespace, the tenant, the key's thumbprint and the `jti`),
/// with a control character, a bidi override and a long tail of its own.
#[derive(Clone)]
struct QuotingJtis;

/// The tail a [`QuotingJtis`] text ends with: longer than any cut of a
/// store's text.
const QUOTED_TAIL: usize = 600;

impl axess_factors::jwt::verifier::JtiReplayStore for QuotingJtis {
    async fn check_and_record(
        &self,
        jti: &str,
        _: Duration,
    ) -> Result<(), axess_factors::jwt::verifier::JtiReplayError> {
        Err(axess_factors::jwt::verifier::JtiReplayError::Backend(
            format!(
                "SET {jti} failed\n\u{7}WARN forged line\u{202E}{}",
                "x".repeat(QUOTED_TAIL)
            ),
        ))
    }
}

/// What a replay store says when it cannot answer reaches the caller of
/// `prove_request`, and the warn line it writes, made safe: no character
/// the log-text predicate escapes, and no more of the store's text than the
/// cut keeps, through the service's own path from the proof to the store.
#[tokio::test]
async fn a_replay_store_quoting_the_key_reaches_the_caller_and_the_log_escaped_and_cut() {
    use axess_identity::log_text::escapes;
    let (plain, _) = service().await;
    register(&plain, KeyProofShape::App).await.unwrap();
    let quoting = plain
        .with_request_proofs(QuotingJtis, Duration::from_secs(60))
        .unwrap();

    let capture = axess_testing::mock_tracing::TracingCapture::install();
    let refusal = ask(&quoting, &riding(&key(), 20, "j1"))
        .await
        .expect_err("a store that cannot answer proves nothing");
    let DeviceKeyError::ReplayStore(text) = &refusal else {
        panic!("a store that cannot answer refuses as a store fault: {refusal:?}");
    };
    assert!(text.starts_with("SET axess.device-key.request:"), "{text}");
    assert!(!text.chars().any(escapes), "{text:?}");
    // The cut is the request service's own bound on a store's text.
    assert!(text.len() <= 256, "{} bytes", text.len());
    let shown = refusal.to_string();
    assert!(!shown.chars().any(escapes), "{shown:?}");

    let lines: Vec<_> = capture
        .events()
        .into_iter()
        .filter(|event| event.message.contains("the replay store did not answer"))
        .collect();
    assert_eq!(lines.len(), 1, "{lines:?}");
    let line = &lines[0].message;
    assert!(line.contains(text.as_str()), "{line}");
    assert!(!line.chars().any(escapes), "{line:?}");
    assert!(!line.contains(&"x".repeat(QUOTED_TAIL)), "the tail was cut");
}

/// The lifetime request proofs are taken with is between one second and
/// five minutes, both included, and the replay store must record.
#[tokio::test]
async fn request_proofs_take_a_lifetime_within_its_bounds_and_a_store_that_records() {
    let (service, _) = service().await;
    assert!(!service.accepts_request_proofs());
    for secs in [1, 300] {
        let on = service
            .clone()
            .with_request_proofs(Jtis::default(), Duration::from_secs(secs))
            .unwrap();
        assert!(on.accepts_request_proofs(), "{secs}");
    }
    for age in [
        Duration::ZERO,
        Duration::from_millis(999),
        Duration::from_secs(301),
    ] {
        let refused = service.clone().with_request_proofs(Jtis::default(), age);
        assert_eq!(refused.err().map(|e| e.setting), Some("max_age"), "{age:?}");
    }
    let unrecorded = service.clone().with_request_proofs(
        axess_factors::jwt::verifier::NoReplay,
        Duration::from_secs(60),
    );
    assert_eq!(unrecorded.err().map(|e| e.setting), Some("replay"));
}

const REQUEST_URL: &str = "https://app.example/dashboard";

/// A proof by `signer` over `GET /dashboard` with `jti`, made at `secs`.
fn riding(signer: &SoftwareKey, secs: i64, jti: &str) -> String {
    let target = ProofTarget {
        method: "GET",
        url: REQUEST_URL,
    };
    signer.sign_request(target, at(secs).unix_seconds(), jti)
}

/// Ask `service`, as a request that holds the bound session, whether `jws`
/// proves the test device's key at second 20.
async fn ask(service: &Service, jws: &str) -> Result<crate::device_key::ProvenKey, Refusal> {
    ask_as(service, RequestProofSender::BoundSession, jws).await
}

async fn ask_as(
    service: &Service,
    sender: RequestProofSender,
    jws: &str,
) -> Result<crate::device_key::ProvenKey, Refusal> {
    let proof = RequestProof {
        jws,
        method: "GET",
        url: REQUEST_URL,
    };
    service
        .prove_request(&tenant(), &dev_id("laptop"), sender, proof, at(20))
        .await
}

/// A request proof by the device's key stands once and is counted, and its
/// `jti` is recorded under this service's namespace, the tenant and the key,
/// for the span over which the proof is accepted. It is refused when
/// replayed, when another key signed it and when it is dated further ahead
/// than clocks differ, and a refused proof records no `jti`. A replay, and
/// another key's proof under the bound session, are counted as refused;
/// another key's proof beside nothing but the device's identifier is counted
/// apart. A proof the replay store cannot answer is refused and counted as
/// unanswered, with the refusals unchanged, a service that takes no request
/// proofs counts nothing, and a device that has no key or is revoked proves
/// nothing.
#[tokio::test]
async fn a_request_proof_stands_once_for_the_devices_key() {
    let recorder = Arc::new(crate::testing::RecordingMetrics::default());
    let jtis = Jtis::default();
    let (plain, sink) = service().await;
    let suspicious = || {
        sink.count(
            AuthEventType::DeviceKeyProofRefused,
            AuthEventStatus::Suspicious,
        )
    };
    let service = plain
        .clone()
        .with_metrics(crate::metrics::MetricSinks::noop().with_device_keys(recorder.clone()))
        .with_request_proofs(jtis.clone(), Duration::from_secs(60))
        .unwrap();
    let thumbprint = register(&service, KeyProofShape::App)
        .await
        .unwrap()
        .thumbprint;

    let proven = ask(&service, &riding(&key(), 20, "j1")).await.unwrap();
    assert_eq!(
        proven,
        crate::device_key::ProvenKey {
            tenant: tenant(),
            device: dev_id("laptop"),
            thumbprint,
        }
    );
    assert_eq!(recorder.count("request_proof_accepted"), 1);
    assert_eq!(
        jtis.seen.lock().unwrap().as_slice(),
        &[(
            format!(
                "axess.device-key.request:{}:{}:j1",
                tenant(),
                thumbprint.to_text()
            ),
            Duration::from_secs(66)
        )]
    );

    assert!(matches!(
        ask(&service, &riding(&key(), 20, "j1")).await,
        Err(DeviceKeyError::Replayed)
    ));
    assert_eq!(recorder.count("request_proof_refused"), 1);
    assert_eq!(suspicious(), 1, "a replayed proof was captured: recorded");
    // Another key's proof, sound under the key it carries, is not the
    // device's. Beside nothing but the identifier anybody can send it: it is
    // counted apart and writes no row. Under the bound session it is the
    // session cookie held without the key.
    let unbound = RequestProofSender::Unbound;
    assert!(matches!(
        ask_as(&service, unbound, &riding(&other_key(), 20, "j2")).await,
        Err(DeviceKeyError::Proof(KeyProofError::Signature))
    ));
    assert_eq!(suspicious(), 1, "anybody can post another key's proof");
    assert_eq!(recorder.count("unbound_request_proof_refused"), 1);
    assert_eq!(recorder.count("request_proof_refused"), 1);
    assert!(matches!(
        ask(&service, &riding(&other_key(), 20, "j2")).await,
        Err(DeviceKeyError::Proof(KeyProofError::Signature))
    ));
    assert_eq!(suspicious(), 2, "the session cookie without the key");
    assert_eq!(recorder.count("request_proof_refused"), 2);
    // Five seconds ahead of the server's clock is what clocks differ by;
    // six is a proof made before it is used.
    assert!(ask(&service, &riding(&key(), 25, "j3")).await.is_ok());
    assert!(matches!(
        ask(&service, &riding(&key(), 26, "j4")).await,
        Err(DeviceKeyError::Proof(KeyProofError::Time))
    ));
    assert_eq!(
        jtis.seen.lock().unwrap().len(),
        2,
        "a refused proof records no jti"
    );
    let down = service
        .clone()
        .with_request_proofs(
            Jtis {
                down: true,
                ..Jtis::default()
            },
            Duration::from_secs(60),
        )
        .unwrap();
    let refused = recorder.count("request_proof_refused");
    assert!(matches!(
        ask(&down, &riding(&key(), 20, "j5")).await,
        Err(DeviceKeyError::ReplayStore(_))
    ));
    assert_eq!(recorder.count("request_proof_unanswered"), 1);
    assert_eq!(recorder.count("request_proof_refused"), refused);
    let off = plain
        .clone()
        .with_metrics(crate::metrics::MetricSinks::noop().with_device_keys(recorder.clone()));
    let calls = recorder.calls().len();
    assert!(matches!(
        ask(&off, &riding(&key(), 20, "j6")).await,
        Err(DeviceKeyError::RequestProofsOff)
    ));
    assert_eq!(
        recorder.calls().len(),
        calls,
        "a service that takes none counts none"
    );

    assert!(
        service
            .forget_device_key(&tenant(), &dev_id("laptop"), at(21))
            .await
            .unwrap()
    );
    assert!(matches!(
        ask(&service, &riding(&key(), 20, "j7")).await,
        Err(DeviceKeyError::Keyless)
    ));
    service
        .store()
        .set_trust_level(
            &tenant(),
            &dev_id("laptop"),
            DeviceTrustLevel::Revoked,
            at(22),
        )
        .await
        .unwrap();
    assert!(matches!(
        ask(&service, &riding(&key(), 20, "j8")).await,
        Err(DeviceKeyError::Ended)
    ));
}

/// Two nodes, each with a cache in front of the one device store. A node
/// whose cache holds the device from before its revocation on the other
/// node refuses the next request proof all the same: the row is read past
/// the cache.
#[tokio::test]
async fn a_revocation_on_another_node_ends_request_proofs_at_once() {
    use crate::CachedDeviceStore;
    let shared = MemoryDeviceStore::new();
    shared
        .save(&device("laptop", 1, DeviceTrustLevel::Seen, at(0)), at(0))
        .await
        .unwrap();
    let clock = Arc::new(axess_clock::testing::MockClock::at_reference());
    let node = |store: &MemoryDeviceStore| {
        CachedDeviceStore::with_options(store.clone(), 64, Duration::from_secs(60), clock.clone())
    };
    let (here, there) = (node(&shared), node(&shared));
    let service = DeviceKeyService::new(here.clone(), DeviceKeyConfig::new(ORIGIN))
        .unwrap()
        .with_rng(MockRng::new(21))
        .with_request_proofs(Jtis::default(), Duration::from_secs(60))
        .unwrap();
    let url = service.config().registration_url(ORIGIN);
    let jws = signed(&key(), KeyProofShape::App, &url, OFFER, true);
    service
        .register_device_key(
            &tenant(),
            &dev_id("laptop"),
            &user(),
            proof(&jws, KeyProofShape::App, &url),
            OFFER,
            at(10),
        )
        .await
        .unwrap();
    let request = |sender: RequestProofSender, jti: &str| {
        let jws = riding(&key(), 20, jti);
        let service = service.clone();
        async move {
            let proof = RequestProof {
                jws: &jws,
                method: "GET",
                url: REQUEST_URL,
            };
            service
                .prove_request(&tenant(), &dev_id("laptop"), sender, proof, at(20))
                .await
        }
    };
    let (bound, unbound) = (
        RequestProofSender::BoundSession,
        RequestProofSender::Unbound,
    );
    assert!(request(bound, "j1").await.is_ok());
    // This node's cache now holds the live row.
    assert!(
        here.load(&tenant(), &dev_id("laptop"))
            .await
            .unwrap()
            .is_some()
    );
    there
        .set_trust_level(
            &tenant(),
            &dev_id("laptop"),
            DeviceTrustLevel::Revoked,
            at(21),
        )
        .await
        .unwrap();
    assert_eq!(
        here.load(&tenant(), &dev_id("laptop"))
            .await
            .unwrap()
            .map(|row| row.trust_level),
        Some(DeviceTrustLevel::Seen),
        "this node's cache still holds the row from before the revocation"
    );
    // A request with no bound session is read through the cache: it is
    // still recognised from the cached row, and that is all it gets. The
    // step that would bind a session to the device reads the row fresh and
    // binds nothing.
    let recognised = request(unbound, "j2")
        .await
        .expect("recognised from the cached row");
    assert!(matches!(
        service
            .claim_for_binding(&recognised, &user(), at(22))
            .await,
        Err(DeviceKeyError::Ended)
    ));
    // A request of the bound session is read past the cache: ended.
    assert!(matches!(
        request(bound, "j3").await,
        Err(DeviceKeyError::Ended)
    ));
}

/// The layer's view of the service takes a request proof only when the
/// service accepts them.
#[tokio::test]
async fn the_layer_takes_request_proofs_only_where_the_service_accepts_them() {
    use crate::device_key::erased::ErasedDeviceKeys;
    let (plain, _) = service().await;
    let service = plain
        .clone()
        .with_request_proofs(Jtis::default(), Duration::from_secs(60))
        .unwrap();
    register(&service, KeyProofShape::App).await.unwrap();
    let jws = riding(&key(), 20, "j1");
    let proof = || RequestProof {
        jws: &jws,
        method: "GET",
        url: REQUEST_URL,
    };
    let sender = RequestProofSender::BoundSession;
    let (tenant, device) = (tenant(), dev_id("laptop"));
    let off: &dyn ErasedDeviceKeys = &plain;
    assert!(!off.takes_request_proofs());
    assert_eq!(
        off.request_proof(&tenant, &device, sender, proof(), at(20))
            .await,
        None
    );
    let on: &dyn ErasedDeviceKeys = &service;
    assert!(on.takes_request_proofs());
    assert!(
        on.request_proof(&tenant, &device, sender, proof(), at(20))
            .await
            .is_some()
    );
}

/// A proof by another key on a request that holds the bound session is the
/// session cookie held without the key: the layer's view of the service
/// records it as `Suspicious`. The same proof beside nothing but a device's
/// identifier, which anybody can send, records nothing.
#[tokio::test]
async fn a_wrong_key_under_a_bound_session_is_recorded() {
    use crate::device_key::erased::ErasedDeviceKeys;
    let (plain, sink) = service().await;
    let service = plain
        .with_request_proofs(Jtis::default(), Duration::from_secs(60))
        .unwrap();
    register(&service, KeyProofShape::App).await.unwrap();
    let jws = riding(&other_key(), 20, "j1");
    let proof = || RequestProof {
        jws: &jws,
        method: "GET",
        url: REQUEST_URL,
    };
    let suspicious = || {
        sink.count(
            AuthEventType::DeviceKeyProofRefused,
            AuthEventStatus::Suspicious,
        )
    };
    let (tenant, device) = (tenant(), dev_id("laptop"));
    let erased: &dyn ErasedDeviceKeys = &service;
    assert_eq!(
        erased
            .request_proof(
                &tenant,
                &device,
                RequestProofSender::Unbound,
                proof(),
                at(20)
            )
            .await,
        None
    );
    assert_eq!(suspicious(), 0);
    assert_eq!(
        erased
            .request_proof(
                &tenant,
                &device,
                RequestProofSender::BoundSession,
                proof(),
                at(20),
            )
            .await,
        None
    );
    assert_eq!(suspicious(), 1);
}

/// A row the session layer writes goes to the service's own sink.
#[tokio::test]
async fn the_layers_rows_go_to_the_services_sink() {
    use crate::device_key::erased::ErasedDeviceKeys;
    let (service, sink) = service().await;
    let event = AuthEventBuilder::success(AuthEventType::SessionKeyBound)
        .maybe_attributed_to(Some(&user()), Some(&tenant()))
        .with_device(dev_id("laptop"))
        .build_at(at(30));
    let erased: &dyn ErasedDeviceKeys = &service;
    erased.emit(event).await;
    assert_eq!(
        sink.count(AuthEventType::SessionKeyBound, AuthEventStatus::Success),
        1
    );
}

/// The router holds the two configured paths, for `POST` only, and nothing
/// else.
#[tokio::test]
async fn the_router_holds_the_two_configured_paths() {
    use tower::ServiceExt;
    let (service, _) = service().await;
    let router: axum::Router = service.router();
    let status = |path: &str| {
        let request = axum::http::Request::get(path)
            .body(axum::body::Body::empty())
            .unwrap();
        let router = router.clone();
        async move { router.oneshot(request).await.unwrap().status() }
    };
    let config = service.config();
    for path in [config.registration_path(), config.refresh_path()] {
        assert_eq!(
            status(path).await,
            axum::http::StatusCode::METHOD_NOT_ALLOWED,
            "{path}"
        );
    }
    assert_eq!(
        status("/axess/device-keys").await,
        axum::http::StatusCode::NOT_FOUND
    );
}

/// A device made before anyone signed in has no owner. Registering a key on
/// it claims it for the user who registers, in the store's own conditional
/// write, so the key is never on a device anyone may take.
#[tokio::test]
async fn a_registration_claims_an_unowned_device_for_its_user() {
    let store = MemoryDeviceStore::new();
    let mut row = device("laptop", 1, DeviceTrustLevel::Seen, at(0));
    row.user_id = None;
    store.save(&row, at(0)).await.unwrap();
    let service = DeviceKeyService::new(store, DeviceKeyConfig::new(ORIGIN))
        .unwrap()
        .with_rng(MockRng::new(21));
    register(&service, KeyProofShape::Browser).await.unwrap();
    let row = service
        .store()
        .load_fresh(&tenant(), &dev_id("laptop"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.user_id, Some(user()));
}

/// A secret holder's device is read before anything it sent: one that has
/// no key is answered as keyless whatever came with the secret, with no
/// suspicious row and no refused proof counted.
#[tokio::test]
async fn a_keyless_device_is_keyless_whatever_its_secret_holder_sends() {
    let recorder = Arc::new(crate::testing::RecordingMetrics::default());
    let (service, sink) = service().await;
    let service = service
        .with_metrics(crate::metrics::MetricSinks::noop().with_device_keys(recorder.clone()));
    let (t, d) = (tenant(), dev_id("laptop"));
    let url = "https://app.example/token";
    let sound = signed(&key(), KeyProofShape::App, url, "any", true);
    for jws in ["garbage", "a.b.c", sound.as_str()] {
        assert!(
            matches!(
                service
                    .prove_key_of_secret_holder(
                        &t,
                        &d,
                        Some(proof(jws, KeyProofShape::App, url)),
                        at(5)
                    )
                    .await,
                Err(DeviceKeyError::Keyless)
            ),
            "{jws}"
        );
    }
    assert_eq!(
        sink.count(
            AuthEventType::DeviceKeyProofRefused,
            AuthEventStatus::Suspicious
        ),
        0
    );
    assert!(recorder.calls().is_empty(), "{:?}", recorder.calls());
}
