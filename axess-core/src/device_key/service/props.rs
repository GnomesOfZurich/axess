//! Over any sequence of refreshes, stale proofs, replays, foreign keys and
//! clock steps, the service accepts a proof exactly when it is the key's
//! signature over the current, unexpired challenge, and accepts no proof
//! twice.

use super::*;
use crate::device::store::MemoryDeviceStore;
use crate::device::store::consistency::{at, dev_id, device, tenant, user};
use crate::testing::mock_random::MockRng;
use axess_factors::key_proof::testing::SoftwareKey;
use proptest::prelude::*;

const ORIGIN: &str = "https://app.example";

#[derive(Debug, Clone)]
enum Step {
    /// Move the clock forward this many seconds.
    Wait(i64),
    /// Sign the challenge the client was last handed.
    Refresh,
    /// Present again the last proof that was presented.
    Replay,
    /// Sign the challenge the client was last handed with another key.
    Foreign,
    /// Sign a challenge that was never issued.
    Invented,
}

fn step() -> impl Strategy<Value = Step> {
    prop_oneof![
        (1i64..900).prop_map(Step::Wait),
        Just(Step::Refresh),
        Just(Step::Replay),
        Just(Step::Foreign),
        Just(Step::Invented),
    ]
}

fn sign(key: &SoftwareKey, url: &str, challenge: &str) -> String {
    let target = ProofTarget {
        method: "POST",
        url,
    };
    key.sign(
        axess_factors::key_proof::KeyProofShape::Browser,
        target,
        challenge,
        false,
    )
}

/// What the model says the client holds: the challenge it was last handed,
/// when that challenge was issued, and the challenges already used.
struct Model {
    current: String,
    issued: i64,
    used: Vec<String>,
}

fn refresh_proof<'a>(jws: &'a str, url: &'a str) -> KeyProof<'a> {
    KeyProof {
        jws,
        shape: KeyProofShape::Browser,
        method: "POST",
        url,
    }
}

async fn run(steps: Vec<Step>) -> Result<(), TestCaseError> {
    let store = MemoryDeviceStore::new();
    store
        .save(&device("laptop", 1, DeviceTrustLevel::Seen, at(0)), at(0))
        .await
        .unwrap();
    let config = DeviceKeyConfig::new(ORIGIN);
    let ttl = config.challenge_ttl().as_secs() as i64;
    let service = DeviceKeyService::new(store, config)
        .unwrap()
        .with_rng(MockRng::new(41));
    let (key, stranger) = (
        SoftwareKey::from_seed([7; 32]),
        SoftwareKey::from_seed([8; 32]),
    );
    let (t, d) = (tenant(), dev_id("laptop"));
    let registration = service.config().registration_url(ORIGIN);
    let refresh = service.config().refresh_url(ORIGIN);

    let offer = "v1.offer";
    let jws = key.sign(
        axess_factors::key_proof::KeyProofShape::Browser,
        ProofTarget {
            method: "POST",
            url: &registration,
        },
        offer,
        true,
    );
    let registered = service
        .register_device_key(
            &t,
            &d,
            &user(),
            KeyProof {
                jws: &jws,
                shape: KeyProofShape::Browser,
                method: "POST",
                url: &registration,
            },
            offer,
            at(0),
        )
        .await
        .unwrap();
    let mut model = Model {
        current: registered.challenge.to_text(),
        issued: 0,
        used: Vec::new(),
    };
    let mut now = 0i64;
    // The last proof presented, the challenge it answers, and whether the
    // key signed it.
    let mut last: Option<(String, String, bool)> = None;

    for step in steps {
        let (presented, challenge, honest) = match step {
            Step::Wait(secs) => {
                now += secs;
                continue;
            }
            Step::Refresh => {
                let challenge = model.current.clone();
                (sign(&key, &refresh, &challenge), challenge, true)
            }
            Step::Replay => match last.clone() {
                Some(presented) => presented,
                None => continue,
            },
            Step::Foreign => {
                let challenge = model.current.clone();
                (sign(&stranger, &refresh, &challenge), challenge, false)
            }
            Step::Invented => {
                let challenge = format!("invented-{now}");
                (sign(&key, &refresh, &challenge), challenge, true)
            }
        };
        let outcome = service
            .prove_device_key(&t, &d, refresh_proof(&presented, &refresh), at(now))
            .await;
        let current_and_fresh = challenge == model.current && now - model.issued < ttl;
        match outcome {
            Ok(proved) => {
                prop_assert!(honest, "a foreign signature was accepted");
                prop_assert!(current_and_fresh, "a proof over {challenge} was accepted");
                prop_assert!(
                    !model.used.contains(&challenge),
                    "a proof was accepted twice"
                );
                model.used.push(challenge.clone());
                model.current = proved.next_challenge.to_text();
                model.issued = now;
            }
            Err(DeviceKeyError::Stale { current }) => {
                prop_assert!(!current_and_fresh || !honest || model.used.contains(&challenge));
                if current.to_text() != model.current {
                    // An expired challenge was replaced, now.
                    prop_assert!(now - model.issued >= ttl);
                    model.current = current.to_text();
                    model.issued = now;
                }
            }
            Err(DeviceKeyError::Proof(_)) => {
                prop_assert!(!honest, "the key's own signature was refused");
            }
            Err(other) => return Err(TestCaseError::fail(format!("{other:?}"))),
        }
        last = Some((presented, challenge, honest));
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn a_proof_is_accepted_exactly_once_and_only_over_the_current_challenge(
        steps in prop::collection::vec(step(), 1..24)
    ) {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(run(steps))?;
    }
}
