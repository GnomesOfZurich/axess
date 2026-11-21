//! DPoP verification against a replay store every node shares.
//!
//! [`verify_dpop_proof`] records a proof's `jti` in a [`DpopJtiCache`], and
//! that trait is synchronous, so only a cache in the process can stand
//! behind it: a fleet of resource servers each keeps its own, and a proof
//! accepted by one node is accepted once more by every other. This module
//! runs the same checks and records the `jti` in an asynchronous
//! [`JtiReplayStore`] instead, which a store every node reaches can
//! implement (`ValkeyJtiReplayStore` in axess-core). [`MemoryJtiCache`]
//! implements both traits, so one process can use either path.

use std::sync::Mutex;
use std::time::Duration;

use axess_clock::{SignedDuration, Timestamp};

use super::{
    DpopJtiCache, DpopVerified, DpopVerifyRequest, JtiInsert, MemoryJtiCache, verify_dpop_proof,
};
use crate::jwt::verifier::{JtiReplayError, JtiReplayStore};
use crate::oauth::OAuthError;

/// What [`verify_dpop_proof_with_store`] checks a proof against: the fields
/// of [`DpopVerifyRequest`] but the replay cache, which the store replaces.
#[derive(Clone, Copy)]
pub struct DpopProofRequest<'a> {
    /// The raw `DPoP` header value (compact JWS).
    pub proof_jwt: &'a str,
    /// HTTP method of the request being protected.
    pub htm: &'a str,
    /// Canonical request URL: scheme, authority and path.
    pub htu: &'a str,
    /// The access token the request carries, for the `ath` check.
    pub access_token: Option<&'a str>,
    /// Maximum allowed clock skew for `iat`, as
    /// [`DpopVerifyRequest::max_iat_skew`] counts it.
    pub max_iat_skew: Duration,
}

/// Prints the method, the URL and the skew. The proof and the access token
/// are credentials and print as `***`. The method and the URL are the
/// request's, so the sender's: each is escaped and cut at
/// `REMOTE_VALUE_LOG_BYTES`, as a refusal quotes them.
impl std::fmt::Debug for DpopProofRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DpopProofRequest")
            .field("proof_jwt", &"***")
            .field(
                "htm",
                &format_args!(
                    "{}",
                    crate::log_text::log_safe(self.htm, super::REMOTE_VALUE_LOG_BYTES)
                ),
            )
            .field(
                "htu",
                &format_args!(
                    "{}",
                    crate::log_text::log_safe(self.htu, super::REMOTE_VALUE_LOG_BYTES)
                ),
            )
            .field("access_token", &self.access_token.map(|_| "***"))
            .field("max_iat_skew", &self.max_iat_skew)
            .finish()
    }
}

/// The namespace DPoP `jti`s are recorded in by
/// [`verify_dpop_proof_with_store`].
const DPOP_JTI_NAMESPACE: &str = "axess.dpop";

/// A cache that accepts every `jti` and keeps the one it was handed, so the
/// checks can run first and the record be made in the shared store after.
struct Deferred(Mutex<Option<(String, Timestamp)>>);

impl DpopJtiCache for Deferred {
    fn try_insert(&self, jti: &str, expires_at: Timestamp) -> bool {
        let mut held = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *held = Some((jti.to_owned(), expires_at));
        true
    }
}

/// [`verify_dpop_proof`] with the `jti` recorded in `store`.
///
/// Every check of [`verify_dpop_proof`] runs first, in its order, so a
/// proof that fails one records nothing. A `jti` the store already holds is
/// refused as a replay, and a store that cannot answer refuses the proof:
/// a replay check that fails open is no check. The entry is kept for the
/// span over which the proof stays acceptable, as the in-process cache
/// keeps it, and is recorded as `axess.dpop:<key thumbprint>:<jti>`, so it
/// shares nothing with what another verifier or another key records.
pub async fn verify_dpop_proof_with_store<R: JtiReplayStore>(
    req: DpopProofRequest<'_>,
    now: Timestamp,
    store: &R,
) -> Result<DpopVerified, OAuthError> {
    let deferred = Deferred(Mutex::new(None));
    let verified = verify_dpop_proof(
        DpopVerifyRequest {
            proof_jwt: req.proof_jwt,
            htm: req.htm,
            htu: req.htu,
            access_token: req.access_token,
            max_iat_skew: req.max_iat_skew,
            jti_cache: &deferred,
        },
        now,
    )?;
    let held = deferred
        .0
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take();
    let Some((jti, expires_at)) = held else {
        return Err(OAuthError::IdTokenValidation(
            "DPoP proof verified without a `jti` to record; rejecting".to_string(),
        ));
    };
    // At least a second: an entry that expires as it is written records
    // nothing.
    let ttl = Duration::try_from(expires_at.since(now))
        .unwrap_or_default()
        .max(Duration::from_secs(1));
    // Under the verifier's own namespace and the key that signed the proof:
    // a store that other verifiers record into never takes their `jti` for
    // this one's, and one client's `jti` never refuses another's.
    let record = format!("{DPOP_JTI_NAMESPACE}:{}:{jti}", verified.thumbprint);
    match store.check_and_record(&record, ttl).await {
        Ok(()) => Ok(verified),
        Err(JtiReplayError::AlreadyUsed(_)) => Err(OAuthError::IdTokenValidation(
            "DPoP `jti` replayed within skew window; rejecting".to_string(),
        )),
        Err(JtiReplayError::Backend(_)) => Err(OAuthError::IdTokenValidation(
            "DPoP replay store could not answer; rejecting".to_string(),
        )),
    }
}

/// The in-process cache as a [`JtiReplayStore`], for a single node: the JWT
/// verifier (`JwtVerifier::with_replay_store`) and
/// [`verify_dpop_proof_with_store`] can use it where a fleet would use a
/// shared store. The entry expires `ttl` after the cache's own clock reads
/// now, and the capacity bound applies as it does to `try_insert`: a full
/// cache refuses rather than forgets a live `jti`, and says so as a store
/// that could not answer ([`JtiReplayError::Backend`]), never as a replay.
impl JtiReplayStore for MemoryJtiCache {
    async fn check_and_record(&self, jti: &str, ttl: Duration) -> Result<(), JtiReplayError> {
        let expires_at = SignedDuration::try_from(ttl)
            .ok()
            .and_then(|ttl| self.clock.now().checked_add(ttl))
            .ok_or_else(|| JtiReplayError::Backend("replay window does not fit a date".into()))?;
        match self.insert(jti, expires_at) {
            JtiInsert::Recorded => Ok(()),
            JtiInsert::Held => Err(JtiReplayError::already_used(jti)),
            // Not a replay: the cache cannot record, so it cannot answer.
            JtiInsert::Full => Err(JtiReplayError::Backend(
                "the in-process replay cache is at its capacity".into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axess_clock::testing::MockClock;
    use std::sync::Arc;

    const HTU: &str = "https://api.example.com/resource";

    fn cache(clock: &MockClock) -> MemoryJtiCache {
        MemoryJtiCache::new().with_clock(Arc::new(clock.clone()))
    }

    /// A proof for `HTU` signed at `iat` with the given `jti` bytes.
    fn proof(iat: i64, jti: u8) -> String {
        let key = crate::oauth::DpopKey::from_seed([3; 32]);
        super::super::super::dpop::generate_dpop_proof(&key, "GET", HTU, None, iat, [jti; 16])
            .expect("a proof")
            .proof_jwt
    }

    fn request(jwt: &str) -> DpopProofRequest<'_> {
        DpopProofRequest {
            proof_jwt: jwt,
            htm: "GET",
            htu: HTU,
            access_token: None,
            max_iat_skew: Duration::from_secs(60),
        }
    }

    #[tokio::test]
    async fn a_proof_is_accepted_once_by_a_shared_store() {
        let clock = MockClock::at_reference();
        let now = MockClock::reference_time();
        let store = cache(&clock);
        let jwt = proof(now.unix_seconds(), 1);
        assert!(
            verify_dpop_proof_with_store(request(&jwt), now, &store)
                .await
                .is_ok()
        );
        let replay = verify_dpop_proof_with_store(request(&jwt), now, &store).await;
        let text = replay.expect_err("a replay is refused").to_string();
        assert!(text.contains("replayed"), "{text}");
        // Another proof is accepted.
        let other = proof(now.unix_seconds(), 2);
        assert!(
            verify_dpop_proof_with_store(request(&other), now, &store)
                .await
                .is_ok()
        );
    }

    /// A proof that fails a check records nothing: the same `jti` on a proof
    /// that passes is still accepted.
    #[tokio::test]
    async fn a_refused_proof_records_nothing() {
        let clock = MockClock::at_reference();
        let now = MockClock::reference_time();
        let store = cache(&clock);
        let jwt = proof(now.unix_seconds(), 7);
        let wrong_method = DpopProofRequest {
            htm: "POST",
            ..request(&jwt)
        };
        assert!(
            verify_dpop_proof_with_store(wrong_method, now, &store)
                .await
                .is_err()
        );
        assert!(
            verify_dpop_proof_with_store(request(&jwt), now, &store)
                .await
                .is_ok()
        );
    }

    struct Down;

    impl JtiReplayStore for Down {
        async fn check_and_record(&self, jti: &str, ttl: Duration) -> Result<(), JtiReplayError> {
            Err(JtiReplayError::Backend(format!(
                "unreachable: {} bytes for {ttl:?}",
                jti.len()
            )))
        }
    }

    /// A store that cannot answer refuses the proof.
    #[tokio::test]
    async fn a_store_that_cannot_answer_refuses_the_proof() {
        let now = MockClock::reference_time();
        let jwt = proof(now.unix_seconds(), 9);
        let refused = verify_dpop_proof_with_store(request(&jwt), now, &Down).await;
        let text = refused.expect_err("fails closed").to_string();
        assert!(text.contains("could not answer"), "{text}");
    }

    /// A request prints neither the proof nor the access token.
    #[test]
    fn a_request_prints_no_credential() {
        let request = DpopProofRequest {
            access_token: Some("secret-access-token"),
            ..request("header.payload.signature")
        };
        let text = format!("{request:?}");
        assert!(!text.contains("secret-access-token"), "{text}");
        assert!(!text.contains("header.payload"), "{text}");
        assert!(text.contains("GET") && text.contains(HTU), "{text}");
        assert!(format!("{:?}", self::request("p")).contains("access_token: None"));
        let method = format!("PATCH\u{202E}{}", "X".repeat(500));
        let text = format!(
            "{:?}",
            DpopProofRequest {
                htm: &method,
                ..self::request("p")
            }
        );
        assert!(
            !text.contains(&"X".repeat(64)) && text.contains("\\u{202e}"),
            "{text}"
        );
    }

    /// What the shared store is handed: the `jti` under the verifier's
    /// namespace and the proof's key, for the span over which the proof
    /// stays acceptable (twice the skew and a second).
    #[tokio::test]
    async fn the_record_names_the_verifier_and_the_key_and_lasts_the_window() {
        #[derive(Default)]
        struct Seen(Mutex<Vec<(String, Duration)>>);
        impl JtiReplayStore for Seen {
            async fn check_and_record(
                &self,
                jti: &str,
                ttl: Duration,
            ) -> Result<(), JtiReplayError> {
                self.0.lock().unwrap().push((jti.to_owned(), ttl));
                Ok(())
            }
        }
        let now = MockClock::reference_time();
        let store = Seen::default();
        let verified =
            verify_dpop_proof_with_store(request(&proof(now.unix_seconds(), 4)), now, &store)
                .await
                .expect("a sound proof");
        let seen = store.0.lock().unwrap();
        let [(record, ttl)] = seen.as_slice() else {
            panic!("one record, got {seen:?}");
        };
        let jti = record
            .strip_prefix(&format!("axess.dpop:{}:", verified.thumbprint))
            .expect("namespace and key first");
        assert!(!jti.is_empty() && !jti.contains(':'), "{jti}");
        assert_eq!(*ttl, Duration::from_secs(121));
    }

    /// A cache at its capacity cannot record: that is a store that could
    /// not answer, and is never reported as a replay.
    #[tokio::test]
    async fn a_full_memory_cache_is_a_store_fault_and_not_a_replay() {
        let clock = MockClock::at_reference();
        let store = cache(&clock).with_capacity(1);
        let ttl = Duration::from_secs(30);
        assert!(store.check_and_record("a", ttl).await.is_ok());
        assert!(matches!(
            store.check_and_record("b", ttl).await,
            Err(JtiReplayError::Backend(_))
        ));
        assert!(matches!(
            store.check_and_record("a", ttl).await,
            Err(JtiReplayError::AlreadyUsed(_))
        ));
        let now = MockClock::reference_time();
        let refused =
            verify_dpop_proof_with_store(request(&proof(now.unix_seconds(), 5)), now, &store).await;
        let text = refused.expect_err("a full cache refuses").to_string();
        assert!(text.contains("could not answer"), "{text}");
    }

    /// As a replay store the cache keeps an entry for its `ttl` on its own
    /// clock and forgets it after.
    #[tokio::test]
    async fn the_memory_cache_keeps_an_entry_for_its_ttl() {
        let clock = MockClock::at_reference();
        let store = cache(&clock);
        let ttl = Duration::from_secs(30);
        assert!(store.check_and_record("a", ttl).await.is_ok());
        assert!(matches!(
            store.check_and_record("a", ttl).await,
            Err(JtiReplayError::AlreadyUsed(_))
        ));
        clock.advance_secs(29);
        assert!(store.check_and_record("a", ttl).await.is_err());
        clock.advance_secs(1);
        assert!(store.check_and_record("a", ttl).await.is_ok());
    }
}
