//! Test material for the Workload API client: a certificate authority that
//! mints X.509 SVIDs, unsigned JWT SVIDs, a listener that records what the
//! watchers report, and a world that puts a fake agent, a mock clock and a
//! client together.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType, date_time_ymd,
};

/// A day of January 2026, the month the mock clock's reference time opens:
/// `Day(1)` is 2026-01-01T00:00:00Z, the reference time itself.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Day(pub(crate) u8);

/// The mock clock's reference time, 2026-01-01T00:00:00Z, in seconds since
/// the Unix epoch.
pub(crate) const REFERENCE: i64 = 1_767_225_600;

/// One minted X.509 SVID.
#[derive(Debug, Clone)]
pub(crate) struct Minted {
    pub(crate) spiffe_id: String,
    /// The leaf, DER.
    pub(crate) cert_der: Vec<u8>,
    /// The private key, PKCS#8 DER.
    pub(crate) key_der: Vec<u8>,
}

/// A certificate authority of one trust domain.
pub(crate) struct TestCa {
    issuer: Issuer<'static, KeyPair>,
    cert_der: Vec<u8>,
}

impl TestCa {
    /// An authority named `name`, valid through the 2020s.
    pub(crate) fn new(name: &str) -> Self {
        Self::valid_until(name, 2030, 1)
    }

    /// An authority named `name` whose own certificate runs out at the
    /// start of `until`: for a bundle that still lists a retired authority.
    pub(crate) fn expiring(name: &str, until: Day) -> Self {
        Self::valid_until(name, 2026, until.0)
    }

    /// An authority valid from 2020 to the start of the given day of
    /// January of `year`.
    fn valid_until(name: &str, year: i32, day: u8) -> Self {
        let key = KeyPair::generate().expect("authority key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("authority params");
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.not_before = date_time_ymd(2020, 1, 1);
        params.not_after = date_time_ymd(year, 1, day);
        let cert_der = params
            .self_signed(&key)
            .expect("authority certificate")
            .der()
            .to_vec();
        Self {
            issuer: Issuer::new(params, key),
            cert_der,
        }
    }

    /// The authority's certificate, DER: the trust domain's bundle.
    pub(crate) fn bundle_der(&self) -> Vec<u8> {
        self.cert_der.clone()
    }

    /// An X.509 SVID for `spiffe_id`, valid from the start of `from` to the
    /// start of `until`.
    pub(crate) fn svid(&self, spiffe_id: &str, from: Day, until: Day) -> Minted {
        self.leaf(vec![uri(spiffe_id)], IsCa::NoCa, from, until, spiffe_id)
    }

    /// A leaf with the given names and CA flag, for the SVIDs a client must
    /// refuse.
    pub(crate) fn leaf(
        &self,
        names: Vec<SanType>,
        is_ca: IsCa,
        from: Day,
        until: Day,
        spiffe_id: &str,
    ) -> Minted {
        let key = KeyPair::generate().expect("leaf key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("leaf params");
        params
            .distinguished_name
            .push(DnType::CommonName, "workload");
        params.subject_alt_names = names;
        params.is_ca = is_ca;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        params.not_before = date_time_ymd(2026, 1, from.0);
        params.not_after = date_time_ymd(2026, 1, until.0);
        let certificate = params
            .signed_by(&key, &self.issuer)
            .expect("leaf certificate");
        Minted {
            spiffe_id: spiffe_id.to_owned(),
            cert_der: certificate.der().to_vec(),
            key_der: key.serialize_der(),
        }
    }
}

/// `pkcs8`, a P-256 private key as the test authority writes one, without
/// the public key it carries: the same key in the shorter encoding RFC 5915
/// allows, which says nothing about whose key it is.
pub(crate) fn without_public_key(pkcs8: &[u8]) -> Vec<u8> {
    // PrivateKeyInfo { 0, { id-ecPublicKey, prime256v1 },
    //   OCTET STRING { ECPrivateKey { 1, OCTET STRING (32), [1] { point } } } }
    assert_eq!(pkcs8.len(), 138, "a P-256 key with its public key");
    assert_eq!(&pkcs8[..6], &[0x30, 0x81, 0x87, 0x02, 0x01, 0x00]);
    assert_eq!(&pkcs8[29..36], &[0x30, 0x6B, 0x02, 0x01, 0x01, 0x04, 0x20]);
    assert_eq!(pkcs8[68], 0xA1, "the public key follows the private one");
    let algorithm = &pkcs8[6..27];
    let private = &pkcs8[34..68];
    let mut out = vec![0x30, 0x41, 0x02, 0x01, 0x00];
    out.extend_from_slice(algorithm);
    out.extend_from_slice(&[0x04, 0x27, 0x30, 0x25, 0x02, 0x01, 0x01]);
    out.extend_from_slice(private);
    out
}

/// A URI subject alternative name.
pub(crate) fn uri(value: &str) -> SanType {
    SanType::URI(value.try_into().expect("an IA5 string"))
}

/// A JWT with the given claims and a signature nobody checks: what a
/// holder reads of its own SVID is the payload.
pub(crate) fn unsigned_jwt(claims: &serde_json::Value) -> String {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","kid":"k1","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    format!("{header}.{payload}.c2lnbmF0dXJl")
}

/// A JWT SVID for `spiffe_id` and `audience`, issued at `issued_at` and
/// expiring at `expires_at`, both in seconds since the Unix epoch.
pub(crate) fn jwt_svid(
    spiffe_id: &str,
    audience: &[&str],
    issued_at: i64,
    expires_at: i64,
) -> String {
    unsigned_jwt(&serde_json::json!({
        "sub": spiffe_id,
        "aud": audience,
        "iat": issued_at,
        "exp": expires_at,
    }))
}

#[cfg(unix)]
pub(crate) use world::{World, served, settled, within};

/// Records every watcher event as a line, and lets a test wait for one.
#[cfg(unix)]
pub(crate) struct Recorder {
    lines: tokio::sync::watch::Sender<Vec<String>>,
    errors: std::sync::Mutex<Vec<String>>,
}

#[cfg(unix)]
impl Default for Recorder {
    fn default() -> Self {
        Self {
            lines: tokio::sync::watch::Sender::new(Vec::new()),
            errors: std::sync::Mutex::new(Vec::new()),
        }
    }
}

#[cfg(unix)]
impl crate::workload::spire::WorkloadApiListener for Recorder {
    fn on_event(&self, event: &crate::workload::spire::WorkloadApiEvent<'_>) {
        let line = match event {
            crate::workload::spire::WorkloadApiEvent::Rotated { kind, .. } => {
                format!("rotated:{}", kind.as_str())
            }
            crate::workload::spire::WorkloadApiEvent::RefreshFailed {
                kind,
                error,
                consecutive_failures,
                still_serving,
                ..
            } => {
                self.errors
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(error.to_string());
                format!(
                    "failed:{}:serving={still_serving}:run={consecutive_failures}",
                    kind.as_str()
                )
            }
            crate::workload::spire::WorkloadApiEvent::BundleSkipped { kind, key, .. } => {
                format!("skipped:{}:{key}", kind.as_str())
            }
            crate::workload::spire::WorkloadApiEvent::Expired { kind, .. } => {
                format!("expired:{}", kind.as_str())
            }
            crate::workload::spire::WorkloadApiEvent::Withdrawn { kind, .. } => {
                format!("withdrawn:{}", kind.as_str())
            }
            crate::workload::spire::WorkloadApiEvent::WithdrawalDeferred { kind, .. } => {
                format!("deferred:{}", kind.as_str())
            }
            crate::workload::spire::WorkloadApiEvent::Stopped { kind, error } => {
                self.errors
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(error.to_string());
                format!("stopped:{}", kind.as_str())
            }
        };
        self.lines.send_modify(|lines| lines.push(line));
    }
}

#[cfg(unix)]
impl Recorder {
    /// Every line so far.
    pub(crate) fn lines(&self) -> Vec<String> {
        self.lines.borrow().clone()
    }

    /// The text of every refresh error so far.
    pub(crate) fn errors(&self) -> Vec<String> {
        self.errors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// How many lines start with `prefix`.
    pub(crate) fn count(&self, prefix: &str) -> usize {
        self.lines
            .borrow()
            .iter()
            .filter(|line| line.starts_with(prefix))
            .count()
    }

    /// Wait until at least `count` lines start with `prefix`.
    pub(crate) async fn at_least(&self, count: usize, prefix: &str) {
        let mut lines = self.lines.subscribe();
        let reached = lines.wait_for(|lines| {
            lines.iter().filter(|line| line.starts_with(prefix)).count() >= count
        });
        let outcome = within(reached).await;
        assert!(outcome.is_ok(), "the recorder was dropped");
    }
}

#[cfg(unix)]
mod world {
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;

    use axess_identity::TrustDomain;
    use tokio::task::JoinHandle;

    use super::{Minted, Recorder};
    use crate::metrics::MetricSinks;
    use crate::testing::spire_agent::{FakeSpireAgent, FakeX509Svid};
    use crate::testing::{MockClock, MockRng, RecordingMetrics};
    use crate::workload::spire::{Endpoint, SpireClient, SpireClientBuilder};

    /// `future`, or a panic when it has not completed within an hour of the
    /// runtime's time. On a paused runtime with a [`World`] that hour passes
    /// in a few seconds once nothing else happens, so a wait for something
    /// that never happens fails the test instead of hanging it.
    pub(crate) async fn within<F: Future>(future: F) -> F::Output {
        match tokio::time::timeout(Duration::from_secs(3600), future).await {
            Ok(output) => output,
            Err(_) => panic!("nothing happened within an hour of runtime time"),
        }
    }

    /// Wait until `condition` holds, looking every few milliseconds of the
    /// runtime's time: for what a test can only read, such as how many calls
    /// the fake agent has open.
    pub(crate) async fn settled(condition: impl Fn() -> bool) {
        within(async {
            while !condition() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
    }

    /// How far a paused runtime's time may jump at once while a world is
    /// alive; see [`World::new`].
    const PACE: Duration = Duration::from_millis(10);

    /// A socket directory, a mock clock at the reference time, the
    /// recorders a client reports to, and the pacer of the runtime's time.
    pub(crate) struct World {
        dir: tempfile::TempDir,
        pub(crate) clock: MockClock,
        pub(crate) metrics: Arc<RecordingMetrics>,
        pub(crate) recorder: Arc<Recorder>,
        pacer: JoinHandle<()>,
    }

    impl Drop for World {
        fn drop(&mut self) {
            self.pacer.abort();
        }
    }

    impl World {
        /// A world, in a test on a paused runtime.
        ///
        /// A paused runtime moves its time to the next timer whenever it has
        /// nothing to run, and it counts a wait for the socket as nothing to
        /// run: the park that collects a socket's readiness moves the time
        /// too. With only a ten-second call timeout pending, one exchange
        /// with the fake agent would move the time ten seconds and time the
        /// call out. The pacer is a timer every [`PACE`], so no single move
        /// is longer than that: an exchange costs milliseconds of runtime
        /// time, as it does in real time, and a wait of many seconds is
        /// still passed in a moment. What the client decides is read from
        /// the mock clock, which only the test moves.
        pub(crate) fn new() -> Self {
            let pacer = tokio::spawn(async {
                loop {
                    tokio::time::sleep(PACE).await;
                }
            });
            Self {
                dir: socket_dir(),
                clock: MockClock::at_reference(),
                metrics: Arc::new(RecordingMetrics::default()),
                recorder: Arc::new(Recorder::default()),
                pacer,
            }
        }

        /// Where the agent listens.
        pub(crate) fn socket(&self) -> PathBuf {
            self.dir.path().join("agent.sock")
        }

        /// Start the agent.
        pub(crate) fn agent(&self) -> FakeSpireAgent {
            FakeSpireAgent::start(self.socket()).expect("the agent's socket")
        }

        /// A client builder for `trust_domain`, on the world's clock and
        /// recorders, with a seeded random source.
        pub(crate) fn builder(&self, trust_domain: &str) -> SpireClientBuilder {
            let endpoint = Endpoint::unix(self.socket()).expect("an absolute socket path");
            self.builder_at(endpoint, trust_domain)
        }

        /// As [`builder`](Self::builder), for an agent at `endpoint`.
        pub(crate) fn builder_at(
            &self,
            endpoint: Endpoint,
            trust_domain: &str,
        ) -> SpireClientBuilder {
            SpireClient::builder(
                endpoint,
                TrustDomain::new(trust_domain).expect("a trust domain"),
            )
            .with_clock(Arc::new(self.clock.clone()))
            .with_rng(Arc::new(MockRng::new(7)))
            .with_metrics(MetricSinks::noop().with_rotation(self.metrics.clone()))
            .with_listener(self.recorder.clone())
        }

        /// A client for `trust_domain` with the defaults of
        /// [`builder`](Self::builder).
        pub(crate) fn client(&self, trust_domain: &str) -> SpireClient {
            self.builder(trust_domain).build()
        }
    }

    /// A temporary directory whose socket path fits in a `sockaddr_un`. The
    /// platform's temporary directory can be too deep for that; `/tmp` is
    /// not.
    fn socket_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("a temporary directory");
        if dir.path().join("agent.sock").as_os_str().len() < 100 {
            return dir;
        }
        tempfile::Builder::new()
            .prefix("spire")
            .tempdir_in("/tmp")
            .expect("a temporary directory under /tmp")
    }

    /// `minted` as the fake agent serves it, with `bundle_der` as the trust
    /// domain's bundle.
    pub(crate) fn served(minted: &Minted, bundle_der: &[u8]) -> FakeX509Svid {
        FakeX509Svid {
            spiffe_id: minted.spiffe_id.clone(),
            cert_chain_der: minted.cert_der.clone(),
            private_key_der: minted.key_der.clone(),
            bundle_der: bundle_der.to_vec(),
            hint: String::new(),
        }
    }
}
