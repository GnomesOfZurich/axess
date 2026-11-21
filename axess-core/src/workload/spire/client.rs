//! The Workload API client: one call each for the five methods, and the
//! watchers that keep what they return current.

use std::sync::Arc;
use std::time::Duration;

use axess_clock::{Clock, SystemClock};
use axess_identity::{TrustDomain, WorkloadId};
use axess_rng::{SecureRng, SystemRng};
use serde_json::{Map, Value};

use super::backoff::BackoffPolicy;
use super::bundle::{JwtBundleSet, SkippedBundle, X509BundleSet};
use super::endpoint::Endpoint;
use super::error::{SpireError, remote_text};
use super::feed::{JwtBundleFeed, JwtSvidFeed, X509BundleFeed, X509Feed};
use super::observe::{NoopWorkloadApiListener, WorkloadApiListener};
use super::proto;
use super::source::{JwtBundleSource, JwtSvidSource, X509BundleSource, X509Source};
use super::svid::{JwtSvid, SvidSelector, X509Context, X509Svid, admit_jwt, admit_x509};
use super::transport::{Message, Responses, TARGET, open};
use crate::metrics::{MetricSinks, RotationMetrics, WorkloadCredentialKind};

/// The largest message the client reads unless told otherwise: 4 MiB, the
/// usual gRPC limit.
pub const DEFAULT_MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;

/// What every call and every watcher of one client shares.
pub(crate) struct ClientInner {
    pub(crate) endpoint: Endpoint,
    pub(crate) trust_domain: TrustDomain,
    pub(crate) selector: SvidSelector,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) rng: Arc<dyn SecureRng>,
    pub(crate) metrics: Arc<dyn RotationMetrics>,
    pub(crate) listener: Arc<dyn WorkloadApiListener>,
    pub(crate) call_timeout: Duration,
    pub(crate) check_interval: Duration,
    pub(crate) backoff: BackoffPolicy,
    pub(crate) jwt_refresh_percent: u8,
    pub(crate) recheck_percent: u8,
    pub(crate) max_bundle_age: Duration,
    pub(crate) withdrawal_grace: Duration,
    pub(crate) max_message_bytes: usize,
}

impl ClientInner {
    /// Open `method` and wait for its first message, within the call
    /// timeout. An agent answers a stream at once with what it holds, or
    /// with a status saying why it holds nothing.
    pub(crate) async fn first_message(
        &self,
        method: &'static str,
        request: &[u8],
    ) -> Result<(Message, Responses), SpireError> {
        let opened = async {
            let mut responses =
                open(&self.endpoint, method, request, self.max_message_bytes).await?;
            match responses.next_message().await? {
                Some(message) => Ok((message, responses)),
                None => Err(SpireError::Malformed(
                    "the call ended without a message".to_owned(),
                )),
            }
        };
        match tokio::time::timeout(self.call_timeout, opened).await {
            Ok(outcome) => outcome,
            Err(_) => Err(SpireError::Timeout(self.call_timeout)),
        }
    }

    /// Call a unary `method`, within the call timeout.
    pub(crate) async fn unary(
        &self,
        method: &'static str,
        request: &[u8],
    ) -> Result<Message, SpireError> {
        let call = async {
            open(&self.endpoint, method, request, self.max_message_bytes)
                .await?
                .single_message()
                .await
        };
        match tokio::time::timeout(self.call_timeout, call).await {
            Ok(outcome) => outcome,
            Err(_) => Err(SpireError::Timeout(self.call_timeout)),
        }
    }

    /// Refuse a selector that names an identity of another trust domain
    /// than the client's: no answer of the agent could satisfy it.
    pub(crate) fn check_selector(&self) -> Result<(), SpireError> {
        if let SvidSelector::SpiffeId(id) = &self.selector {
            let presented = id.trust_domain();
            if presented != self.trust_domain {
                return Err(SpireError::TrustDomainMismatch {
                    expected: self.trust_domain.clone(),
                    presented: presented.as_str().to_owned(),
                });
            }
        }
        Ok(())
    }
}

/// Refuse an audience list a JWT SVID cannot be asked for.
pub(crate) fn check_audience(audience: &[String]) -> Result<(), SpireError> {
    if audience.is_empty() || audience.iter().any(String::is_empty) {
        return Err(SpireError::Request(
            "a JWT SVID is fetched for at least one audience, none of them empty".to_owned(),
        ));
    }
    Ok(())
}

/// A client of the SPIFFE Workload API of a local SPIRE agent.
///
/// Cheap to clone; clones share one configuration. A method named
/// `fetch_*` asks the agent once. A method named `watch_*` starts a task
/// that keeps the answer current and returns a source to read it from; see
/// [`X509Source`] for what a source promises.
///
/// The client is built for one trust domain, as the resolvers are: an SVID
/// the agent issues for another is refused.
///
/// ```no_run
/// use axess_core::workload::spire::{Endpoint, SpireClient};
/// use axess_identity::TrustDomain;
///
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let client = SpireClient::builder(
///     Endpoint::from_env()?,
///     TrustDomain::new("prod.example.com")?,
/// )
/// .build();
///
/// // Once:
/// let svid = client.fetch_x509_svid().await?;
/// println!("{} until {}", svid.spiffe_id(), svid.not_after());
///
/// // Kept current:
/// let source = client.watch_x509()?;
/// source.ready().await;
/// let current = source.svid()?;
/// # let _ = current;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct SpireClient {
    inner: Arc<ClientInner>,
}

impl std::fmt::Debug for SpireClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpireClient")
            .field("endpoint", &self.inner.endpoint)
            .field("trust_domain", &self.inner.trust_domain)
            .finish_non_exhaustive()
    }
}

/// Builds a [`SpireClient`]. Every setting has a default but the endpoint
/// and the trust domain.
pub struct SpireClientBuilder {
    inner: ClientInner,
}

impl SpireClientBuilder {
    /// The clock every expiry and every refresh point is judged by.
    /// Defaults to the system clock.
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.inner.clock = clock;
        self
    }

    /// The random source the back-off's jitter is drawn from. Defaults to
    /// the operating system's.
    pub fn with_rng(mut self, rng: Arc<dyn SecureRng>) -> Self {
        self.inner.rng = rng;
        self
    }

    /// Where the watchers count: the rotation concern of `sinks`.
    pub fn with_metrics(mut self, sinks: MetricSinks) -> Self {
        self.inner.metrics = sinks.rotation();
        self
    }

    /// Who hears each watcher event.
    pub fn with_listener(mut self, listener: Arc<dyn WorkloadApiListener>) -> Self {
        self.inner.listener = listener;
        self
    }

    /// Which of the workload's identities the client is for, when the agent
    /// has several. Defaults to the first. It decides every SVID the client
    /// fetches, X.509 and JWT alike: a client built for one identity never
    /// hands out another's certificate or token. A workload that acts under
    /// two identities builds two clients.
    pub fn with_svid_selector(mut self, selector: SvidSelector) -> Self {
        self.inner.selector = selector;
        self
    }

    /// How long a call may take to connect and deliver its first message.
    /// Defaults to ten seconds; a zero is read as one millisecond.
    pub fn with_call_timeout(mut self, timeout: Duration) -> Self {
        self.inner.call_timeout = timeout.max(Duration::from_millis(1));
        self
    }

    /// How often a watcher reads the clock to see whether what it holds is
    /// due for a refresh or has expired. Defaults to one second; a shorter
    /// interval than ten milliseconds is read as ten.
    pub fn with_check_interval(mut self, interval: Duration) -> Self {
        self.inner.check_interval = interval.max(Duration::from_millis(10));
        self
    }

    /// The waits between attempts that fail.
    pub fn with_backoff(mut self, policy: BackoffPolicy) -> Self {
        self.inner.backoff = policy;
        self
    }

    /// How far into a JWT SVID's lifetime a source asks the agent for the
    /// next one, in percent, read as at least 1 and at most 99. Defaults to
    /// 50: a token valid for five minutes is replaced after two and a half.
    /// Nothing pushes a JWT SVID, so this is the whole of its rotation; an
    /// agent that still answers with the token the source holds is asked
    /// again at a slowing pace.
    pub fn with_jwt_refresh_percent(mut self, percent: u8) -> Self {
        self.inner.jwt_refresh_percent = percent.clamp(1, 99);
        self
    }

    /// When a source stops trusting an open stream to have told it
    /// everything and asks the agent on a second request, in percent, read
    /// as at least 1 and at most 99. For an X.509 SVID it is a share of the
    /// SVID's lifetime; for a bundle set, of the maximum bundle age since
    /// the agent last confirmed the set. Defaults to 75.
    ///
    /// An agent pushes a rotated X.509 SVID on the open stream at a point
    /// of its own choosing, about half the lifetime in SPIRE's defaults.
    /// The check is the safety net for a stream that has stalled, so it
    /// belongs clearly after the agent's point: at 75 it never fires while
    /// the agent rotates on time, and it leaves a quarter of the lifetime
    /// to recover in. The open stream is kept while the check runs, and is
    /// replaced only by a stream that brought something newer. An agent
    /// configured to rotate later than this point is asked a few times more
    /// than it needs to be, and nothing else.
    pub fn with_recheck_percent(mut self, percent: u8) -> Self {
        self.inner.recheck_percent = percent.clamp(1, 99);
        self
    }

    /// How long a bundle set is served after the agent last confirmed it.
    /// Defaults to one hour; less than a second is read as a second.
    ///
    /// A bundle set has no expiry of its own, and a source that cannot
    /// reach its agent cannot learn that an authority or a key was
    /// withdrawn. Past this age the bundle sources stop serving the set
    /// ([`SpireError::Stale`]) and the key sets made from it are emptied,
    /// so verification fails closed until the agent answers again. A source
    /// confirms its set well inside the age, at the recheck point.
    pub fn with_max_bundle_age(mut self, age: Duration) -> Self {
        self.inner.max_bundle_age = age.max(Duration::from_secs(1));
        self
    }

    /// How long a source goes on serving what the agent has withdrawn with
    /// `PERMISSION_DENIED`. Defaults to zero: what the agent withdraws is
    /// served no longer, which is what the SPIFFE Workload API standard has
    /// a client do (sections 5.2 and 6.2).
    ///
    /// **A grace departs from that.** The agent's `PERMISSION_DENIED` does
    /// not say why: a registration entry that tooling deletes and creates
    /// again a moment later reads the same as one an operator removed, and
    /// with no grace it takes a healthy workload's identity away until the
    /// agent issues it again. For the length of the grace a workload whose
    /// identity really was withdrawn goes on presenting it. The grace never
    /// serves anything past its expiry, it ends as soon as the agent issues
    /// the identity again, and it does not cover an answer that holds SVIDs
    /// and not the selected one, which is honoured at once. A source serving
    /// under grace reports it: a `WithdrawalDeferred` event and the
    /// `workload_credential_withdrawal_deferred` counter.
    pub fn with_withdrawal_grace(mut self, grace: Duration) -> Self {
        self.inner.withdrawal_grace = grace;
        self
    }

    /// The largest message the client reads. Defaults to
    /// [`DEFAULT_MAX_MESSAGE_BYTES`].
    pub fn with_max_message_bytes(mut self, max: usize) -> Self {
        self.inner.max_message_bytes = max;
        self
    }

    /// The client.
    pub fn build(self) -> SpireClient {
        SpireClient {
            inner: Arc::new(self.inner),
        }
    }
}

/// A JWT SVID the agent validated: whose it is, and what it claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedJwtSvid {
    spiffe_id: WorkloadId,
    trust_domain: TrustDomain,
    claims: Map<String, Value>,
}

impl ValidatedJwtSvid {
    /// The SPIFFE ID the agent read from the token.
    pub fn spiffe_id(&self) -> &WorkloadId {
        &self.spiffe_id
    }

    /// The trust domain of the SPIFFE ID. The agent accepts a token of any
    /// trust domain it holds a bundle for, federated ones included: which
    /// of them a service admits is checked against this.
    pub fn trust_domain(&self) -> &TrustDomain {
        &self.trust_domain
    }

    /// The token's claims.
    pub fn claims(&self) -> &Map<String, Value> {
        &self.claims
    }
}

impl SpireClient {
    /// A builder for a client of the agent at `endpoint`, for a workload of
    /// `trust_domain`.
    pub fn builder(endpoint: Endpoint, trust_domain: TrustDomain) -> SpireClientBuilder {
        SpireClientBuilder {
            inner: ClientInner {
                endpoint,
                trust_domain,
                selector: SvidSelector::First,
                clock: Arc::new(SystemClock),
                rng: Arc::new(SystemRng),
                metrics: MetricSinks::noop().rotation(),
                listener: Arc::new(NoopWorkloadApiListener),
                call_timeout: Duration::from_secs(10),
                check_interval: Duration::from_secs(1),
                backoff: BackoffPolicy::default(),
                jwt_refresh_percent: 50,
                recheck_percent: 75,
                max_bundle_age: Duration::from_secs(60 * 60),
                withdrawal_grace: Duration::ZERO,
                max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
            },
        }
    }

    /// The endpoint the client calls.
    pub fn endpoint(&self) -> &Endpoint {
        &self.inner.endpoint
    }

    /// The trust domain the client was built for.
    pub fn trust_domain(&self) -> &TrustDomain {
        &self.inner.trust_domain
    }

    /// The workload's X.509 SVIDs and the bundles that come with them, as
    /// the agent holds them now. The context is a snapshot: its SVIDs had
    /// not expired when it was fetched, and a source keeps them current.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn fetch_x509_context(&self) -> Result<X509Context, SpireError> {
        let inner = &self.inner;
        inner.check_selector()?;
        let (message, _) = inner.first_message(proto::FETCH_X509_SVID, &[]).await?;
        let context = admit_x509(
            proto::decode_x509_svid_response(&message)?,
            &inner.trust_domain,
            &inner.selector,
            inner.clock.now(),
        )?;
        log_skipped(
            WorkloadCredentialKind::X509Svid,
            context.bundles().skipped(),
        );
        Ok(context)
    }

    /// The workload's X.509 SVID, as the agent holds it now.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn fetch_x509_svid(&self) -> Result<Arc<X509Svid>, SpireError> {
        Ok(self.fetch_x509_context().await?.svid().clone())
    }

    /// The X.509 bundles of the workload's trust domain and of those
    /// federated with it, as the agent holds them now.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn fetch_x509_bundles(&self) -> Result<X509BundleSet, SpireError> {
        let (message, _) = self
            .inner
            .first_message(proto::FETCH_X509_BUNDLES, &[])
            .await?;
        let set = X509BundleSet::from_raw(
            proto::decode_x509_bundles_response(&message)?,
            &self.inner.trust_domain,
            self.inner.clock.now(),
        )?;
        log_skipped(WorkloadCredentialKind::X509Bundles, set.skipped());
        Ok(set)
    }

    /// A JWT SVID for `audience`, for the identity the client's
    /// [`SvidSelector`] names (the agent's first, by default). `audience`
    /// names who the token is presented to, and is not empty.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn fetch_jwt_svid<I, S>(&self, audience: I) -> Result<JwtSvid, SpireError>
    where
        I: IntoIterator<Item = S> + Send,
        S: Into<String>,
    {
        let audience: Vec<String> = audience.into_iter().map(Into::into).collect();
        fetch_jwt_svid(&self.inner, &audience).await
    }

    /// The JWT bundles of the workload's trust domain and of those
    /// federated with it, as the agent holds them now.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn fetch_jwt_bundles(&self) -> Result<JwtBundleSet, SpireError> {
        let (message, _) = self
            .inner
            .first_message(proto::FETCH_JWT_BUNDLES, &[])
            .await?;
        let set = JwtBundleSet::from_raw(
            proto::decode_jwt_bundles_response(&message)?,
            &self.inner.trust_domain,
        )?;
        log_skipped(WorkloadCredentialKind::JwtBundles, set.skipped());
        Ok(set)
    }

    /// Have the agent validate `token`, a JWT SVID presented to this
    /// workload as `audience`. The agent checks the signature against the
    /// bundle of the token's trust domain, the audience and the expiry, and
    /// answers [`SpireError::Status`] when it refuses the token or does not
    /// offer the method ([`GrpcCode::Unimplemented`](super::GrpcCode)).
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn validate_jwt_svid(
        &self,
        audience: &str,
        token: &str,
    ) -> Result<ValidatedJwtSvid, SpireError> {
        if audience.is_empty() || token.is_empty() {
            return Err(SpireError::Request(
                "a JWT SVID is validated for an audience, and neither is empty".to_owned(),
            ));
        }
        let request = proto::encode_validate_jwt_svid_request(audience, token);
        let message = self.inner.unary(proto::VALIDATE_JWT_SVID, &request).await?;
        let raw = proto::decode_validate_jwt_svid_response(&message)?;
        // Both fields of the answer are mandatory, and a validated JWT-SVID
        // has claims (`sub`, `aud` and `exp` at the least): an answer
        // without them is discarded.
        if raw.claims.is_empty() {
            return Err(SpireError::Refused(
                "the validation answer holds no claims".to_owned(),
            ));
        }
        let spiffe_id = WorkloadId::parse(&raw.spiffe_id).map_err(|_| {
            SpireError::refused("the validated SPIFFE ID is not valid", &raw.spiffe_id)
        })?;
        Ok(ValidatedJwtSvid {
            trust_domain: spiffe_id.trust_domain(),
            spiffe_id,
            claims: raw.claims,
        })
    }

    /// Keep the workload's X.509 SVID and its bundles current.
    ///
    /// The watcher is a task on the current tokio runtime; called outside
    /// one, this answers [`SpireError::NoRuntime`]. A selector that names an
    /// identity of another trust domain is refused here, before any task is
    /// started.
    pub fn watch_x509(&self) -> Result<X509Source, SpireError> {
        self.inner.check_selector()?;
        X509Source::start(self.inner.clone(), X509Feed)
    }

    /// Keep the X.509 bundles current, for a workload that verifies peers
    /// and presents no X.509 SVID of its own. Outside a tokio runtime this
    /// answers [`SpireError::NoRuntime`].
    pub fn watch_x509_bundles(&self) -> Result<X509BundleSource, SpireError> {
        X509BundleSource::start(self.inner.clone(), X509BundleFeed)
    }

    /// Keep the JWT bundles current, for verifying JWT SVIDs. Outside a
    /// tokio runtime this answers [`SpireError::NoRuntime`].
    pub fn watch_jwt_bundles(&self) -> Result<JwtBundleSource, SpireError> {
        JwtBundleSource::start(self.inner.clone(), JwtBundleFeed::default())
    }

    /// Keep a JWT SVID for `audience` current, for the identity the
    /// client's [`SvidSelector`] names.
    ///
    /// What can never succeed is refused here, before any task is started:
    /// an empty audience list or an empty audience ([`SpireError::Request`]),
    /// a selector that names an identity of another trust domain
    /// ([`SpireError::TrustDomainMismatch`]), and a call outside a tokio
    /// runtime ([`SpireError::NoRuntime`]).
    pub fn watch_jwt_svid<I, S>(&self, audience: I) -> Result<JwtSvidSource, SpireError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let audience: Vec<String> = audience.into_iter().map(Into::into).collect();
        check_audience(&audience)?;
        self.inner.check_selector()?;
        JwtSvidSource::start(self.inner.clone(), JwtSvidFeed { audience })
    }
}

/// Log the bundle entries a one-shot fetch left out. A watcher reports
/// them to its metrics and its listener as well.
fn log_skipped(kind: WorkloadCredentialKind, skipped: &[SkippedBundle]) {
    for entry in skipped {
        tracing::warn!(
            target: TARGET,
            kind = kind.as_str(),
            key = entry.key(),
            error = %entry.error(),
            "workload API bundle entry left out",
        );
    }
}

/// The `spiffe_id` a `JWTSVIDRequest` carries for the client's selector:
/// the identity it names, or none, which asks for every identity's token.
pub(crate) fn jwt_request(inner: &ClientInner, audience: &[String]) -> Vec<u8> {
    let spiffe_id = match &inner.selector {
        SvidSelector::SpiffeId(id) => Some(id.as_str()),
        SvidSelector::First | SvidSelector::Hint(_) => None,
    };
    proto::encode_jwt_svid_request(audience, spiffe_id)
}

/// One `FetchJWTSVID` call: the SVID the client's selector names, admitted.
async fn fetch_jwt_svid(inner: &ClientInner, audience: &[String]) -> Result<JwtSvid, SpireError> {
    check_audience(audience)?;
    inner.check_selector()?;
    let message = inner
        .unary(proto::FETCH_JWT_SVID, &jwt_request(inner, audience))
        .await?;
    admit_jwt_response(inner, &message, audience)
}

/// Admit the SVID of a `JWTSVIDResponse` that the client's selector names:
/// the first, the one for a SPIFFE ID, or the one with a hint. An answer
/// without it is refused; another identity's token is never taken in its
/// place.
pub(crate) fn admit_jwt_response(
    inner: &ClientInner,
    message: &[u8],
    audience: &[String],
) -> Result<JwtSvid, SpireError> {
    let decoded = proto::decode_jwt_svid_response(message)?;
    let none_sent = decoded.is_empty();
    let mut svids = decoded.into_iter();
    let chosen = match &inner.selector {
        SvidSelector::First => svids.next(),
        SvidSelector::SpiffeId(id) => svids.find(|svid| id.as_str() == svid.spiffe_id),
        SvidSelector::Hint(hint) => svids.find(|svid| *hint == svid.hint),
    };
    let Some(raw) = chosen else {
        // As for X.509: no SVID at all is a mandatory field left out, and
        // SVIDs with none for the selected identity is that identity no
        // longer issued.
        return Err(match &inner.selector {
            SvidSelector::SpiffeId(id) if !none_sent => SpireError::NotIssued(id.to_string()),
            SvidSelector::Hint(hint) if !none_sent => {
                SpireError::NotIssued(format!("the hint {}", remote_text(hint)))
            }
            _ => SpireError::Refused("the response holds no JWT SVID".to_owned()),
        });
    };
    admit_jwt(raw, &inner.trust_domain, audience, inner.clock.now())
}

#[cfg(all(test, unix))]
mod tests;
