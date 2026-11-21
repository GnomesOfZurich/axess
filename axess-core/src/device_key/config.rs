//! How device keys are offered, proven and enforced.

use std::sync::Arc;
use std::time::Duration;

use super::KeyBindingPolicy;

/// A [`DeviceKeyConfig`] setting outside what is accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("device key setting `{setting}` {problem}")]
pub struct DeviceKeyConfigError {
    /// The setting's name.
    pub setting: &'static str,
    /// What is wrong with its value.
    pub problem: &'static str,
}

/// The head of a request, as an origin resolver
/// ([`DeviceKeyConfig::with_origin_fn`]) reads it.
#[derive(Debug, Clone, Copy)]
pub struct RequestHead<'a> {
    /// The request's URI; its authority is the host on HTTP/2.
    pub uri: &'a axum::http::Uri,
    /// The request's headers; `Host` names the host on HTTP/1.1.
    pub headers: &'a axum::http::HeaderMap,
    /// The request's extensions, where an outer layer may have put a tenant.
    pub extensions: &'a axum::http::Extensions,
}

impl<'a> RequestHead<'a> {
    /// The head of `request`.
    pub fn of<B>(request: &'a axum::http::Request<B>) -> Self {
        Self {
            uri: request.uri(),
            headers: request.headers(),
            extensions: request.extensions(),
        }
    }

    /// The host the request was sent to: the URI's authority, else the
    /// `Host` header.
    pub fn host(&self) -> Option<&'a str> {
        self.uri
            .authority()
            .map(|authority| authority.as_str())
            .or_else(|| {
                self.headers
                    .get(axum::http::header::HOST)
                    .and_then(|value| value.to_str().ok())
            })
    }
}

/// Answers the origin of a request: what a proof that names its URL must
/// have been made for.
type OriginFn = Arc<dyn Fn(RequestHead<'_>) -> Option<String> + Send + Sync>;

/// Where the origin of a request comes from.
#[derive(Clone)]
enum OriginSource {
    /// One origin for every request.
    One(Arc<str>),
    /// The listed origin whose host is the request's.
    Listed(Arc<[Arc<str>]>),
    /// Whatever the deployment's function answers, and whether an answer
    /// that is not an origin has been reported yet.
    Resolved(OriginFn, Arc<std::sync::atomic::AtomicBool>),
}

impl std::fmt::Debug for OriginSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::One(origin) => f.debug_tuple("One").field(origin).finish(),
            Self::Listed(origins) => f.debug_tuple("Listed").field(origins).finish(),
            Self::Resolved(..) => f.write_str("Resolved(..)"),
        }
    }
}

/// The host part of `origin` when it is an origin this configuration
/// accepts: `https`, or `http` where `secure` is off; a host and no path,
/// query, fragment or user information.
fn authority_of(origin: &str, secure: bool) -> Option<&str> {
    let authority = match origin.strip_prefix("https://") {
        Some(rest) => rest,
        None if !secure => origin.strip_prefix("http://")?,
        None => return None,
    };
    let plain = !authority.is_empty()
        && !authority
            .bytes()
            .any(|b| matches!(b, b'/' | b'?' | b'#' | b'@') || b.is_ascii_whitespace());
    plain.then_some(authority)
}

/// Settings of the device-key service and of the session layer that
/// enforces it. [`new`](Self::new) takes the origin; everything else has a
/// default, and [`validate`](Self::validate) names a value outside its
/// range.
///
/// A deployment served at more than one origin (a host per tenant) lists
/// them ([`with_origins`](Self::with_origins)) or answers them per request
/// ([`with_origin_fn`](Self::with_origin_fn)): the origin of a request is
/// then the one its host is served at.
///
/// What is held to the origin: a proof in the app shape names its URL
/// (`htu`), which must be this origin and the path it was sent to, at the
/// two key paths and on a request that carries a request proof. A proof in
/// the browser shape names no URL in the revision of the draft the wire
/// constants follow, so no claim holds it to an origin; it is bound to its
/// endpoint by the challenge it answers, which the server minted for one
/// session and device. The origin is also what the session description a
/// registration answers with states as its scope.
///
/// | Setting | Default | Accepted |
/// |---|---|---|
/// | policy | [`KeyBindingPolicy::Prefer`] | |
/// | proof lifetime | 10 minutes | 1 minute to 1 hour |
/// | acceptance grace | 30 seconds | at most 5 minutes |
/// | challenge lifetime | 20 minutes | more than proof lifetime plus grace, at most 24 hours |
/// | registration window | 2 minutes | 10 seconds to 15 minutes |
/// | registration path | `/axess/device-key` | an absolute path |
/// | refresh path | `/axess/device-key/refresh` | another absolute path |
/// | proof cookie name | `__Host-axess_device_proof` | a cookie name |
#[derive(Debug, Clone)]
pub struct DeviceKeyConfig {
    origin: OriginSource,
    policy: KeyBindingPolicy,
    proof_ttl: Duration,
    acceptance_grace: Duration,
    challenge_ttl: Duration,
    registration_window: Duration,
    registration_path: Arc<str>,
    refresh_path: Arc<str>,
    proof_cookie_name: Arc<str>,
    secure: bool,
}

impl DeviceKeyConfig {
    /// Shortest and longest proof lifetime accepted.
    pub const PROOF_TTL_RANGE: (Duration, Duration) =
        (Duration::from_secs(60), Duration::from_secs(3600));
    /// Longest acceptance grace accepted.
    pub const MAX_ACCEPTANCE_GRACE: Duration = Duration::from_secs(300);
    /// Longest challenge lifetime accepted.
    pub const MAX_CHALLENGE_TTL: Duration = Duration::from_secs(24 * 3600);
    /// Shortest and longest registration window accepted.
    pub const REGISTRATION_WINDOW_RANGE: (Duration, Duration) =
        (Duration::from_secs(10), Duration::from_secs(900));

    /// Settings for a deployment served at `origin`: the scheme and host
    /// (and port, when it is not the default) a proof that names its URL
    /// must have been made for, such as `https://app.example`. No path, no
    /// trailing slash.
    pub fn new(origin: impl Into<Arc<str>>) -> Self {
        Self {
            origin: OriginSource::One(origin.into()),
            policy: KeyBindingPolicy::default(),
            proof_ttl: Duration::from_secs(600),
            acceptance_grace: Duration::from_secs(30),
            challenge_ttl: Duration::from_secs(1200),
            registration_window: Duration::from_secs(120),
            registration_path: Arc::from("/axess/device-key"),
            refresh_path: Arc::from("/axess/device-key/refresh"),
            proof_cookie_name: Arc::from("__Host-axess_device_proof"),
            secure: true,
        }
    }

    /// [`new`](Self::new) for a development server on plain HTTP: the proof
    /// cookie loses its `__Host-` prefix and its `Secure` attribute (a
    /// browser drops a `Secure` cookie from plain HTTP), and an `http`
    /// origin is accepted. Never use it behind HTTPS.
    pub fn insecure_for_local_development(origin: impl Into<Arc<str>>) -> Self {
        Self {
            proof_cookie_name: Arc::from("axess_device_proof"),
            secure: false,
            ..Self::new(origin)
        }
    }

    /// Serve at each of `origins`: the origin of a request, which a proof
    /// that names its URL must have been made for, is the listed origin
    /// whose host is the host the request was sent to (its URI's authority,
    /// else its `Host` header), compared without regard to case. A request to a host not listed has no origin, and
    /// the key paths are not answered for it. Replaces the origin given to
    /// [`new`](Self::new).
    pub fn with_origins<I, O>(mut self, origins: I) -> Self
    where
        I: IntoIterator<Item = O>,
        O: Into<Arc<str>>,
    {
        self.origin = OriginSource::Listed(origins.into_iter().map(Into::into).collect());
        self
    }

    /// Answer the origin of each request with `origin`, from its head: the
    /// host, the headers, a tenant an outer layer put in the extensions.
    /// `None`, or an answer that is not an origin this configuration
    /// accepts, leaves the request without one, and the key paths are not
    /// answered for it. Answer only origins the deployment serves: the host
    /// a request names is the client's to choose. Replaces the origin given
    /// to [`new`](Self::new).
    pub fn with_origin_fn<F>(mut self, origin: F) -> Self
    where
        F: Fn(RequestHead<'_>) -> Option<String> + Send + Sync + 'static,
    {
        self.origin = OriginSource::Resolved(
            Arc::new(origin),
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
        );
        self
    }

    /// Choose the policy (default [`KeyBindingPolicy::Prefer`]).
    pub fn with_policy(mut self, policy: KeyBindingPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// How long a proof cookie lives in the client: what a copied cookie
    /// store is still worth, against one device-row write per lifetime per
    /// active device.
    pub fn with_proof_ttl(mut self, ttl: Duration) -> Self {
        self.proof_ttl = ttl;
        self
    }

    /// How long past its expiry the server still accepts a proof cookie, to
    /// cover a request in flight when the client's timer fires.
    pub fn with_acceptance_grace(mut self, grace: Duration) -> Self {
        self.acceptance_grace = grace;
        self
    }

    /// The oldest challenge a proof may answer. It must exceed the proof
    /// lifetime plus the grace, or every routine refresh would find its
    /// challenge expired and take two round trips.
    pub fn with_challenge_ttl(mut self, ttl: Duration) -> Self {
        self.challenge_ttl = ttl;
        self
    }

    /// How long after a login a key registration is offered and accepted,
    /// and how long [`KeyBindingPolicy::Require`] serves a session that is
    /// not bound. The window runs from the time the login completed
    /// (`signed_in_at`); a step-up, an impersonation and an id rotation keep
    /// that time, so none of them reopens or extends the window.
    pub fn with_registration_window(mut self, window: Duration) -> Self {
        self.registration_window = window;
        self
    }

    /// The path a key is registered at.
    pub fn with_registration_path(mut self, path: impl Into<Arc<str>>) -> Self {
        self.registration_path = path.into();
        self
    }

    /// The path a proof is refreshed at.
    pub fn with_refresh_path(mut self, path: impl Into<Arc<str>>) -> Self {
        self.refresh_path = path.into();
        self
    }

    /// The proof cookie's name. A suffix naming the device is appended, so
    /// two devices registered in one browser profile keep separate cookies.
    pub fn with_proof_cookie_name(mut self, name: impl Into<Arc<str>>) -> Self {
        self.proof_cookie_name = name.into();
        self
    }

    /// The one origin of a configuration built with [`new`](Self::new),
    /// `None` for one that lists origins or resolves them per request.
    pub fn origin(&self) -> Option<&str> {
        match &self.origin {
            OriginSource::One(origin) => Some(origin),
            OriginSource::Listed(_) | OriginSource::Resolved(..) => None,
        }
    }

    /// The origin of `request`, which a proof that names its URL must have
    /// been made for, `None` when it
    /// has none.
    pub fn origin_for(&self, request: RequestHead<'_>) -> Option<String> {
        match &self.origin {
            OriginSource::One(origin) => Some(origin.to_string()),
            OriginSource::Listed(origins) => {
                let host = request.host()?;
                origins
                    .iter()
                    .find(|origin| {
                        authority_of(origin, self.secure)
                            .is_some_and(|authority| authority.eq_ignore_ascii_case(host))
                    })
                    .map(|origin| origin.to_string())
            }
            OriginSource::Resolved(resolve, reported) => {
                let origin = resolve(request)?;
                if authority_of(&origin, self.secure).is_some() {
                    return Some(origin);
                }
                // The function's fault, not the request's: said once.
                if !reported.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    tracing::error!(
                        "the device-key origin function answered a value that is not an \
                         origin this configuration accepts (a scheme and a host, no path); \
                         such a request is treated as one for a host that is not served"
                    );
                }
                None
            }
        }
    }

    /// The policy.
    pub fn policy(&self) -> KeyBindingPolicy {
        self.policy
    }

    /// The proof cookie's lifetime.
    pub fn proof_ttl(&self) -> Duration {
        self.proof_ttl
    }

    /// The acceptance grace.
    pub fn acceptance_grace(&self) -> Duration {
        self.acceptance_grace
    }

    /// The challenge lifetime.
    pub fn challenge_ttl(&self) -> Duration {
        self.challenge_ttl
    }

    /// The registration window.
    pub fn registration_window(&self) -> Duration {
        self.registration_window
    }

    /// The registration path.
    pub fn registration_path(&self) -> &str {
        &self.registration_path
    }

    /// The refresh path.
    pub fn refresh_path(&self) -> &str {
        &self.refresh_path
    }

    /// The proof cookie's name, before the device suffix.
    pub fn proof_cookie_name(&self) -> &str {
        &self.proof_cookie_name
    }

    /// Whether the proof cookie is sent `Secure`.
    pub fn secure(&self) -> bool {
        self.secure
    }

    /// The URL a registration proof made for `origin` names.
    pub fn registration_url(&self, origin: &str) -> String {
        format!("{origin}{}", self.registration_path)
    }

    /// The URL a refresh proof made for `origin` names.
    pub fn refresh_url(&self, origin: &str) -> String {
        format!("{origin}{}", self.refresh_path)
    }

    /// Check every setting against what is accepted, naming the first that
    /// is not. [`DeviceKeyService::new`](super::DeviceKeyService::new) calls
    /// it, so a service never runs on a refused configuration.
    pub fn validate(&self) -> Result<(), DeviceKeyConfigError> {
        let refuse = |setting, problem| Err(DeviceKeyConfigError { setting, problem });
        let origin_problem = if self.secure {
            "must be https:// and a host, with no path"
        } else {
            "must be https:// or http:// and a host, with no path"
        };
        match &self.origin {
            OriginSource::One(origin) => {
                if authority_of(origin, self.secure).is_none() {
                    return refuse("origin", origin_problem);
                }
            }
            OriginSource::Listed(origins) => {
                if origins.is_empty() {
                    return refuse("origins", "must list at least one origin");
                }
                if origins
                    .iter()
                    .any(|origin| authority_of(origin, self.secure).is_none())
                {
                    return refuse("origins", origin_problem);
                }
            }
            OriginSource::Resolved(..) => {}
        }
        if !within(self.proof_ttl, Self::PROOF_TTL_RANGE) {
            return refuse("proof_ttl", "must be between 1 minute and 1 hour");
        }
        if self.acceptance_grace > Self::MAX_ACCEPTANCE_GRACE {
            return refuse("acceptance_grace", "must be at most 5 minutes");
        }
        if self.challenge_ttl <= self.proof_ttl + self.acceptance_grace {
            return refuse(
                "challenge_ttl",
                "must exceed the proof lifetime plus the acceptance grace",
            );
        }
        if self.challenge_ttl > Self::MAX_CHALLENGE_TTL {
            return refuse("challenge_ttl", "must be at most 24 hours");
        }
        if !within(self.registration_window, Self::REGISTRATION_WINDOW_RANGE) {
            return refuse(
                "registration_window",
                "must be between 10 seconds and 15 minutes",
            );
        }
        if !is_plain_path(&self.registration_path) {
            return refuse(
                "registration_path",
                "must be an absolute path of visible ASCII with no `?`, `#`, `\"` or `\\`",
            );
        }
        if !is_plain_path(&self.refresh_path) {
            return refuse(
                "refresh_path",
                "must be an absolute path of visible ASCII with no `?`, `#`, `\"` or `\\`",
            );
        }
        if self.registration_path == self.refresh_path {
            return refuse("refresh_path", "must differ from the registration path");
        }
        let name = &*self.proof_cookie_name;
        if name.is_empty()
            || name.len() > 64
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        {
            return refuse(
                "proof_cookie_name",
                "must be 1 to 64 letters, digits, `_`, `-` or `.`",
            );
        }
        let host_prefixed = name
            .as_bytes()
            .get(..7)
            .is_some_and(|head| head.eq_ignore_ascii_case(b"__Host-"));
        if host_prefixed && !self.secure {
            return refuse("proof_cookie_name", "a `__Host-` name needs `Secure`");
        }
        Ok(())
    }
}

fn within(value: Duration, (low, high): (Duration, Duration)) -> bool {
    (low..=high).contains(&value)
}

/// An absolute path of visible ASCII with no query, fragment, double quote
/// or backslash. The registration path is sent inside a quoted
/// structured-field string, where the last two would need an escape and
/// anything outside visible ASCII is not allowed at all.
fn is_plain_path(path: &str) -> bool {
    path.starts_with('/')
        && path
            .bytes()
            .all(|b| matches!(b, 0x21..=0x7e) && !matches!(b, b'?' | b'#' | b'"' | b'\\'))
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod origin_tests {
    use super::*;

    fn request(host: Option<&str>, authority: Option<&str>) -> axum::http::Request<()> {
        let uri = match authority {
            Some(authority) => format!("https://{authority}/axess/device-key"),
            None => "/axess/device-key".to_string(),
        };
        let mut builder = axum::http::Request::post(uri);
        if let Some(host) = host {
            builder = builder.header(axum::http::header::HOST, host);
        }
        builder.body(()).unwrap()
    }

    fn origin(config: &DeviceKeyConfig, request: &axum::http::Request<()>) -> Option<String> {
        config.origin_for(RequestHead::of(request))
    }

    #[test]
    fn one_origin_answers_every_request() {
        let config = DeviceKeyConfig::new("https://app.example");
        assert_eq!(
            origin(&config, &request(Some("elsewhere.example"), None)).as_deref(),
            Some("https://app.example")
        );
    }

    /// Two tenants on two hosts: each request is held to the origin of the
    /// host it was sent to, the `Host` header on HTTP/1.1 and the URI's
    /// authority on HTTP/2, compared without regard to case; a host not
    /// listed has no origin.
    #[test]
    fn listed_origins_answer_the_requests_own_host() {
        let config = DeviceKeyConfig::new("https://unused.example")
            .with_origins(["https://acme.example", "https://beta.example:8443"]);
        assert_eq!(config.validate(), Ok(()));
        assert_eq!(config.origin(), None);
        let cases = [
            (
                request(Some("acme.example"), None),
                Some("https://acme.example"),
            ),
            (
                request(Some("ACME.example"), None),
                Some("https://acme.example"),
            ),
            (
                request(None, Some("beta.example:8443")),
                Some("https://beta.example:8443"),
            ),
            (request(Some("beta.example"), None), None),
            (request(Some("evil.example"), None), None),
            (request(None, None), None),
        ];
        for (request, expected) in cases {
            assert_eq!(
                origin(&config, &request).as_deref(),
                expected,
                "{request:?}"
            );
        }
    }

    #[test]
    fn listed_origins_are_checked() {
        let empty: [&str; 0] = [];
        let refused = |config: DeviceKeyConfig| config.validate().err().map(|e| e.setting);
        assert_eq!(
            refused(DeviceKeyConfig::new("https://a.example").with_origins(empty)),
            Some("origins")
        );
        assert_eq!(
            refused(
                DeviceKeyConfig::new("https://a.example")
                    .with_origins(["https://a.example", "http://b.example"])
            ),
            Some("origins")
        );
    }

    /// A function of the request decides; an answer that is not an origin
    /// the configuration accepts is no origin.
    #[test]
    fn a_resolver_decides_and_its_answers_are_checked() {
        let config =
            DeviceKeyConfig::new("https://unused.example").with_origin_fn(|head| {
                match head.host()? {
                    "acme.example" => Some("https://acme.example".to_string()),
                    "plain.example" => Some("http://plain.example".to_string()),
                    "path.example" => Some("https://path.example/x".to_string()),
                    _ => None,
                }
            });
        assert_eq!(config.validate(), Ok(()));
        assert_eq!(
            origin(&config, &request(Some("acme.example"), None)).as_deref(),
            Some("https://acme.example")
        );
        for host in ["plain.example", "path.example", "other.example"] {
            assert_eq!(origin(&config, &request(Some(host), None)), None, "{host}");
        }
        assert!(format!("{config:?}").contains("Resolved(..)"));
    }
}
