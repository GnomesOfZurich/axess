//! Shared-secret authentication for internal machine callers.
//!
//! Some routes are called by another service rather than by a person: a
//! mail relay posting a bounce, an intake worker handing over a document,
//! a scheduler poking a job. Such a caller cannot sign in, and often the
//! only credential it can be given is a string both ends know. This
//! module makes the check for that string once, properly, instead of
//! leaving each handler to compare strings by hand.
//!
//! ## How strong this is
//!
//! **A shared secret is the weakest machine credential axess offers.**
//! Reach for it only when the caller cannot do better. From weakest to
//! strongest:
//!
//! 1. **A presented secret** ([`ServiceSecretLayer::bearer`](crate::middleware::service_secret::ServiceSecretLayer::bearer),
//!    [`ServiceSecretLayer::header`](crate::middleware::service_secret::ServiceSecretLayer::header)). The secret itself travels with
//!    every request. Anyone who sees one request (a logging proxy, a
//!    misrouted trace, a TLS-terminating load balancer you do not run)
//!    holds the credential and can replay it, against any route that
//!    accepts it, until it is rotated. It never expires on its own.
//! 2. **A signed request** ([`ServiceSecretLayer::signed`](crate::middleware::service_secret::ServiceSecretLayer::signed)). The caller
//!    sends an HMAC-SHA256 signature over a timestamp, the method, the
//!    path and the body, and the secret never leaves either end. A
//!    captured request cannot be altered, cannot be aimed at another
//!    route, is refused once it is older than the tolerance (five minutes
//!    by default), and is refused if seen twice within it. Prefer this
//!    whenever you write the caller.
//! 3. **A signed token from an identity provider** (the `jwt` feature,
//!    workload identity) or **mutual TLS** (the `mtls` feature). The
//!    caller holds a private key or a short-lived token issued to it, so
//!    the server holds nothing that would let it impersonate the caller,
//!    and credentials expire without anyone rotating them. Prefer these
//!    whenever the caller can hold a key.
//!
//! In every mode the secret is shared: whoever can read the server's
//! configuration can act as the caller. None of the modes encrypt
//! anything, so the route still needs TLS.
//!
//! ## What every mode does
//!
//! - Accepts any of several named secrets, so a secret can be rotated by
//!   adding the new one, moving callers over, then dropping the old one.
//! - Refuses a secret shorter than [`MIN_SECRET_LEN`](crate::middleware::service_secret::MIN_SECRET_LEN) bytes. Generate one
//!   with `openssl rand -hex 32`.
//! - Keeps only values derived from each secret, never the secret, and
//!   compares in constant time against every configured secret on every
//!   request, so neither a secret's length nor which caller matched shows
//!   in timing.
//! - Tells the handler which caller it was, through [`ServiceCaller`](crate::middleware::service_secret::ServiceCaller).
//! - Answers `404 Not Found` when no secret is configured, so a route that
//!   has not been given a secret is indistinguishable from one that does
//!   not exist, and `401 Unauthorized` when the credential is missing or
//!   wrong.
//!
//! ## Wiring
//!
//! ```rust,no_run
//! use axess_core::middleware::service_secret::{
//!     ServiceCaller, ServiceSecret, ServiceSecretLayer, ServiceSecrets, SignedRequests,
//! };
//! use axum::{Router, routing::post};
//!
//! async fn bounce(caller: ServiceCaller) -> String {
//!     format!("accepted from {}", caller.name())
//! }
//!
//! # fn build() -> Result<(), axess_core::middleware::service_secret::ServiceSecretError> {
//! // Reads INTAKE_WEBHOOK_SECRET_FILE, falling back to INTAKE_WEBHOOK_SECRET.
//! let secrets: ServiceSecrets = ServiceSecret::from_env("intake", "INTAKE_WEBHOOK_SECRET")?
//!     .into_iter()
//!     .collect();
//!
//! let app: Router = Router::new()
//!     .route("/webhooks/bounce", post(bounce))
//!     .layer(ServiceSecretLayer::signed(secrets, SignedRequests::default()));
//! # let _ = app;
//! # Ok(())
//! # }
//! ```
//!
//! The caller signs with the same secret through [`ServiceSigner`](crate::middleware::service_secret::ServiceSigner);
//! [`SIGNATURE_HEADER`](crate::middleware::service_secret::SIGNATURE_HEADER) documents the scheme for a caller
//! not written in Rust.

mod signature;

pub use signature::{SIGNATURE_HEADER, ServiceSigner, SignedRequests};

use axum::{
    body::Body,
    extract::{FromRequestParts, Request},
    http::{
        HeaderMap, StatusCode,
        header::{AUTHORIZATION, HeaderName, HeaderValue, WWW_AUTHENTICATE},
        request::Parts,
    },
    response::{IntoResponse, Response},
};
use sha2::{Digest, Sha256};
use signature::Verifier;
use std::{
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use subtle::{Choice, ConstantTimeEq};
use tower::{Layer, Service};
use zeroize::Zeroizing;

/// The shortest secret accepted, in bytes after trimming: 32, which is
/// what `openssl rand -hex 16` prints and half of what
/// `openssl rand -hex 32` does.
pub const MIN_SECRET_LEN: usize = 32;

/// Why a secret could not be loaded.
#[derive(Debug, thiserror::Error)]
pub enum ServiceSecretError {
    /// The secret file could not be read.
    #[error("cannot read the secret for `{name}` from {path}: {source}")]
    Read {
        /// The caller the secret belongs to.
        name: String,
        /// The file that was read.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The secret was shorter than [`MIN_SECRET_LEN`] bytes after
    /// trimming, which includes empty.
    #[error("the secret for `{name}` is {len} bytes; at least {MIN_SECRET_LEN} are required")]
    TooShort {
        /// The caller the secret belongs to.
        name: String,
        /// Its length in bytes after trimming.
        len: usize,
    },
}

/// One caller's secret, kept only as values derived from it.
///
/// The plaintext is not retained: a presented secret is matched against
/// its SHA-256 digest, and a signed request against an HMAC key derived
/// from it. `{:?}` shows the caller's name and nothing else.
#[derive(Clone)]
pub struct ServiceSecret {
    name: Arc<str>,
    digest: [u8; 32],
    signing_key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for ServiceSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceSecret")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl ServiceSecret {
    /// A secret for the caller `name`.
    ///
    /// Surrounding whitespace is trimmed, so a value read from a file with
    /// a trailing newline means what it says.
    ///
    /// # Errors
    ///
    /// [`ServiceSecretError::TooShort`] when fewer than
    /// [`MIN_SECRET_LEN`] bytes are left after trimming.
    pub fn new(name: impl Into<Arc<str>>, secret: &str) -> Result<Self, ServiceSecretError> {
        let name = name.into();
        let secret = secret.trim();
        if secret.len() < MIN_SECRET_LEN {
            return Err(ServiceSecretError::TooShort {
                name: name.to_string(),
                len: secret.len(),
            });
        }
        Ok(Self {
            name,
            digest: Sha256::digest(secret.as_bytes()).into(),
            signing_key: signature::derive_key(secret.as_bytes()),
        })
    }

    /// Read the secret for `name` from a file, as mounted by a container
    /// secret store.
    ///
    /// # Errors
    ///
    /// [`ServiceSecretError::Read`] when the file cannot be read, and
    /// [`ServiceSecretError::TooShort`] when it holds too short a secret.
    pub fn from_file(
        name: impl Into<Arc<str>>,
        path: impl AsRef<Path>,
    ) -> Result<Self, ServiceSecretError> {
        let name = name.into();
        let path = path.as_ref();
        let secret = Zeroizing::new(std::fs::read_to_string(path).map_err(|source| {
            ServiceSecretError::Read {
                name: name.to_string(),
                path: path.to_path_buf(),
                source,
            }
        })?);
        Self::new(name, &secret)
    }

    /// Read the secret for `name` from the environment, following the
    /// `_FILE` convention: `{var}_FILE` names a file holding the secret
    /// and wins when set; otherwise `{var}` holds the secret itself.
    ///
    /// Returns `Ok(None)` when neither is set, which leaves the route
    /// unconfigured (and answering `404`).
    ///
    /// # Errors
    ///
    /// As [`ServiceSecret::from_file`] and [`ServiceSecret::new`]. A
    /// variable that is set but empty is an error rather than "unset", so
    /// a misconfigured deployment fails loudly at start-up.
    pub fn from_env(
        name: impl Into<Arc<str>>,
        var: &str,
    ) -> Result<Option<Self>, ServiceSecretError> {
        let name = name.into();
        if let Some(path) = std::env::var_os(format!("{var}_FILE")) {
            return Self::from_file(name, path).map(Some);
        }
        match std::env::var(var) {
            Ok(secret) => Self::new(name, &Zeroizing::new(secret)).map(Some),
            Err(_) => Ok(None),
        }
    }

    /// The caller this secret identifies.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// A signer for the calling side, to sign requests that a
    /// [`ServiceSecretLayer::signed`] route verifies with this secret.
    pub fn signer(&self) -> ServiceSigner {
        ServiceSigner::from_key(self.signing_key.clone())
    }
}

/// The set of secrets a route accepts.
///
/// Empty means unconfigured: every request is answered `404`.
#[derive(Clone, Debug, Default)]
pub struct ServiceSecrets {
    secrets: Vec<ServiceSecret>,
}

impl ServiceSecrets {
    /// No secrets: the route answers `404` until one is added.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a secret, as when rotating in a new one beside the old.
    #[must_use]
    pub fn with(mut self, secret: ServiceSecret) -> Self {
        self.secrets.push(secret);
        self
    }

    /// Whether any secret is configured.
    pub fn is_configured(&self) -> bool {
        !self.secrets.is_empty()
    }

    /// The caller whose secret is `presented`, if any.
    ///
    /// Every configured secret is compared, whether or not an earlier one
    /// matched, so the time taken does not say which caller it was.
    pub fn identify(&self, presented: &[u8]) -> Option<ServiceCaller> {
        let presented: [u8; 32] = Sha256::digest(presented).into();
        self.first_match(|secret| secret.digest.ct_eq(&presented))
    }

    /// The first secret for which `hit` holds, having asked of every one.
    fn first_match(&self, hit: impl Fn(&ServiceSecret) -> Choice) -> Option<ServiceCaller> {
        let mut found: Option<&ServiceSecret> = None;
        for secret in &self.secrets {
            if bool::from(hit(secret)) && found.is_none() {
                found = Some(secret);
            }
        }
        found.map(|secret| ServiceCaller(Arc::clone(&secret.name)))
    }
}

impl FromIterator<ServiceSecret> for ServiceSecrets {
    fn from_iter<I: IntoIterator<Item = ServiceSecret>>(iter: I) -> Self {
        Self {
            secrets: iter.into_iter().collect(),
        }
    }
}

impl Extend<ServiceSecret> for ServiceSecrets {
    fn extend<I: IntoIterator<Item = ServiceSecret>>(&mut self, iter: I) {
        self.secrets.extend(iter);
    }
}

/// The internal caller a request was authenticated as.
///
/// Inserted into the request extensions by [`ServiceSecretLayer`], and
/// extractable in a handler. Extracting it on a route the layer does not
/// cover is a wiring mistake and answers `500`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceCaller(Arc<str>);

impl ServiceCaller {
    /// The name the matching secret was configured under.
    pub fn name(&self) -> &str {
        &self.0
    }
}

impl<S: Send + Sync> FromRequestParts<S> for ServiceCaller {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<ServiceCaller>()
            .cloned()
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

/// How the caller proves it holds the secret.
#[derive(Clone, Debug)]
enum Mode {
    /// `Authorization: Bearer <secret>`.
    Bearer,
    /// The whole value of the named header is the secret.
    Header(HeaderName),
    /// A signature in [`SIGNATURE_HEADER`].
    Signed(Arc<Verifier>),
}

impl Mode {
    fn presented<'h>(&self, headers: &'h HeaderMap) -> Option<&'h [u8]> {
        match self {
            Self::Bearer => {
                let value = headers.get(AUTHORIZATION)?.as_bytes();
                let (scheme, rest) = value.split_at_checked(7)?;
                scheme
                    .eq_ignore_ascii_case(b"bearer ")
                    .then(|| rest.trim_ascii())
            }
            Self::Header(name) => Some(headers.get(name)?.as_bytes().trim_ascii()),
            Self::Signed(_) => None,
        }
    }
}

/// Tower [`Layer`] admitting only requests from a caller holding one of
/// the configured secrets. See the [module docs](crate::middleware::service_secret) for how strong
/// each mode is.
#[derive(Clone, Debug)]
pub struct ServiceSecretLayer {
    secrets: Arc<ServiceSecrets>,
    mode: Mode,
}

impl ServiceSecretLayer {
    /// Accept a secret presented as `Authorization: Bearer <secret>`.
    ///
    /// The weakest mode: the secret travels with every request and a
    /// captured one can be replayed. Prefer [`ServiceSecretLayer::signed`]
    /// when you write the caller.
    pub fn bearer(secrets: ServiceSecrets) -> Self {
        Self::with_mode(secrets, Mode::Bearer)
    }

    /// Accept a secret presented as the whole value of the header `name`.
    ///
    /// As weak as [`ServiceSecretLayer::bearer`]; for callers that can
    /// only be told to set a fixed header.
    pub fn header(secrets: ServiceSecrets, name: HeaderName) -> Self {
        Self::with_mode(secrets, Mode::Header(name))
    }

    /// Accept requests signed with a configured secret, as
    /// [`ServiceSigner`] signs them.
    ///
    /// The body is read in full to verify it, up to
    /// [`SignedRequests::max_body_bytes`], and handed on unchanged.
    pub fn signed(secrets: ServiceSecrets, config: SignedRequests) -> Self {
        Self::with_mode(secrets, Mode::Signed(Arc::new(Verifier::new(config))))
    }

    fn with_mode(secrets: ServiceSecrets, mode: Mode) -> Self {
        Self {
            secrets: Arc::new(secrets),
            mode,
        }
    }
}

impl<S> Layer<S> for ServiceSecretLayer {
    type Service = ServiceSecretService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ServiceSecretService {
            inner,
            secrets: Arc::clone(&self.secrets),
            mode: self.mode.clone(),
        }
    }
}

/// Tower [`Service`] produced by [`ServiceSecretLayer`].
#[derive(Clone, Debug)]
pub struct ServiceSecretService<S> {
    inner: S,
    secrets: Arc<ServiceSecrets>,
    mode: Mode,
}

/// The answer to a request that did not authenticate.
fn refusal(secrets: &ServiceSecrets, mode: &Mode) -> Response {
    if !secrets.is_configured() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let mut response = StatusCode::UNAUTHORIZED.into_response();
    if matches!(mode, Mode::Bearer) {
        response
            .headers_mut()
            .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    }
    response
}

impl<S> Service<Request<Body>> for ServiceSecretService<S>
where
    S: Service<Request<Body>, Response = Response> + Send + Clone + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        // `poll_ready` readied `self.inner`, not a clone of it: call the
        // readied one and leave a fresh clone in its place.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let secrets = Arc::clone(&self.secrets);

        if let Mode::Signed(verifier) = &self.mode {
            let verifier = Arc::clone(verifier);
            let mode = self.mode.clone();
            return Box::pin(async move {
                if !secrets.is_configured() {
                    return Ok(refusal(&secrets, &mode));
                }
                match verifier.verify(&secrets, req).await {
                    Ok(req) => inner.call(req).await,
                    Err(status) if status == StatusCode::UNAUTHORIZED => {
                        Ok(refusal(&secrets, &mode))
                    }
                    Err(status) => Ok(status.into_response()),
                }
            });
        }

        let caller = self
            .mode
            .presented(req.headers())
            .and_then(|presented| secrets.identify(presented));
        let Some(caller) = caller else {
            let refused = refusal(&secrets, &self.mode);
            return Box::pin(async move { Ok(refused) });
        };
        let mut req = req;
        req.extensions_mut().insert(caller);
        Box::pin(inner.call(req))
    }
}

#[cfg(test)]
mod tests;
