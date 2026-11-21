//! An in-process SPIRE agent: the SPIFFE Workload API served on a Unix
//! domain socket or a loopback TCP port, from answers the test sets.
//!
//! [`FakeSpireAgent`] is a fixture, not a mock: it speaks gRPC over HTTP/2
//! on a real socket, so the client under test runs its production path end
//! to end. It attests nobody and signs nothing. A test hands it the SVIDs
//! and bundles to serve (minted however the test likes), changes them to
//! play a rotation, drops its connections to play an agent restart, and
//! reads back what the client asked for.
//!
//! The fake writes the method paths and the metadata key of the Workload
//! API itself and takes neither from the client, so a client whose names
//! drift is answered `UNIMPLEMENTED` or `INVALID_ARGUMENT` here.
//!
//! ```no_run
//! use axess_core::testing::spire_agent::{FakeSpireAgent, WorkloadApiMethod};
//!
//! # async fn run() -> std::io::Result<()> {
//! let dir = tempfile::tempdir()?;
//! let agent = FakeSpireAgent::start(dir.path().join("agent.sock"))?;
//! // Nothing is served yet: every method answers PERMISSION_DENIED, as an
//! // agent does for a workload it has no registration entry for.
//! agent.set_jwt_bundles(&[("example.org", br#"{"keys":[]}"#.as_slice())]);
//! assert_eq!(agent.calls(WorkloadApiMethod::FetchJwtBundles), 0);
//! # Ok(())
//! # }
//! ```
//!
//! Compiled with the `spire` feature on Unix.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderValue, Request, Response};
use h2::server::SendResponse;
use h2::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};

use crate::workload::spire::Endpoint;
use crate::workload::spire::wire::{Field, FrameDecoder, Reader, frame, put_bytes, put_varint};

/// The metadata key a call carries with the value `true`, as the Workload
/// API names it.
const SECURITY_METADATA: &str = "workload.spiffe.io";

/// gRPC `PERMISSION_DENIED`, what an agent answers a workload it has no
/// identity for.
const PERMISSION_DENIED: u32 = 7;
/// gRPC `INVALID_ARGUMENT`, what an agent answers a call without the
/// security metadata.
const INVALID_ARGUMENT: u32 = 3;
/// gRPC `UNIMPLEMENTED`.
const UNIMPLEMENTED: u32 = 12;

/// The five methods of the Workload API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WorkloadApiMethod {
    /// `FetchX509SVID`, a stream.
    FetchX509Svid,
    /// `FetchX509Bundles`, a stream.
    FetchX509Bundles,
    /// `FetchJWTSVID`, one answer.
    FetchJwtSvid,
    /// `FetchJWTBundles`, a stream.
    FetchJwtBundles,
    /// `ValidateJWTSVID`, one answer.
    ValidateJwtSvid,
}

impl WorkloadApiMethod {
    const ALL: [Self; 5] = [
        Self::FetchX509Svid,
        Self::FetchX509Bundles,
        Self::FetchJwtSvid,
        Self::FetchJwtBundles,
        Self::ValidateJwtSvid,
    ];

    /// The request path of the method, as the Workload API names it: the
    /// service `SpiffeWorkloadAPI`, which is in no package, and the method.
    fn path(self) -> &'static str {
        match self {
            Self::FetchX509Svid => "/SpiffeWorkloadAPI/FetchX509SVID",
            Self::FetchX509Bundles => "/SpiffeWorkloadAPI/FetchX509Bundles",
            Self::FetchJwtSvid => "/SpiffeWorkloadAPI/FetchJWTSVID",
            Self::FetchJwtBundles => "/SpiffeWorkloadAPI/FetchJWTBundles",
            Self::ValidateJwtSvid => "/SpiffeWorkloadAPI/ValidateJWTSVID",
        }
    }

    fn of_path(path: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|method| method.path() == path)
    }

    fn streams(self) -> bool {
        matches!(
            self,
            Self::FetchX509Svid | Self::FetchX509Bundles | Self::FetchJwtBundles
        )
    }
}

/// One X.509 SVID for the fake to serve, as the bytes of its message.
#[derive(Debug, Clone, Default)]
pub struct FakeX509Svid {
    /// `spiffe_id`.
    pub spiffe_id: String,
    /// `x509_svid`: DER certificates end to end, leaf first.
    pub cert_chain_der: Vec<u8>,
    /// `x509_svid_key`: PKCS#8 DER.
    pub private_key_der: Vec<u8>,
    /// `bundle`: the trust domain's authorities, DER end to end.
    pub bundle_der: Vec<u8>,
    /// `hint`.
    pub hint: String,
}

/// One JWT SVID for the fake to serve.
#[derive(Debug, Clone, Default)]
pub struct FakeJwtSvid {
    /// `spiffe_id`.
    pub spiffe_id: String,
    /// `svid`: the token.
    pub token: String,
    /// `hint`.
    pub hint: String,
}

/// What a method answers with.
#[derive(Debug, Clone)]
enum Answer {
    /// A gRPC status other than OK, and its message.
    Status(u32, String),
    /// One message, framed by the fake.
    Message(Vec<u8>),
    /// The JWT SVIDs of the workload's identities: a call is answered with
    /// those of the identity it names, or with all when it names none.
    JwtSvids(Vec<FakeJwtSvid>),
    /// Bytes written to the response body as they are, with no frame around
    /// them: for a test of what the client does with a broken frame.
    Body(Vec<u8>),
}

struct State {
    answers: BTreeMap<WorkloadApiMethod, watch::Sender<Answer>>,
    /// The calls of each method that are being served now.
    open: BTreeMap<WorkloadApiMethod, AtomicUsize>,
    requests: Mutex<Vec<(WorkloadApiMethod, Vec<u8>)>>,
    require_security_header: AtomicBool,
    hold_updates: AtomicBool,
    connections: Mutex<JoinSet<()>>,
}

impl State {
    /// The state of an agent that has issued nothing.
    fn new() -> Arc<Self> {
        let answers = WorkloadApiMethod::ALL
            .into_iter()
            .map(|method| {
                let initial = if method == WorkloadApiMethod::ValidateJwtSvid {
                    Answer::Status(UNIMPLEMENTED, "validation is not offered".to_owned())
                } else {
                    Answer::Status(PERMISSION_DENIED, "no identity issued".to_owned())
                };
                (method, watch::Sender::new(initial))
            })
            .collect();
        let open = WorkloadApiMethod::ALL
            .into_iter()
            .map(|method| (method, AtomicUsize::new(0)))
            .collect();
        Arc::new(Self {
            answers,
            open,
            requests: Mutex::new(Vec::new()),
            require_security_header: AtomicBool::new(true),
            hold_updates: AtomicBool::new(false),
            connections: Mutex::new(JoinSet::new()),
        })
    }

    fn answer(&self, method: WorkloadApiMethod) -> &watch::Sender<Answer> {
        // Every method has an entry from construction.
        &self.answers[&method]
    }

    fn set(&self, method: WorkloadApiMethod, answer: Answer) {
        self.answer(method).send_replace(answer);
    }

    /// Serve the connection `io` until it closes or the agent drops it.
    fn serve<T>(self: &Arc<Self>, io: T)
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let connection = serve_connection(io, self.clone());
        self.connections
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .spawn(connection);
    }
}

/// Counts a call as open for as long as it is served.
struct OpenCall {
    state: Arc<State>,
    method: WorkloadApiMethod,
}

impl OpenCall {
    fn new(state: &Arc<State>, method: WorkloadApiMethod) -> Self {
        state.open[&method].fetch_add(1, Ordering::SeqCst);
        Self {
            state: state.clone(),
            method,
        }
    }
}

impl Drop for OpenCall {
    fn drop(&mut self) {
        self.state.open[&self.method].fetch_sub(1, Ordering::SeqCst);
    }
}

/// A Workload API endpoint on a Unix domain socket or a loopback TCP port,
/// serving what the test sets. Dropping it stops the listener, closes every
/// connection and removes the socket.
pub struct FakeSpireAgent {
    state: Arc<State>,
    endpoint: Endpoint,
    /// The socket file to remove, when the agent listens on one.
    socket: Option<PathBuf>,
    accept: JoinHandle<()>,
}

impl std::fmt::Debug for FakeSpireAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeSpireAgent")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

impl Drop for FakeSpireAgent {
    fn drop(&mut self) {
        self.accept.abort();
        self.drop_connections();
        if let Some(socket) = &self.socket {
            // The socket may be gone already (a temporary directory removed
            // first); there is nothing to do about a failure here.
            let removed = std::fs::remove_file(socket);
            drop(removed);
        }
    }
}

fn invalid_input(error: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, error.to_string())
}

impl FakeSpireAgent {
    /// Listen on the Unix domain socket `socket`, an absolute path that
    /// must not exist. Until a test sets an answer, every method answers
    /// `PERMISSION_DENIED` ("no identity issued"), except
    /// `ValidateJWTSVID`, which answers `UNIMPLEMENTED`.
    ///
    /// Must be called inside a tokio runtime.
    pub fn start(socket: impl AsRef<Path>) -> std::io::Result<Self> {
        let socket = socket.as_ref().to_path_buf();
        let endpoint = Endpoint::unix(&socket).map_err(invalid_input)?;
        let listener = UnixListener::bind(&socket)?;
        let state = State::new();
        let serving = state.clone();
        let accept = tokio::spawn(async move {
            while let Ok((io, _)) = listener.accept().await {
                serving.serve(io);
            }
        });
        Ok(Self {
            state,
            endpoint,
            socket: Some(socket),
            accept,
        })
    }

    /// Listen on a loopback TCP port the system picks, with the answers of
    /// [`start`](Self::start). [`endpoint`](Self::endpoint) is where.
    ///
    /// Must be called inside a tokio runtime.
    pub fn start_tcp() -> std::io::Result<Self> {
        let listener = std::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
        listener.set_nonblocking(true)?;
        let endpoint = Endpoint::tcp_loopback(listener.local_addr()?).map_err(invalid_input)?;
        let listener = TcpListener::from_std(listener)?;
        let state = State::new();
        let serving = state.clone();
        let accept = tokio::spawn(async move {
            while let Ok((io, _)) = listener.accept().await {
                serving.serve(io);
            }
        });
        Ok(Self {
            state,
            endpoint,
            socket: None,
            accept,
        })
    }

    /// The endpoint a client connects to.
    pub fn endpoint(&self) -> Endpoint {
        self.endpoint.clone()
    }

    /// Serve these X.509 SVIDs, the first as the default, with these
    /// federated bundles (trust domain, DER authorities end to end). Open
    /// `FetchX509SVID` streams receive the new answer at once, as they do
    /// when an agent rotates.
    pub fn set_x509_svids(&self, svids: &[FakeX509Svid], federated_bundles: &[(&str, &[u8])]) {
        let mut message = Vec::new();
        for svid in svids {
            let mut entry = Vec::new();
            put_bytes(&mut entry, 1, svid.spiffe_id.as_bytes());
            put_bytes(&mut entry, 2, &svid.cert_chain_der);
            put_bytes(&mut entry, 3, &svid.private_key_der);
            put_bytes(&mut entry, 4, &svid.bundle_der);
            put_bytes(&mut entry, 5, svid.hint.as_bytes());
            put_bytes(&mut message, 1, &entry);
        }
        for (trust_domain, bundle) in federated_bundles {
            put_bytes(&mut message, 3, &map_entry(trust_domain, bundle));
        }
        self.state
            .set(WorkloadApiMethod::FetchX509Svid, Answer::Message(message));
    }

    /// Serve these X.509 bundles (trust domain, DER authorities end to end)
    /// on `FetchX509Bundles`.
    pub fn set_x509_bundles(&self, bundles: &[(&str, &[u8])]) {
        let mut message = Vec::new();
        for (trust_domain, bundle) in bundles {
            put_bytes(&mut message, 2, &map_entry(trust_domain, bundle));
        }
        self.state.set(
            WorkloadApiMethod::FetchX509Bundles,
            Answer::Message(message),
        );
    }

    /// Serve these JWT bundles (trust domain, JWKS document) on
    /// `FetchJWTBundles`.
    pub fn set_jwt_bundles(&self, bundles: &[(&str, &[u8])]) {
        let mut message = Vec::new();
        for (trust_domain, bundle) in bundles {
            put_bytes(&mut message, 1, &map_entry(trust_domain, bundle));
        }
        self.state
            .set(WorkloadApiMethod::FetchJwtBundles, Answer::Message(message));
    }

    /// Answer `FetchJWTSVID` from these SVIDs, one for each identity of the
    /// workload, whatever audience is asked for. A call that names a SPIFFE
    /// ID is answered with that identity's SVIDs alone, and with
    /// `PERMISSION_DENIED` when there is none; a call that names no ID is
    /// answered with all of them. [`jwt_audiences`](Self::jwt_audiences)
    /// and [`jwt_subjects`](Self::jwt_subjects) say what was asked.
    pub fn set_jwt_svids(&self, svids: &[FakeJwtSvid]) {
        self.state.set(
            WorkloadApiMethod::FetchJwtSvid,
            Answer::JwtSvids(svids.to_vec()),
        );
    }

    /// Answer `ValidateJWTSVID` by accepting every token as `spiffe_id`
    /// with `claims`. [`validations`](Self::validations) says what was
    /// presented.
    pub fn accept_validations(
        &self,
        spiffe_id: &str,
        claims: &serde_json::Map<String, serde_json::Value>,
    ) {
        let mut message = Vec::new();
        put_bytes(&mut message, 1, spiffe_id.as_bytes());
        put_bytes(&mut message, 2, &encode_struct(claims));
        self.state
            .set(WorkloadApiMethod::ValidateJwtSvid, Answer::Message(message));
    }

    /// Answer `method` with a gRPC status other than OK. An open stream of
    /// the method ends with it.
    pub fn refuse(&self, method: WorkloadApiMethod, grpc_status: u32, message: &str) {
        self.state
            .set(method, Answer::Status(grpc_status, message.to_owned()));
    }

    /// Answer `method` with `message` as one gRPC message, whatever it
    /// holds: for a test of a response that does not decode.
    pub fn answer_with_message(&self, method: WorkloadApiMethod, message: &[u8]) {
        self.state.set(method, Answer::Message(message.to_vec()));
    }

    /// Answer `method` with `body` written to the response as it is, with
    /// no gRPC frame around it: for a test of a broken frame.
    pub fn answer_with_body(&self, method: WorkloadApiMethod, body: &[u8]) {
        self.state.set(method, Answer::Body(body.to_vec()));
    }

    /// Whether a call without the `workload.spiffe.io: true` metadata is
    /// refused with `INVALID_ARGUMENT`, as an agent refuses it. On by
    /// default.
    pub fn require_security_header(&self, required: bool) {
        self.state
            .require_security_header
            .store(required, Ordering::SeqCst);
    }

    /// While held, a stream that is open is sent nothing new: an answer set
    /// in the meantime reaches only the streams opened after it. This is an
    /// agent whose stream has stalled, which a client has to notice by its
    /// own clock.
    pub fn hold_updates(&self, hold: bool) {
        self.state.hold_updates.store(hold, Ordering::SeqCst);
    }

    /// Close every open connection, as an agent that restarts does. The
    /// listener stays, so a client that reconnects is served again.
    pub fn drop_connections(&self) {
        self.state
            .connections
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .abort_all();
    }

    /// How many calls of `method` have arrived.
    pub fn calls(&self, method: WorkloadApiMethod) -> usize {
        self.state
            .requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|(called, _)| *called == method)
            .count()
    }

    /// How many calls of `method` are open now: answered so far and neither
    /// ended by the agent nor let go of by the client.
    pub fn open_calls(&self, method: WorkloadApiMethod) -> usize {
        self.state.open[&method].load(Ordering::SeqCst)
    }

    /// The SPIFFE ID each `FetchJWTSVID` call so far asked for, in order:
    /// empty for a call that named none.
    pub fn jwt_subjects(&self) -> Vec<String> {
        self.requests_of(WorkloadApiMethod::FetchJwtSvid)
            .iter()
            .map(|request| strings_of_field(request, 2).pop().unwrap_or_default())
            .collect()
    }

    /// The audiences of each `FetchJWTSVID` call so far, in order.
    pub fn jwt_audiences(&self) -> Vec<Vec<String>> {
        self.requests_of(WorkloadApiMethod::FetchJwtSvid)
            .iter()
            .map(|request| strings_of_field(request, 1))
            .collect()
    }

    /// The `(audience, token)` of each `ValidateJWTSVID` call so far.
    pub fn validations(&self) -> Vec<(String, String)> {
        self.requests_of(WorkloadApiMethod::ValidateJwtSvid)
            .iter()
            .map(|request| {
                let first = |field| strings_of_field(request, field).pop().unwrap_or_default();
                (first(1), first(2))
            })
            .collect()
    }

    fn requests_of(&self, method: WorkloadApiMethod) -> Vec<Vec<u8>> {
        self.state
            .requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|(called, _)| *called == method)
            .map(|(_, request)| request.clone())
            .collect()
    }
}

/// One entry of a `map<string, bytes>`.
fn map_entry(key: &str, value: &[u8]) -> Vec<u8> {
    let mut entry = Vec::new();
    put_bytes(&mut entry, 1, key.as_bytes());
    put_bytes(&mut entry, 2, value);
    entry
}

/// A JSON object as a `google.protobuf.Struct`.
fn encode_struct(fields: &serde_json::Map<String, serde_json::Value>) -> Vec<u8> {
    let mut out = Vec::new();
    for (key, value) in fields {
        let mut entry = Vec::new();
        put_bytes(&mut entry, 1, key.as_bytes());
        put_bytes(&mut entry, 2, &encode_value(value));
        put_bytes(&mut out, 1, &entry);
    }
    out
}

/// A JSON value as a `google.protobuf.Value`.
fn encode_value(value: &serde_json::Value) -> Vec<u8> {
    let mut out = Vec::new();
    match value {
        serde_json::Value::Null => {
            put_varint(&mut out, 1 << 3);
            put_varint(&mut out, 0);
        }
        serde_json::Value::Number(number) => {
            put_varint(&mut out, (2 << 3) | 1);
            let double = number.as_f64().unwrap_or_default();
            out.extend_from_slice(&double.to_bits().to_le_bytes());
        }
        serde_json::Value::String(text) => put_bytes(&mut out, 3, text.as_bytes()),
        serde_json::Value::Bool(flag) => {
            put_varint(&mut out, 4 << 3);
            put_varint(&mut out, u64::from(*flag));
        }
        serde_json::Value::Object(fields) => put_bytes(&mut out, 5, &encode_struct(fields)),
        serde_json::Value::Array(values) => {
            let mut list = Vec::new();
            for value in values {
                put_bytes(&mut list, 1, &encode_value(value));
            }
            put_bytes(&mut out, 6, &list);
        }
    }
    out
}

/// Every string written to field `number` of `message`.
fn strings_of_field(message: &[u8], number: u32) -> Vec<String> {
    let mut found = Vec::new();
    let mut reader = Reader::new(message);
    while let Ok(Some((field, value))) = reader.next_field() {
        if let (true, Field::Bytes(text)) = (field == number, value) {
            found.push(String::from_utf8_lossy(text).into_owned());
        }
    }
    found
}

/// The message of a `FetchJWTSVID` answer holding `svids`.
fn jwt_svids_message(svids: &[&FakeJwtSvid]) -> Vec<u8> {
    let mut message = Vec::new();
    for svid in svids {
        let mut entry = Vec::new();
        put_bytes(&mut entry, 1, svid.spiffe_id.as_bytes());
        put_bytes(&mut entry, 2, svid.token.as_bytes());
        put_bytes(&mut entry, 3, svid.hint.as_bytes());
        put_bytes(&mut message, 1, &entry);
    }
    message
}

async fn serve_connection<T>(io: T, state: Arc<State>)
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Ok(mut connection) = h2::server::handshake(io).await else {
        return;
    };
    // Dropped with the connection, which ends every call on it.
    let mut calls = JoinSet::new();
    while let Some(Ok((request, respond))) = connection.accept().await {
        calls.spawn(serve_call(request, respond, state.clone()));
    }
}

async fn serve_call(
    request: Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    state: Arc<State>,
) {
    let method = WorkloadApiMethod::of_path(request.uri().path());
    let has_security_header = request
        .headers()
        .get(SECURITY_METADATA)
        .is_some_and(|value| value == "true");
    let Some(message) = read_request(request.into_body()).await else {
        return;
    };
    let Some(method) = method else {
        end_call(&mut respond, None, UNIMPLEMENTED, "unknown method");
        return;
    };
    // The identity a `FetchJWTSVID` call names: field 2 of its request.
    let named = strings_of_field(&message, 2).pop().unwrap_or_default();
    state
        .requests
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push((method, message));
    if state.require_security_header.load(Ordering::SeqCst) && !has_security_header {
        end_call(
            &mut respond,
            None,
            INVALID_ARGUMENT,
            "security header missing from request",
        );
        return;
    }
    // Dropped when the answers end, and with this task when the connection
    // closes under them.
    let open = OpenCall::new(&state, method);
    send_answers(method, &named, respond, &state).await;
    drop(open);
}

/// Answer one call of `method`: once, or for a stream with every answer the
/// test sets until the call ends.
async fn send_answers(
    method: WorkloadApiMethod,
    named: &str,
    mut respond: SendResponse<Bytes>,
    state: &State,
) {
    let mut answers = state.answer(method).subscribe();
    let mut body: Option<SendStream<Bytes>> = None;
    loop {
        let answer = answers.borrow_and_update().clone();
        let bytes = match answer {
            Answer::Status(status, message) => {
                end_call(&mut respond, body.take(), status, &message);
                return;
            }
            Answer::Message(message) => frame(&message),
            Answer::JwtSvids(svids) => {
                let asked: Vec<&FakeJwtSvid> = svids
                    .iter()
                    .filter(|svid| named.is_empty() || svid.spiffe_id == named)
                    .collect();
                if asked.is_empty() && !named.is_empty() {
                    let refused = "no identity issued";
                    end_call(&mut respond, body.take(), PERMISSION_DENIED, refused);
                    return;
                }
                frame(&jwt_svids_message(&asked))
            }
            Answer::Body(raw) => Bytes::from(raw),
        };
        if body.is_none() {
            let Ok(opened) = respond.send_response(response_head(), false) else {
                return;
            };
            body = Some(opened);
        }
        let Some(stream) = body.as_mut() else {
            return;
        };
        if stream.send_data(bytes, false).is_err() {
            return;
        }
        if !method.streams() {
            end_call(&mut respond, body.take(), 0, "");
            return;
        }
        // The stream stays open until the answer changes, or until the
        // client lets go of it.
        loop {
            let gone = std::future::poll_fn(|cx| stream.poll_reset(cx));
            tokio::select! {
                changed = answers.changed() => {
                    if changed.is_err() {
                        return;
                    }
                }
                _ = gone => return,
            }
            // Held: the change is seen and not sent.
            if !state.hold_updates.load(Ordering::SeqCst) {
                break;
            }
        }
    }
}

/// The request message of a call: the body is read to its end.
async fn read_request(mut body: RecvStream) -> Option<Vec<u8>> {
    let mut decoder = FrameDecoder::new(usize::MAX);
    while let Some(chunk) = body.data().await {
        let chunk = chunk.ok()?;
        if !chunk.is_empty() {
            body.flow_control().release_capacity(chunk.len()).ok()?;
        }
        decoder.push(&chunk);
    }
    let message = decoder.next_message().ok().flatten();
    Some(message.map(|message| message.to_vec()).unwrap_or_default())
}

fn response_head() -> Response<()> {
    let mut response = Response::new(());
    response
        .headers_mut()
        .insert("content-type", HeaderValue::from_static("application/grpc"));
    response
}

/// End a call with `status`: in the trailers when the response is open, in
/// the response headers when nothing was sent yet.
fn end_call(
    respond: &mut SendResponse<Bytes>,
    body: Option<SendStream<Bytes>>,
    status: u32,
    message: &str,
) {
    let mut outcome = HeaderMap::new();
    outcome.insert("grpc-status", HeaderValue::from(status));
    if !message.is_empty()
        && let Ok(value) = HeaderValue::from_str(&percent_encoded(message))
    {
        outcome.insert("grpc-message", value);
    }
    // A client that has gone away makes either send fail; the call is over
    // both ways.
    match body {
        Some(mut body) => drop(body.send_trailers(outcome)),
        None => {
            let mut response = response_head();
            response.headers_mut().extend(outcome);
            drop(respond.send_response(response, true));
        }
    }
}

/// A status message as gRPC writes it in a header: every byte outside
/// printable ASCII, and the percent sign, as `%XX`.
fn percent_encoded(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    for byte in message.bytes() {
        if (0x20..=0x7E).contains(&byte) && byte != b'%' {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests;
