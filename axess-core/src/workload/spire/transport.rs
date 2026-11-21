//! gRPC over HTTP/2 to the agent, as much as five methods need.
//!
//! One call is one connection: the socket is local, a call is either a
//! long-lived stream or rare, and a connection that carries one stream has
//! one thing that can fail. A call sends its request message and half-closes;
//! the agent answers with any number of messages and a status in the
//! trailers, or with a status alone.
//!
//! Nothing here encrypts or authenticates: the socket is the boundary. On a
//! Unix domain socket that is the permissions of its directory; on TCP it is
//! nothing, which is why [`Endpoint`] refuses a TCP address off the loopback
//! interface unless it is asked for by name.
//!
//! Every request carries the metadata `workload.spiffe.io: true`. The
//! Workload API requires it so that a request forged through a
//! server-side-request-forgery hole, which cannot set a header, is refused
//! by the agent.

use std::future::Future;
use std::pin::Pin;

use axum::body::Bytes;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use super::endpoint::{Address, Endpoint};
use super::error::{GrpcCode, SpireError, remote_text};
use super::wire::{FrameDecoder, frame};

/// The metadata key every Workload API request carries, with the value
/// `true`.
pub(crate) const SECURITY_HEADER: &str = "workload.spiffe.io";

/// The `tracing` target of the client's events.
pub(crate) const TARGET: &str = "axess::workload::spire";

/// One message of an answer. It may hold a private key or a token, so it
/// wipes itself when dropped.
pub(crate) type Message = Zeroizing<Vec<u8>>;

type ResponseHead =
    Pin<Box<dyn Future<Output = Result<axum::http::Response<h2::RecvStream>, h2::Error>> + Send>>;

enum State {
    /// The request is sent; the response headers have not arrived.
    Head(ResponseHead),
    /// The headers are read; messages arrive on the body.
    Body(h2::RecvStream),
    /// The call has ended.
    Done,
}

/// The messages one call answers with, in order.
pub(crate) struct Responses {
    state: State,
    decoder: FrameDecoder,
    /// Drives the connection; aborted when the call is dropped.
    driver: JoinHandle<()>,
}

impl Drop for Responses {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

/// Connect to `endpoint`, send `message` to `method` and half-close.
pub(crate) async fn open(
    endpoint: &Endpoint,
    method: &'static str,
    message: &[u8],
    max_message_bytes: usize,
) -> Result<Responses, SpireError> {
    let connect_failed =
        |error: std::io::Error| SpireError::Connect(remote_text(&error.to_string()));
    match endpoint.address() {
        #[cfg(unix)]
        Address::Unix(path) => {
            let io = tokio::net::UnixStream::connect(path)
                .await
                .map_err(connect_failed)?;
            call(io, method, message, max_message_bytes).await
        }
        #[cfg(not(unix))]
        Address::Unix(_) => Err(SpireError::Connect(
            "Unix domain sockets are not available on this platform".to_owned(),
        )),
        // Clear text, to whoever answers there: see `Endpoint` on what a TCP
        // endpoint gives up.
        Address::Tcp(address) => {
            let io = tokio::net::TcpStream::connect(address)
                .await
                .map_err(connect_failed)?;
            call(io, method, message, max_message_bytes).await
        }
    }
}

async fn call<T>(
    io: T,
    method: &'static str,
    message: &[u8],
    max_message_bytes: usize,
) -> Result<Responses, SpireError>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sender, connection) = h2::client::handshake(io).await.map_err(transport)?;
    let driver = tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::debug!(
                target: TARGET,
                error = %remote_text(&error.to_string()),
                "workload API connection closed with an error",
            );
        }
    });
    // From here on the driver is owned by `Responses`, or aborted below.
    let opened = send(sender, method, message).await;
    match opened {
        Ok(head) => Ok(Responses {
            state: State::Head(head),
            decoder: FrameDecoder::new(max_message_bytes),
            driver,
        }),
        Err(error) => {
            driver.abort();
            Err(error)
        }
    }
}

async fn send(
    sender: h2::client::SendRequest<Bytes>,
    method: &'static str,
    message: &[u8],
) -> Result<ResponseHead, SpireError> {
    // The authority is a placeholder: the socket is the address, and gRPC
    // servers on a local socket do not read it.
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("http://localhost/SpiffeWorkloadAPI/{method}"))
        .header(header::CONTENT_TYPE, "application/grpc")
        .header(header::TE, "trailers")
        .header("grpc-accept-encoding", "identity")
        .header(SECURITY_HEADER, "true")
        .body(())
        .map_err(|error| SpireError::Transport(error.to_string()))?;
    let mut sender = sender.ready().await.map_err(transport)?;
    let (response, mut body) = sender.send_request(request, false).map_err(transport)?;
    body.send_data(frame(message), true).map_err(transport)?;
    Ok(Box::pin(response))
}

impl Responses {
    /// The next message, or `None` when the call ended with status OK.
    ///
    /// Cancel-safe: a call dropped while it waits has consumed nothing it
    /// did not keep.
    pub(crate) async fn next_message(&mut self) -> Result<Option<Message>, SpireError> {
        loop {
            if let Some(message) = self.decoder.next_message()? {
                return Ok(Some(message));
            }
            match &mut self.state {
                State::Head(head) => {
                    let response = head.as_mut().await.map_err(transport)?;
                    let (parts, body) = response.into_parts();
                    if parts.status != StatusCode::OK {
                        self.state = State::Done;
                        return Err(SpireError::Transport(format!(
                            "the agent answered HTTP {}",
                            parts.status.as_u16()
                        )));
                    }
                    if !is_grpc(&parts.headers) {
                        self.state = State::Done;
                        return Err(SpireError::Malformed(
                            "the answer's content type is not application/grpc".to_owned(),
                        ));
                    }
                    // A status in the headers is a call that ended with no
                    // message ("trailers only").
                    if let Some(outcome) = grpc_status(&parts.headers) {
                        self.state = State::Done;
                        return outcome.map(|()| None);
                    }
                    self.state = State::Body(body);
                }
                State::Body(body) => match body.data().await {
                    Some(chunk) => {
                        let chunk = chunk.map_err(transport)?;
                        if !chunk.is_empty() {
                            body.flow_control()
                                .release_capacity(chunk.len())
                                .map_err(transport)?;
                        }
                        self.decoder.push(&chunk);
                    }
                    None => {
                        let trailers = body.trailers().await.map_err(transport)?;
                        self.state = State::Done;
                        if !self.decoder.is_empty() {
                            return Err(SpireError::Malformed(
                                "the stream ended inside a message".to_owned(),
                            ));
                        }
                        let outcome = trailers.as_ref().and_then(grpc_status);
                        return match outcome {
                            Some(outcome) => outcome.map(|()| None),
                            None => Err(SpireError::Transport(
                                "the stream ended without a gRPC status".to_owned(),
                            )),
                        };
                    }
                },
                State::Done => return Ok(None),
            }
        }
    }

    /// The one message of a unary call. A call that answers none, or more
    /// than one, is refused.
    pub(crate) async fn single_message(mut self) -> Result<Message, SpireError> {
        let Some(message) = self.next_message().await? else {
            return Err(SpireError::Malformed(
                "the call ended without a message".to_owned(),
            ));
        };
        match self.next_message().await? {
            None => Ok(message),
            Some(_) => Err(SpireError::Malformed(
                "a unary call answered more than one message".to_owned(),
            )),
        }
    }
}

fn transport(error: h2::Error) -> SpireError {
    SpireError::Transport(remote_text(&error.to_string()))
}

fn is_grpc(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/grpc"))
}

/// The outcome a `grpc-status` header states, `None` when the map has none.
/// A status that is not a number is an error of its own, since the call's
/// outcome is then unknown.
fn grpc_status(headers: &HeaderMap) -> Option<Result<(), SpireError>> {
    let status = headers.get("grpc-status")?;
    let Some(status) = status
        .to_str()
        .ok()
        .and_then(|text| text.parse::<u32>().ok())
    else {
        return Some(Err(SpireError::Malformed(
            "the gRPC status is not a number".to_owned(),
        )));
    };
    if status == 0 {
        return Some(Ok(()));
    }
    let message = headers
        .get("grpc-message")
        .map(|value| percent_decoded(value.as_bytes()))
        .unwrap_or_default();
    Some(Err(SpireError::Status {
        code: GrpcCode::from_status(status),
        message: remote_text(&message),
    }))
}

/// A `grpc-message` with its percent escapes undone. gRPC percent-encodes
/// the message because a header value cannot carry every byte; an escape
/// that is not two hex digits is kept as written.
pub(crate) fn percent_decoded(value: &[u8]) -> String {
    let hex = |byte: u8| char::from(byte).to_digit(16);
    let mut out = Vec::with_capacity(value.len());
    let mut index = 0;
    while index < value.len() {
        let pair = (value.get(index + 1), value.get(index + 2));
        match (value[index], pair) {
            (b'%', (Some(high), Some(low))) => match (hex(*high), hex(*low)) {
                (Some(high), Some(low)) => {
                    out.push((high * 16 + low) as u8);
                    index += 3;
                }
                _ => {
                    out.push(b'%');
                    index += 1;
                }
            },
            (byte, _) => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests;
