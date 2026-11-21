//! Where the Workload API is served.
//!
//! SPIFFE names the endpoint with a URI, by convention in the environment
//! variable `SPIFFE_ENDPOINT_SOCKET`: `unix:///run/spire/sockets/agent.sock`
//! for a Unix domain socket, `tcp://127.0.0.1:8081` for TCP. The parser
//! applies the Workload Endpoint rules: a `unix` URI has no authority and an
//! absolute path; a `tcp` URI has an IP address, not a host name, a port, and
//! no path; neither has a query, a fragment or user information.
//!
//! # What a TCP endpoint gives up
//!
//! The client speaks to the agent in clear text and does not authenticate
//! it: the socket is the boundary. A Unix domain socket is guarded by the
//! permissions of the directory it lies in. A TCP port is guarded by nothing:
//! over it the workload's private key, its tokens and the trust bundles its
//! verifiers rely on cross unencrypted, and whoever answers on the address is
//! taken for the agent.
//!
//! So a TCP address is accepted only on the loopback interface, where the
//! bytes do not leave the host, and that still leaves any local process that
//! binds the port before the agent does in the agent's place. An address off
//! the loopback interface is refused by [`Endpoint::parse`],
//! [`Endpoint::from_env`] and [`Endpoint::tcp_loopback`];
//! [`Endpoint::tcp_clear_text`] is the one way to build it, and its name is
//! what the caller accepts.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use super::error::{SpireError, remote_text};

/// The environment variable SPIFFE reads the endpoint address from.
pub const ENDPOINT_SOCKET_ENV: &str = "SPIFFE_ENDPOINT_SOCKET";

/// The address of a Workload API endpoint: a Unix domain socket, or a TCP
/// socket.
///
/// An endpoint is built by [`unix`](Self::unix), [`tcp_loopback`](Self::tcp_loopback),
/// [`parse`](Self::parse) or [`from_env`](Self::from_env), each of which
/// checks what it is given, or by [`tcp_clear_text`](Self::tcp_clear_text),
/// which says what it does not check. There is no other way to make one, so
/// an `Endpoint` always holds an absolute socket path or an address its
/// maker chose knowingly.
///
/// ```
/// use axess_core::workload::spire::Endpoint;
///
/// let endpoint: Endpoint = "unix:///run/spire/sockets/agent.sock".parse()?;
/// assert_eq!(endpoint.to_string(), "unix:///run/spire/sockets/agent.sock");
/// assert!("unix://host/agent.sock".parse::<Endpoint>().is_err());
/// assert!("tcp://localhost:8081".parse::<Endpoint>().is_err());
/// // Off the loopback interface the connection would carry the private
/// // key in clear text across the network: refused.
/// assert!("tcp://10.0.0.7:8081".parse::<Endpoint>().is_err());
/// # Ok::<(), axess_core::workload::spire::SpireError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Endpoint {
    address: Address,
}

/// The two kinds of address an endpoint has.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum Address {
    /// A Unix domain socket at an absolute path.
    Unix(PathBuf),
    /// A TCP socket at an IP address and port.
    Tcp(SocketAddr),
}

impl Endpoint {
    /// The Unix domain socket at `path`. The path is absolute (a relative
    /// one would name a different socket in every working directory), names
    /// a file and holds no NUL.
    pub fn unix(path: impl AsRef<Path>) -> Result<Self, SpireError> {
        let path = path.as_ref();
        let refuse = |why: &str| {
            Err(SpireError::Endpoint(format!(
                "{why}: {}",
                remote_text(&path.to_string_lossy())
            )))
        };
        let bytes = path.as_os_str().as_encoded_bytes();
        if !path.is_absolute() {
            return refuse("the socket path is not absolute");
        }
        if bytes.iter().all(|byte| *byte == b'/') {
            return refuse("the socket path names no socket");
        }
        if bytes.contains(&0) {
            return refuse("the socket path holds a NUL");
        }
        Ok(Self {
            address: Address::Unix(path.to_path_buf()),
        })
    }

    /// The TCP socket at `address`, which is on the loopback interface
    /// (`127.0.0.0/8` or `::1`). Any other address is refused: see the
    /// module documentation on what a TCP endpoint gives up, and
    /// [`tcp_clear_text`](Self::tcp_clear_text) for the way around.
    pub fn tcp_loopback(address: SocketAddr) -> Result<Self, SpireError> {
        if !address.ip().is_loopback() {
            return Err(SpireError::Endpoint(format!(
                "a tcp endpoint off the loopback interface is refused: {address} would carry the \
                 workload's private key and tokens in clear text to a peer nobody authenticated"
            )));
        }
        Ok(Self {
            address: Address::Tcp(address),
        })
    }

    /// The TCP socket at `address`, wherever it is.
    ///
    /// **This gives up the confidentiality of everything the agent serves
    /// and the authentication of the agent.** The connection is clear text:
    /// the X.509 SVID's private key, every JWT SVID and the trust bundles
    /// cross the network readable to whoever sits on the path. Nothing
    /// proves that the peer is the agent: whoever answers on the address
    /// hands the workload its identity and the authorities its verifiers
    /// trust. Use it only where the network path itself is protected and
    /// owned end to end (inside one network namespace, over a tunnel that
    /// authenticates both ends). No URI and no environment variable builds
    /// such an endpoint; it takes this call.
    pub fn tcp_clear_text(address: SocketAddr) -> Self {
        Self {
            address: Address::Tcp(address),
        }
    }

    /// Parse a `unix:` or `tcp:` endpoint URI. A `tcp` address off the
    /// loopback interface is refused.
    pub fn parse(uri: &str) -> Result<Self, SpireError> {
        let refuse = |why: &str| Err(SpireError::Endpoint(format!("{why}: {}", remote_text(uri))));
        if uri.contains(['?', '#']) {
            return refuse("an endpoint URI has no query and no fragment");
        }
        if let Some(rest) = uri.strip_prefix("unix:") {
            // `unix:///path` has an empty authority; `unix:/path` has none.
            let path = rest.strip_prefix("//").unwrap_or(rest);
            if !path.starts_with('/') {
                return refuse("a unix endpoint has no authority and an absolute path");
            }
            return Self::unix(path);
        }
        if let Some(rest) = uri.strip_prefix("tcp://") {
            if rest.contains('@') {
                return refuse("a tcp endpoint has no user information");
            }
            if rest.contains('/') {
                return refuse("a tcp endpoint has no path");
            }
            // `SocketAddr` reads `1.2.3.4:5` and `[::1]:5`, and nothing with
            // a host name in it.
            return match SocketAddr::from_str(rest) {
                Ok(address) => Self::tcp_loopback(address),
                Err(_) => refuse("a tcp endpoint is an IP address and a port"),
            };
        }
        refuse("an endpoint URI starts with unix: or tcp://")
    }

    /// The endpoint named by [`ENDPOINT_SOCKET_ENV`], read as
    /// [`parse`](Self::parse) reads it. An unset variable and a value that
    /// is not valid Unicode are both refused: no path is guessed.
    pub fn from_env() -> Result<Self, SpireError> {
        match std::env::var(ENDPOINT_SOCKET_ENV) {
            Ok(value) => Self::parse(&value),
            Err(std::env::VarError::NotPresent) => Err(SpireError::Endpoint(format!(
                "{ENDPOINT_SOCKET_ENV} is not set"
            ))),
            Err(std::env::VarError::NotUnicode(_)) => Err(SpireError::Endpoint(format!(
                "{ENDPOINT_SOCKET_ENV} is not valid Unicode"
            ))),
        }
    }

    /// The socket path of a Unix endpoint.
    pub fn unix_path(&self) -> Option<&Path> {
        match &self.address {
            Address::Unix(path) => Some(path),
            Address::Tcp(_) => None,
        }
    }

    /// The address of a TCP endpoint.
    pub fn tcp_address(&self) -> Option<SocketAddr> {
        match &self.address {
            Address::Tcp(address) => Some(*address),
            Address::Unix(_) => None,
        }
    }

    pub(crate) fn address(&self) -> &Address {
        &self.address
    }
}

impl FromStr for Endpoint {
    type Err = SpireError;

    fn from_str(uri: &str) -> Result<Self, Self::Err> {
        Self::parse(uri)
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.address {
            Address::Unix(path) => write!(f, "unix://{}", path.display()),
            Address::Tcp(address) => write!(f, "tcp://{address}"),
        }
    }
}

#[cfg(test)]
mod tests;
