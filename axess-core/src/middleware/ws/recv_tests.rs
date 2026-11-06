//! `recv` over a real socket: a revocation that is already signalled wins
//! over messages the client has already sent.

use super::*;
use crate::session::store::MemorySessionRegistry;
use axum::{Router, extract::ws::WebSocketUpgrade, routing::get};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

/// Connections raced: the unbiased `select!` hands over a queued message
/// about half the time, so a dozen make a false pass a one in 4,096 chance.
const CONNECTIONS: usize = 12;
/// Frames each client sends before the revocation is noticed.
const QUEUED: usize = 50;

/// One masked text frame ("x") with an all-zero mask key.
const FRAME: [u8; 7] = [0x81, 0x81, 0, 0, 0, 0, b'x'];

/// A server whose handler waits for the supervisor's signal, then reports how
/// many messages `recv` still delivered.
async fn serve(
    registry: MemorySessionRegistry,
    user: UserId,
    session: SessionId,
) -> (u16, tokio::sync::mpsc::UnboundedReceiver<usize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let (report, delivered) = tokio::sync::mpsc::unbounded_channel();
    let app = Router::new().route(
        "/ws",
        get(move |upgrade: WebSocketUpgrade| {
            let (registry, user, session, report) =
                (registry.clone(), user, session, report.clone());
            async move {
                upgrade.on_upgrade(move |socket| async move {
                    let options = WatchOptions {
                        poll_interval: Duration::from_secs(1),
                        ..WatchOptions::default()
                    };
                    let mut socket = RevocationAwareSocket::with_options(
                        socket, registry, user, session, options,
                    );
                    // The watcher has ended and its signal is queued.
                    while !socket.watch_task().is_finished() {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    let mut count = 0;
                    while let Some(Ok(_)) = socket.recv().await {
                        count += 1;
                    }
                    report.send(count).expect("report");
                })
            }
        }),
    );
    tokio::spawn(async move { axum::serve(listener, app).await });
    (port, delivered)
}

async fn client(port: u16) {
    let mut tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    tcp.write_all(
        b"GET /ws HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
          Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
    )
    .await
    .expect("handshake");
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(tcp.read_u8().await.expect("response"));
    }
    for _ in 0..QUEUED {
        tcp.write_all(&FRAME).await.expect("frame");
    }
    // Hold the connection open until the server is done with it.
    let mut rest = Vec::new();
    let _ = tcp.read_to_end(&mut rest).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_signalled_revocation_beats_messages_already_sent() {
    let registry = MemorySessionRegistry::new();
    let user = axess_identity::testing::user("ws-user");
    let session = SessionId::new(&crate::testing::mock_random::MockRng::new(7));
    registry.register(&user, &session).await.expect("register");
    registry
        .invalidate_session(&user, &session)
        .await
        .expect("revoke");
    let (port, mut delivered) = serve(registry, user, session).await;
    for _ in 0..CONNECTIONS {
        tokio::spawn(client(port));
    }
    for _ in 0..CONNECTIONS {
        let count = delivered.recv().await.expect("report");
        assert_eq!(count, 0, "a message was delivered after the revocation");
    }
}
