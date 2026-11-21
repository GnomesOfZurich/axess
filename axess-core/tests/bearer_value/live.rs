//! The same flows at rest: the session store, the registry and the sid
//! store on a live Valkey under one fresh prefix, with a second connection
//! in `MONITOR` for the length of the run. Every command the server
//! received is searched. The client library is built without a monitor
//! feature, so the monitor is a plain connection speaking the wire
//! protocol. A neighbour's commands are in the stream too; the ids are
//! random, so none of theirs can hold one of this run's.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axess_core::federation::valkey_logout::ValkeySidStore;
use axess_core::testing::valkey_sweep::KeySweep;
use axess_core::{ValkeySessionRegistry, ValkeySessionStore};
use fred::prelude::{ClientLike, Config};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::doors::{RecordingSid, RecordingStore};
use crate::search::saw_key;

fn live_url() -> String {
    std::env::var("VALKEY_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into())
}

/// The arguments of one `MONITOR` line, unescaped: the server writes each
/// argument in double quotes, with `\\`, `\"`, `\n`, `\r`, `\t`, `\a`, `\b`
/// and `\xHH` for every byte that is not printable.
fn arguments(line: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut bytes = line.iter().copied().peekable();
    while let Some(b) = bytes.next() {
        if b != b'"' {
            continue;
        }
        let mut arg = Vec::new();
        while let Some(b) = bytes.next() {
            match b {
                b'"' => break,
                b'\\' => match bytes.next() {
                    Some(b'n') => arg.push(b'\n'),
                    Some(b'r') => arg.push(b'\r'),
                    Some(b't') => arg.push(b'\t'),
                    Some(b'a') => arg.push(0x07),
                    Some(b'b') => arg.push(0x08),
                    Some(b'x') => {
                        let high = bytes.next().unwrap_or(b'0');
                        let low = bytes.next().unwrap_or(b'0');
                        let hex = [high, low];
                        let text = std::str::from_utf8(&hex).unwrap_or("00");
                        arg.push(u8::from_str_radix(text, 16).unwrap_or(0));
                    }
                    Some(other) => arg.push(other),
                    None => break,
                },
                other => arg.push(other),
            }
        }
        out.push(arg);
    }
    out
}

/// A connection in `MONITOR`, collecting every line the server sends.
struct Monitor {
    lines: Arc<Mutex<Vec<Vec<u8>>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Monitor {
    async fn start(url: &str) -> Self {
        let authority = url
            .split_once("://")
            .map_or(url, |(_, rest)| rest)
            .split('/')
            .next()
            .expect("host:port");
        let mut stream = TcpStream::connect(authority).await.expect("connect");
        stream
            .write_all(b"*1\r\n$7\r\nMONITOR\r\n")
            .await
            .expect("MONITOR");
        let mut reader = BufReader::new(stream);
        let mut ok = Vec::new();
        reader.read_until(b'\n', &mut ok).await.expect("the reply");
        assert!(ok.starts_with(b"+OK"), "{}", String::from_utf8_lossy(&ok));
        let lines = Arc::new(Mutex::new(Vec::new()));
        let sink = lines.clone();
        let task = tokio::spawn(async move {
            loop {
                let mut line = Vec::new();
                match reader.read_until(b'\n', &mut line).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => sink.lock().unwrap().push(line),
                }
            }
        });
        Self { lines, task }
    }

    /// Every line, and every argument of every line, received so far.
    fn stop(self) -> Vec<Vec<u8>> {
        self.task.abort();
        let lines = self.lines.lock().unwrap().clone();
        let mut out = Vec::new();
        for line in lines {
            out.extend(arguments(&line));
            out.push(line);
        }
        out
    }
}

#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn no_command_the_server_receives_holds_a_session_id() {
    let url = live_url();
    // Every key of the run is under this prefix, and removed when the test
    // ends, also when it fails.
    let sweep = KeySweep::node(url.as_str(), "bearer");
    let prefix = sweep.prefix().to_owned();
    let clock = axess_core::testing::fixtures::test_clock();
    let monitor = Monitor::start(&url).await;
    let client = fred::prelude::Client::new(Config::from_url(&url).unwrap(), None, None, None);
    client.init().await.expect("connect");

    let store = RecordingStore::over(
        ValkeySessionStore::new(client.clone(), axess_core::testing::test_key(43))
            .with_prefix(format!("{{{prefix}}}:session")),
    );
    let registry = ValkeySessionRegistry::with_options(
        client.clone(),
        format!("{{{prefix}}}:registry"),
        Duration::from_secs(3600),
    )
    .await
    .expect("a registry")
    .with_clock(Arc::new(clock.clone()));
    let sid = RecordingSid::over(Arc::new(
        ValkeySidStore::new(client.clone()).with_prefix(format!("{prefix}:logout")),
    ));
    let w = crate::world::world(clock, store.clone(), registry, sid);
    let expected = crate::flows::run(&w, &store).await;
    // The endings the layer runs in tasks of their own finish first.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let commands = monitor.stop();

    {
        let bearers = w.bearers.lock().unwrap();
        bearers.assert_absent("the commands the server received", &commands);
        assert!(
            expected.mismatches.is_empty(),
            "the flows did not run as expected: {:#?}",
            expected.mismatches
        );
        for key in expected
            .stored
            .iter()
            .chain(&expected.registered)
            .chain(&expected.mapped)
        {
            assert!(saw_key(&commands, key), "the server was sent {key:?}");
        }
    }
    client.quit().await.ok();
}
