// Invariant: once a signed request has been accepted, no later
// header for the same (stamp, method, target, body) is accepted under ANY
// scheme (v3, v2 or v1 stripped/recombined). A header with one mutated hex
// digit is never accepted.
// Drives the real public API end to end: ServiceSecretLayer::signed +
// ServiceSigner::sign_for through an axum Router (Verifier::check is
// pub(super), so no `fuzzing` feature is needed for this one). Needs
// axess-core feature `service-secret`. While the gap is open it finds: the v3 request
// replayed as `t=..,v2=..` is accepted once.
#![no_main]

use axess_clock::Clock;
use axess_core::middleware::service_secret::{
    SIGNATURE_HEADER, ServiceSecret, ServiceSecretLayer, ServiceSecrets, SignedRequests,
};
use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Method, Request, StatusCode},
    routing::post,
};
use chrono::{DateTime, Utc};
use libfuzzer_sys::fuzz_target;
use std::sync::{Arc, LazyLock};
use tower::ServiceExt as _;

const SECRET: &str = "relay-secret-0123456789abcdef0123456789";
const AUDIENCE: &str = "billing";
const EPOCH: i64 = 1_790_000_000;

struct Fixed(DateTime<Utc>);
impl Clock for Fixed {
    fn now(&self) -> DateTime<Utc> {
        self.0
    }
}

static RT: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
});

fn app() -> Router {
    // A fresh app (and replay cache) per input so inputs are independent.
    let secrets: ServiceSecrets = [ServiceSecret::new("relay", SECRET).expect("long enough")]
        .into_iter()
        .collect();
    let until = DateTime::from_timestamp(EPOCH + 1000, 0).expect("ts");
    let config = SignedRequests::default()
        .audience(AUDIENCE)
        .accept_v2_until(until)
        .accept_unaddressed_until(until)
        .clock(Arc::new(Fixed(
            DateTime::from_timestamp(EPOCH, 0).expect("ts"),
        )));
    Router::new()
        .route("/hook", post(|| async { "ok" }))
        .layer(ServiceSecretLayer::signed(secrets, config).expect("addressed"))
}

async fn send(app: &Router, header: &str, body: &[u8]) -> StatusCode {
    let Ok(req) = Request::builder()
        .method(Method::POST)
        .uri("/hook")
        .header(SIGNATURE_HEADER, header)
        .body(Body::from(body.to_vec()))
    else {
        return StatusCode::BAD_REQUEST; // header bytes not representable
    };
    app.clone().oneshot(req).await.expect("infallible").status()
}

/// `t=..,v2=..,v3=..` -> the individual `k=v` parts.
fn parts(h: &str) -> Vec<(String, String)> {
    h.split(',')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.into(), v.into()))
        .collect()
}
fn only(p: &[(String, String)], keep: &[&str]) -> String {
    p.iter()
        .filter(|(k, _)| keep.contains(&k.as_str()))
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(",")
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let (ctl, body) = (data[0], &data[1..]);
    let body = &body[..body.len().min(4096)];
    RT.block_on(async {
        let app = app();
        let signer = ServiceSecret::new("caller", SECRET)
            .expect("long enough")
            .signer();
        let stamp = EPOCH - i64::from(ctl % 60);
        let header = signer
            .sign_for(
                AUDIENCE,
                stamp,
                &Method::POST,
                "/hook",
                &HeaderMap::new(),
                body,
            )
            .to_str()
            .expect("ascii")
            .to_owned();

        // Mutated header (one hex digit of the v3 tag changed) is never
        // accepted. Only v3 is mutated: the route checks the highest scheme
        // the header carries, so a corrupted v2 beside a valid v3 is
        // legitimately accepted and would not be a finding.
        let v3_at = header.find(",v3=").expect("sign_for emits v3") + 4;
        let pos = v3_at + usize::from(ctl) % (header.len() - v3_at);
        let mut m = header.clone().into_bytes();
        if m[pos].is_ascii_hexdigit() {
            m[pos] = if m[pos] == b'0' { b'1' } else { b'0' };
            let mutated = String::from_utf8(m).expect("ascii");
            assert_ne!(
                send(&app, &mutated, body).await,
                StatusCode::OK,
                "mutated header accepted: {mutated}"
            );
        }

        // Accept once, under the full header.
        assert_eq!(
            send(&app, &header, body).await,
            StatusCode::OK,
            "genuine request refused"
        );

        // No replay under any scheme subset.
        let p = parts(&header);
        for keep in [
            &["t", "v2", "v3"][..],
            &["t", "v2"],
            &["t", "v3"],
            &["t", "v3", "v2"],
        ] {
            let replay = only(&p, keep);
            assert_ne!(
                send(&app, &replay, body).await,
                StatusCode::OK,
                "replay accepted as {replay}"
            );
        }
        // v1 -> v2 upgrade replay needs the v1 tag, which only the crate can
        // compute (signature::sign_bytes is pub(super)). Expose it behind a
        // `fuzzing` feature, e.g.
        //   #[cfg(feature = "fuzzing")] pub use signature::sign_bytes as fuzz_sign_v1;
        // then: accept `t=..,v1=..`, replay as `t=..,v2=..` and assert != 200.
    });
});
