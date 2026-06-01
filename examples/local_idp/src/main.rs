//! # axess-example-local-idp
//!
//! Production-pattern example for `axess::local_idp::LocalIdp`. Boots
//! an in-process IdP that signs workload-identity JWTs against an
//! RSA-2048 key stored on disk, serves the discovery document + JWKS,
//! and exposes a `POST /admin/rotate` endpoint that swaps the current
//! signing key without dropping in-flight verifications.
//!
//! ## What this example demonstrates
//!
//! - A custom [`axess::local_idp::LocalIdpKeyStore`] implementation
//!   (`FileLocalIdpKeyStore`); RSA PEM, directory layout, atomic
//!   rotation via `current.kid` pointer file with rename().
//! - Mounting [`axess::local_idp::LocalIdp::router`] for the two
//!   standard discovery endpoints.
//! - Mounting a separate `/issue` endpoint that mints tokens via
//!   [`axess::local_idp::LocalIdp::mint`].
//! - Mounting an `/admin/rotate` endpoint that calls
//!   [`axess::local_idp::LocalIdp::rotate_signing_key`] and persists
//!   the swap through the file-backed store.
//!
//! ## Running
//!
//! ```sh
//! cargo run -p axess-example-local-idp
//! ```
//!
//! On first launch the example mints an RSA-2048 key, writes it to
//! `./keys/historical/v1.pem`, and marks it current. The store layout
//! looks like:
//!
//! ```text
//! keys/
//!   current.kid          # text file containing the current kid
//!   historical/
//!     v1.pem             # PKCS#8 PEM, every key (current or historical)
//! ```
//!
//! See `README.md` for the full curl walkthrough.

use axess::local_idp::{
    IssuanceError, LoadedKeys, LocalIdp, LocalIdpKeyStore, LocalIdpSigningKey, MintClaims,
};
use axess::{Clock, SystemClock};
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use chrono::Duration;
use rsa::RsaPrivateKey;
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;

const RSA_KEY_BITS: usize = 2048;
const ISSUER: &str = "http://localhost:3000";
const BIND: &str = "127.0.0.1:3000";

// ── Key store ────────────────────────────────────────────────────────────────

/// File-backed [`LocalIdpKeyStore`] using a small directory layout:
///
/// - `historical/{kid}.pem`; every key (current and historical) is
///   stored once, addressed by kid.
/// - `current.kid`; a text file naming the current kid; rotated
///   atomically via temp-file + rename.
///
/// The trait's `rotate` method receives the new [`LocalIdpSigningKey`]
/// the operator has already written into `historical/`; this impl only
/// has to flip the pointer file. That keeps the rotation path safe
/// against partial writes (the new key file existed before the pointer
/// flip, so a crash mid-rotation leaves the old key still current).
#[derive(Clone)]
struct FileLocalIdpKeyStore {
    root: PathBuf,
    // Serialise rotations so two concurrent operators can't race the
    // pointer flip. Reads (`load_all`) don't need the mutex; they
    // take a consistent snapshot via a single `current.kid` read.
    rotate_lock: Arc<Mutex<()>>,
}

#[derive(Debug, Error)]
enum FileKeyStoreError {
    #[error("io error reading {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("malformed key at {path}: {source}")]
    Malformed {
        path: String,
        #[source]
        source: axess::local_idp::LocalIdpKeyError,
    },
    #[error("current.kid pointer references missing key {kid}")]
    MissingCurrent { kid: String },
}

impl FileLocalIdpKeyStore {
    fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            rotate_lock: Arc::new(Mutex::new(())),
        }
    }

    fn historical_dir(&self) -> PathBuf {
        self.root.join("historical")
    }

    fn pointer_path(&self) -> PathBuf {
        self.root.join("current.kid")
    }

    fn key_path(&self, kid: &str) -> PathBuf {
        self.historical_dir().join(format!("{kid}.pem"))
    }

    fn read_pointer(&self) -> Result<String, FileKeyStoreError> {
        let path = self.pointer_path();
        std::fs::read_to_string(&path)
            .map(|s| s.trim().to_string())
            .map_err(|e| FileKeyStoreError::Io {
                path: path.display().to_string(),
                source: e,
            })
    }

    fn read_key(&self, kid: &str) -> Result<LocalIdpSigningKey, FileKeyStoreError> {
        let path = self.key_path(kid);
        let pem = std::fs::read_to_string(&path).map_err(|e| FileKeyStoreError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        LocalIdpSigningKey::from_rsa_pem(&pem, kid.to_string(), jsonwebtoken::Algorithm::RS256)
            .map_err(|e| FileKeyStoreError::Malformed {
                path: path.display().to_string(),
                source: e,
            })
    }

    fn list_kids(&self) -> Result<Vec<String>, FileKeyStoreError> {
        let dir = self.historical_dir();
        let entries = std::fs::read_dir(&dir).map_err(|e| FileKeyStoreError::Io {
            path: dir.display().to_string(),
            source: e,
        })?;
        let mut kids = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| FileKeyStoreError::Io {
                path: dir.display().to_string(),
                source: e,
            })?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("pem")
                && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
            {
                kids.push(stem.to_string());
            }
        }
        kids.sort();
        Ok(kids)
    }
}

impl LocalIdpKeyStore for FileLocalIdpKeyStore {
    type Error = FileKeyStoreError;

    fn load_all(
        &self,
    ) -> impl std::future::Future<Output = Result<LoadedKeys, Self::Error>> + Send {
        let store = self.clone();
        async move {
            let current_kid = store.read_pointer()?;
            let all_kids = store.list_kids()?;
            if !all_kids.iter().any(|k| k == &current_kid) {
                return Err(FileKeyStoreError::MissingCurrent { kid: current_kid });
            }
            let current = store.read_key(&current_kid)?;
            let mut historical = Vec::new();
            for kid in all_kids {
                if kid != current_kid {
                    historical.push(store.read_key(&kid)?);
                }
            }
            Ok(LoadedKeys {
                current,
                historical,
            })
        }
    }

    fn rotate(
        &self,
        new_current: LocalIdpSigningKey,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        let store = self.clone();
        async move {
            let rotate_guard = store.rotate_lock.lock().await;
            let new_kid = new_current.key_id().to_string();

            // The trait expects the new key's PEM to already live at
            // `historical/{kid}.pem`; operators wrote it before calling
            // rotate. Verify it's there so we don't flip the pointer at
            // a missing file.
            let key_path = store.key_path(&new_kid);
            if !key_path.exists() {
                return Err(FileKeyStoreError::MissingCurrent { kid: new_kid });
            }

            // Atomic pointer flip: write to a sibling temp file then
            // rename over `current.kid`. POSIX `rename(2)` is atomic on
            // the same filesystem; a crash before the rename leaves the
            // old pointer intact.
            let tmp_path = store.root.join("current.kid.tmp");
            std::fs::write(&tmp_path, &new_kid).map_err(|e| FileKeyStoreError::Io {
                path: tmp_path.display().to_string(),
                source: e,
            })?;
            std::fs::rename(&tmp_path, store.pointer_path()).map_err(|e| {
                FileKeyStoreError::Io {
                    path: store.pointer_path().display().to_string(),
                    source: e,
                }
            })?;
            drop(rotate_guard);
            Ok(())
        }
    }
}

// ── Bootstrap ────────────────────────────────────────────────────────────────

/// On a fresh checkout there's no key on disk. Generate one so the
/// example runs out of the box. Real deployments delete this code and
/// provision keys out-of-band (Vault, kubectl, openssl genrsa).
fn bootstrap_initial_key(root: &Path) -> std::io::Result<()> {
    let historical = root.join("historical");
    std::fs::create_dir_all(&historical)?;
    let pointer = root.join("current.kid");
    if pointer.exists() {
        return Ok(());
    }
    let mut rng = rsa::rand_core::OsRng;
    let key = RsaPrivateKey::new(&mut rng, RSA_KEY_BITS).expect("RSA key generation");
    let pem = key
        .to_pkcs8_pem(LineEnding::LF)
        .expect("PKCS#8 PEM encoding");
    std::fs::write(historical.join("v1.pem"), pem.as_bytes())?;
    std::fs::write(&pointer, "v1")?;
    tracing::info!(
        kid = "v1",
        path = %historical.join("v1.pem").display(),
        "bootstrapped initial signing key; delete the keys/ dir to reset"
    );
    Ok(())
}

/// Generate a new RSA key, write its PEM into `historical/`, and
/// return the kid + the parsed [`LocalIdpSigningKey`]. The two-phase
/// rotation flow ([`FileLocalIdpKeyStore::rotate`]) requires the key
/// file to exist before the pointer flip; this helper handles both.
fn mint_and_persist_new_key(
    store: &FileLocalIdpKeyStore,
    kid: &str,
) -> Result<LocalIdpSigningKey, Box<dyn std::error::Error + Send + Sync>> {
    let mut rng = rsa::rand_core::OsRng;
    let key = RsaPrivateKey::new(&mut rng, RSA_KEY_BITS)?;
    let pem = key.to_pkcs8_pem(LineEnding::LF)?;
    let path = store.key_path(kid);
    std::fs::write(&path, pem.as_bytes())?;
    let parsed =
        LocalIdpSigningKey::from_rsa_pem(&pem, kid.to_string(), jsonwebtoken::Algorithm::RS256)?;
    Ok(parsed)
}

// ── HTTP surface ─────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    idp: LocalIdp<FileLocalIdpKeyStore>,
    store: FileLocalIdpKeyStore,
    // `iat` / `exp` flow through this clock so a DST simulation can
    // pin token issuance time by swapping in a `MockClock`.
    clock: Arc<dyn Clock>,
}

#[derive(Deserialize)]
struct IssueRequest {
    subject: String,
    #[serde(default)]
    audience: Option<String>,
    /// Token lifetime in seconds. Defaults to 300 (5 minutes).
    #[serde(default = "default_ttl_secs")]
    ttl_secs: i64,
}

fn default_ttl_secs() -> i64 {
    300
}

#[derive(Serialize)]
struct IssueResponse {
    token: String,
}

async fn issue_handler(
    State(state): State<AppState>,
    Json(req): Json<IssueRequest>,
) -> Result<Json<IssueResponse>, (StatusCode, String)> {
    let now = state.clock.now();
    let mut claims =
        MintClaims::new(req.subject, now + Duration::seconds(req.ttl_secs)).with_issued_at(now);
    if let Some(aud) = req.audience {
        claims = claims.with_audience(aud);
    }
    let token = state
        .idp
        .mint(&claims)
        .await
        .map_err(|e: IssuanceError<FileKeyStoreError>| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("mint failed: {e}"),
            )
        })?;
    Ok(Json(IssueResponse { token }))
}

#[derive(Deserialize)]
struct RotateRequest {
    /// kid for the new key. The example's admin endpoint generates the
    /// key and persists it for you (a real ops flow would generate
    /// out-of-band and just call rotate).
    new_kid: String,
}

#[derive(Serialize)]
struct RotateResponse {
    new_current: String,
    historical: Vec<String>,
}

async fn rotate_handler(
    State(state): State<AppState>,
    Json(req): Json<RotateRequest>,
) -> Result<Json<RotateResponse>, (StatusCode, String)> {
    // Phase 1: generate the new key + write its PEM to historical/.
    let new_key = mint_and_persist_new_key(&state.store, &req.new_kid)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("keygen: {e}")))?;

    // Phase 2: ask LocalIdp to rotate. The store's `rotate` impl flips
    // the pointer atomically; LocalIdp updates its in-memory state +
    // JWKS so subsequent mints use the new key.
    state
        .idp
        .rotate_signing_key(new_key)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("rotate: {e}")))?;

    let jwks = state.idp.jwks().await;
    let kids: Vec<String> = jwks
        .keys
        .iter()
        .filter_map(|k| k.common.key_id.clone())
        .collect();
    Ok(Json(RotateResponse {
        new_current: req.new_kid,
        historical: kids,
    }))
}

async fn root_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        "axess-example-local-idp; try GET /.well-known/openid-configuration, GET /jwks.json, POST /issue, POST /admin/rotate\n",
    )
}

// ── main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let key_dir: PathBuf = std::env::var("LOCAL_IDP_KEY_DIR")
        .unwrap_or_else(|_| "./keys".to_string())
        .into();
    bootstrap_initial_key(&key_dir)?;

    let store = FileLocalIdpKeyStore::new(key_dir);
    let idp = LocalIdp::from_key_store(ISSUER, store.clone())
        .await?
        .with_max_ttl(Duration::hours(1));
    let state = AppState {
        idp: idp.clone(),
        store,
        clock: Arc::new(SystemClock),
    };

    // Mount the discovery router and the admin/issue endpoints on the
    // same axum app. The two `Router` instances live under disjoint
    // path prefixes so axum's nest/merge plumbing wires them cleanly.
    let admin_router: Router = Router::new()
        .route("/", get(root_handler))
        .route("/issue", post(issue_handler))
        .route("/admin/rotate", post(rotate_handler))
        .with_state(state);
    let app = admin_router.merge(idp.router());

    let listener = tokio::net::TcpListener::bind(BIND).await?;
    tracing::info!(
        bind = BIND,
        issuer = ISSUER,
        discovery_url = %idp.discovery_url(),
        "axess-example-local-idp listening"
    );
    axum::serve(listener, app).await?;
    Ok(())
}
