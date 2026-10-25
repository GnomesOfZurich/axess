//! # axess-example-workload-identity, `--bin local-idp`
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
//! cargo run -p axess-example-workload-identity --bin local-idp
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
//! `POST /issue` and `POST /admin/rotate` require
//! `Authorization: Bearer <token>`. Set `LOCAL_IDP_ADMIN_TOKEN` (16+
//! characters) or read the one generated at startup from the log.
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

// ── Key files ────────────────────────────────────────────────────────────────

/// Write a private key to a NEW file readable by the owner only. Refuses an
/// existing path, so a key that is already in use is never overwritten.
fn write_private_key(path: &Path, pem: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(pem)
}

/// A key id becomes a file name, so it must not be able to name a
/// different path: letters, digits, `-` and `_`, 1 to 64 characters.
fn valid_kid(kid: &str) -> bool {
    (1..=64).contains(&kid.len())
        && kid
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
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
    write_private_key(&historical.join("v1.pem"), pem.as_bytes())?;
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
    if !valid_kid(kid) {
        return Err("new_kid must be 1 to 64 characters of letters, digits, '-' or '_'".into());
    }
    let mut rng = rsa::rand_core::OsRng;
    let key = RsaPrivateKey::new(&mut rng, RSA_KEY_BITS)?;
    let pem = key.to_pkcs8_pem(LineEnding::LF)?;
    let path = store.key_path(kid);
    write_private_key(&path, pem.as_bytes())?;
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
    /// Bearer token the mint and rotate endpoints require.
    admin_token: Arc<str>,
}

/// Admit only requests carrying `Authorization: Bearer <admin token>`.
///
/// `/issue` mints a token for any subject and `/admin/rotate` replaces the
/// signing key, so neither may be open to whoever can reach the port. The
/// comparison does not stop at the first differing byte.
async fn require_admin(
    State(state): State<AppState>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let presented = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    let expected = state.admin_token.as_bytes();
    let presented = presented.as_bytes();
    let same_length = presented.len() == expected.len();
    let diff = expected
        .iter()
        .zip(presented.iter().chain(std::iter::repeat(&0)))
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    if same_length && diff == 0 {
        next.run(request).await
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
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
    if req.ttl_secs <= 0 {
        return Err((StatusCode::BAD_REQUEST, "ttl_secs must be positive".into()));
    }
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
            // The cause goes to the log; the caller learns only that it failed.
            tracing::warn!(error = %e, "mint failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "mint failed".to_string())
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
    if !valid_kid(&req.new_kid) {
        return Err((
            StatusCode::BAD_REQUEST,
            "new_kid must be 1 to 64 characters of letters, digits, '-' or '_'".into(),
        ));
    }
    let new_key = mint_and_persist_new_key(&state.store, &req.new_kid).map_err(|e| {
        tracing::warn!(error = %e, "key generation failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "key generation failed (does that kid already exist?)".to_string(),
        )
    })?;

    // Phase 2: ask LocalIdp to rotate. The store's `rotate` impl flips
    // the pointer atomically; LocalIdp updates its in-memory state +
    // JWKS so subsequent mints use the new key.
    state.idp.rotate_signing_key(new_key).await.map_err(|e| {
        tracing::warn!(error = %e, "rotation failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "rotation failed".to_string(),
        )
    })?;

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
        "axess-example-workload-identity local-idp; try GET /.well-known/openid-configuration, GET /jwks.json, POST /issue, POST /admin/rotate\n",
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
    // The mint and rotate endpoints need a bearer token. Use the one the
    // operator supplies, or draw a fresh one and print it once.
    let admin_token: Arc<str> = match std::env::var("LOCAL_IDP_ADMIN_TOKEN") {
        Ok(t) if t.len() >= 16 => t.into(),
        Ok(_) => return Err("LOCAL_IDP_ADMIN_TOKEN must be at least 16 characters".into()),
        Err(_) => {
            let mut bytes = [0u8; 24];
            axess::SecureRng::fill_bytes(&axess::SystemRng, &mut bytes);
            let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
            tracing::info!(token = %token, "generated an admin token for /issue and /admin/rotate");
            token.into()
        }
    };
    let state = AppState {
        idp: idp.clone(),
        store,
        clock: Arc::new(SystemClock),
        admin_token,
    };

    // Mount the discovery router and the admin/issue endpoints on the
    // same axum app. The two `Router` instances live under disjoint
    // path prefixes so axum's nest/merge plumbing wires them cleanly.
    let guarded: Router = Router::new()
        .route("/issue", post(issue_handler))
        .route("/admin/rotate", post(rotate_handler))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_admin,
        ))
        .with_state(state);
    let admin_router: Router = Router::new().route("/", get(root_handler)).merge(guarded);
    let app = admin_router.merge(idp.router());

    let listener = tokio::net::TcpListener::bind(BIND).await?;
    tracing::info!(
        bind = BIND,
        issuer = ISSUER,
        discovery_url = %idp.discovery_url(),
        "local IdP listening"
    );
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_kid_cannot_name_another_path() {
        for bad in [
            "",
            "../escape",
            "a/b",
            "a\\b",
            "..",
            "v1.pem",
            "a b",
            &"k".repeat(65),
        ] {
            assert!(!valid_kid(bad), "{bad:?} must be refused");
        }
        for good in ["v1", "2026-10_rotation", "K"] {
            assert!(valid_kid(good), "{good:?} must be accepted");
        }
    }

    #[test]
    fn a_private_key_file_is_never_overwritten_and_is_owner_only() {
        let dir = std::env::temp_dir().join(format!("local-idp-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("k.pem");
        write_private_key(&path, b"first").unwrap();
        assert!(write_private_key(&path, b"second").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "group/other bits must be clear: {mode:o}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
