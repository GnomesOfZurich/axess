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
//!     v2.pem.new         # a key minted for a rotation not yet made
//!   rotated_at/
//!     v1                 # when v1 stopped being current
//!   retired/
//!     v0.pem             # keys taken out of the JWKS, kept for audit
//! ```
//!
//! A key can be retired only once its longest-lived token has expired, a kid
//! that was used (current, historical or retired) is never used again, and a
//! rotation that fails leaves no key file behind. A new key is staged as
//! `{kid}.pem.new` and takes its `.pem` name inside the rotation, so a crash
//! in between does not publish a key that has no rotation record. A
//! historical key from a store that kept no rotation record is stamped the
//! first time the store loads it, and can be retired that long after.
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
///   stored once, addressed by kid. A key minted for a rotation waits as
///   `historical/{kid}.pem.new`, which nothing reads, until `rotate` renames
///   it.
/// - `current.kid`; a text file naming the current kid; rotated
///   atomically via temp-file + rename.
///
/// The trait's `rotate` method receives the new [`LocalIdpSigningKey`]
/// the operator has already staged in `historical/`; this impl gives the
/// key file its `.pem` name and flips the pointer file. That keeps the
/// rotation path safe against partial writes (a crash mid-rotation leaves
/// the old key still current and the new one unpublished).
#[derive(Clone)]
struct FileLocalIdpKeyStore {
    root: PathBuf,
    // Serialise rotations so two concurrent operators can't race the
    // pointer flip. Reads (`load_all`) don't need the mutex; they
    // take a consistent snapshot via a single `current.kid` read.
    rotate_lock: Arc<Mutex<()>>,
    // Stamps the moment a key stops being current. The same clock the
    // retire check reads (the state's), so the two cannot disagree.
    clock: Arc<dyn Clock>,
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
    fn new(root: impl Into<PathBuf>, clock: Arc<dyn Clock>) -> Self {
        Self {
            root: root.into(),
            rotate_lock: Arc::new(Mutex::new(())),
            clock,
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

    /// Where a key minted for a rotation waits until `rotate` renames it to
    /// [`key_path`](Self::key_path). `list_kids` reads only `.pem` files.
    fn staged_key_path(&self, kid: &str) -> PathBuf {
        self.historical_dir().join(format!("{kid}.pem.new"))
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

    fn rotated_at_path(&self, kid: &str) -> PathBuf {
        self.root.join("rotated_at").join(kid)
    }

    /// Note the moment `kid` stopped being the current key. Every token it
    /// signed is valid for at most [`MAX_TTL_SECS`] after that.
    fn record_rotation(&self, kid: &str, at: chrono::DateTime<chrono::Utc>) -> std::io::Result<()> {
        let path = self.rotated_at_path(kid);
        std::fs::create_dir_all(path.parent().expect("a file in rotated_at"))?;
        std::fs::write(path, at.to_rfc3339())
    }

    /// Whether `kid` names a key this store holds or has archived. A kid that
    /// has been used is never used for another key: tokens and the archive
    /// are told apart by it.
    fn kid_taken(&self, kid: &str) -> bool {
        self.key_path(kid).exists()
            || self.staged_key_path(kid).exists()
            || self
                .root
                .join("retired")
                .join(format!("{kid}.pem"))
                .exists()
    }

    /// True when `kid` is a historical key that may still have live tokens:
    /// no rotation was recorded for it (an unreadable record), or fewer than
    /// [`MAX_TTL_SECS`] have passed since. Keys that do not exist or are
    /// current are not blocked here; the IdP answers for those.
    fn retire_blocked(&self, kid: &str) -> Result<bool, FileKeyStoreError> {
        let now = self.clock.now();
        if !valid_kid(kid) || !self.key_path(kid).exists() || self.read_pointer()? == kid {
            return Ok(false);
        }
        let recorded = std::fs::read_to_string(self.rotated_at_path(kid))
            .ok()
            .and_then(|t| chrono::DateTime::parse_from_rfc3339(t.trim()).ok());
        Ok(match recorded {
            Some(at) => now < at.to_utc() + Duration::seconds(MAX_TTL_SECS),
            None => true,
        })
    }

    /// Remove the staged key of a rotation that did not complete, so the
    /// next start does not find a key that never signed anything. The
    /// current key, and a key already renamed into place, are never removed.
    async fn discard_unused_key(&self, kid: &str) {
        let _guard = self.rotate_lock.lock().await;
        if valid_kid(kid)
            && self.read_pointer().is_ok_and(|current| current != kid)
            && let Err(e) = std::fs::remove_file(self.staged_key_path(kid))
        {
            tracing::warn!(error = %e, "could not remove the key of a failed rotation");
        }
    }

    /// Stamp every historical key that has no rotation record with the
    /// current time. A store that predates the records leaves its keys
    /// unstamped, and an unstamped key can never be retired; the stamp makes
    /// it retirable [`MAX_TTL_SECS`] after this first read, later than it
    /// strictly had to be and so safe.
    fn stamp_unrecorded(&self, current: &str, kids: &[String]) {
        for kid in kids.iter().filter(|k| k.as_str() != current) {
            if !self.rotated_at_path(kid).exists()
                && let Err(e) = self.record_rotation(kid, self.clock.now())
            {
                tracing::warn!(error = %e, kid = %kid, "could not stamp a key with no rotation record");
            }
        }
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
            store.stamp_unrecorded(&current_kid, &all_kids);
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

            // The trait expects the new key's PEM to be staged at
            // `historical/{kid}.pem.new`; operators wrote it before calling
            // rotate. Verify it's there so we don't flip the pointer at a
            // missing file, then give it the name `load_all` reads.
            let staged = store.staged_key_path(&new_kid);
            let key_path = store.key_path(&new_kid);
            if !staged.exists() {
                return Err(FileKeyStoreError::MissingCurrent { kid: new_kid });
            }
            std::fs::rename(&staged, &key_path).map_err(|e| FileKeyStoreError::Io {
                path: staged.display().to_string(),
                source: e,
            })?;

            // Any failure from here leaves the key unpublished again: it goes
            // back to its staged name, and the old key stays current.
            let flip = (|| {
                // Remember when the outgoing key stopped signing, so it is
                // not retired while its tokens are still valid.
                let outgoing = store.read_pointer()?;
                if outgoing != new_kid {
                    store
                        .record_rotation(&outgoing, store.clock.now())
                        .map_err(|e| FileKeyStoreError::Io {
                            path: store.rotated_at_path(&outgoing).display().to_string(),
                            source: e,
                        })?;
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
                })
            })();
            if let Err(e) = flip {
                if let Err(undo) = std::fs::rename(&key_path, &staged) {
                    tracing::warn!(error = %undo, "could not unpublish the key of a failed rotation");
                }
                return Err(e);
            }
            drop(rotate_guard);
            Ok(())
        }
    }

    fn retire(
        &self,
        key_id: &str,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        let store = self.clone();
        let kid = key_id.to_string();
        async move {
            let _guard = store.rotate_lock.lock().await;
            // A kid that is not a plain name cannot address a key file, and
            // the current key is never retired from under the pointer.
            if !valid_kid(&kid) || store.read_pointer()? == kid {
                return Ok(false);
            }
            let from = store.key_path(&kid);
            if !from.exists() {
                return Ok(false);
            }
            // Moved aside, not deleted: the file is the only copy of a key
            // that signed tokens, and the move is what a later audit needs.
            let retired_dir = store.root.join("retired");
            std::fs::create_dir_all(&retired_dir).map_err(|e| FileKeyStoreError::Io {
                path: retired_dir.display().to_string(),
                source: e,
            })?;
            let to = retired_dir.join(format!("{kid}.pem"));
            // `rename` replaces its target: an archived key is never replaced.
            if to.exists() {
                return Err(FileKeyStoreError::Io {
                    path: to.display().to_string(),
                    source: std::io::Error::from(std::io::ErrorKind::AlreadyExists),
                });
            }
            std::fs::rename(&from, &to).map_err(|e| FileKeyStoreError::Io {
                path: from.display().to_string(),
                source: e,
            })?;
            Ok(true)
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
    if store.kid_taken(kid) {
        return Err("that kid is already in use or archived".into());
    }
    let mut rng = rsa::rand_core::OsRng;
    let key = RsaPrivateKey::new(&mut rng, RSA_KEY_BITS)?;
    let pem = key.to_pkcs8_pem(LineEnding::LF)?;
    // Staged, not published: the key takes its `.pem` name inside `rotate`.
    let path = store.staged_key_path(kid);
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

/// Longest token lifetime `/issue` grants, in seconds. Matches the cap the
/// IdP itself enforces, so the request is refused here with a clear status
/// instead of failing inside the mint.
const MAX_TTL_SECS: i64 = 3600;

/// Validate an `/issue` request and compute the token's expiry. A lifetime
/// outside `1..=MAX_TTL_SECS` is refused (a huge value would overflow the
/// date arithmetic), and a token must name an audience: one without `aud` is
/// accepted by every verifier that does not pin one.
fn validated_expiry(
    now: chrono::DateTime<chrono::Utc>,
    ttl_secs: i64,
    audience: Option<&str>,
) -> Result<chrono::DateTime<chrono::Utc>, (StatusCode, String)> {
    if !(1..=MAX_TTL_SECS).contains(&ttl_secs) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("ttl_secs must be between 1 and {MAX_TTL_SECS}"),
        ));
    }
    if audience.is_none_or(|a| a.trim().is_empty()) {
        return Err((StatusCode::BAD_REQUEST, "audience is required".into()));
    }
    now.checked_add_signed(Duration::seconds(ttl_secs))
        .ok_or((StatusCode::BAD_REQUEST, "ttl_secs out of range".into()))
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
    let expires_at = validated_expiry(now, req.ttl_secs, req.audience.as_deref())?;
    let mut claims = MintClaims::new(req.subject, expires_at).with_issued_at(now);
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
    if state.store.kid_taken(&req.new_kid) {
        return Err((
            StatusCode::CONFLICT,
            "that kid is already in use or archived; pick a new one".into(),
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
    if let Err(e) = state.idp.rotate_signing_key(new_key).await {
        tracing::warn!(error = %e, "rotation failed");
        // The new key never became current; without this the next start
        // would load its file and publish it.
        state.store.discard_unused_key(&req.new_kid).await;
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "rotation failed".to_string(),
        ));
    }

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

#[derive(Deserialize)]
struct RetireRequest {
    kid: String,
}

/// Drop a historical key from the JWKS once no token it signed can still be
/// valid (rotation time plus [`MAX_TTL_SECS`]).
async fn retire_handler(
    State(state): State<AppState>,
    Json(req): Json<RetireRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    match state.store.retire_blocked(&req.kid) {
        Ok(false) => {}
        Ok(true) => {
            return Err((
                StatusCode::CONFLICT,
                format!(
                    "tokens signed by that key may still be valid; retire it {MAX_TTL_SECS} seconds after the rotation that replaced it"
                ),
            ));
        }
        Err(e) => {
            tracing::warn!(error = %e, "retire check failed");
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "retire failed".into()));
        }
    }
    match state.idp.retire_historical_key(&req.kid).await {
        Ok(true) => Ok(StatusCode::NO_CONTENT),
        Ok(false) => Err((StatusCode::NOT_FOUND, "no such historical key".into())),
        Err(IssuanceError::RetireCurrentKey) => Err((
            StatusCode::CONFLICT,
            "the current key cannot be retired; rotate first".into(),
        )),
        Err(e) => {
            tracing::warn!(error = %e, "retire failed");
            Err((StatusCode::INTERNAL_SERVER_ERROR, "retire failed".into()))
        }
    }
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

    // One clock for token times, rotation stamps and the retire check.
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let store = FileLocalIdpKeyStore::new(key_dir, clock.clone());
    let idp = LocalIdp::from_key_store(ISSUER, store.clone())
        .await?
        .with_max_ttl(Duration::seconds(MAX_TTL_SECS));
    // The mint and rotate endpoints need a bearer token. Use the one the
    // operator supplies, or draw a fresh one and print it once.
    let admin_token: Arc<str> = match std::env::var("LOCAL_IDP_ADMIN_TOKEN") {
        Ok(t) if t.len() >= 16 => t.into(),
        Ok(_) => return Err("LOCAL_IDP_ADMIN_TOKEN must be at least 16 characters".into()),
        Err(_) => {
            let mut bytes = [0u8; 24];
            axess::SecureRng::fill_bytes(&axess::SystemRng, &mut bytes);
            let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
            // Printed once to stderr, never through the log pipeline, where a
            // bearer credential would be retained and shipped.
            eprintln!("generated admin token for /issue and /admin/rotate: {token}");
            tracing::info!("generated an admin token; printed once to stderr");
            token.into()
        }
    };
    let state = AppState {
        idp: idp.clone(),
        store,
        clock,
        admin_token,
    };

    // Mount the discovery router and the admin/issue endpoints on the
    // same axum app. The two `Router` instances live under disjoint
    // path prefixes so axum's nest/merge plumbing wires them cleanly.
    let guarded: Router = Router::new()
        .route("/issue", post(issue_handler))
        .route("/admin/rotate", post(rotate_handler))
        .route("/admin/retire", post(retire_handler))
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

// A binary is its own crate root, so a plain `mod tests;` would look beside
// the file and cargo would read `src/bin/tests.rs` as another binary.
#[cfg(test)]
#[path = "local-idp/tests.rs"]
mod tests;
