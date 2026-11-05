//! The key TOTP secrets are sealed under is readable by its owner only, both
//! when it is created and when an older run left it wider.

#![cfg(unix)]

use axess_example_sqlite::web::app::factor_secret_key_at;
use std::os::unix::fs::PermissionsExt;

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("axess-key-{name}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir.join("factor-secret.key")
}

fn mode(path: &std::path::Path) -> u32 {
    std::fs::metadata(path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777
}

#[test]
fn a_new_key_file_is_private() {
    let path = scratch("new");
    factor_secret_key_at(&path).expect("key");
    assert_eq!(mode(&path), 0o600, "key file mode");
}

#[test]
fn a_wider_key_file_is_narrowed_and_the_key_kept() {
    let path = scratch("wide");
    let first = factor_secret_key_at(&path).expect("key");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
    let second = factor_secret_key_at(&path).expect("key");
    assert_eq!(first, second, "the key changed");
    assert_eq!(mode(&path), 0o600, "key file mode");
}

/// A start that finds a valid key reads it and narrows its mode; it does not
/// write the file, so a kill or a second start cannot leave it empty.
#[test]
fn an_existing_key_file_is_not_rewritten() {
    let path = scratch("keep");
    let hex = "ab".repeat(32);
    std::fs::write(&path, format!("{hex}\n")).expect("write");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
    let before = std::fs::metadata(&path).expect("metadata");

    let key = factor_secret_key_at(&path).expect("key");

    assert_eq!(key, [0xab; 32]);
    assert_eq!(
        std::fs::read_to_string(&path).expect("read"),
        format!("{hex}\n"),
        "the file was rewritten"
    );
    assert_eq!(mode(&path), 0o600);
    assert_eq!(
        std::os::unix::fs::MetadataExt::ino(&before),
        std::os::unix::fs::MetadataExt::ino(&std::fs::metadata(&path).expect("metadata")),
        "the file was replaced"
    );
}

/// Several starts at once on a fresh path all end up with the key of the one
/// that created the file, and the file holds that key.
#[test]
fn starts_racing_to_create_the_key_file_agree() {
    let path = scratch("race");
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let path = path.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                factor_secret_key_at(&path).expect("key")
            })
        })
        .collect();
    let keys: Vec<[u8; 32]> = handles
        .into_iter()
        .map(|h| h.join().expect("thread"))
        .collect();
    assert!(keys.iter().all(|k| *k == keys[0]), "starts disagree");
    let stored = std::fs::read_to_string(&path).expect("read");
    let hex: String = keys[0].iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(stored.trim(), hex);
    let leftovers = std::fs::read_dir(path.parent().expect("dir"))
        .expect("dir")
        .count();
    assert_eq!(leftovers, 1, "a staging file was left behind");
}

/// A file that holds no key is an error, not a reason to mint a new key.
#[test]
fn a_file_without_a_key_stops_the_start_and_is_left_alone() {
    let path = scratch("empty");
    std::fs::write(&path, "").expect("write");
    assert!(factor_secret_key_at(&path).is_err());
    assert_eq!(std::fs::read_to_string(&path).expect("read"), "");
}
