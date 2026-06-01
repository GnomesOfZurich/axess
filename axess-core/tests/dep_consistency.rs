//! Dependency consistency checks.
//!
//! 1. All workspace crates must have the same version.
//! 2. Critical ecosystem crates (axum, tower, http, hyper) must not have
//!    multiple semver-incompatible versions in the dependency tree.

/// All axess workspace crates (including examples) must share the same version.
#[test]
fn workspace_crates_have_same_version() {
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();

    let cargo_toml_paths = [
        "axess/Cargo.toml",
        "axess-core/Cargo.toml",
        "axess-factors/Cargo.toml",
        "axess-macros/Cargo.toml",
        "examples/sqlite/Cargo.toml",
        "examples/oauth/Cargo.toml",
        "examples/authz/Cargo.toml",
    ];

    let workspace_root_toml = std::fs::read_to_string(workspace_root.join("Cargo.toml"))
        .expect("failed to read workspace root Cargo.toml");
    let workspace_version = workspace_root_toml
        .lines()
        .find(|line| line.trim_start().starts_with("version = \""))
        .and_then(|line| line.split('"').nth(1))
        .expect("no version found in workspace root Cargo.toml")
        .to_string();

    let mut versions: Vec<(String, String)> = Vec::new();

    for path in &cargo_toml_paths {
        let full_path = workspace_root.join(path);
        let content = std::fs::read_to_string(&full_path)
            .unwrap_or_else(|e| panic!("failed to read {path}: {e}"));

        let version_line = content
            .lines()
            .find(|line| line.starts_with("version"))
            .unwrap_or_else(|| panic!("no version line found in {path}"));

        let version = if version_line.contains("workspace = true") {
            workspace_version.clone()
        } else {
            version_line
                .split('"')
                .nth(1)
                .unwrap_or_else(|| panic!("no literal version found in {path}"))
                .to_string()
        };

        versions.push((path.to_string(), version));
    }

    let expected = &versions[0].1;
    let mismatches: Vec<_> = versions.iter().filter(|(_, v)| v != expected).collect();

    assert!(
        mismatches.is_empty(),
        "\nWorkspace version mismatch! Expected all crates to be {expected}.\n\n{}\n",
        mismatches
            .iter()
            .map(|(path, ver)| format!("  {path}: {ver}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Run `cargo tree --duplicates` and assert that no critical crate appears
/// with multiple semver-incompatible versions.
///
/// `cargo tree -d` only outputs crates that have more than one version
/// in the tree. If a critical crate appears in that output at all, we have
/// a problem.
#[test]
fn no_duplicate_critical_crates() {
    let output = std::process::Command::new("cargo")
        .args([
            "tree",
            "--duplicates",
            "--depth=0",
            "--workspace",
            "--all-features",
        ])
        .output()
        .expect("failed to run `cargo tree`");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Crates where duplicate versions cause trait-mismatch compile errors.
    // The `cargo tree -d --depth=0` output lists only the top-level duplicated
    // crate names + versions (e.g. "http v0.2.12" and "http v1.3.1").
    // Crates where version mismatches cause compile errors (trait incompatibility).
    let critical = [
        // Axum ecosystem; trait compat requires same major.minor.
        "axum",
        "axum-core",
        // Tower ecosystem.
        "tower",
        "tower-layer",
        "tower-service",
        // HTTP types; axum, tower, hyper all share these.
        "http",
        "http-body",
        "http-body-util",
        // Hyper; the HTTP transport.
        "hyper",
        "hyper-util",
        // Serialization; must agree on derive macros.
        "serde",
    ];

    let mut duplicates = Vec::new();

    for crate_name in &critical {
        let prefix = format!("{crate_name} v");
        let versions: Vec<&str> = stdout
            .lines()
            .filter(|line| line.starts_with(&prefix))
            .collect();

        // Deduplicate; cargo tree -d sometimes lists the same version twice
        // when it appears in multiple feature configurations.
        let unique: std::collections::BTreeSet<&str> = versions.iter().copied().collect();

        if unique.len() > 1 {
            duplicates.push(format!(
                "  {crate_name}:\n{}",
                unique
                    .iter()
                    .map(|v| format!("    {v}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            ));
        }
    }

    assert!(
        duplicates.is_empty(),
        "\nFound multiple versions of critical crates in the dependency tree.\n\
         This will cause trait-mismatch compile errors.\n\n{}\n\n\
         Fix: align versions in Cargo.toml or add workspace [patch] entries.\n",
        duplicates.join("\n\n")
    );
}
